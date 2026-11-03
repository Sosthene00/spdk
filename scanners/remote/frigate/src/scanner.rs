use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use bitcoin::absolute::Height;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use electrum_streaming_client::notification::Notification;
use electrum_streaming_client::response::SpSubscribeResp;
use electrum_streaming_client::{ElectrumScriptHash, Event, request, response};
use futures::channel::mpsc::{Receiver, Sender, channel};
use futures::{SinkExt as _, StreamExt as _};
use log::{debug, error, info, warn};
use silentpayments::receiving::Receiver as SpReceiver;
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, generate_script_pubkey_from_output_key,
};
use spdk_core::scanner::{DiscoveredOutput, ScanResult, Scanner};
use tokio::time::sleep;

use crate::client::FrigateClient;

/// Total scan-setup attempts: one initial attempt plus [`SUBSCRIBE_RETRIES`]
/// retries of the whole connect + subscribe.
const SUBSCRIBE_ATTEMPTS: u32 = SUBSCRIBE_RETRIES + 1;
/// Retries of the whole connect + subscribe per failure episode.
const SUBSCRIBE_RETRIES: u32 = 3;
/// Backoff between connect + subscribe attempts.
const SUBSCRIBE_RETRY_BACKOFF: Duration = Duration::from_secs(5);
/// Consecutive transaction-fetch failures (counted after each call's request
/// retries were exhausted) tolerated before the connection is treated as
/// broken and the scan task ends.
const MAX_CONSECUTIVE_TX_FETCH_FAILURES: u32 = 10;

/// A processed mempool discovery (height `0` history entry) whose outputs are ours, held
/// until the script-hash subscription reports a confirmation height for its transaction.
///
/// The Frigate protocol sends a mempool transaction once on the subscription and must not
/// re-notify it when it confirms, so confirmation is observed from the canonical source:
/// the script's history, fetched when one of its script-hash notifications fires.
struct MempoolHolding {
    discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
}

pub struct FrigateScanner {
    client: FrigateClient,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    labels: Option<Vec<u32>>,
    /// Server address, kept so a failed connect + subscribe can be retried on
    /// a fresh connection.
    host_url: String,
}

impl FrigateScanner {
    pub async fn new(
        host_url: String,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        labels: Option<Vec<u32>>,
    ) -> anyhow::Result<Self> {
        let client = FrigateClient::connect(&host_url).await?;
        Ok(Self {
            client,
            b_scan,
            sp_receiver,
            labels,
            host_url,
        })
    }

    /// Performs the whole scan setup — connection (plain TCP or `ssl://`
    /// TLS) plus silent-payment
    /// subscribe — as one unit: one initial attempt plus
    /// [`SUBSCRIBE_RETRIES`] retries with a [`SUBSCRIBE_RETRY_BACKOFF`] sleep
    /// between attempts. Every attempt after the first uses a fresh
    /// connection: the previous client is dropped (its worker aborted) because
    /// its connect or subscribe failed.
    ///
    /// Returns the subscribe response of the successful attempt, or the last
    /// error after all attempts failed; the caller then logs
    /// `frigate scan failed permanently: <e>` and ends the scan, closing the
    /// receivers.
    async fn connect_and_subscribe(
        &mut self,
        requested_start: u32,
    ) -> anyhow::Result<SpSubscribeResp> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=SUBSCRIBE_ATTEMPTS {
            if attempt > 1 {
                self.client.worker.abort();
                match FrigateClient::connect(&self.host_url).await {
                    Ok(client) => self.client = client,
                    Err(e) => {
                        let err = anyhow::anyhow!(
                            "connect attempt {attempt}/{SUBSCRIBE_ATTEMPTS} failed: {e}"
                        );
                        warn!("{err}");
                        last_err = Some(err);
                        sleep(SUBSCRIBE_RETRY_BACKOFF).await;
                        continue;
                    }
                }
            }

            let subscribe_params = request::SpSubscribe {
                scan_priv_key: self.b_scan,
                spend_pub_key: self.sp_receiver.receiving_code().m_pubkey(),
                start_height: Some(requested_start),
                labels: self.labels.clone(),
            };
            match self.client.subscribe(subscribe_params).await {
                Ok(sub) => {
                    info!(
                        "subscribed: address={} start_height={} (requested {requested_start}) labels={:?}",
                        sub.address, sub.start_height, sub.labels
                    );
                    return Ok(sub);
                }
                Err(e) => {
                    let err = anyhow::anyhow!(
                        "subscribe attempt {attempt}/{SUBSCRIBE_ATTEMPTS} failed: {e}"
                    );
                    warn!("{err}");
                    last_err = Some(err);
                    if attempt < SUBSCRIBE_ATTEMPTS {
                        sleep(SUBSCRIBE_RETRY_BACKOFF).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("connect + subscribe failed after {SUBSCRIBE_ATTEMPTS} attempts")
        }))
    }

    /// Reports whether the client's consecutive transaction-fetch failures
    /// exceeded [`MAX_CONSECUTIVE_TX_FETCH_FAILURES`]; the connection is then
    /// treated as broken: the permanent-failure line is logged and the scan
    /// task must end, closing the receivers.
    fn tx_connection_broken(&self) -> bool {
        let failures = self.client.consecutive_tx_fetch_failures();
        if failures > MAX_CONSECUTIVE_TX_FETCH_FAILURES {
            error!(
                "frigate scan failed permanently: {failures} consecutive transaction-fetch failures (limit {MAX_CONSECUTIVE_TX_FETCH_FAILURES}); connection treated as broken"
            );
            true
        } else {
            false
        }
    }

    /// Starts a scan and keeps listening for confirmed spends of discovered outputs.
    ///
    /// Mempool discoveries are not skipped: the Frigate protocol sends a mempool
    /// transaction (history entry with height `0`) once on the subscription and must not
    /// re-notify it when it confirms, so the scanner retrieves the transaction, derives
    /// the owned outputs, subscribes to their script hashes, and holds the result. The
    /// script-hash subscription is the canonical source of confirmation height: once a
    /// held discovery's txid shows a confirmation height in its script's history, the
    /// discovery is emitted on the scan receiver with that height and the hash of the
    /// block header at it, and the holding is dropped.
    ///
    /// The scan receiver stays open in monitor mode and keeps delivering discoveries
    /// for the life of the task: per the Frigate protocol, the first progress `1.0`
    /// notification ends the historical scan and subsequent notifications are live
    /// updates carrying newly found transactions, whose discoveries are forwarded on
    /// the scan channel even at heights past the range end. The task ends when the
    /// consumer drops the receiver (a send error stops the scan output while spent
    /// monitoring keeps running). The spent receiver delivers confirmed spends of
    /// discovered outputs over the same lifetime.
    ///
    /// The historical range is enforced client-side: the Frigate protocol only carries a
    /// start height, so confirmed history entries past the inclusive end are dropped
    /// while the historical scan is running, and the historical scan completes when the
    /// server reports progress `1.0` or the range end is seen. When the end equals the
    /// current tip (tip-sync usage) the behavior is identical to a scan that runs until
    /// progress `1.0`.
    ///
    /// Failure semantics: transient request failures are retried inside the
    /// client (3 attempts per request, 500 ms × attempt backoff). A
    /// transaction whose fetch still fails is error!-logged with its txid and
    /// skipped, so one poisoned transaction never kills the scan; more than
    /// ten consecutive fetch failures end the task as a broken connection. A
    /// failed subscribe or an ended event stream retries the whole connect +
    /// subscribe with backoff; when that fails too, the task logs
    /// `frigate scan failed permanently: <e>` and returns, closing both
    /// receivers. A closed receiver after that log means the scan FAILED —
    /// it must never be read as "no outputs found"; only a receiver that
    /// closes with no error-level log stands for a normal end. A reconnect
    /// re-delivers the full subscription history from the start height, so
    /// discoveries already sent may be sent again; consumers should treat
    /// `ScanResult`s as idempotent per outpoint.
    pub fn scan_blocks_with_spent_outputs(
        self,
        range: std::ops::RangeInclusive<Height>,
    ) -> (Receiver<ScanResult>, Receiver<HashSet<OutPoint>>) {
        self.start_scan(range, true)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "scan orchestration will be refactored later"
    )]
    fn start_scan(
        mut self,
        range: std::ops::RangeInclusive<Height>,
        monitor_spent: bool,
    ) -> (Receiver<ScanResult>, Receiver<HashSet<OutPoint>>) {
        let requested_start = range.start().to_consensus_u32();
        let end_height = range.end().to_consensus_u32();
        info!(
            "start: {} end: {}",
            range.start().to_consensus_u32(),
            range.end().to_consensus_u32(),
        );

        let (scan_tx, scan_rx) = channel(100_000);
        let (mut spent_tx, spent_rx) = channel(100_000);

        tokio::spawn(async move {
            let mut scan_tx = Some(scan_tx);
            let mut tracked_scripts: HashMap<ElectrumScriptHash, HashSet<OutPoint>> =
                HashMap::new();
            let mut inspected_txids: HashMap<ElectrumScriptHash, HashSet<Txid>> = HashMap::new();
            let mut highest_confirmed_height: u32 = 0;
            // Mempool discoveries awaiting confirmation, indexed by the script hash of
            // every discovered output (a discovery with outputs under several scripts is
            // indexed under each), so the script-hash notification of any of its outputs
            // finds it.
            let mut mempool_holdings: HashMap<ElectrumScriptHash, HashMap<Txid, MempoolHolding>> =
                HashMap::new();
            let mut historical_scan_complete = false;
            // Per the Frigate protocol, the first progress `1.0` notification ends the
            // historical scan; subsequent notifications are live updates carrying newly
            // found transactions. Once that boundary is crossed in monitor mode, the
            // range-end filter no longer applies: live discoveries past the requested
            // range end must still be delivered on the scan channel.
            let mut live_updates = false;
            // Set when the finite scan reaches the range end: the task then
            // ends in success and must not reconnect.
            let mut scan_complete = false;

            if let Err(e) = self.connect_and_subscribe(requested_start).await {
                error!("frigate scan failed permanently: {e}");
                return;
            }

            loop {
                // A connection that fails every transaction fetch (e.g. a
                // friglet rejecting transaction.get for confirmed txs) keeps
                // the event stream alive, so the consecutive-failure count is
                // the only signal: end the task on it before the next event.
                if self.tx_connection_broken() {
                    return;
                }

                while let Some(event) = self.client.events.next().await {
                    let Event::Notification(notification) = event else {
                        continue;
                    };

                    match notification {
                        Notification::SpSubscribe(sp_subscribe_notification) => {
                            let histories = sp_subscribe_notification.history;
                            let progress = sp_subscribe_notification.progress;
                            let mut secrets_by_height: BTreeMap<u32, HashMap<Txid, PublicKey>> =
                                BTreeMap::new();
                            let mut mempool_tx_tweaks: Vec<(Txid, PublicKey)> = Vec::new();

                            debug!("Received history {histories:#?}");
                            info!("Found a total of {} output(s)", histories.len());

                            for history in &histories {
                                if history.height == 0 {
                                    // The protocol sends a mempool transaction once on the
                                    // subscription and must not re-notify it on confirmation;
                                    // process it now and hold the result until the script-hash
                                    // subscription reports the confirmation.
                                    debug!("Processing mempool transaction {}", history.tx_hash);
                                    mempool_tx_tweaks.push((history.tx_hash, history.tweak_key));
                                    continue;
                                }

                                highest_confirmed_height =
                                    highest_confirmed_height.max(history.height);
                                if history.height > end_height && !(monitor_spent && live_updates) {
                                    debug!(
                                        "Skipping history transaction {} at height {} past range end {end_height}",
                                        history.tx_hash, history.height
                                    );
                                    continue;
                                }

                                secrets_by_height
                                    .entry(history.height)
                                    .or_default()
                                    .insert(history.tx_hash, history.tweak_key);
                            }

                            for (height, tx_tweaks) in secrets_by_height {
                                let blk_header = match self.client.get_block_header(height).await {
                                    Ok(header) => header,
                                    Err(e) => {
                                        error!(
                                            "Unable to fetch block header at height {height}: {e}"
                                        );
                                        return;
                                    }
                                };
                                let blkheight = match Height::from_consensus(height) {
                                    Ok(height) => height,
                                    Err(e) => {
                                        error!(
                                            "Invalid block height {height} received from Frigate: {e}"
                                        );
                                        return;
                                    }
                                };

                                for (txid, tweak) in tx_tweaks {
                                    let full_tx = match self.client.get_transaction(txid).await {
                                        Ok(full_tx) => full_tx,
                                        Err(e) => {
                                            error!(
                                                "Skipping transaction {txid} after all retry attempts failed: {e}"
                                            );
                                            if self.tx_connection_broken() {
                                                return;
                                            }
                                            continue;
                                        }
                                    };
                                    let discovered_outputs = match process_outputs(
                                        &full_tx.tx,
                                        &self.b_scan,
                                        &self.sp_receiver,
                                        &tweak,
                                    ) {
                                        Ok(outputs) => outputs,
                                        Err(e) => {
                                            warn!("Skipping malformed transaction {txid}: {e}");
                                            continue;
                                        }
                                    };

                                    if monitor_spent
                                        && let Err(e) = subscribe_outputs(
                                            &mut self.client,
                                            &mut tracked_scripts,
                                            &discovered_outputs,
                                            &mut inspected_txids,
                                            &mut spent_tx,
                                            monitor_spent,
                                        )
                                        .await
                                    {
                                        error!(
                                            "Unable to subscribe discovered output scripts / sweep pre-subscription spends: {e}; stopping monitor"
                                        );
                                        return;
                                    }

                                    let scan_res = ScanResult {
                                        blkheight,
                                        blkhash: blk_header.header.block_hash(),
                                        discovered_inputs: HashSet::new(),
                                        discovered_outputs,
                                    };

                                    if let Some(sender) = scan_tx.as_mut() {
                                        if let Err(e) = sender.send(scan_res).await {
                                            error!(
                                                "Unable to send scan result: {e}; stopping scan output"
                                            );
                                            scan_tx = None;
                                            if !monitor_spent {
                                                return;
                                            }
                                        } else {
                                            info!("Scan result sent!");
                                        }
                                    }
                                }
                            }

                            // Mempool discoveries: the protocol requires retrieving every
                            // announced transaction and subscribing to all owned outputs, in
                            // both modes; the ScanResults surface only in monitor mode (see
                            // `Scanner::scan_blocks` for the finite-mode contract).
                            for (txid, tweak) in mempool_tx_tweaks {
                                let full_tx = match self.client.get_transaction(txid).await {
                                    Ok(full_tx) => full_tx,
                                    Err(e) => {
                                        error!(
                                            "Skipping mempool transaction {txid} after all retry attempts failed: {e}"
                                        );
                                        if self.tx_connection_broken() {
                                            return;
                                        }
                                        continue;
                                    }
                                };
                                let discovered_outputs = match process_outputs(
                                    &full_tx.tx,
                                    &self.b_scan,
                                    &self.sp_receiver,
                                    &tweak,
                                ) {
                                    Ok(outputs) => outputs,
                                    Err(e) => {
                                        warn!("Skipping malformed mempool transaction {txid}: {e}");
                                        continue;
                                    }
                                };
                                if discovered_outputs.is_empty() {
                                    debug!(
                                        "Mempool transaction {txid} holds no recognizable output; nothing to hold"
                                    );
                                    continue;
                                }

                                // Their scripts must be tracked so the confirmation (and any
                                // later spend) arrives via the existing script-hash
                                // notifications.
                                if let Err(e) = subscribe_outputs(
                                    &mut self.client,
                                    &mut tracked_scripts,
                                    &discovered_outputs,
                                    &mut inspected_txids,
                                    &mut spent_tx,
                                    monitor_spent,
                                )
                                .await
                                {
                                    error!(
                                        "Unable to subscribe discovered output scripts / sweep pre-subscription spends: {e}; stopping monitor"
                                    );
                                    return;
                                }

                                if !monitor_spent {
                                    debug!(
                                        "Mempool transaction {txid} processed in finite scan; its ScanResult surfaces only in monitor mode"
                                    );
                                    continue;
                                }

                                for output in discovered_outputs.values() {
                                    let script_hash = ElectrumScriptHash::from(
                                        output.txout.script_pubkey.as_script(),
                                    );
                                    mempool_holdings
                                        .entry(script_hash)
                                        .or_default()
                                        .entry(txid)
                                        .or_insert_with(|| MempoolHolding {
                                            discovered_outputs: discovered_outputs.clone(),
                                        });
                                }
                                info!("Holding mempool discovery {txid} until it confirms");
                            }

                            // A discovery that confirmed between the server's history snapshot
                            // and the script-hash subscriptions above gets no status-change
                            // notification for that script, so check the held scripts once
                            // here. `mempool_holdings` is empty before this notification's
                            // processing, so its keys are exactly the freshly held scripts
                            // (plus any holding from an earlier notification, for which the
                            // check is idempotent).
                            if monitor_spent {
                                let script_hashes: Vec<ElectrumScriptHash> =
                                    mempool_holdings.keys().copied().collect();
                                for script_hash in script_hashes {
                                    match self.client.get_history(script_hash).await {
                                        Ok(history) => {
                                            emit_confirmed_mempool_discoveries(
                                                &mut self.client,
                                                script_hash,
                                                &mut mempool_holdings,
                                                &history,
                                                &mut scan_tx,
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            error!(
                                                "Unable to inspect history for script hash {script_hash}: {e}"
                                            );
                                        }
                                    }
                                }
                            }

                            // Per the Frigate protocol, the first progress `1.0` notification
                            // ends the historical scan; the histories above were still
                            // filtered by the range end, and from the next notification on,
                            // monitor mode forwards every discovery (`live_updates` above).
                            if progress >= 1.0f32 {
                                live_updates = true;
                            }

                            // The server streams history ordered by height, so once the highest
                            // confirmed height seen reaches the (client-enforced) range end the
                            // inclusive range is fully covered even if the server's progress is
                            // still below 1.0.
                            if highest_confirmed_height >= end_height || progress >= 1.0f32 {
                                if !monitor_spent {
                                    info!(
                                        "Range end {end_height} reached (highest confirmed height {highest_confirmed_height}, progress {progress}); scan complete, stopping early"
                                    );
                                    scan_complete = true;
                                    break;
                                }

                                if !historical_scan_complete {
                                    historical_scan_complete = true;
                                    info!(
                                        "Range end {end_height} reached (highest confirmed height {highest_confirmed_height}, progress {progress}); monitoring spent outputs and mempool confirmations"
                                    );
                                }
                            }
                        }
                        Notification::ScriptHash(notification) if monitor_spent => {
                            let script_hash = notification.script_hash();

                            // One history fetch serves both the mempool-confirmation check and
                            // the spend detection below.
                            let history = match self.client.get_history(script_hash).await {
                                Ok(history) => history,
                                Err(e) => {
                                    error!(
                                        "Unable to inspect history for script hash {script_hash}: {e}"
                                    );
                                    continue;
                                }
                            };

                            // Before spend detection: a held mempool discovery is confirmed
                            // once its txid shows a confirmation height in the script's history
                            // (the canonical confirmation channel); emit it with the confirmed
                            // block's height and hash, then drop the holding.
                            emit_confirmed_mempool_discoveries(
                                &mut self.client,
                                script_hash,
                                &mut mempool_holdings,
                                &history,
                                &mut scan_tx,
                            )
                            .await;

                            let spent = confirmed_spent_outpoints(
                                &mut self.client,
                                &history,
                                script_hash,
                                &tracked_scripts,
                                &mut inspected_txids,
                            )
                            .await;

                            if spent.is_empty() {
                                continue;
                            }

                            for outpoints in tracked_scripts.values_mut() {
                                outpoints.retain(|outpoint| !spent.contains(outpoint));
                            }
                            tracked_scripts.retain(|_, outpoints| !outpoints.is_empty());

                            if let Err(e) = spent_tx.send(spent).await {
                                error!("Unable to send spent output update: {e}; stopping monitor");
                                return;
                            }
                        }
                        Notification::ScriptHash(_) => {
                            debug!("Ignoring script-hash notification in finite scan");
                        }
                        notification => {
                            debug!("Ignoring unsupported notification: {notification:?}");
                        }
                    }
                }

                if scan_complete {
                    info!("frigate scan complete; receivers closed after a successful scan");
                    return;
                }

                // The event stream ended mid-scan: the connection is gone.
                // Retry the whole connect + subscribe on a fresh connection;
                // the server re-sends the full subscription history, so
                // already-delivered discoveries may be delivered again.
                warn!("frigate event stream ended mid-scan; reconnecting");
                if let Err(e) = self.connect_and_subscribe(requested_start).await {
                    error!("frigate scan failed permanently: {e}");
                    return;
                }
            }
        });

        (scan_rx, spent_rx)
    }
}

impl Scanner for FrigateScanner {
    /// Scans the inclusive `range` for silent payments outputs.
    ///
    /// Finite scan contract: this mode reports confirmed history only. Mempool
    /// transactions (history entries with height `0`) are still processed and their
    /// output scripts are subscribed (the protocol requires subscribing to every
    /// announced transaction), but their `ScanResults` deliberately do not surface here:
    /// without the script-hash monitor there is no confirmation channel to learn a
    /// confirmation height from, and a finite scan must not report an unconfirmed
    /// discovery. Use [`FrigateScanner::scan_blocks_with_spent_outputs`] to see mempool
    /// discoveries; each is emitted there when it confirms.
    ///
    /// The range end is enforced client-side (the Frigate protocol only carries a start
    /// height): history entries past the end are dropped, and the scan stops as soon as
    /// the end is reached or the server reports progress `1.0`. When the end equals the
    /// current tip (tip-sync usage) the behavior is identical to before: the scan runs
    /// until progress `1.0`.
    ///
    /// Failure semantics: transient request failures are retried inside the
    /// client (3 attempts per request, 500 ms × attempt backoff). A
    /// transaction whose fetch still fails is error!-logged with its txid and
    /// skipped, so one poisoned transaction never kills the scan; more than
    /// ten consecutive fetch failures end the task as a broken connection. A
    /// failed subscribe or an ended event stream retries the whole connect +
    /// subscribe with backoff; when that fails too, the task logs
    /// `frigate scan failed permanently: <e>` and returns, closing the
    /// receiver. A closed receiver after that log means the scan FAILED —
    /// it must never be read as "no outputs found"; only a receiver that
    /// closes with no error-level log stands for the normal end (the range
    /// end was reached). A reconnect re-delivers the full subscription
    /// history from the start height, so discoveries already sent may be sent
    /// again; consumers should treat `ScanResult`s as idempotent per
    /// outpoint.
    fn scan_blocks(self, range: std::ops::RangeInclusive<Height>) -> Receiver<ScanResult> {
        let (scan_rx, spent_rx) = self.start_scan(range, false);
        drop(spent_rx);
        scan_rx
    }
}

/// Subscribes to the script hash of every discovered output and tracks its outpoints.
///
/// For a script tracked for the first time, the first successful
/// `scripthash_subscribe` is immediately followed by a confirmed-spend sweep: the
/// script's confirmed history is fetched and `confirmed_spent_outpoints` is run over
/// it, any already-spent outpoints are removed from `tracked_scripts`, and the result
/// is forwarded on the spent channel exactly like a notification-driven spend (monitor
/// mode only). The sweep runs once per newly tracked script: the Frigate protocol
/// reports a script's pre-existing history only in the subscribe response (`Some`
/// status means the script already has history) and does not re-notify it, so without
/// this sweep the output of a rescan/recovery scenario that was spent long ago would
/// stay tracked as spendable.
///
/// Scope of the sweep: it covers confirmed spends that pre-date the subscription.
/// Spends inside the historical scan window after a discovery are NOT covered by this
/// path — the local scanner covers those via block inputs, the frigate path does not.
///
/// Subscribe and history-fetch errors are logged and skipped (the script stays
/// tracked; a later script-hash notification re-runs spend detection for it), and so are
/// transaction-fetch failures inside the sweep, which leave the transaction uninspected
/// for a later script-hash notification to retry. Only a failure to forward a spend on
/// the spent channel is fatal, matching the notification-driven spend path.
async fn subscribe_outputs(
    client: &mut FrigateClient,
    tracked_scripts: &mut HashMap<ElectrumScriptHash, HashSet<OutPoint>>,
    discovered_outputs: &HashMap<OutPoint, DiscoveredOutput>,
    inspected_txids: &mut HashMap<ElectrumScriptHash, HashSet<Txid>>,
    spent_tx: &mut Sender<HashSet<OutPoint>>,
    monitor_spent: bool,
) -> anyhow::Result<()> {
    for (outpoint, output) in discovered_outputs {
        let script_hash = ElectrumScriptHash::from(output.txout.script_pubkey.as_script());
        let first_output_for_script = !tracked_scripts.contains_key(&script_hash);
        tracked_scripts
            .entry(script_hash)
            .or_default()
            .insert(*outpoint);

        if !first_output_for_script {
            continue;
        }

        let request = request::ScriptHashSubscribe { script_hash };
        match client.scripthash_subscribe(request).await {
            // A `Some` status means the script already has history: its
            // pre-subscription transactions will not re-notify, hence the sweep below.
            Ok(status) => {
                debug!(
                    "Subscribed to script hash {script_hash} (already had history: {})",
                    status.is_some()
                );
            }
            Err(e) => {
                error!("Unable to subscribe to script hash {script_hash}: {e}");
                continue;
            }
        }

        if !monitor_spent {
            continue;
        }

        let history = match client.get_history(script_hash).await {
            Ok(history) => history,
            Err(e) => {
                error!("Unable to inspect history for script hash {script_hash}: {e}");
                continue;
            }
        };
        let spent = confirmed_spent_outpoints(
            client,
            &history,
            script_hash,
            tracked_scripts,
            inspected_txids,
        )
        .await;

        if spent.is_empty() {
            continue;
        }

        if let Some(outpoints) = tracked_scripts.get_mut(&script_hash) {
            outpoints.retain(|outpoint| !spent.contains(outpoint));
        }
        tracked_scripts.retain(|_, outpoints| !outpoints.is_empty());

        if let Err(e) = spent_tx.send(spent).await {
            return Err(anyhow::anyhow!("failed to forward spent outputs: {e}"));
        }
    }

    Ok(())
}

/// Detects confirmed spends among the tracked outpoints of one script hash.
///
/// Every confirmed history transaction not inspected yet is fetched (the
/// client retries transient failures) and its inputs are checked against the
/// script's tracked outpoints; inspected txids are remembered so each
/// transaction is inspected once.
///
/// A transaction whose fetch still fails after those retries is error!-logged
/// with its txid and skipped WITHOUT being marked inspected, so a later
/// notification for the script retries it; one poisoned transaction never
/// fails spend detection. Each such failure counts toward the client's
/// consecutive transaction-fetch failures, which the scanner uses to end the
/// task when the connection is broken.
async fn confirmed_spent_outpoints(
    client: &mut FrigateClient,
    history: &[response::Tx],
    script_hash: ElectrumScriptHash,
    tracked_scripts: &HashMap<ElectrumScriptHash, HashSet<OutPoint>>,
    inspected_txids: &mut HashMap<ElectrumScriptHash, HashSet<Txid>>,
) -> HashSet<OutPoint> {
    let Some(owned_outpoints) = tracked_scripts.get(&script_hash) else {
        return HashSet::new();
    };

    let inspected_for_script = inspected_txids.entry(script_hash).or_default();
    let mut spent = HashSet::new();
    for history_entry in history {
        if history_entry.confirmation_height().is_none() {
            continue;
        }

        let txid = history_entry.txid();
        if inspected_for_script.contains(&txid) {
            continue;
        }

        let full_tx = match client.get_transaction(txid).await {
            Ok(full_tx) => full_tx,
            Err(e) => {
                error!(
                    "Unable to fetch transaction {txid} for script hash {script_hash} after all retry attempts failed: {e}"
                );
                continue;
            }
        };
        for input in full_tx.tx.input {
            if owned_outpoints.contains(&input.previous_output) {
                spent.insert(input.previous_output);
            }
        }
        inspected_for_script.insert(txid);
    }

    spent
}

/// Emits `ScanResult`s for held mempool discoveries that the given script history shows
/// as confirmed, then drops those holdings from every script-hash index.
///
/// A held discovery is confirmed once its txid appears in `history` with a confirmation
/// height; the emitted result carries that height and the hash of the block header at
/// it. A discovery whose block-header fetch fails is kept, so a later script-hash
/// notification can retry it; a holding is dropped once processed, even if the scan
/// channel is already closed.
async fn emit_confirmed_mempool_discoveries(
    client: &mut FrigateClient,
    script_hash: ElectrumScriptHash,
    mempool_holdings: &mut HashMap<ElectrumScriptHash, HashMap<Txid, MempoolHolding>>,
    history: &[response::Tx],
    scan_tx: &mut Option<Sender<ScanResult>>,
) {
    let Some(holdings) = mempool_holdings.get(&script_hash) else {
        return;
    };

    let mut confirmed: Vec<(Txid, ScanResult)> = Vec::new();
    for (txid, holding) in holdings {
        let Some(confirmed_height) = history.iter().find_map(|entry| {
            if entry.txid() == *txid {
                entry.confirmation_height()
            } else {
                None
            }
        }) else {
            continue;
        };
        let confirmed_height = confirmed_height.to_consensus_u32();

        let blk_header = match client.get_block_header(confirmed_height).await {
            Ok(header) => header,
            Err(e) => {
                error!(
                    "Unable to fetch block header at height {confirmed_height} for mempool discovery {txid}: {e}"
                );
                continue;
            }
        };
        let blkheight = match Height::from_consensus(confirmed_height) {
            Ok(height) => height,
            Err(e) => {
                error!("Invalid block height {confirmed_height} received from Frigate: {e}");
                continue;
            }
        };

        confirmed.push((
            *txid,
            ScanResult {
                blkheight,
                blkhash: blk_header.header.block_hash(),
                discovered_inputs: HashSet::new(),
                discovered_outputs: holding.discovered_outputs.clone(),
            },
        ));
    }

    for (txid, scan_res) in confirmed {
        if let Some(sender) = scan_tx.as_mut() {
            if let Err(e) = sender.send(scan_res).await {
                error!("Unable to send scan result: {e}; stopping scan output");
                *scan_tx = None;
            } else {
                info!("Mempool discovery {txid} confirmed; ScanResult sent");
            }
        }
        drop_mempool_holding(mempool_holdings, &txid);
    }
}

/// Removes a confirmed mempool discovery (by txid) from every script-hash index.
fn drop_mempool_holding(
    mempool_holdings: &mut HashMap<ElectrumScriptHash, HashMap<Txid, MempoolHolding>>,
    txid: &Txid,
) {
    for holdings in mempool_holdings.values_mut() {
        holdings.remove(txid);
    }
    mempool_holdings.retain(|_, holdings| !holdings.is_empty());
}

fn process_outputs(
    tx: &Transaction,
    b_scan: &SecretKey,
    sp_receiver: &SpReceiver,
    tweak: &PublicKey,
) -> anyhow::Result<HashMap<OutPoint, DiscoveredOutput>> {
    let secret = calculate_ecdh_shared_secret(tweak, b_scan);
    let txid: Txid = tx.compute_txid();
    let outputs_to_check = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_idx, x)| x.script_pubkey.is_p2tr())
        .map(|(idx, txout)| {
            let output_key = XOnlyPublicKey::from_slice(&txout.script_pubkey.as_bytes()[2..])
                .map_err(|e| anyhow::anyhow!("invalid Taproot output key at index {idx}: {e}"))?;
            let vout = u32::try_from(idx)
                .map_err(|e| anyhow::anyhow!("output index {idx} does not fit in u32: {e}"))?;
            Ok((vout, txout.value, output_key))
        })
        .collect::<anyhow::Result<Vec<(u32, bitcoin::Amount, XOnlyPublicKey)>>>()?;

    let output_keys: Vec<XOnlyPublicKey> = outputs_to_check
        .iter()
        .map(|(_, _, output_key)| *output_key)
        .collect();

    let ours = sp_receiver.scan_transaction(&secret, &output_keys)?;

    let mut res = HashMap::new();
    for (vout, value, output_key) in outputs_to_check {
        for (label, map) in &ours {
            if let Some(tweak) = map.get(&output_key) {
                let outpoint = OutPoint { txid, vout };
                let spk_bytes = generate_script_pubkey_from_output_key(output_key);
                let script_pubkey = ScriptBuf::from_bytes(spk_bytes.to_vec());

                res.insert(
                    outpoint,
                    DiscoveredOutput {
                        txout: TxOut {
                            value,
                            script_pubkey,
                        },
                        tweak: *tweak,
                        label: label.clone(),
                    },
                );
                break;
            }
        }
    }

    Ok(res)
}
