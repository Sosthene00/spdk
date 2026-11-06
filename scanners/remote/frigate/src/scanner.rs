use std::collections::{BTreeMap, HashMap, HashSet};
use std::pin::Pin;
use std::task::{Context, Poll};

use backend_frigate::FrigateClient;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey};
use electrum_streaming_client::notification::{
    HeaderNotification, Notification, ScriptHashNotification, SpNotification,
};
use electrum_streaming_client::{ElectrumScriptHash, Event, request};
use futures::channel::mpsc::{Receiver, Sender, channel};
use futures::{SinkExt as _, Stream, StreamExt as _};
use log::{debug, error, info, warn};
use silentpayments::receiving::Receiver as SpReceiver;
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret, generate_script_pubkey_from_output_key,
};
use spdk_core::scanner::{DiscoveredOutput, ScanResult};
use tokio::task::JoinHandle;

const EVENT_BUFFER: usize = 100_000;
/// Consecutive transaction-fetch failures (counted after each call's request
/// retries were exhausted) tolerated before the connection is treated as
/// broken and the worker stops.
const MAX_CONSECUTIVE_TX_FETCH_FAILURES: u32 = 10;

/// Events from a [`FrigateScanner`] worker.
///
/// Historical results arrive before the first [`FrigateEvent::CaughtUp`]. Later events are the
/// current phase: new blocks, mempool transactions, tip changes, and spends. The worker does not
/// retract a confirmed output whose block is later reorged.
#[derive(Debug)]
pub enum FrigateEvent {
    /// Owned outputs confirmed in a block.
    Confirmed(ScanResult),
    /// Owned outputs seen in the mempool. A later [`FrigateEvent::Confirmed`] reports confirmation.
    Unconfirmed {
        txid: Txid,
        discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
    },
    /// The historical scan has reached progress `1.0`. Emitted once.
    CaughtUp,
    /// The chain tip. A same-height notice with a different hash is a reorg of the tip block.
    Tip { height: Height, hash: BlockHash },
    /// Outpoints spent in a confirmed transaction.
    Spent(HashSet<OutPoint>),
    /// The connection ended. No further events follow.
    Disconnected(String),
}

/// Handle for a running Frigate worker.
///
/// Dropping the handle aborts the worker. The stream ends after [`FrigateEvent::Disconnected`]
/// or when the worker stops.
#[must_use = "dropping the handle aborts the frigate worker"]
pub struct FrigateHandle {
    events: Receiver<FrigateEvent>,
    worker: JoinHandle<()>,
}

impl Drop for FrigateHandle {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

impl Stream for FrigateHandle {
    type Item = FrigateEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events.poll_next_unpin(cx)
    }
}

enum Stop {
    CallerGone,
    Disconnect(String),
}

struct Watch {
    tracked_scripts: HashMap<ElectrumScriptHash, HashSet<OutPoint>>,
    inspected_txids: HashMap<ElectrumScriptHash, HashSet<Txid>>,
    unconfirmed: HashMap<Txid, HashMap<OutPoint, DiscoveredOutput>>,
    caught_up: bool,
}

pub struct FrigateScanner {
    client: FrigateClient,
    b_scan: SecretKey,
    sp_receiver: SpReceiver,
    labels: Option<Vec<u32>>,
    /// Outputs of earlier runs of this wallet (script → outpoints). Re-subscribed on `start`,
    /// so spend monitoring survives a restart: the Frigate protocol re-delivers silent payment
    /// history only from the requested start height, so without this, outputs confirmed before
    /// the checkpoint would never be watched for spends again.
    previous_outputs: HashMap<ScriptBuf, HashSet<OutPoint>>,
    tip_height: Height,
    tip_hash: BlockHash,
}

impl FrigateScanner {
    pub async fn new(
        host_url: String,
        b_scan: SecretKey,
        sp_receiver: SpReceiver,
        labels: Option<Vec<u32>>,
        previous_outputs: HashMap<ScriptBuf, HashSet<OutPoint>>,
    ) -> anyhow::Result<Self> {
        let client = FrigateClient::connect(&host_url, None).await?;
        let (tip_height, tip_hash) = client.block_height().await?;
        Ok(Self {
            client,
            b_scan,
            sp_receiver,
            labels,
            previous_outputs,
            tip_height,
            tip_hash,
        })
    }

    /// Subscribe from `from` and run until this handle is dropped or the connection ends.
    ///
    /// The first events are the current tip and historical matches. [`FrigateEvent::CaughtUp`]
    /// marks the end of history. The worker then keeps forwarding live block, mempool, tip, and
    /// spend events.
    ///
    /// The outputs of earlier runs (passed to [`FrigateScanner::new`]) are re-subscribed right
    /// after the silent payment subscribe, and their history is swept once: the Frigate protocol
    /// reports a script's pre-existing history only in the subscribe response and does not
    /// re-notify it, so this is the only chance to detect spends that happened while the wallet
    /// was offline. They surface as [`FrigateEvent::Spent`].
    ///
    /// On [`FrigateEvent::Disconnected`] the consumer may rebuild a scanner (passing its
    /// persisted outputs as `previous_outputs`) and `start` again from its checkpoint height:
    /// history from there is re-delivered, and consumers should treat confirmed outpoints as
    /// idempotent.
    pub fn start(self, from: Height) -> FrigateHandle {
        info!("Frigate scan from {}", from.to_consensus_u32());
        let (mut tx, events) = channel(EVENT_BUFFER);
        let worker = tokio::spawn(async move {
            if let Err(Stop::Disconnect(message)) = self.run(from, &mut tx).await {
                let _ = tx.send(FrigateEvent::Disconnected(message)).await;
            }
        });
        FrigateHandle { events, worker }
    }

    async fn run(mut self, from: Height, tx: &mut Sender<FrigateEvent>) -> Result<(), Stop> {
        if !send(
            tx,
            FrigateEvent::Tip {
                height: self.tip_height,
                hash: self.tip_hash,
            },
        )
        .await
        {
            return Err(Stop::CallerGone);
        }

        let subscribe_params = request::SpSubscribe {
            scan_priv_key: self.b_scan,
            spend_pub_key: self.sp_receiver.receiving_code().m_pubkey(),
            start_height: Some(from.to_consensus_u32()),
            labels: self.labels.take(),
        };
        if let Err(err) = self.client.subscribe(subscribe_params).await {
            return Err(Stop::Disconnect(format!(
                "silent payment subscribe failed: {err}"
            )));
        }

        let mut watch = Watch {
            tracked_scripts: HashMap::new(),
            inspected_txids: HashMap::new(),
            unconfirmed: HashMap::new(),
            caught_up: false,
        };

        for (script, outpoints) in std::mem::take(&mut self.previous_outputs) {
            let script_hash = ElectrumScriptHash::from(script.as_script());
            watch
                .tracked_scripts
                .entry(script_hash)
                .or_default()
                .extend(outpoints);
            let request = request::ScriptHashSubscribe { script_hash };
            match self.client.scripthash_subscribe(request).await {
                Ok(_) => sweep_script(&self.client, script_hash, &mut watch, tx).await?,
                // The script stays tracked: if a spend arrives later, the
                // script-hash notification re-runs the sweep.
                Err(err) => {
                    error!("Unable to resubscribe previous output script {script_hash}: {err}");
                }
            }
        }

        while let Some(event) = self.client.events.next().await {
            let Event::Notification(notification) = event else {
                continue;
            };
            match notification {
                Notification::SpSubscribe(notification) => {
                    self.on_silent_payments(notification, tx, &mut watch)
                        .await?;
                }
                Notification::ScriptHash(notification) => {
                    self.on_script_hash(notification, tx, &mut watch).await?;
                }
                Notification::Header(header) => self.on_header(header, tx).await?,
                Notification::Unknown(notification) => {
                    debug!("Ignoring unsupported notification: {notification:?}");
                }
            }
        }

        Err(Stop::Disconnect("frigate event stream ended".to_owned()))
    }

    async fn on_silent_payments(
        &mut self,
        notification: SpNotification,
        tx: &mut Sender<FrigateEvent>,
        watch: &mut Watch,
    ) -> Result<(), Stop> {
        let mut confirmed_by_height: BTreeMap<u32, Vec<(Txid, PublicKey)>> = BTreeMap::new();
        let mut mempool = Vec::new();
        for history in notification.history {
            if history.height == 0 {
                mempool.push((history.tx_hash, history.tweak_key));
            } else {
                confirmed_by_height
                    .entry(history.height)
                    .or_default()
                    .push((history.tx_hash, history.tweak_key));
            }
        }

        for (height, tweaks) in confirmed_by_height {
            let header =
                self.client
                    .get_block_header(height)
                    .await
                    .map_err(|err| Stop::Disconnect(format!("block header {height} failed: {err}")))?;
            let blkheight = Height::from_consensus(height)
                .map_err(|err| Stop::Disconnect(format!("invalid block height {height}: {err}")))?;
            let blkhash = header.header.block_hash();
            for (txid, tweak) in tweaks {
                let Some(discovered_outputs) = self.discover(txid, &tweak).await? else {
                    continue;
                };
                watch.unconfirmed.remove(&txid);
                subscribe_outputs(&self.client, watch, &discovered_outputs, tx).await?;
                if !send(
                    tx,
                    FrigateEvent::Confirmed(ScanResult {
                        blkheight,
                        blkhash,
                        discovered_inputs: HashSet::new(),
                        discovered_outputs,
                    }),
                )
                .await
                {
                    return Err(Stop::CallerGone);
                }
            }
        }

        for (txid, tweak) in mempool {
            let Some(discovered_outputs) = self.discover(txid, &tweak).await? else {
                continue;
            };
            subscribe_outputs(&self.client, watch, &discovered_outputs, tx).await?;
            watch.unconfirmed.insert(txid, discovered_outputs.clone());
            if !send(
                tx,
                FrigateEvent::Unconfirmed {
                    txid,
                    discovered_outputs,
                },
            )
            .await
            {
                return Err(Stop::CallerGone);
            }
        }

        if notification.progress >= 1.0 && !watch.caught_up {
            watch.caught_up = true;
            info!("Frigate scan caught up");
            if !send(tx, FrigateEvent::CaughtUp).await {
                return Err(Stop::CallerGone);
            }
        }
        Ok(())
    }

    async fn on_script_hash(
        &mut self,
        notification: ScriptHashNotification,
        tx: &mut Sender<FrigateEvent>,
        watch: &mut Watch,
    ) -> Result<(), Stop> {
        let script_hash = notification.script_hash();
        if !watch.tracked_scripts.contains_key(&script_hash) {
            debug!("Ignoring script-hash notification for untracked script {script_hash}");
            return Ok(());
        }
        sweep_script(&self.client, script_hash, watch, tx).await
    }

    async fn on_header(
        &mut self,
        header: HeaderNotification,
        tx: &mut Sender<FrigateEvent>,
    ) -> Result<(), Stop> {
        let notified = header.height();
        let new_height = Height::from_consensus(notified)
            .map_err(|err| Stop::Disconnect(format!("invalid tip height {notified}: {err}")))?;
        let new_hash = header.header().block_hash();
        if new_height < self.tip_height
            || (new_height == self.tip_height && new_hash != self.tip_hash)
        {
            warn!(
                "Chain tip moved from {} ({}) to {new_height} ({new_hash})",
                self.tip_height, self.tip_hash
            );
        } else if new_hash != self.tip_hash {
            info!(
                "Chain tip advanced from {} to {new_height}",
                self.tip_height
            );
        } else {
            debug!("Header notification repeats tip {new_height}");
            return Ok(());
        }

        self.tip_height = new_height;
        self.tip_hash = new_hash;
        if !send(
            tx,
            FrigateEvent::Tip {
                height: new_height,
                hash: new_hash,
            },
        )
        .await
        {
            return Err(Stop::CallerGone);
        }
        Ok(())
    }

    /// Fetches `txid` and returns its owned outputs, or `None` when the
    /// transaction holds none of ours or could not be processed.
    ///
    /// A transaction fetch that exhausts the client's retries is skipped (with
    /// a warning) unless the consecutive-failure budget is exceeded, in which
    /// case the connection is treated as broken and the worker stops with
    /// `Stop::Disconnect` (surfaced as [`FrigateEvent::Disconnected`]).
    async fn discover(
        &self,
        txid: Txid,
        tweak: &PublicKey,
    ) -> Result<Option<HashMap<OutPoint, DiscoveredOutput>>, Stop> {
        let full_tx = match self.client.get_transaction(txid).await {
            Ok(full_tx) => full_tx,
            Err(err) => {
                let failures = self.client.consecutive_tx_fetch_failures();
                if failures > MAX_CONSECUTIVE_TX_FETCH_FAILURES {
                    return Err(Stop::Disconnect(format!(
                        "{failures} consecutive transaction-fetch failures (limit {MAX_CONSECUTIVE_TX_FETCH_FAILURES}); connection treated as broken"
                    )));
                }
                warn!("Skipping transaction {txid} after fetch failure: {err}");
                return Ok(None);
            }
        };
        match process_outputs(&full_tx.tx, &self.b_scan, &self.sp_receiver, tweak) {
            Ok(outputs) if outputs.is_empty() => {
                debug!("No owned outputs in {txid}");
                Ok(None)
            }
            Ok(outputs) => Ok(Some(outputs)),
            Err(err) => {
                warn!("Skipping malformed transaction {txid}: {err}");
                Ok(None)
            }
        }
    }
}

async fn send(tx: &mut Sender<FrigateEvent>, event: FrigateEvent) -> bool {
    tx.send(event).await.is_ok()
}

/// Subscribes to the script hash of every discovered output and tracks its outpoints.
///
/// For a script tracked for the first time, the subscription is immediately followed by a
/// history sweep: the Frigate protocol reports a script's pre-existing history only in the
/// subscribe response and does not re-notify it, so spends that pre-date the subscription
/// (an output spent inside the block we just learned about, or while the wallet was offline)
/// are detected here and emitted as [`FrigateEvent::Spent`].
///
/// Subscribe failures are logged and skipped (the script stays tracked; a later script-hash
/// notification re-runs the sweep). Only a failure to forward an event on the channel is fatal.
async fn subscribe_outputs(
    client: &FrigateClient,
    watch: &mut Watch,
    discovered_outputs: &HashMap<OutPoint, DiscoveredOutput>,
    tx: &mut Sender<FrigateEvent>,
) -> Result<(), Stop> {
    for (outpoint, output) in discovered_outputs {
        let script_hash = ElectrumScriptHash::from(output.txout.script_pubkey.as_script());
        let first_output_for_script = !watch.tracked_scripts.contains_key(&script_hash);
        watch
            .tracked_scripts
            .entry(script_hash)
            .or_default()
            .insert(*outpoint);

        if !first_output_for_script {
            continue;
        }

        let request = request::ScriptHashSubscribe { script_hash };
        if let Err(err) = client.scripthash_subscribe(request).await {
            error!("Unable to subscribe to script hash {script_hash}: {err}");
            continue;
        }

        sweep_script(client, script_hash, watch, tx).await?;
    }
    Ok(())
}

/// Fetches `script_hash`'s history once and forwards the events it yields.
///
/// Held mempool discoveries that now show a confirmation height become
/// [`FrigateEvent::Confirmed`]; unseen confirmed transactions spending tracked outpoints
/// become [`FrigateEvent::Spent`]. History and transaction fetch failures are logged and
/// skipped WITHOUT being marked inspected, so a later notification for the script retries
/// them; each transaction-fetch failure counts toward the client's consecutive-failure
/// budget. Only a failure to forward an event on the channel is fatal (the consumer is gone).
async fn sweep_script(
    client: &FrigateClient,
    script_hash: ElectrumScriptHash,
    watch: &mut Watch,
    tx: &mut Sender<FrigateEvent>,
) -> Result<(), Stop> {
    let events = script_events(client, script_hash, watch).await?;
    emit_script_events(script_hash, events, watch, tx).await
}

/// Applies the event bookkeeping (dropping spent outpoints from tracking, together with the
/// script's inspection cache once it has no tracked outpoints left) and forwards the events.
async fn emit_script_events(
    script_hash: ElectrumScriptHash,
    events: Vec<FrigateEvent>,
    watch: &mut Watch,
    tx: &mut Sender<FrigateEvent>,
) -> Result<(), Stop> {
    for event in events {
        if let FrigateEvent::Spent(ref spent) = event {
            for outpoints in watch.tracked_scripts.values_mut() {
                outpoints.retain(|outpoint| !spent.contains(outpoint));
            }
            watch
                .tracked_scripts
                .retain(|_, outpoints| !outpoints.is_empty());
            // The script left tracking: its inspection cache can no longer grow.
            watch.inspected_txids.remove(&script_hash);
        }
        if !send(tx, event).await {
            return Err(Stop::CallerGone);
        }
    }
    Ok(())
}

/// Turns one fetch of `script_hash`'s history into events.
///
/// A held mempool discovery is confirmed once its txid shows a confirmation height in the
/// script's history (the canonical confirmation channel — the Frigate protocol does not
/// re-notify a mempool transaction when it confirms). Every confirmed history transaction not
/// inspected yet is fetched and its inputs are checked against the script's tracked outpoints;
/// inspected txids are remembered so each transaction is inspected once.
///
/// Errors: a `get_history` failure is logged and yields no events (the next notification for
/// the script re-runs the sweep); a transaction fetch that exhausts the client's retries is
/// skipped uninspected unless the consecutive-failure budget is exceeded, in which case the
/// connection is treated as broken and `Stop::Disconnect` propagates (the worker stops and
/// surfaces [`FrigateEvent::Disconnected`]; the txid stays uninspected so a restart re-checks it).
async fn script_events(
    client: &FrigateClient,
    script_hash: ElectrumScriptHash,
    watch: &mut Watch,
) -> Result<Vec<FrigateEvent>, Stop> {
    let Some(owned_outpoints) = watch.tracked_scripts.get(&script_hash).cloned() else {
        return Ok(Vec::new());
    };

    let history = match client.get_history(script_hash).await {
        Ok(history) => history,
        Err(err) => {
            // Transient: the next notification for this script re-runs the sweep.
            error!("Unable to inspect history for script hash {script_hash}: {err}");
            return Ok(Vec::new());
        }
    };

    let mut events = Vec::new();
    let mut spent = HashSet::new();
    let mut newly_inspected = HashSet::new();

    for entry in history {
        let Some(height) = entry.confirmation_height() else {
            continue;
        };
        let txid = entry.txid();

        if let Some(discovered_outputs) = watch.unconfirmed.remove(&txid) {
            match client.get_block_header(height.to_consensus_u32()).await {
                Ok(header) => events.push(FrigateEvent::Confirmed(ScanResult {
                    blkheight: height,
                    blkhash: header.header.block_hash(),
                    discovered_inputs: HashSet::new(),
                    discovered_outputs,
                })),
                Err(err) => {
                    error!("Unable to fetch block header at height {height} for {txid}: {err}");
                    watch.unconfirmed.insert(txid, discovered_outputs);
                }
            }
        }

        let already_inspected = watch
            .inspected_txids
            .get(&script_hash)
            .is_some_and(|seen| seen.contains(&txid));
        if already_inspected || newly_inspected.contains(&txid) {
            continue;
        }

        let full_tx = match client.get_transaction(txid).await {
            Ok(full_tx) => full_tx,
            Err(err) => {
                let failures = client.consecutive_tx_fetch_failures();
                if failures > MAX_CONSECUTIVE_TX_FETCH_FAILURES {
                    return Err(Stop::Disconnect(format!(
                        "{failures} consecutive transaction-fetch failures (limit {MAX_CONSECUTIVE_TX_FETCH_FAILURES}); connection treated as broken"
                    )));
                }
                error!("Unable to fetch transaction {txid}: {err}");
                continue;
            }
        };
        for input in full_tx.tx.input {
            if owned_outpoints.contains(&input.previous_output) {
                spent.insert(input.previous_output);
            }
        }
        newly_inspected.insert(txid);
    }

    if !newly_inspected.is_empty() {
        watch
            .inspected_txids
            .entry(script_hash)
            .or_default()
            .extend(newly_inspected);
    }

    if !spent.is_empty() {
        events.push(FrigateEvent::Spent(spent));
    }
    Ok(events)
}

pub fn process_outputs(
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
