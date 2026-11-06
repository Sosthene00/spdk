# frigate — event-driven remote silent-payment scanner

`frigate` is a remote-scanner backend for spdk. It connects to an electrum
server speaking the Frigate silent-payments extension — a full Frigate server
or a single-user `friglet` — subscribes the wallet's scan key, and stays
listening: unlike a poll/rescan loop, the worker registers events as the
server delivers them (historical catch-up, live blocks, mempool, tip changes,
spends) and forwards them as a `FrigateEvent` stream. The wire side is the
`electrum_streaming_client` (ESC, pinned to the frigate ≤ 1.4.1 wire);
the silent-payment scan/tweak math runs locally, only the subscription
crosses the network.

## Usage

```rust,ignore
use std::collections::HashMap;
use bitcoin::absolute::Height;
use frigate::{FrigateEvent, FrigateScanner};
use futures::StreamExt as _;

let scanner = FrigateScanner::new(
    "ssl://frigate.example.com:50001".to_owned(),
    scan_priv_key,
    sp_receiver,
    None, // labels
    HashMap::new(), // previous_outputs: script -> outpoints of earlier runs
).await?;

let mut handle = scanner.start(Height::from_consensus(checkpoint)?);
while let Some(event) = handle.next().await {
    match event {
        FrigateEvent::Tip { height, .. } => { /* chain tip */ }
        FrigateEvent::Confirmed(scan_result) => { /* persist; idempotent per outpoint */ }
        FrigateEvent::Unconfirmed { txid, .. } => { /* mempool discovery */ }
        FrigateEvent::CaughtUp => { /* historical scan done */ }
        FrigateEvent::Spent(outpoints) => { /* mark spent */ }
        FrigateEvent::Disconnected(reason) => break, // restart from checkpoint
    }
}
```

A runnable example lives in `examples/frigate_scanner.rs`; it connects to
`FRIGATE_URL` (default `127.0.0.1:50001`, plain TCP — or `ssl://host:port`
for TLS).

## The consumer contract (foreground-service usage)

The worker is a long-lived listener, but it does not manage its own
connection lifetime: it runs until the handle is dropped or the connection
ends (`FrigateEvent::Disconnected`). A wallet embedding it — e.g. Dana's
foreground service — owns reconnection and persistence:

- **Persist a checkpoint** (highest confirmed height processed) and the owned
  outputs (script → outpoints). On restart, pass them as `previous_outputs`
  and `start` from the checkpoint.
- **Dedupe by outpoint.** History from the checkpoint is re-delivered on every
  restart, so the same `Confirmed` can arrive more than once; treat
  discoveries as idempotent per outpoint.
- **`previous_outputs` keeps spend monitoring alive across restarts.** The
  protocol re-delivers silent-payment history only from the requested start
  height and reports a script's pre-existing history only in the subscribe
  response, so without re-subscribing older outputs, their spends would never
  be seen again. They are swept once at subscribe: offline spends surface as
  `Spent`.
- **Event order is not total.** A `Spent` for an outpoint can precede its
  `Confirmed`/`Unconfirmed` (same-block spends sweep before the discovery is
  forwarded). Key state on outpoints, not on event order.
- **Reorgs are signalled, not retracted.** The worker does not retract a
  confirmed output whose block is later reorged; a same-height `Tip` with a
  different hash (or a height drop) is the signal to re-verify discoveries
  against their `ScanResult.blkhash`.
- **Failure semantics.** Requests retry transient failures internally
  (3 attempts, backoff); a transaction whose fetch still fails is skipped and
  retried on the next notification. Ten consecutive transaction-fetch
  failures (counted after the per-request retries) end the worker as
  `Disconnected` — a broken connection, not "no outputs". A `Disconnected`
  after that log means the listener FAILED; restart it from the checkpoint.

## Trust model

Read this before pointing the scanner anywhere but localhost.

- **The scan private key is SENT to the server.** This is the Frigate
  remote-scanner model: the server derives the silent-payment tweaks and
  reports matching outputs, so it learns everything the scan key knows. This
  matches the BIP-352 index-server spec: the service is trusted, and a user
  should rotate the wallet after leaving a hosted service.
- **TLS (`ssl://`) is strongly recommended off-LAN.** `FrigateClient::connect`
  speaks plain TCP for `host:port` and verified TLS for `ssl://host:port`; the
  scan key crosses the wire on every subscribe, so anything outside a trusted
  LAN should be reached over `ssl://`.
- **Single-user friglet instances answer with their own wallet snapshot
  regardless of the keys sent** (verified 2026-11-03). A friglet serves the
  wallet it was launched with: point the scanner at the matching wallet or at
  a real Frigate server, or you will scan someone else's snapshot.

## Version support

`FrigateClient::connect` negotiates `server.version` in the range 1.3.2–1.4.1
(the ESC pin's wire). Frigate 1.6-line servers / friglet answering with the
object-shaped subscribe response are not supported yet.
