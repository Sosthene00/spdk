//! Smoke test: prove the typed silent-payments subscribe works against a live
//! Frigate/Friglet electrum server, over plain TCP or TLS (`ssl://` URL).
//!
//! Throwaway keys only (scan key = all-ones, spend key = secp256k1 generator): the
//! server scan finds nothing, so an empty history IS the expected pass shape.
//!
//! Usage: `FRIGATE_URL=127.0.0.1:50001` (plain TCP) or
//! `FRIGATE_URL=ssl://frigate.2140.dev:50002` (TLS)
//! via `cargo run -q -p frigate --example sp_subscribe_smoke`

use std::str::FromStr as _;
use std::time::Duration;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use electrum_streaming_client::Event;
use electrum_streaming_client::notification::Notification;
use electrum_streaming_client::request::{self, SupportedVersion};
use backend_frigate::FrigateClient;
use futures::StreamExt as _;

/// secp256k1 generator point used as a throwaway spend key.
const SPEND_PK: &str = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
/// Throwaway scan key (all-ones); the server scan finds nothing for it.
const SCAN_SK_BYTES: [u8; 32] = [1u8; 32];
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let url = std::env::var("FRIGATE_URL").unwrap_or_else(|_| "127.0.0.1:50001".to_owned());

    // FrigateClient::connect picks plain TCP vs TLS from the URL scheme.
    let frigate_client = FrigateClient::connect(&url).await?;

    let version = frigate_client
        .client
        .send_request(request::ServerVersion {
            client_name: "spdk-sp-subscribe-smoke".into(),
            protocol_version: SupportedVersion::Range(["1.3.2".into(), "1.4.1".into()]),
        })
        .await?;
    let server_software = version.server_software;
    let protocol_version = version.protocol_version;
    println!("handshake -> server={server_software} protocol={protocol_version}");

    let tip = frigate_client
        .client
        .send_request(request::HeadersSubscribe)
        .await?;
    let tip_height = tip.height;
    let tip_hash = tip.header.block_hash();
    println!("tip -> height={tip_height} hash={tip_hash}");

    let scan_priv_key = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_pub_key = PublicKey::from_str(SPEND_PK)?;
    let start_height = tip_height.saturating_sub(5);
    let sub = frigate_client
        .client
        .send_request(request::SpSubscribe {
            scan_priv_key,
            spend_pub_key,
            start_height: Some(start_height),
            labels: None,
        })
        .await?;
    let address = sub.address;
    let labels = sub.labels;
    let resp_start_height = sub.start_height;
    println!(
        "SpSubscribeResp -> address={address} labels={labels:?} start_height={resp_start_height}"
    );

    // Move the event receiver out for the wait; the worker handle stays
    // reachable on the partially-moved client for the abort below.
    let mut events = frigate_client.events;

    let notification = tokio::time::timeout(NOTIFICATION_TIMEOUT, async move {
        while let Some(event) = events.next().await {
            if let Event::Notification(Notification::SpSubscribe(sp)) = event {
                return Some(sp);
            }
        }
        None
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for the first SpNotification"))?
    .ok_or_else(|| anyhow::anyhow!("event stream ended before the first SpNotification"))?;
    let progress = notification.progress;
    let history_len = notification.history.len();
    println!("SpNotification -> progress={progress} history_len={history_len}");

    frigate_client.worker.abort();
    Ok(())
}
