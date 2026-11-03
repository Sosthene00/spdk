//! Smoke test: prove `scan_blocks` honors `RangeInclusive::end` client-side.
//!
//! Mirrors `sp_subscribe_smoke` for tip discovery, then runs the real `FrigateScanner` over the
//! bounded range `start = tip - 50 ..= end = tip - 45`. Expected pass shape against a server
//! whose history extends past the range end: only in-range results (if any) are forwarded and
//! the scan loop terminates early with the "Range end ... reached" log line.
//!
//! Usage: `RUST_LOG=frigate=info FRIGATE_URL=127.0.0.1:50001 cargo run -q -p frigate --example range_smoke`

use std::time::Duration;

use bitcoin::Network;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use electrum_streaming_client::request::{self, SupportedVersion};
use electrum_streaming_client::AsyncClient;
use frigate::Scanner;
use spdk_core::scanner::Scanner as _;
use spdk_wallet::client::{SpClient, SpendKey};
use tokio::net::TcpStream;

const NETWORK: Network = Network::Signet;
/// Throwaway keys: the server scan finds nothing for them (same shape as `sp_subscribe_smoke`).
const SCAN_SK_BYTES: [u8; 32] = [1u8; 32];
const SPEND_SK_BYTES: [u8; 32] = [2u8; 32];
/// Bounded range: start = tip - `RANGE_BACK`, end = start + `RANGE_LEN`.
const RANGE_BACK: u32 = 50;
const RANGE_LEN: u32 = 5;
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let url = std::env::var("FRIGATE_URL").unwrap_or_else(|_| "127.0.0.1:50001".to_owned());

    // Tip discovery over a throwaway control connection (mirrors sp_subscribe_smoke).
    let stream = TcpStream::connect(&url).await?;
    let (reader, writer) = stream.into_split();
    let (client, _events, worker) = AsyncClient::new_tokio(reader, writer);
    let worker = tokio::spawn(worker);

    let version = client
        .send_request(request::ServerVersion {
            client_name: "spdk-range-smoke".into(),
            protocol_version: SupportedVersion::Range(["1.3.2".into(), "1.4.1".into()]),
        })
        .await?;
    println!(
        "handshake -> server={} protocol={}",
        version.server_software, version.protocol_version
    );

    let tip = client.send_request(request::HeadersSubscribe).await?;
    let tip_height = tip.height;
    println!("tip -> height={tip_height}");
    worker.abort();

    let start_height = tip_height.saturating_sub(RANGE_BACK);
    let end_height = start_height + RANGE_LEN;
    println!("range -> start={start_height} end={end_height} (tip={tip_height})");

    let scan_sk = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_sk = SecretKey::from_slice(&SPEND_SK_BYTES)?;
    let sp_client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), NETWORK)?;
    let sp_receiver = sp_client.receiver();

    let scanner = Scanner::new(url, scan_sk, sp_receiver, None).await?;
    let mut rx = scanner.scan_blocks(
        Height::from_consensus(start_height)?..=Height::from_consensus(end_height)?,
    );

    tokio::time::timeout(
        NOTIFICATION_TIMEOUT,
        async {
            while let Ok(update) = rx.recv().await {
                println!(
                    "ScanResult -> height={} hash={} outputs={}",
                    update.blkheight.to_consensus_u32(),
                    update.blkhash,
                    update.discovered_outputs.len()
                );
                for (outpoint, output) in &update.discovered_outputs {
                    println!(
                        "  outpoint={outpoint} value={} label={:?}",
                        output.txout.value, output.label
                    );
                }
            }
        },
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for the scan to complete"))?;

    println!("RANGE-SMOKE-EXIT=0");
    Ok(())
}
