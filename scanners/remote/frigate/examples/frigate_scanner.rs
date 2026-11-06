use std::collections::HashSet;

use bitcoin::Network;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use frigate::{FrigateEvent, FrigateScanner};
use futures::StreamExt as _;
use spdk_wallet::client::{SpClient, SpendKey};

const NETWORK: Network = Network::Signet;
const FRIGATE_BACKEND_URL: &str = "100.81.213.115:50102";
const SCAN_START_HEIGHT: u32 = 326_000;

// scan & spend key bytes, these should be randomly generated,
// but for this example we use simple byte arrays
const SCAN_SK_BYTES: [u8; 32] = [0x01; 32];
const SPEND_SK_BYTES: [u8; 32] = [0x02; 32];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let scan_sk = SecretKey::from_slice(&SCAN_SK_BYTES)?;
    let spend_sk = SecretKey::from_slice(&SPEND_SK_BYTES)?;

    let sp_client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), NETWORK)?;
    let sp_receiver = sp_client.receiver();

    let frigate_scanner = FrigateScanner::new(
        FRIGATE_BACKEND_URL.to_owned(),
        scan_sk,
        sp_receiver,
        None,
        HashSet::new(),
    )
    .await?;

    println!("Receiving code for this key pair + network:");
    println!("{}", sp_client.receiving_code());

    let start = Height::from_consensus(SCAN_START_HEIGHT)?;
    let mut handle = frigate_scanner.start(start);

    // The worker keeps running after catch-up. This example stops there.
    while let Some(event) = handle.next().await {
        println!("{event:#?}");
        if matches!(event, FrigateEvent::CaughtUp) {
            break;
        }
    }

    Ok(())
}
