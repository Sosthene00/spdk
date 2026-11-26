//! Loud-failure contract for the local scanner.
//!
//! Rig regression (2026-11-26): when every per-block fetch errored, the scan
//! task swallowed the error behind a `warn!` log and the receiver saw a clean
//! channel close — the app reported a successful "complete, 0 tweaks" scan
//! and the wallet looked healthy while discovering nothing.
//!
//! Contract: a scan whose block fetches fail must surface the error through
//! the scan channel; "complete" must never be reported for a failed scan.

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, Network, OutPoint};
use futures::{Stream, StreamExt as _, stream};
use local_scanner::SpScanner;
use spdk_core::chain::{BoxedBlockData, ChainBackend, UtxoData};
use spdk_core::scanner::Scanner as _;
use spdk_wallet::client::{SpClient, SpendKey};

static KEEP_SCANNING: AtomicBool = AtomicBool::new(true);

/// Backend whose every block fetch fails — the rig's dustLimit-rejection
/// scenario reproduced at the backend boundary.
struct AllBlocksErrorBackend;

#[async_trait]
impl ChainBackend for AllBlocksErrorBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        _dust_limit: Amount,
        _with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>> {
        // Height does not implement Step; count the range instead.
        let blocks = range.end().to_consensus_u32() - range.start().to_consensus_u32() + 1;
        Box::pin(stream::iter(
            (0..blocks).map(|_| Err(anyhow::anyhow!("mock: block fetch failed"))),
        ))
    }

    async fn detect_spent_outpoints(
        &self,
        _block_height: Height,
        _block_hash: BlockHash,
        _outpoints: HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>> {
        Ok(HashSet::new())
    }

    async fn utxos(&self, _block_height: Height) -> Result<Vec<UtxoData>> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn scan_surfaces_fetch_errors_instead_of_silent_success() {
    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_key = SpendKey::Secret(SecretKey::from_slice(&[0x02; 32]).unwrap());
    let client = SpClient::new(scan_sk, spend_key, Network::Bitcoin).unwrap();

    let scanner = SpScanner::new(
        Box::new(AllBlocksErrorBackend),
        scan_sk,
        client.receiver(),
        HashSet::new(),
        Amount::from_sat(546),
        true,
        &KEEP_SCANNING,
    );

    let range = Height::from_consensus(100).unwrap()..=Height::from_consensus(101).unwrap();
    let updates: Vec<_> = scanner.scan_blocks(range).collect().await;

    assert!(
        !updates.is_empty(),
        "scan channel closed with zero items: the fetch error was swallowed \
         and the scan would report 'complete, 0 tweaks processed'"
    );
    // After the fix the channel carries `Result<ScanResult>`; the surfaced
    // failure shows up as an `Err(..)` item. (Compared via the debug dump so
    // the test also compiles against the pre-fix item type, where the red
    // state is the empty-channel assertion above.)
    let debug = format!("{updates:?}");
    assert!(
        debug.contains("Err("),
        "expected the fetch error to be surfaced through the scan channel, \
         got: {debug}"
    );
}
