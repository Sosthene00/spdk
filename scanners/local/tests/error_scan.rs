//! Scanner-level failure surfacing (kanban t_e93f85c2, fix step 4): a scan
//! whose per-block data fetches or processing fail must never be
//! indistinguishable from a healthy completion that found nothing. The scan
//! reports a terminal failure marker on its final `ScanResult`.

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, Network, OutPoint};
use bitcoin::hashes::Hash as _;
use futures::{Stream, StreamExt as _, stream};
use local_scanner::SpScanner;
use spdk_core::chain::{BoxedBlockData, ChainBackend, UtxoData};
use spdk_core::scanner::Scanner as _;
use spdk_wallet::client::{SpClient, SpendKey};

const DUST_LIMIT: Amount = Amount::from_sat(546);

static KEEP_SCANNING: AtomicBool = AtomicBool::new(true);

/// Backend that serves minimal empty block data for `ok_heights` and a loud
/// error for every other height in the requested range.
struct FailingBackend {
    ok_heights: HashSet<u32>,
}

fn empty_block_data(n: u32) -> Result<BoxedBlockData> {
    use backend_blindbit_v1::structs::{BlindbitV1BlockData, FilterData};

    let blkhash = BlockHash::from_slice(&[0x11; 32])?;
    Ok(Box::new(BlindbitV1BlockData {
        blkheight: Height::from_consensus(n)?,
        blkhash,
        tweaks: vec![],
        new_utxo_filter: FilterData { block_hash: blkhash, data: vec![] },
        spent_filter: FilterData { block_hash: blkhash, data: vec![] },
    }))
}

#[async_trait]
impl ChainBackend for FailingBackend {
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        _dust_limit: Amount,
        _with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>> {
        let ok = self.ok_heights.clone();
        let range = range.start().to_consensus_u32()..=range.end().to_consensus_u32();
        let s = stream::iter(range).then(move |n| {
            let ok = ok.clone();
            async move {
                if ok.contains(&n) {
                    empty_block_data(n)
                } else {
                    Err(anyhow!("boom: block {n} unavailable"))
                }
            }
        });
        Box::pin(s)
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

fn scanner_for(backend: FailingBackend) -> SpScanner {
    let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let client = SpClient::new(scan_sk, SpendKey::Secret(spend_sk), Network::Bitcoin).unwrap();
    SpScanner::new(
        Box::new(backend),
        scan_sk,
        client.receiver(),
        HashSet::new(),
        DUST_LIMIT,
        true,
        &KEEP_SCANNING,
    )
}

#[tokio::test]
async fn scan_reports_terminal_failure_when_every_block_fetch_errors() {
    let scanner = scanner_for(FailingBackend { ok_heights: HashSet::new() });

    let start = Height::from_consensus(100).unwrap();
    let end = Height::from_consensus(102).unwrap();
    let results: Vec<_> = scanner.scan_blocks(start..=end).collect().await;

    assert_eq!(results.len(), 1, "exactly the terminal failure result");
    assert!(
        results[0].error.as_deref().unwrap_or_default().contains("boom"),
        "terminal marker must carry the underlying error, got: {:?}",
        results[0].error
    );
    assert!(results[0].discovered_outputs.is_empty());
    assert!(results[0].discovered_inputs.is_empty());
}

#[tokio::test]
async fn scan_survives_partial_failures_and_marks_them_terminally() {
    let scanner =
        scanner_for(FailingBackend { ok_heights: HashSet::from([100, 102]) });

    let start = Height::from_consensus(100).unwrap();
    let end = Height::from_consensus(102).unwrap();
    let results: Vec<_> = scanner.scan_blocks(start..=end).collect().await;

    assert_eq!(results.len(), 3, "two healthy blocks + the terminal marker");
    assert!(results[0].error.is_none(), "block 100 must scan healthily");
    assert!(results[1].error.is_none(), "block 102 must scan healthily");
    let last = results.last().unwrap();
    assert!(
        last.error.as_deref().unwrap_or_default().contains("boom"),
        "final result must carry the failure marker, got: {:?}",
        last.error
    );
}
