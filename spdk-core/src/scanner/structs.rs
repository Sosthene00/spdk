use std::collections::{HashMap, HashSet};

use bitcoin::absolute::Height;
use bitcoin::secp256k1::Scalar;
use bitcoin::{BlockHash, OutPoint, TxOut};
use silentpayments::receiving::Label;

#[derive(Debug)]
pub struct ScanResult {
    pub blkheight: Height,
    pub blkhash: BlockHash,
    pub discovered_inputs: HashSet<OutPoint>,
    pub discovered_outputs: HashMap<OutPoint, DiscoveredOutput>,
    /// Terminal scan-failure marker. The final result of a scan carries
    /// `Some(message)` when per-block data fetches or processing failed:
    /// a stream that ends without this marker is a healthy completion,
    /// a stream whose last result carries it is NOT — a failed scan must
    /// never be indistinguishable from a completed scan that found
    /// nothing.
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredOutput {
    pub txout: TxOut,
    pub tweak: Scalar,
    pub label: Option<Label>,
}
