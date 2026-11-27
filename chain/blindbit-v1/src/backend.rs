use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::pin::Pin;

use anyhow::{Result, bail};
use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::{Amount, BlockHash, OutPoint, Txid};
use futures::{Stream, StreamExt as _, stream};
use spdk_core::chain::{BoxedBlockData, ChainBackend, SpentIndexData, UtxoData};
use tokio::sync::OnceCell;

use crate::BackendInfo;
use crate::api_structs::InfoResponse;
use crate::client::BlindbitClient;
use crate::structs::BlindbitV1BlockData;
use crate::utils::input_hashes_map;

const CONCURRENT_FILTER_REQUESTS: usize = 200;

#[derive(Debug)]
pub struct BlindbitBackend {
    client: BlindbitClient,
    /// Lazily probed and retained /info response; shared by all
    /// subsequent requests on this backend.
    info: OnceCell<InfoResponse>,
}

impl BlindbitBackend {
    pub fn new(host_url: &str) -> Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(host_url)?,
            info: OnceCell::new(),
        })
    }

    pub async fn info(&self) -> Result<BackendInfo> {
        Ok(self.capabilities().await?.clone())
    }

    /// Probe the backend's `/info` endpoint exactly once and retain the
    /// full `InfoResponse` for the lifetime of this backend. Concurrent
    /// callers share a single probe; failures are retried on the next
    /// call.
    async fn capabilities(&self) -> Result<&InfoResponse> {
        self.info
            .get_or_try_init(|| probe_info(self.client.clone()))
            .await
    }

    pub async fn block_height(&self) -> Result<Height> {
        self.client.block_height().await
    }

    pub async fn forward_tx(&self, tx_hex: String) -> Result<Txid> {
        self.client.forward_tx(tx_hex).await
    }
}

#[async_trait]
impl ChainBackend for BlindbitBackend {
    /// High-level function to get block data for a range of blocks.
    /// Block data includes all the information needed to determine if a block is relevant for
    /// scanning, but does not include utxos, or spent index.
    /// These need to be fetched separately afterwards, if it is determined this block is relevant.
    fn get_block_data_for_range(
        &self,
        range: RangeInclusive<Height>,
        dust_limit: Amount,
        with_cutthrough: bool,
    ) -> Pin<Box<dyn Stream<Item = Result<BoxedBlockData>> + Send>> {
        let client = self.client.clone();
        let info = self.info.clone();

        // convert range to u32 since Height does not implement Step
        let range = range.start().to_consensus_u32()..=range.end().to_consensus_u32();

        let res = stream::iter(range)
            .filter_map(move |n| {
                let client = client.clone();
                let info = info.clone();

                async move {
                    // blindbit v1 never indexes the genesis block: its index
                    // starts at height 1 and the tweak/filter endpoints hard-
                    // error (500) for height 0. The genesis block provably
                    // contains no silent-payment data (a single unspendable
                    // coinbase output, no taproot, no tweaks), so skip it
                    // instead of failing every 0..=tip rescan at its first
                    // block.
                    if n == 0 {
                        return None;
                    }
                    Some(async move {
                        let blkheight = Height::from_consensus(n)?;
                    // Lazy capability probe: the first block item triggers a
                    // single /info request; concurrent items share it and
                    // later ranges reuse the retained response.
                    let capabilities = info
                        .get_or_try_init(|| probe_info(client.clone()))
                        .await?
                        .clone();
                    // Request-flavor selection per the probed capability
                    // flags. `with_cutthrough` is advisory only: the
                    // capability the server actually serves wins, so a
                    // hardcoded cut-through request can never force a
                    // flavor the backend does not provide.
                    let flavor = select_flavor(&capabilities, with_cutthrough)?;
                    let tweaks = match flavor {
                        TweakFlavor::CutThrough => {
                            client.tweaks(blkheight, dust_limit).await?
                        }
                        TweakFlavor::BasicIndex => {
                            // Basic flavor serves the FULL index: no
                            // dustLimit query parameter is sent.
                            client.tweak_index(blkheight, None).await?
                        }
                    };
                    // Runtime sanity probe: an empty result from the
                    // cut-through flavor is cross-checked against the
                    // basic index; a discrepancy means the backend is
                    // lying about its capability flags.
                    if tweaks.is_empty() && matches!(flavor, TweakFlavor::CutThrough) {
                        let cross_check = client.tweak_index(blkheight, None).await?;
                        if !cross_check.is_empty() {
                            bail!(
                                "backend lying about capabilities: /tweaks (cut-through) returned 0 tweaks for block {blkheight} but /tweak-index returned {}",
                                cross_check.len()
                            );
                        }
                    }
                    let new_utxo_filter = client.filter_new_utxos(blkheight).await?;
                    let spent_filter = client.filter_spent(blkheight).await?;
                    let blkhash = new_utxo_filter.block_hash;
                    Ok(Box::new(BlindbitV1BlockData {
                        blkheight,
                        blkhash,
                        tweaks,
                        new_utxo_filter: new_utxo_filter.into(),
                        spent_filter: spent_filter.into(),
                    }) as BoxedBlockData)
                    })
                }
            })
            .buffered(CONCURRENT_FILTER_REQUESTS);

        Box::pin(res)
    }

    async fn detect_spent_outpoints(
        &self,
        block_height: Height,
        block_hash: BlockHash,
        outpoints: HashSet<OutPoint>,
    ) -> Result<HashSet<OutPoint>> {
        let response = self.client.spent_index(block_height).await?;
        if block_hash != response.block_hash {
            bail!("Mismatched block hash");
        }

        let index_data: SpentIndexData = response.into();

        let input_hashes_map = input_hashes_map(&outpoints, block_hash)?;

        let mut res = HashSet::new();

        for spent in index_data.data {
            let hex: &[u8] = spent.as_ref();
            if let Some(outpoint) = input_hashes_map.get(hex) {
                res.insert(*outpoint);
            }
        }

        Ok(res)
    }

    async fn utxos(&self, block_height: Height) -> Result<Vec<UtxoData>> {
        self.client
            .utxos(block_height)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
}

/// Fetch and retain the backend's capability flags: a single `/info`
/// request whose full `InfoResponse` is cached by the caller (via a
/// `OnceCell`) and logged once per process.
async fn probe_info(client: BlindbitClient) -> Result<InfoResponse> {
    let info = client.info().await?;
    log::info!(
        "blindbit capability probe: network={} height={} tweaks_only={} \
         tweaks_full_basic={} tweaks_full_with_dust_filter={} \
         tweaks_cut_through_with_dust_filter={}",
        info.network,
        info.height,
        info.tweaks_only,
        info.tweaks_full_basic,
        info.tweaks_full_with_dust_filter,
        info.tweaks_cut_through_with_dust_filter
    );
    Ok(info)
}

/// The tweak-request flavor selected for this backend, based on the
/// server's advertised capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TweakFlavor {
    /// `/tweaks/{h}?dustLimit=N` — cut-through with server-side dust filter.
    CutThrough,
    /// `/tweak-index/{h}` — full basic index, NO dustLimit parameter.
    BasicIndex,
}

/// Choose the request flavor the server actually serves. The requested
/// flavor (`with_cutthrough`) is preferred when the server supports it,
/// but capability wins: an unsupported request is never sent. If the
/// server advertises no compatible flavor at all, this fails loudly —
/// a blind scan that silently returns zero tweaks is never acceptable.
fn select_flavor(info: &InfoResponse, with_cutthrough: bool) -> Result<TweakFlavor> {
    let cut_through_served = info.tweaks_cut_through_with_dust_filter;
    let basic_served = info.tweaks_full_basic;

    let flavor = if with_cutthrough {
        if cut_through_served {
            TweakFlavor::CutThrough
        } else if basic_served {
            TweakFlavor::BasicIndex
        } else {
            bail!(
                "blindbit backend serves no compatible tweak index (tweaks_full_basic={basic_served} \
                 tweaks_cut_through_with_dust_filter={cut_through_served})"
            );
        }
    } else if basic_served {
        TweakFlavor::BasicIndex
    } else if cut_through_served {
        TweakFlavor::CutThrough
    } else {
        bail!(
            "blindbit backend serves no compatible tweak index (tweaks_full_basic={basic_served} \
                 tweaks_cut_through_with_dust_filter={cut_through_served})"
        );
    };
    Ok(flavor)
}
