use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use bitcoin::absolute::Height;
use bitcoin::{Amount, BlockHash, OutPoint, Txid};
use futures::{FutureExt as _, Stream, StreamExt as _, future::Shared, stream};
use spdk_core::chain::{BoxedBlockData, ChainBackend, SpentIndexData, UtxoData};

use crate::BackendInfo;
use crate::client::BlindbitClient;
use crate::structs::BlindbitV1BlockData;
use crate::utils::input_hashes_map;

const CONCURRENT_FILTER_REQUESTS: usize = 200;

/// Which tweaks endpoint the server actually serves, resolved once per
/// `get_block_data_for_range` call from the server's `/info` capabilities.
///
/// Blindbit deployments differ: cut-through builds serve `/tweaks` with a
/// dust filter, full-index builds serve `/tweak-index` (with or without
/// dust-filter support). Asking a server for an endpoint it does not support
/// yields either a hard rejection or a silent empty list — the latter once
/// made whole wallets scan "successfully" without discovering anything.
#[derive(Debug, Clone, Copy)]
enum TweakSource {
    /// Cut-through tweaks with the client's dust limit (`/tweaks?dustLimit=`).
    CutThrough,
    /// Full tweak index (`/tweak-index`), optionally dust-filtered.
    FullIndex { with_dust: bool },
}

async fn resolve_tweak_source(
    client: BlindbitClient,
    with_cutthrough: bool,
) -> Result<TweakSource> {
    let info = client.info().await?;
    if with_cutthrough && info.tweaks_cut_through_with_dust_filter {
        return Ok(TweakSource::CutThrough);
    }
    if info.tweaks_full_with_dust_filter {
        return Ok(TweakSource::FullIndex { with_dust: true });
    }
    if info.tweaks_full_basic {
        return Ok(TweakSource::FullIndex { with_dust: false });
    }
    bail!(
        "blindbit server serves no usable tweaks endpoint for full scanning \
         (tweaks_only={}, tweaks_full_basic={}, tweaks_full_with_dust_filter={}, \
         tweaks_cut_through_with_dust_filter={}) — refusing to scan blindly",
        info.tweaks_only,
        info.tweaks_full_basic,
        info.tweaks_full_with_dust_filter,
        info.tweaks_cut_through_with_dust_filter
    )
}

#[derive(Debug)]
pub struct BlindbitBackend {
    client: BlindbitClient,
}

impl BlindbitBackend {
    pub fn new(host_url: &str) -> Result<Self> {
        Ok(Self {
            client: BlindbitClient::new(host_url)?,
        })
    }

    pub async fn info(&self) -> Result<BackendInfo> {
        self.client.info().await
    }

    pub async fn block_height(&self) -> Result<Height> {
        self.client.block_height().await
    }

    pub async fn block_hash(&self, block_height: Height) -> Result<BlockHash> {
        self.client.block_hash(block_height).await
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

        // convert range to u32 since Height does not implement Step
        let range = range.start().to_consensus_u32()..=range.end().to_consensus_u32();

        // Probe the server's capabilities once and share the result across
        // every block future (`Shared` starts the underlying future on the
        // first poll and hands the outcome to all clones; the `Arc` wrapper
        // keeps the shared output `Clone` despite `anyhow::Error`).
        let probe: Shared<_> = resolve_tweak_source(client.clone(), with_cutthrough)
            .map(Arc::new)
            .shared();

        let res = stream::iter(range)
            .map(move |n| {
                let client = client.clone();
                let probe = probe.clone();

                async move {
                    let blkheight = Height::from_consensus(n)?;
                    let source: TweakSource = match probe.clone().await.as_ref() {
                        Ok(source) => *source,
                        Err(e) => return Err(anyhow!("{e:#}")),
                    };
                    let tweaks = match source {
                        TweakSource::CutThrough => {
                            client.tweaks(blkheight, Some(dust_limit)).await?
                        }
                        TweakSource::FullIndex { with_dust } => {
                            client
                                .tweak_index(blkheight, with_dust.then_some(dust_limit))
                                .await?
                        }
                    };
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
