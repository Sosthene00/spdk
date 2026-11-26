//! Backend-level endpoint-selection contract tests.
//!
//! Rig regression (2026-11-26): the blindbit-regtest build reports
//! `tweaks_cut_through_with_dust_filter: false` and
//! `tweaks_full_with_dust_filter: false` but `tweaks_full_basic: true`.
//! The backend nevertheless called the cut-through `/tweaks` endpoint with
//! `?dustLimit=600`, got a silent `[]`, and the scan reported "complete,
//! 0 tweaks" — the wallet stayed blind on a fully indexed server.
//!
//! Contract: the backend consults `/info` and uses the strongest tweaks
//! endpoint the server actually supports, omitting the dustLimit query when
//! the server reports no dust-filter support.

mod support;

use backend_blindbit_v1::BlindbitBackend;
use bitcoin::Amount;
use bitcoin::absolute::Height;
use futures::StreamExt as _;
use spdk_core::chain::ChainBackend as _;
use support::Route;

const TWEAK: &str = "03419c05e3cf33db05aea9a162cf5cef8caa89f984d3fe40950d24bb01aa92d724";
const BLOCK_HASH: &str = "0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c";
const HEIGHT: u32 = 10_932;

fn info_body() -> String {
    // Verbatim flags from the rig's blindbit-regtest /info (2026-11-26).
    "{\"network\":\"regtest\",\"height\":15167,\"tweaks_only\":false,\
     \"tweaks_full_basic\":true,\"tweaks_full_with_dust_filter\":false,\
     \"tweaks_cut_through_with_dust_filter\":false}"
        .to_owned()
}

fn filter_body() -> String {
    format!(
        "{{\"block_hash\":\"{BLOCK_HASH}\",\"block_height\":{HEIGHT},\"data\":\"00\",\"filter_type\":1}}"
    )
}

fn routes() -> Vec<(&'static str, Route)> {
    vec![
        ("/info", Route::Static(200, info_body())),
        // The rig's cut-through endpoint silently serves an empty list.
        ("/tweaks", Route::Static(200, "[]".to_owned())),
        (
            "/tweak-index",
            Route::DustLimitRejected(format!("[\"{TWEAK}\"]")),
        ),
        ("/filter/new-utxos", Route::Static(200, filter_body())),
        ("/filter/spent", Route::Static(200, filter_body())),
    ]
}

/// Dana scans with cut-through enabled and the default dustLimit of 600 sats.
/// On a full-index server without dust-filter support the scan must still
/// find the block's tweaks via the full index, with no dustLimit query.
#[tokio::test]
async fn cutthrough_scan_on_full_index_server_finds_index_tweaks() {
    let (server, port) = support::spawn(routes());
    let backend = BlindbitBackend::new(&format!("http://127.0.0.1:{port}")).expect("backend");

    let range = Height::from_consensus(HEIGHT).unwrap()..=Height::from_consensus(HEIGHT).unwrap();
    let items: Vec<_> = backend
        .get_block_data_for_range(range, Amount::from_sat(600), true)
        .collect()
        .await;

    assert_eq!(items.len(), 1, "exactly one block in range");
    let block = items[0]
        .as_ref()
        .unwrap_or_else(|e| panic!("block fetch failed: {e:#}"));
    assert_eq!(
        block.tweaks().len(),
        1,
        "expected the funding tweak from the full index — 0 tweaks here is \
         the exact silent blindness observed on the rig"
    );

    let requests = server.requests();
    assert!(
        !requests.iter().any(|r| r.starts_with("/tweaks/")),
        "cut-through endpoint must not be used when /info reports no \
         cut-through support; requests: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|r| r.starts_with("/tweak-index/") && !r.contains("dustLimit=")),
        "the full index must be fetched without a dustLimit query when the \
         server reports no dust-filter support; requests: {requests:?}"
    );
}

/// A server that supports neither the cut-through endpoint nor any full index
/// must fail loudly, not scan an empty chain.
#[tokio::test]
async fn unsupported_server_configuration_fails_loudly() {
    let (_server, port) = support::spawn(vec![(
        "/info",
        Route::Static(
            200,
            "{\"network\":\"regtest\",\"height\":15167,\"tweaks_only\":false,\
             \"tweaks_full_basic\":false,\"tweaks_full_with_dust_filter\":false,\
             \"tweaks_cut_through_with_dust_filter\":false}"
                .to_owned(),
        ),
    )]);
    let backend = BlindbitBackend::new(&format!("http://127.0.0.1:{port}")).expect("backend");

    let range = Height::from_consensus(HEIGHT).unwrap()..=Height::from_consensus(HEIGHT).unwrap();
    let items: Vec<_> = backend
        .get_block_data_for_range(range, Amount::from_sat(600), true)
        .collect()
        .await;

    let errors: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_ref().err().map(|e| format!("{e:#}")))
        .collect();
    assert!(
        !errors.is_empty(),
        "a server with no usable tweaks endpoint must error per block, \
         never scan silently; items: {} of {}",
        errors.len(),
        items.len()
    );
    assert!(
        errors[0].contains("no usable tweaks endpoint"),
        "error should explain the server's capability gap, got: {}",
        errors[0]
    );
}
