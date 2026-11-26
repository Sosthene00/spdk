//! Client/backend-level contract tests for the blindbit error surface.
//!
//! Regression probes for the silent-discovery defect (rig 2026-11-26): the
//! server answers `{"error": ...}` envelopes and the surfaced error must
//! carry the server's own message, instead of opaque serde parse noise like
//! "invalid type: map, expected a sequence".
//!
//! The tests drive `get_block_data_for_range` — the API dana actually calls.

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
    // Verbatim capability flags from the rig's blindbit-regtest /info.
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

fn backend(port: u16) -> BlindbitBackend {
    BlindbitBackend::new(&format!("http://127.0.0.1:{port}")).expect("backend")
}

fn range() -> std::ops::RangeInclusive<Height> {
    Height::from_consensus(HEIGHT).unwrap()..=Height::from_consensus(HEIGHT).unwrap()
}

/// The exact response the rig's blindbit-regtest gives for
/// `/tweak-index/{h}?dustLimit=600`: HTTP 400 with an error envelope.
/// The surfaced error must carry the server's message, not serde noise.
#[tokio::test]
async fn error_envelope_on_http_400_carries_server_message() {
    let (_server, port) = support::spawn(vec![
        ("/info", Route::Static(200, info_body())),
        (
            "/tweak-index",
            Route::Static(
                400,
                "{\"error\":\"Server does not allow dustLimits\"}".to_owned(),
            ),
        ),
    ]);

    let items: Vec<_> = backend(port)
        .get_block_data_for_range(range(), Amount::from_sat(600), false)
        .collect()
        .await;

    assert!(!items.is_empty(), "stream must yield the failed block");
    let Err(err) = &items[0] else {
        panic!("an HTTP 400 error envelope must fail the block fetch")
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("does not allow dustLimits"),
        "error must surface the server's message, got: {text}"
    );
}

/// An error envelope delivered with HTTP 200 must still be a loud error —
/// never silently decoded into an empty tweak list.
#[tokio::test]
async fn error_envelope_on_http_200_is_loud_error() {
    let (_server, port) = support::spawn(vec![
        ("/info", Route::Static(200, info_body())),
        (
            "/tweak-index",
            Route::Static(
                200,
                "{\"error\":\"Server does not allow dustLimits\"}".to_owned(),
            ),
        ),
    ]);

    let items: Vec<_> = backend(port)
        .get_block_data_for_range(range(), Amount::from_sat(600), false)
        .collect()
        .await;

    assert!(!items.is_empty(), "stream must yield the failed block");
    let Err(err) = &items[0] else {
        panic!("an error envelope is not a tweak index")
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("does not allow dustLimits"),
        "error must surface the server's message, got: {text}"
    );
}

/// Positive control: a full-index response body parses into the tweak list
/// (the arm the rig's `/tweak-index/{h}` without dustLimit actually serves).
#[tokio::test]
async fn valid_index_body_parses() {
    let (_server, port) = support::spawn(vec![
        ("/info", Route::Static(200, info_body())),
        ("/tweak-index", Route::Static(200, format!("[\"{TWEAK}\"]"))),
        ("/filter/new-utxos", Route::Static(200, filter_body())),
        ("/filter/spent", Route::Static(200, filter_body())),
    ]);

    let items: Vec<_> = backend(port)
        .get_block_data_for_range(range(), Amount::from_sat(600), false)
        .collect()
        .await;

    assert_eq!(items.len(), 1, "exactly one block in range");
    let block = match &items[0] {
        Ok(block) => block,
        Err(e) => panic!("valid index body must parse, got error: {e:#}"),
    };
    assert_eq!(block.tweaks().len(), 1, "the indexed tweak must be found");
}
