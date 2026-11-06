//! Regression test for the frigate scanning math ([`frigate::process_outputs`])
//! against the canonical BIP-352 test vectors (review finding F8: this
//! money-touching scanner crate had zero tests).
//!
//! Vector provenance (entry 6 of the file below):
//! <https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json>
//! comment: "Single recipient: taproot only inputs with even y-values" —
//! receiving side, no labels, single P2TR output, mainnet `sp1q...` address.
//!
//! The vector file carries no serialized transaction, so the transaction under
//! scan is reconstructed from the vector: inputs = `given.vin` outpoints
//! (empty `scriptSig` / default witness — `process_outputs` only reads the
//! outpoints via `compute_txid` and the outputs), outputs = `given.outputs`
//! x-only keys as P2TR scripts (`OP_1 <32>`; the vector has no amounts, so the
//! value is 0 sats and is not asserted).
//!
//! The per-transaction tweak the Frigate oracle serves is derived the way the
//! vector expresses it most directly for a receiver: `tweak = input_hash *
//! A_sum`, with `input_hash = hash_BIP0352/Inputs(smallest_outpoint || A_sum)`
//! per BIP-352 ("Receiver"/"Specification": `outpoint` is the 36-byte
//! `COutPoint` serialization — 32-byte txid least-significant-byte first,
//! 4-byte vout least-significant byte first — and the hash is the BIP-340
//! tagged hash with tag `BIP0352/Inputs`). The derivation is cross-checked
//! against the vector's `expected.tweak` field, so a wrong input-hash
//! implementation fails the test loudly. (The alternative named in the task
//! card, `tweak_key = k*G`, would be the tweaked *output* key, not the oracle
//! tweak — the receive path multiplies `b_scan` into `input_hash * A_sum`.)

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::transaction::Version;
use bitcoin::consensus::serialize as consensus_serialize;
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::witness::Witness;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use frigate::process_outputs;
use spdk_wallet::client::{SpClient, SpendKey};

/// BIP-352 `send_and_receive_test_vectors.json`, entry 6 (receiving side):
/// `given.key_material.scan_priv_key`.
const SCAN_PRIV_KEY_HEX: &str = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
/// `given.key_material.spend_priv_key`.
const SPEND_PRIV_KEY_HEX: &str = "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3";
/// `expected.input_pub_key_sum`: A = sum of the eligible (all-P2TR) input keys.
const INPUT_PUB_KEY_SUM_HEX: &str =
    "038180a2125f9d6dd116e1a6139be4d72fd5057dab6aaabaa5654817c11baeb3ba";
/// `expected.tweak`: `input_hash * A_sum` — what the Frigate oracle sends per
/// transaction and `process_outputs` multiplies by `b_scan`.
const EXPECTED_TWEAK_HEX: &str =
    "02dc59cc8e8873b65c1dd5c416d4fbeb647372c329bd84a70c05b310e222e2c183";
/// `given.outputs[0]`: the transaction's single P2TR output key (x-only).
const GIVEN_OUTPUT_XONLY_HEX: &str =
    "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb";
/// `expected.outputs[0].pub_key`: same output key, echoed as expected.
const EXPECTED_OUTPUT_PUB_HEX: &str =
    "de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb";
/// `expected.outputs[0].priv_key_tweak`: `t_0 = hash(shared_secret || 0)`.
const PRIV_KEY_TWEAK_HEX: &str = "3fb9ce5ce1746ced103c8ed254e81f6690764637ddbc876ec1f9b3ddab776b03";

/// `given.vin` txids (display order); both prevout scriptPubKeys are P2TR
/// (`5120...`), so every input is silent-payment eligible and `A_sum` covers all
/// of them. All vouts are 0.
const VIN_TXIDS: [&str; 2] = [
    "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
    "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
];

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex constant"))
        .collect()
}

/// BIP-352 input hash over the lexicographically smallest serialized outpoint
/// and the sum of eligible input pubkeys.
fn input_hash_scalar(outpoints: &[OutPoint], a_sum: &PublicKey) -> Scalar {
    let mut serialized: Vec<Vec<u8>> = outpoints.iter().map(consensus_serialize).collect();
    serialized.sort();
    let outpoint_l = &serialized[0];

    let tag = sha256::Hash::hash(b"BIP0352/Inputs");
    let mut preimage = Vec::with_capacity(64 + outpoint_l.len() + 33);
    preimage.extend_from_slice(tag.as_byte_array());
    preimage.extend_from_slice(tag.as_byte_array());
    preimage.extend_from_slice(outpoint_l);
    preimage.extend_from_slice(&a_sum.serialize());
    let hash = sha256::Hash::hash(&preimage);
    Scalar::from_be_bytes(hash.to_byte_array()).expect("vector input_hash is a valid scalar")
}

/// Reconstructs the vector's transaction and derives the oracle tweak from the
/// vector's key material; shared by both the positive and the negative test.
fn vector_transaction() -> (Transaction, Vec<OutPoint>, PublicKey) {
    let outpoints: Vec<OutPoint> = VIN_TXIDS
        .iter()
        .map(|txid_hex| OutPoint {
            txid: txid_hex.parse().expect("valid txid constant"),
            vout: 0,
        })
        .collect();
    let inputs: Vec<TxIn> = outpoints
        .iter()
        .map(|op| TxIn {
            previous_output: *op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::default(),
            witness: Witness::default(),
        })
        .collect();

    let mut spk_bytes = Vec::with_capacity(34);
    spk_bytes.extend_from_slice(&[0x51, 0x20]);
    spk_bytes.extend_from_slice(&hex_decode(GIVEN_OUTPUT_XONLY_HEX));

    let tx = Transaction {
        version: Version::non_standard(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
        }],
    };

    let a_sum =
        PublicKey::from_slice(&hex_decode(INPUT_PUB_KEY_SUM_HEX)).expect("valid A_sum constant");
    (tx, outpoints, a_sum)
}

#[test]
fn bip352_receive_vector_scans_expected_output() {
    let secp = Secp256k1::new();

    let scan_sk = SecretKey::from_slice(&hex_decode(SCAN_PRIV_KEY_HEX)).expect("valid scan key");
    let spend_sk = SecretKey::from_slice(&hex_decode(SPEND_PRIV_KEY_HEX)).expect("valid spend key");
    let expected_tweak =
        PublicKey::from_slice(&hex_decode(EXPECTED_TWEAK_HEX)).expect("valid tweak constant");
    let priv_key_tweak = Scalar::from_be_bytes(
        hex_decode(PRIV_KEY_TWEAK_HEX)
            .try_into()
            .expect("32-byte scalar"),
    )
    .expect("valid scalar constant");

    let (tx, outpoints, a_sum) = vector_transaction();

    // Oracle tweak = input_hash * A_sum; must reproduce the vector's
    // `expected.tweak` (cross-check of the input-hash derivation).
    let input_hash = input_hash_scalar(&outpoints, &a_sum);
    let tweak = a_sum
        .mul_tweak(&secp, &input_hash)
        .expect("scalar multiplication of A_sum succeeds");
    assert_eq!(
        tweak, expected_tweak,
        "derived oracle tweak must equal the vector's expected.tweak"
    );

    // Receiver built exactly like examples/frigate_scanner.rs; Network::Bitcoin
    // matches the vector's mainnet `sp1q...` address.
    let sp_client =
        SpClient::new(scan_sk, SpendKey::Secret(spend_sk), Network::Bitcoin).expect("valid wallet");
    let sp_receiver = sp_client.receiver();

    let discovered = process_outputs(&tx, &scan_sk, &sp_receiver, &tweak)
        .expect("scanning the vector transaction succeeds");

    // The transaction's single output is ours, at (txid, vout 0).
    assert_eq!(discovered.len(), 1, "exactly the one P2TR output is ours");
    let expected_outpoint = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    let found = discovered
        .get(&expected_outpoint)
        .expect("the vector's output must be discovered at (txid, vout 0)");

    // Regenerated script_pubkey = OP_1 <expected output key> (P2TR).
    let mut expected_spk = Vec::with_capacity(34);
    expected_spk.extend_from_slice(&[0x51, 0x20]);
    expected_spk.extend_from_slice(&hex_decode(EXPECTED_OUTPUT_PUB_HEX));
    assert_eq!(
        found.txout.script_pubkey.as_bytes(),
        expected_spk.as_slice(),
        "regenerated script_pubkey must be the P2TR script of the vector's output key"
    );

    // The scanned t_0 tweak matches the vector's priv_key_tweak; the vector has
    // no labels, so the label is None.
    assert_eq!(
        found.tweak, priv_key_tweak,
        "scanned t_0 must equal the vector's priv_key_tweak"
    );
    assert!(found.label.is_none(), "vector entry has no labels");
}

#[test]
fn bip352_receive_vector_with_different_b_scan_finds_nothing() {
    let secp = Secp256k1::new();

    let spend_sk = SecretKey::from_slice(&hex_decode(SPEND_PRIV_KEY_HEX)).expect("valid spend key");
    // A different b_scan than the vector's (any valid, distinct scalar).
    let other_b_scan = SecretKey::from_slice(&[0x42u8; 32]).expect("valid scalar");

    let (tx, outpoints, a_sum) = vector_transaction();
    let input_hash = input_hash_scalar(&outpoints, &a_sum);
    let tweak = a_sum
        .mul_tweak(&secp, &input_hash)
        .expect("scalar multiplication of A_sum succeeds");

    let sp_client = SpClient::new(other_b_scan, SpendKey::Secret(spend_sk), Network::Bitcoin)
        .expect("valid wallet");
    let sp_receiver = sp_client.receiver();

    let discovered =
        process_outputs(&tx, &other_b_scan, &sp_receiver, &tweak).expect("scanning succeeds");
    assert!(
        discovered.is_empty(),
        "a different b_scan must not discover any output"
    );
}
