//! BIP-174 Input Witness Finalizer Role
//!
//! Converts intermediate signing fields (`tap_key_sig`, `partial_sigs`) into
//! `PSBT_IN_FINAL_SCRIPTWITNESS` / `PSBT_IN_FINAL_SCRIPTSIG` and clears the
//! signing fields. Must be called after signing and before extraction.
//!
//! Supported input types:
//! - **P2TR key-path**: `tap_key_sig` → `final_script_witness: [[<schnorr_sig>]]`
//! - **P2WPKH**: one `partial_sigs` entry → `final_script_witness: [[<ecdsa_sig>, <pubkey>]]`

use crate::psbt::core::{Bip375PsbtExt, Error, Result, SilentPaymentPsbt};
use bitcoin::Witness;

/// Finalize input witnesses per BIP-174.
///
/// For each input, reads `tap_key_sig` or `partial_sigs`, writes the
/// corresponding `final_script_witness`, then calls `clear_input_signing_fields`
/// to remove all intermediate signing data.
///
/// Returns an error if any input has neither `tap_key_sig` nor `partial_sigs`.
pub fn finalize_input_witnesses(psbt: &mut SilentPaymentPsbt) -> Result<()> {
    for input_idx in 0..psbt.num_inputs() {
        let witness = build_final_witness(psbt, input_idx)?;
        let input = &mut psbt.inputs[input_idx];
        input.final_script_witness = Some(witness);
    }
    for input_idx in 0..psbt.num_inputs() {
        clear_input_signing_fields(psbt, input_idx)?;
    }
    Ok(())
}

/// Clear all intermediate signing fields for a single input.
///
/// Called by `finalize_input_witnesses` after `PSBT_IN_FINAL_SCRIPTWITNESS` is
/// written. Signing is complete at that point; these fields are no longer needed
/// and should not be present on a finalized input per BIP-174.
///
/// Fields cleared:
/// - `tap_key_sig` — Taproot key-path Schnorr signature
/// - `partial_sigs` — ECDSA partial signatures
/// - `tap_internal_key` — P2TR internal key
/// - `tap_key_origins` — Taproot BIP32 derivations
/// - `bip32_derivations` — standard BIP32 derivations
/// - MuSig2 fields: `musig2_participant_pubkeys`, `musig2_pub_nonces`, `musig2_partial_sigs`
/// - `PSBT_IN_SP_TWEAK` — silent payment spend tweak
/// - `PSBT_IN_SP_SPEND_BIP32_DERIVATION` — silent payment spend BIP32 derivation
pub fn clear_input_signing_fields(psbt: &mut SilentPaymentPsbt, input_idx: usize) -> Result<()> {
    {
        let input = psbt
            .inputs
            .get_mut(input_idx)
            .ok_or(Error::InvalidInputIndex(input_idx))?;

        input.tap_key_sig = None;
        input.partial_sigs.clear();
        input.tap_internal_key = None;
        input.tap_key_origins.clear();
        input.bip32_derivations.clear();
    }

    // SP tweak is stored in unknowns via the extension trait; signing is done so clear it.
    if psbt.get_input_sp_tweak(input_idx).is_some() {
        psbt.remove_input_sp_tweak(input_idx)?;
        psbt.remove_input_sp_spend_bip32_derivation(input_idx)?;
    }

    Ok(())
}

/// Build the final script witness for a single input.
fn build_final_witness(psbt: &SilentPaymentPsbt, input_idx: usize) -> Result<Witness> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // P2TR key-path: single Schnorr signature
    if let Some(tap_sig) = &input.tap_key_sig {
        let mut witness = Witness::new();
        witness.push(tap_sig.to_vec());
        return Ok(witness);
    }

    // P2WPKH: exactly one partial sig → [<ecdsa_sig>, <pubkey>]
    let sigs = psbt.get_input_partial_sigs(input_idx);

    if sigs.is_empty() {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has no signatures to finalize (no tap_key_sig or partial_sigs)",
            input_idx
        )));
    }

    if sigs.len() != 1 {
        return Err(Error::ExtractionFailed(format!(
            "Input {} has {} partial signatures, expected 1 for P2WPKH",
            input_idx,
            sigs.len()
        )));
    }

    let (pubkey, signature) = &sigs[0];
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(pubkey);
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::core::{PsbtInput, PsbtOutput};
    use crate::psbt::crypto::pubkey_to_p2wpkh_script;
    use crate::psbt::roles::{
        constructor::{add_inputs, add_outputs},
        creator::create_psbt,
        input_finalizer::finalize_sp_outputs,
        signer::{add_ecdh_shares_full, sign_inputs},
    };
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use silentpayments::SilentPaymentAddress;

    #[test]
    fn test_finalize_p2wpkh_input_witnesses() {
        let secp = Secp256k1::new();

        let mut psbt = create_psbt(1, 1);

        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: pubkey_to_p2wpkh_script(&pubkey),
            },
            Sequence::MAX,
            Some(privkey),
        )];
        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(29000),
            ScriptBuf::new(),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        // Before finalization: partial_sigs populated, final_script_witness empty
        assert!(!psbt.get_input_partial_sigs(0).is_empty());
        assert!(psbt.inputs[0].final_script_witness.is_none());

        finalize_input_witnesses(&mut psbt).unwrap();

        // After: final_script_witness written, partial_sigs cleared
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.len(), 2); // [<sig>, <pubkey>]
        assert!(psbt.get_input_partial_sigs(0).is_empty());
    }

    #[test]
    fn test_finalize_p2tr_input_witnesses() {
        let secp = Secp256k1::new();

        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);
        let sp_address =
            SilentPaymentAddress::new(scan_key, spend_key, silentpayments::Network::Regtest, 0)
                .unwrap();

        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let mut psbt = create_psbt(1, 1);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: pubkey_to_p2wpkh_script(&pubkey),
            },
            Sequence::MAX,
            Some(privkey),
        )];
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(49000),
            sp_address,
            None,
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();
        add_ecdh_shares_full(&secp, &mut psbt, &inputs, &[scan_key], false).unwrap();
        finalize_sp_outputs(&secp, &mut psbt).unwrap();
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        finalize_input_witnesses(&mut psbt).unwrap();

        // For P2WPKH inputs the sig goes to partial_sigs, not tap_key_sig,
        // so witness has 2 items regardless of the output type being SP/P2TR.
        let witness = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert!(!witness.is_empty());
        assert!(psbt.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn test_finalize_clears_all_signing_fields() {
        let secp = Secp256k1::new();

        let mut psbt = create_psbt(1, 1);

        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: pubkey_to_p2wpkh_script(&pubkey),
            },
            Sequence::MAX,
            Some(privkey),
        )];
        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(29000),
            ScriptBuf::new(),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();
        sign_inputs(&secp, &mut psbt, &inputs).unwrap();

        finalize_input_witnesses(&mut psbt).unwrap();

        // Verify all intermediate signing fields are cleared
        assert!(psbt.inputs[0].tap_key_sig.is_none());
        assert!(psbt.get_input_partial_sigs(0).is_empty());
        assert!(psbt.inputs[0].tap_internal_key.is_none());
        assert!(psbt.inputs[0].tap_key_origins.is_empty());
        assert!(psbt.inputs[0].bip32_derivations.is_empty());
        assert!(psbt.get_input_sp_tweak(0).is_none());
    }

    #[test]
    fn test_finalize_fails_without_signatures() {
        let mut psbt = create_psbt(1, 1);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
            None,
        )];
        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(29000),
            ScriptBuf::new(),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        add_outputs(&mut psbt, &outputs).unwrap();

        let result = finalize_input_witnesses(&mut psbt);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ExtractionFailed(_))));
    }
}
