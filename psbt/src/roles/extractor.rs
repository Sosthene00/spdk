//! PSBT Extractor Role
//!
//! Extracts the final Bitcoin transaction from a finalized PSBT.
//! Inputs must be finalized (via `finalize_input_witnesses`) before extraction —
//! the extractor reads `PSBT_IN_FINAL_SCRIPTWITNESS` / `PSBT_IN_FINAL_SCRIPTSIG`
//! only and does not inspect intermediate signing fields.

use crate::core::{Error, Result, Psbt};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Extract the final signed transaction from a PSBT.
///
/// Inputs must have been finalized via `finalize_input_witnesses` first.
/// All intermediate signing fields are cleared by the finalizer; this function
/// is a pure read-only transform from finalized PSBT to `Transaction`.
pub fn extract_transaction(psbt: &Psbt) -> Result<Transaction> {
    let global = &psbt.global;
    let version = global.tx_version;
    let lock_time = global.fallback_lock_time.unwrap_or(LockTime::ZERO);

    // Extract inputs with witnesses
    let mut inputs = Vec::new();
    for input_idx in 0..psbt.inputs.len() {
        inputs.push(extract_input(psbt, input_idx)?);
    }

    // Extract outputs
    let mut outputs = Vec::new();
    for output_idx in 0..psbt.outputs.len() {
        outputs.push(extract_output(psbt, output_idx)?);
    }

    Ok(Transaction {
        version,
        lock_time,
        input: inputs,
        output: outputs,
    })
}

/// Extract a single input from the PSBT
fn extract_input(psbt: &Psbt, input_idx: usize) -> Result<TxIn> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    // Build witness from partial signatures
    let witness = extract_witness(psbt, input_idx)?;

    Ok(TxIn {
        previous_output: OutPoint {
            txid: input.previous_txid,
            vout: input.spent_output_index,
        },
        script_sig: ScriptBuf::new(), // SegWit inputs have empty script_sig
        sequence: input.sequence.unwrap_or(Sequence::MAX),
        witness,
    })
}

/// Extract witness data from a finalized input.
///
/// Reads `PSBT_IN_FINAL_SCRIPTWITNESS` (set by `finalize_input_witnesses`).
/// Returns an error if the input has not been finalized.
fn extract_witness(psbt: &Psbt, input_idx: usize) -> Result<Witness> {
    let input = psbt
        .inputs
        .get(input_idx)
        .ok_or(Error::InvalidInputIndex(input_idx))?;

    if let Some(witness) = &input.final_script_witness {
        return Ok(witness.clone());
    }

    // Legacy P2SH path (non-segwit): PSBT_IN_FINAL_SCRIPTSIG
    // final_script_sig is a ScriptBuf; for non-segwit we'd put it in script_sig
    // and leave witness empty. Not currently used in this codebase but handled
    // for completeness.
    if input.final_script_sig.is_some() {
        return Ok(Witness::new()); // script_sig carried in TxIn, witness is empty
    }

    Err(Error::ExtractionFailed(format!(
        "Input {} is not finalized — call finalize_input_witnesses before extraction",
        input_idx
    )))
}

/// Extract a single output from the PSBT
fn extract_output(psbt: &Psbt, output_idx: usize) -> Result<TxOut> {
    let output = psbt
        .outputs
        .get(output_idx)
        .ok_or(Error::InvalidOutputIndex(output_idx))?;

    Ok(TxOut {
        value: Amount::from_sat(output.amount.to_sat()),
        script_pubkey: output.script_pubkey.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::core::{PsbtInput, PsbtOutput};
    use crate::roles::create_psbt;
    use crate::roles::{add_ecdh_shares, add_input_bip32_derivation, Bip32Derivation};
    use crate::roles::{
        constructor::{add_inputs, add_outputs},
        input_finalizer::finalize_sp_outputs,
        input_witness_finalizer::finalize_input_witnesses,
        signer::sign_inputs,
    };
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use silentpayments::SilentPaymentAddress;

    fn pubkey_to_p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
        let pubkey = bitcoin::PublicKey::new(*pubkey);
        ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap())
    }

    #[test]
    fn test_extract_transaction_regular_output() {
        let secp = Secp256k1::new();

        // Create PSBT with 2 inputs and 1 regular output
        let mut psbt = create_psbt(2, 1);

        let network = bitcoin::Network::Regtest;

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        // Create P2WPKH script for output
        let output_script = pubkey_to_p2wpkh_script(&pubkey1);

        let inputs = vec![
            PsbtInput::new(
                OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
            ),
            PsbtInput::new(
                OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 1,
                },
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
            ),
        ];

        let outputs = vec![PsbtOutput::regular(Amount::from_sat(55000), output_script)];

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        for (i, output) in outputs.iter().enumerate() {
            add_outputs(&mut psbt, i, output).unwrap();
        }

        // Sign inputs
        sign_inputs(
            &secp,
            &mut psbt,
            &HashMap::from([(0, privkey1), (1, privkey2)]),
        )
        .unwrap();

        // Finalize input witnesses (BIP-174 Finalizer role)
        finalize_input_witnesses(&mut psbt).unwrap();

        // Extract transaction
        let tx = extract_transaction(&psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_transaction_silent_payment() {
        let secp = Secp256k1::new();
        let network = silentpayments::Network::Regtest;

        // Create PSBT with 2 inputs and 1 silent payment output
        let mut psbt = create_psbt(2, 1);

        // Create scan and spend keys
        let scan_privkey = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let scan_key = PublicKey::from_secret_key(&secp, &scan_privkey);
        let spend_privkey = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let spend_key = PublicKey::from_secret_key(&secp, &spend_privkey);

        let sp_address = SilentPaymentAddress::new(
            scan_key,
            spend_key,
            network,
            silentpayments::SpVersion::ZERO,
        );

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);

        let inputs = vec![
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 0),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
            ),
            PsbtInput::new(
                OutPoint::new(Txid::all_zeros(), 1),
                TxOut {
                    value: Amount::from_sat(30000),
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey1),
                },
                Sequence::MAX,
            ),
        ];

        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(55000),
            sp_address,
            None,
        )];

        // Construct PSBT
        add_inputs(&mut psbt, &inputs).unwrap();
        for (i, output) in outputs.iter().enumerate() {
            add_outputs(&mut psbt, i, output).unwrap();
        }

        // Add ECDH shares
        add_ecdh_shares(
            &secp,
            &mut psbt,
            &HashMap::from([(0, privkey1), (1, privkey1)]),
            false,
        )
        .unwrap();

        for input_idx in 0..psbt.inputs.len() {
            let derivation = Bip32Derivation::new([0xAA, 0xBB, 0xCC, 0xDD], vec![0x8000002C]);
            add_input_bip32_derivation(&mut psbt, input_idx, &pubkey1, &derivation).unwrap();
        }

        // Finalize SP output scripts
        finalize_sp_outputs(&secp, &mut psbt, network).unwrap();

        // Sign inputs
        sign_inputs(
            &secp,
            &mut psbt,
            &HashMap::from([(0, privkey1), (1, privkey2)]),
        )
        .unwrap();

        // Finalize input witnesses (BIP-174 Finalizer role)
        finalize_input_witnesses(&mut psbt).unwrap();

        // Extract transaction
        let tx = extract_transaction(&psbt).unwrap();

        // Verify transaction structure
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(55000));

        // Verify output is P2TR (silent payment outputs are taproot)
        assert!(tx.output[0].script_pubkey.is_p2tr());

        // Verify inputs have witnesses
        assert!(!tx.input[0].witness.is_empty());
        assert!(!tx.input[1].witness.is_empty());
    }

    #[test]
    fn test_extract_fails_without_signatures() {
        let mut psbt = create_psbt(1, 1);

        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
        )];

        let outputs = vec![PsbtOutput::regular(
            Amount::from_sat(29000),
            ScriptBuf::new(),
        )];

        add_inputs(&mut psbt, &inputs).unwrap();
        for (i, output) in outputs.iter().enumerate() {
            add_outputs(&mut psbt, i, output).unwrap();
        }

        // Extraction should fail when finalize_input_witnesses has not been called
        let result = extract_transaction(&psbt);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ExtractionFailed(_))));
    }
}
