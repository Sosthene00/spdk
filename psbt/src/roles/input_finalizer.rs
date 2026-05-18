//! Silent Payment Output Script Derivation
//!
//! Aggregates ECDH shares and computes final output scripts for silent payments
//! (BIP-352 output derivation). This is distinct from the BIP-174 input witness
//! finalizer — see `input_witness_finalizer.rs` for that role.

use std::collections::HashMap;

use crate::core::utils::is_input_eligible;
use crate::core::{
    aggregate_ecdh_shares, compute_sp_shared_secrets, Bip375PsbtExt, Error, Result,
    Psbt,
};
use bitcoin::{key::TweakedPublicKey, ScriptBuf};
use secp256k1::Secp256k1;
use silentpayments::{
    sending::{generate_recipient_pubkeys, GeneratePubkeysInput},
    Network, SilentPaymentAddress,
};

/// Compute silent payment output scripts from aggregated ECDH shares (BIP-352).
///
/// Per BIP 352, the shared secret for output derivation is:
///   shared_secret = input_hash * aggregated_ecdh_share
/// where input_hash = hash_BIP0352/Inputs(smallest_outpoint || sum_of_pubkeys)
///
/// Note: this derives output *scripts* and is not the BIP-174 input witness
/// finalizer. See `finalize_input_witnesses` for that role.
pub fn finalize_sp_outputs(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut Psbt,
    network: Network,
) -> Result<()> {
    // Aggregate ECDH shares by scan key (detects global vs per-input automatically)
    let aggregated_shares = aggregate_ecdh_shares(psbt)?;

    // BIP-352: only BIP-352-eligible inputs contribute to ECDH shares; ineligible
    // inputs (NUMS taproot, unsupported scripts, etc.) are excluded by design.
    // Coverage is therefore checked against the eligible-input count.
    let eligible_input_count = (0..psbt.num_inputs())
        .filter(|&i| is_input_eligible(&psbt.inputs[i]).unwrap_or(false))
        .count();

    for (scan_key, aggregated) in aggregated_shares.iter() {
        if !aggregated.is_global && aggregated.num_inputs != eligible_input_count {
            let output_idx = (0..psbt.num_outputs())
                .find(|&i| {
                    psbt.get_output_sp_info(i)
                        .map(|(sk, _)| sk == *scan_key)
                        .unwrap_or(false)
                })
                .unwrap_or(0);
            return Err(Error::IncompleteEcdhCoverage(output_idx));
        }
    }

    let mut shared_secrets = compute_sp_shared_secrets(secp, psbt, &aggregated_shares)?;

    let mut inputs: Vec<GeneratePubkeysInput> = Vec::with_capacity(psbt.outputs.len());
    let mut outputs_to_update: HashMap<SilentPaymentAddress, Vec<usize>> = HashMap::new();
    for i in 0..psbt.outputs.len() {
        if let Some((scan_key, spend_key)) = psbt.get_output_sp_info(i) {
            if let Some(input) = inputs.iter_mut().find(|i| i.scan_key == scan_key) {
                input.spend_keys.push(spend_key);
            } else {
                let ecdh_shared_secret =
                    shared_secrets
                        .remove(&scan_key)
                        .ok_or(Error::Other(format!(
                            "Failed to get shared secret for {}",
                            scan_key.to_string()
                        )))?;
                let input = GeneratePubkeysInput {
                    scan_key,
                    ecdh_shared_secret,
                    spend_keys: vec![spend_key],
                    sp_version: silentpayments::SpVersion::ZERO,
                };
                inputs.push(input);
            }
            let sp_address = SilentPaymentAddress::new(
                scan_key,
                spend_key,
                network,
                silentpayments::SpVersion::ZERO,
            );
            if let Some(outputs_idx) = outputs_to_update.get_mut(&sp_address) {
                outputs_idx.push(i);
            } else {
                outputs_to_update.insert(sp_address, vec![i]);
            }
        }
    }
    let outputs = generate_recipient_pubkeys(secp, inputs, network)
        .map_err(|e| Error::Other(format!("{}", e.to_string())))?;

    // Check that we have the same keys in each
    if !outputs
        .keys()
        .all(|addr| outputs_to_update.contains_key(addr))
        || outputs.keys().len() != outputs_to_update.keys().len()
    {
        return Err(Error::Other(
            "Address mismatch in the output of `generate_recipient_pubkeys`".to_string(),
        ));
    }

    let outputs_vec = outputs.into_iter().collect::<Vec<_>>();

    for (sp_address, xonly_keys) in outputs_vec {
        let output_idxs = outputs_to_update
            .remove(&sp_address)
            .expect("We already checked that keys were identical");

        // Check that we have the same number of generated output keys than outputs in the transaction
        if output_idxs.len() != xonly_keys.len() {
            return Err(Error::Other(
                "XOnlyPubkeys mismatch in the output of `generate_recipient_pubkeys`".to_string(),
            ));
        }

        // Now we can simply push the spks at the right index in the psbt
        for i in 0..output_idxs.len() {
            let output_idx = output_idxs[i];
            let xonly_key = xonly_keys[i];

            // Generate the ScriptPubkey
            let spk =
                ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly_key));

            let psbt_out = psbt
                .outputs
                .get_mut(output_idx)
                .ok_or(Error::Other(format!("Can't get output {}", output_idx)))?;
            if !psbt_out.script_pubkey.is_empty() {
                return Err(Error::Other(format!(
                    "Overwriting spk for output {}",
                    output_idx
                )));
            }
            psbt_out.script_pubkey = spk;
        }
    }

    debug_assert!(outputs_to_update.is_empty());

    // Clear tx_modifiable_flags after finalizing outputs
    psbt.global.tx_modifiable_flags = 0x00;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PsbtInput, PsbtOutput};
    use crate::roles::create_psbt;
    use crate::roles::{
        constructor::add_outputs, updater::add_ecdh_shares, updater::add_input_bip32_derivation,
        updater::Bip32Derivation,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};
    use secp256k1::{PublicKey, SecretKey};
    use silentpayments::{Network as SpNetwork, SilentPaymentAddress};

    const NETWORK: Network = Network::Mainnet;

    fn pubkey_to_p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
        let pubkey = bitcoin::PublicKey::new(*pubkey);
        ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap())
    }

    #[test]
    fn test_finalize_sp_outputs_basic() {
        let secp = Secp256k1::new();

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
            SpNetwork::Regtest,
            silentpayments::SpVersion::ZERO,
        );

        // Add output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(50000),
            sp_address,
            None,
        )];
        for (i, output) in outputs.iter().enumerate() {
            add_outputs(&mut psbt, i, output).unwrap();
        }

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);
        let pubkey2 = PublicKey::from_secret_key(&secp, &privkey2);

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
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey2),
                },
                Sequence::MAX,
            ),
        ];
        add_inputs(&mut psbt, &inputs).unwrap();

        // Add ECDH shares
        add_ecdh_shares(
            &secp,
            &mut psbt,
            &HashMap::from([(0, privkey1), (1, privkey2)]),
            false,
        )
        .unwrap();

        let derivation = Bip32Derivation::new([0xAA, 0xBB, 0xCC, 0xDD], vec![0x8000002C]);
        add_input_bip32_derivation(&mut psbt, 0, &pubkey1, &derivation).unwrap();
        add_input_bip32_derivation(&mut psbt, 1, &pubkey2, &derivation).unwrap();

        // Finalize inputs (compute output scripts)
        finalize_sp_outputs(&secp, &mut psbt, NETWORK).unwrap();

        // Verify output script was added
        let script = &psbt.outputs[0].script_pubkey;
        assert!(!script.is_empty());

        // P2TR scripts are 34 bytes: OP_1 + 32-byte x-only pubkey
        assert_eq!(script.len(), 34);
        assert!(script.is_p2tr());
    }

    #[test]
    fn test_incomplete_ecdh_coverage() {
        let secp = Secp256k1::new();

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
            SpNetwork::Regtest,
            silentpayments::SpVersion::ZERO,
        );

        // Add output
        let outputs = vec![PsbtOutput::silent_payment(
            Amount::from_sat(50000),
            sp_address,
            None,
        )];
        for (i, output) in outputs.iter().enumerate() {
            add_outputs(&mut psbt, i, output).unwrap();
        }

        // Only add ECDH share for one input (incomplete)
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let inputs = vec![PsbtInput::new(
            OutPoint::new(Txid::all_zeros(), 0),
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: ScriptBuf::new(),
            },
            Sequence::MAX,
        )];

        // Use partial signing to only add share for input 0
        add_ecdh_shares(&secp, &mut psbt, &HashMap::from([(0, scan_privkey)]), false).unwrap();

        // Finalize should fail due to incomplete coverage
        let result = finalize_sp_outputs(&secp, &mut psbt, NETWORK);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::IncompleteEcdhCoverage(0))));
    }

    #[test]
    fn test_tx_modifiable_flags_cleared_after_finalization() {
        let secp = Secp256k1::new();

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
            NETWORK,
            silentpayments::SpVersion::ZERO,
        );

        // Create inputs with private keys
        let privkey1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let privkey2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pubkey1 = PublicKey::from_secret_key(&secp, &privkey1);
        let pubkey2 = PublicKey::from_secret_key(&secp, &privkey2);

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
                    script_pubkey: pubkey_to_p2wpkh_script(&pubkey2),
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
        finalize_sp_outputs(&secp, &mut psbt, NETWORK).unwrap();

        // Verify tx_modifiable_flags is cleared after finalization
        assert_eq!(
            psbt.global.tx_modifiable_flags, 0x00,
            "tx_modifiable_flags should be 0x00 after finalization (BIP-370)"
        );
    }
}
