//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.
//!
//! This module handles both regular P2WPKH signing and Silent Payment P2TR signing:
//! - **P2PKH inputs**: Signs with ECDSA (legacy) → `partial_sigs`
//! - **P2WPKH inputs**: Signs with ECDSA (SegWit v0) → `partial_sigs`
//! - **P2TR inputs**: Signs with Schnorr (Taproot v1) → `tap_key_sig`, with optional SP tweak

use std::collections::HashMap;

use crate::core::utils::to_rust_dleq;
use crate::core::{utils::is_input_eligible, Error, Psbt, Result};
use bitcoin::consensus::serialize;
use bitcoin::key::TweakedPublicKey;
use bitcoin::{CompressedPublicKey, OutPoint};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use rust_dleq::verify_dleq_proof;
use secp256k1::{Parity, PublicKey, Secp256k1, SecretKey};
use silentpayments::sending::{generate_recipient_pubkeys, GeneratePubkeysInput};
use silentpayments::utils::common::{
    InputHashApplied, Raw, SILENT_PAYMENT_ADDRESS_BYTE_LEN, SharedSecret
};
use silentpayments::SpVersion;

pub trait SignerPsbtExt {
    fn aggregate_ecdh_shares(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()>;
    fn compute_sp_outputs(
        &self,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>>;
    fn set_sp_scriptpubkey(
        &mut self,
        xonly_map: HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>,
    ) -> Result<()>;
    fn sign_sp_inputs(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<Vec<XOnlyPublicKey>>;
}

impl SignerPsbtExt for Psbt {
    fn aggregate_ecdh_shares(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
        let mut scan_keys = Vec::new();
        for (i, output) in self.outputs.iter().enumerate() {
            let Some(sp_info) = output.sp_v0_info.as_ref() else {
                continue;
            };
            let sp_info_bytes = sp_info.as_slice();
            if sp_info_bytes.len() != 66 {
                return Err(Error::InvalidFieldData(format!(
                    "Output {} has invalid SP info length: {}",
                    i,
                    sp_info_bytes.len()
                )));
            }
            let scan_key = PublicKey::from_slice(&sp_info_bytes[..33])?;
            scan_keys.push(scan_key);
        }

        let mut global_ecdh_shares: HashMap<PublicKey, Vec<PublicKey>> =
            scan_keys.iter().map(|key| (*key, Vec::new())).collect();

        let mut input_pubkeys: Vec<PublicKey> = Vec::new();
        for (i, input) in self.inputs.iter_mut().enumerate() {
            // First check that we're spending a silent payment eligible output
            if !is_input_eligible(&input)? {
                continue;
            }

            // We need to take the pubkey being spent
            // If we're spending a sp output, we need to take the bip32 derivation and tweak
            let input_pubkey: PublicKey;
            if let Some(_tweak) = input.sp_tweak {
                // we could take the tweak and spend pubkey and calculate it, but since we're checking the proof below we just take the funding utxo
                let funding_utxo = input.funding_utxo().unwrap();
                // This is a p2tr output, we can take the pubkey from the script
                if funding_utxo.script_pubkey.is_p2tr() {
                    let taproot_output_key =
                        XOnlyPublicKey::from_slice(&funding_utxo.script_pubkey.as_bytes()[2..])?;
                    input_pubkey =
                        PublicKey::from_x_only_public_key(taproot_output_key, Parity::Even);
                } else {
                    // This is not normal, return an error
                    return Err(Error::Other(format!("Input {} is spending a silent payment output with a non-p2tr script pubkey", i)));
                }
            } else {
                // This is another eligible output, we rely on the bip32 derivation to get the pubkey
                if input.bip32_derivations.len() > 1 {
                    return Err(Error::Other(format!(
                        "Input {} has multiple bip32 derivations",
                        i
                    )));
                }
                let (pubkey, (_, _)) =
                    input.bip32_derivations.iter().next().ok_or_else(|| {
                        Error::Other(format!("Input {} missing bip32 derivation", i))
                    })?;
                input_pubkey = pubkey.inner;
            }

            // Then check that we have a ecdh share for that input, one for each silent payment in outputs
            for key in &scan_keys {
                let share =
                    if let Some(share) = input.sp_ecdh_shares.get(&CompressedPublicKey(*key)) {
                        share
                    } else {
                        return Err(Error::Other(format!(
                            "Input {} missing ECDH share for scan key {:?}",
                            i, key
                        )));
                    };

                let proof =
                    if let Some(proof) = input.sp_dleq_proofs.get(&CompressedPublicKey(*key)) {
                        proof
                    } else {
                        return Err(Error::Other(format!(
                            "Input {} missing DLEQ proof for scan key {:?}",
                            i, key
                        )));
                    };

                // Check the proof is valid
                let is_valid =
                    verify_dleq_proof(secp, &input_pubkey, key, &share.0, &to_rust_dleq(*proof), None)
                        .map_err(|e| Error::Other(format!("DLEQ verification failed: {}", e)))?;
                if !is_valid {
                    return Err(Error::Other(format!(
                        "Invalid proof for input {} and scan key {:?}",
                        i, key
                    )));
                }

                // We can add that share to the global map
                global_ecdh_shares.get_mut(key).unwrap().push(share.0);
            }

            input_pubkeys.push(input_pubkey);
        }

        let outpoints: Vec<[u8; 36]> = self
            .inputs
            .iter()
            .map(|input| {
                serialize(&OutPoint::new(input.previous_txid, input.spent_output_index))
                    .try_into()
                    .expect("OutPoint is 36 bytes long")
            })
            .collect();

        let (outpoints_head, outpoints_tail) = outpoints.split_first().expect("At least one input");

        let pubkeys_sum = PublicKey::combine_keys(input_pubkeys.iter().collect::<Vec<&PublicKey>>().as_slice())?;

        for (scan_key, shares) in global_ecdh_shares.iter() {
            let shares_ref: Vec<&PublicKey> = shares.iter().collect();
            let combined_keys = PublicKey::combine_keys(&shares_ref)?;
            let input_hash_applied = SharedSecret::<Raw>::from_inner(&combined_keys).apply_input_hash(secp, &pubkeys_sum, &outpoints_head, &outpoints_tail)
                .map_err(|e| Error::Other(format!("Failed to apply input hash: {}", e)))?;
            self.global.sp_ecdh_shares.insert(
                CompressedPublicKey(*scan_key),
                CompressedPublicKey(input_hash_applied.into_inner()),
            );
        }

        // TODO does adding up all the proofs make a valid proof for global?

        Ok(())
    }

    fn compute_sp_outputs(
        &self,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>> {
        // We must add all the outpoints and use the sum to tweak each ecdh share
        let mut generate_recipients_inputs: HashMap<PublicKey, GeneratePubkeysInput> =
            HashMap::new();
        for output in self.outputs.iter() {
            let Some(sp_info) = output.sp_v0_info.as_ref() else {
                continue;
            };
            let sp_info_bytes = sp_info.as_slice();
            if sp_info_bytes.len() != 66 {
                return Err(Error::InvalidFieldData(format!(
                    "Output has invalid SP info length: {}",
                    sp_info_bytes.len()
                )));
            }
            let scan_key = PublicKey::from_slice(&sp_info_bytes[..33])?;
            let spend_key = PublicKey::from_slice(&sp_info_bytes[33..])?;
            if let Some(input) = generate_recipients_inputs.get_mut(&scan_key) {
                input.spend_keys.push(spend_key);
            } else {
                let share = self
                    .global
                    .sp_ecdh_shares
                    .get(&CompressedPublicKey(scan_key))
                    .ok_or_else(|| {
                        Error::InvalidPsbtState(format!("Missing share for key {}", scan_key))
                    })?;
                let input = GeneratePubkeysInput {
                    scan_key,
                    ecdh_shared_secret: SharedSecret::<InputHashApplied>::from_inner(&share.0),
                    spend_keys: vec![spend_key],
                    sp_version: silentpayments::SpVersion::ZERO,
                };
                generate_recipients_inputs.insert(scan_key, input);
            }
        }
        let res_map =
            generate_recipient_pubkeys(secp, generate_recipients_inputs.into_values().collect())
                .map_err(|e| Error::Other(e.to_string()))?;
        Ok(res_map)
    }

    fn set_sp_scriptpubkey(
        &mut self,
        mut xonly_map: HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>,
    ) -> Result<()> {
        let mut update_outputs = self.outputs.clone();
        for output in update_outputs.iter_mut() {
            if let Some(sp_info) = output.sp_v0_info.as_ref() {
                // Find the matching pubkey
                let mut key = [SpVersion::ZERO.into(); SILENT_PAYMENT_ADDRESS_BYTE_LEN];
                key[1..34].copy_from_slice(&sp_info.as_slice()[..33]);
                key[34..].copy_from_slice(&sp_info.as_slice()[33..]);
                if let Some(xonly_keys) = xonly_map.get_mut(&key) {
                    if xonly_keys.is_empty() {
                        return Err(Error::Other(format!("Not enough keys")));
                    };
                    let xonly_key = xonly_keys.remove(0);
                    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly_key);
                    let script = ScriptBuf::new_p2tr_tweaked(tweaked);
                    output.script_pubkey = script;
                } else {
                    return Err(Error::InvalidPsbtState(format!(
                        "sp_info {:?} doesn't exit in provided map",
                        key
                    )));
                }
            } else {
                // not a sp output
                continue;
            }
        }
        // Check that we used all provided key
        for (_address, xonly_keys) in xonly_map {
            if !xonly_keys.is_empty() {
                return Err(Error::InvalidPsbtState(format!(
                    "Failed to use all provided keys"
                )));
            }
        }

        // Now replace the initial outputs
        self.outputs = update_outputs;

        // Make the psbt non modifiable
        self.global.tx_modifiable_flags = 0u8;

        Ok(())
    }

    fn sign_sp_inputs(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey,
    ) -> Result<Vec<XOnlyPublicKey>> {
        let signed_xonly_keys = self.sign_silent_payment_inputs(&spend_key, secp)
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(signed_xonly_keys)
    }
}
