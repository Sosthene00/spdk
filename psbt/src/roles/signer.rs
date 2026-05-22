//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.
//!
//! This module handles both regular P2WPKH signing and Silent Payment P2TR signing:
//! - **P2PKH inputs**: Signs with ECDSA (legacy) → `partial_sigs`
//! - **P2WPKH inputs**: Signs with ECDSA (SegWit v0) → `partial_sigs`
//! - **P2TR inputs**: Signs with Schnorr (Taproot v1) → `tap_key_sig`, with optional SP tweak

use std::collections::HashMap;

use crate::core::{utils::is_input_eligible, Error, Psbt, Result};
use crate::crypto::dleq_verify_proof;
use crate::roles::Bip375OutputConstructorExt;
use bitcoin::key::TweakedPublicKey;
use bitcoin::CompressedPublicKey;
use bitcoin::{ScriptBuf, Transaction, Witness, XOnlyPublicKey};
use psbt_v2::v2::Extractor;
use secp256k1::{Parity, PublicKey, Secp256k1, SecretKey};
use silentpayments::sending::{generate_recipient_pubkeys, GeneratePubkeysInput};
use silentpayments::utils::common::{
    InputHashApplied, SharedSecret, SILENT_PAYMENT_ADDRESS_BYTE_LEN,
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
    fn finalize(&mut self) -> Result<()>;
    fn extract_tx(self) -> Result<Transaction>;
}

impl SignerPsbtExt for Psbt {
    fn aggregate_ecdh_shares(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
        let scan_keys = self
            .outputs
            .iter()
            .filter_map(|o| {
                if let Some((scan_key, _)) = o.get_sp_info() {
                    Some(scan_key)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut global_ecdh_shares: HashMap<PublicKey, Vec<PublicKey>> =
            scan_keys.iter().map(|key| (*key, Vec::new())).collect();

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
                if !input.bip32_derivations.len() > 1 {
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
                    dleq_verify_proof(secp, &input_pubkey, key, &share.0, proof, None)
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
        }

        for (scan_key, shares) in global_ecdh_shares.iter() {
            let shares_ref: Vec<&PublicKey> = shares.iter().collect();
            let combined_keys = PublicKey::combine_keys(&shares_ref)?;
            self.global.sp_ecdh_shares.insert(
                CompressedPublicKey(*scan_key),
                CompressedPublicKey(combined_keys),
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
        for sp_output in self.outputs.iter().filter(|o| o.sp_v0_info.is_some()) {
            let (scan_key, spend_key) = sp_output.get_sp_info().unwrap();
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

    fn finalize(&mut self) -> Result<()> {
        for (i, input) in self.inputs.iter_mut().enumerate() {
            if let Some(sig) = input.tap_key_sig {
                let mut witness = Witness::new();
                witness.push(sig.to_vec());
                input.final_script_sig = Some(ScriptBuf::new());
                input.final_script_witness = Some(witness);
                input.tap_key_sig = None;
                input.sighash_type = None;
            } else {
                // We can't finalize a partially signed transaction
                return Err(Error::InvalidPsbtState(format!(
                    "Missing signature on input {}",
                    i
                )));
            }
        }
        Ok(())
    }

    fn extract_tx(self) -> Result<Transaction> {
        let extract_tx = Extractor::new(self)
            .map_err(|e| Error::InvalidPsbtState(format!("Psbt not finalized")))?
            .extract_tx()
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(extract_tx)
    }
}
