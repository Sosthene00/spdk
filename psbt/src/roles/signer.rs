//! PSBT Signer Role
//!
//! Adds ECDH shares and signatures to the PSBT.
//!
//! This module handles both regular P2WPKH signing and Silent Payment P2TR signing:
//! - **P2PKH inputs**: Signs with ECDSA (legacy) → `partial_sigs`
//! - **P2WPKH inputs**: Signs with ECDSA (SegWit v0) → `partial_sigs`
//! - **P2TR inputs**: Signs with Schnorr (Taproot v1) → `tap_key_sig`, with optional SP tweak

use std::collections::HashMap;

use crate::core::{utils::is_input_eligible, Bip375PsbtExt, EcdhShareData, Error, Psbt, Result};
use crate::crypto::{dleq_generate_proof, dleq_verify_proof, sign_p2tr_input};
use crate::roles::Bip375OutputConstructorExt;
use bitcoin::sighash::SighashCache;
use bitcoin::{key::TapTweak, CompressedPublicKey};
use bitcoin::{PrivateKey, ScriptBuf, XOnlyPublicKey};
use futures::future::Shared;
use psbt_v2::v2::{Input, Signer};
use rand::RngCore;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use silentpayments::sending::{generate_recipient_pubkeys, GeneratePubkeysInput};
use silentpayments::utils::common::{InputHashApplied, SharedSecret};
use silentpayments::utils::receiving::get_pubkey_from_input;
use silentpayments::utils::{common::Raw, sending::TypedSecretKey};

// pub fn add_input_ecdh_share(
//     secp: &Secp256k1<secp256k1::All>,
//     psbt: &mut Psbt,
//     input_index: usize,
//     private_key: SecretKey,
//     include_dleq: bool,
// ) -> Result<()> {
//     for

//     if scan_keys.is_empty() {
//         return Err(Error::Other("No silent payment outputs".to_string()));
//     }

//     let input = psbt
//         .inputs
//         .get_mut(input_index)
//         .ok_or(Error::InvalidInputIndex(input_index))?;

//     let funding_utxo = input
//         .funding_utxo()
//         .map_err(|_| Error::InvalidInputIndex(input_index))?;

//     // Check that the utxo is eligible for silent payments
//     match is_input_eligible(input) {
//         Ok(false) => {
//             return Err(Error::Other(
//                 "Input is not eligible for silent payments".to_string(),
//             ))
//         }
//         Ok(true) => (),
//         Err(e) => return Err(e), // likely we don't have the funding utxo yet
//     }

//     let is_taproot = funding_utxo.script_pubkey.is_p2tr();

//     // BIP-352: for taproot inputs whose pubkey has odd y, negate the key
//     // so the ECDH share is consistent with the x-only (even-y) convention.
//     let normalized_privkey =
//         TypedSecretKey::<Raw>::new(private_key).normalize_for_input(secp, is_taproot);

//     // Check that the provided private key matches the key spent
//     // We need the *_IN_DERIVATION fields set
//     let pubkey = bitcoin::PublicKey::from(normalized_privkey.as_inner().public_key(secp));
//     let has_any_bip32_derivations = !input.bip32_derivations.is_empty();
//     let private_key_matches_bip32_derivation = input.bip32_derivations.contains_key(&pubkey);
//     let compressed_pubkey =
//         CompressedPublicKey::try_from(pubkey).map_err(|_| Error::InvalidPublicKey)?;
//     let has_any_sp_spend_bip32_derivations = !input.sp_spend_bip32_derivations.is_empty();
//     let private_key_matches_sp_spend_bip32_derivation = input
//         .sp_spend_bip32_derivations
//         .contains_key(&compressed_pubkey);

//     if has_any_bip32_derivations && has_any_sp_spend_bip32_derivations {
//         return Err(Error::InvalidPsbtState(
//             "input cannot use both bip32_derivations and sp_spend_bip32_derivations".to_string(),
//         ));
//     }

//     if has_any_sp_spend_bip32_derivations && !is_taproot {
//         return Err(Error::InvalidPsbtState(
//             "sp_spend_bip32_derivations is only valid for taproot inputs".to_string(),
//         ));
//     }

//     if !private_key_matches_bip32_derivation && !private_key_matches_sp_spend_bip32_derivation {
//         return Err(Error::InvalidPsbtState(
//             "private key does not match any registered input derivation key (missing derivations or wrong private key)".to_string(),
//         ));
//     }

//     for scan_key in &scan_keys {
//         let ecdh_shared_secret: SharedSecret<Raw> =
//             normalized_privkey.calculate_ecdh_shared_secret(scan_key);

//         let dleq_proof = if include_dleq {
//             let mut rand_aux = [0u8; 32];
//             rand::thread_rng().fill_bytes(&mut rand_aux);
//             Some(
//                 dleq_generate_proof(
//                     secp,
//                     normalized_privkey.as_inner(),
//                     scan_key,
//                     &rand_aux,
//                     None,
//                 )
//                 .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
//             )
//         } else {
//             None
//         };

//         let compressed_scan_key =
//             CompressedPublicKey::try_from(bitcoin::PublicKey::from(*scan_key))
//                 .map_err(|_| Error::InvalidPublicKey)?;
//         let compressed_shared_secret = CompressedPublicKey::try_from(bitcoin::PublicKey::from(
//             ecdh_shared_secret.into_inner(),
//         ))
//         .map_err(|_| Error::InvalidPublicKey)?;

//         input
//             .sp_ecdh_shares
//             .insert(compressed_scan_key, compressed_shared_secret);

//         if let Some(proof) = dleq_proof {
//             input.sp_dleq_proofs.insert(compressed_scan_key, proof);
//         }
//     }
//     Ok(())
// }
// /// Add ECDH shares for all inputs (full signing)
// pub fn add_ecdh_shares_full(
//     secp: &Secp256k1<secp256k1::All>,
//     psbt: &mut Psbt,
//     inputs: &[PsbtInput],
//     scan_keys: &[PublicKey],
//     include_dleq: bool,
// ) -> Result<()> {
//     for (input_idx, input) in inputs.iter().enumerate() {
//         let Some(ref privkey) = input.private_key else {
//             return Err(Error::Other(format!(
//                 "Input {} missing private key",
//                 input_idx
//             )));
//         };

//         for scan_key in scan_keys {
//             let share_point = compute_ecdh_share(secp, privkey, scan_key)
//                 .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

//             let dleq_proof = if include_dleq {
//                 let mut rand_aux = [0u8; 32];
//                 rand::thread_rng().fill_bytes(&mut rand_aux);
//                 Some(
//                     dleq_generate_proof(secp, privkey, scan_key, &rand_aux, None)
//                         .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
//                 )
//             } else {
//                 None
//             };

//             let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
//             psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
//         }
//     }
//     Ok(())
// }

// pub fn add_ecdh_shares_partial(
//     secp: &Secp256k1<secp256k1::All>,
//     psbt: &mut Psbt,
//     inputs: &[PsbtInput],
//     scan_keys: &[PublicKey],
//     controlled_indices: &[usize],
//     include_dleq: bool,
// ) -> Result<()> {
//     let controlled_set: HashSet<usize> = controlled_indices.iter().copied().collect();

//     for (input_idx, input) in inputs.iter().enumerate() {
//         if !controlled_set.contains(&input_idx) {
//             continue;
//         }

//         let Some(ref base_privkey) = input.private_key else {
//             return Err(Error::Other(format!(
//                 "Controlled input {} missing private key",
//                 input_idx
//             )));
//         };

//         for scan_key in scan_keys {
//             let share_point = compute_ecdh_share(secp, base_privkey, scan_key)
//                 .map_err(|e| Error::Other(format!("ECDH computation failed: {}", e)))?;

//             let dleq_proof = if include_dleq {
//                 let mut rand_aux = [0u8; 32];
//                 rand::thread_rng().fill_bytes(&mut rand_aux);
//                 Some(
//                     dleq_generate_proof(secp, base_privkey, scan_key, &rand_aux, None)
//                         .map_err(|e| Error::Other(format!("DLEQ generation failed: {}", e)))?,
//                 )
//             } else {
//                 None
//             };

//             let ecdh_share = EcdhShareData::new(*scan_key, share_point, dleq_proof);
//             psbt.add_input_ecdh_share(input_idx, &ecdh_share)?;
//         }
//     }
//     Ok(())
// }

pub trait SignerPsbtExt {
    fn aggregate_ecdh_shares(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()>;
    fn compute_sp_outputs(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()>;
    fn sign_sp_inputs(&mut self, secp: &Secp256k1<secp256k1::All>, spend_key: SecretKey) -> Result<()>;
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

    fn compute_sp_outputs(&mut self, secp: &Secp256k1<secp256k1::All>) -> Result<()> {
        let network = silentpayments::Network::Mainnet; // We don't really care about the network, we'll see later

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
        generate_recipient_pubkeys(
            secp,
            generate_recipients_inputs.into_values().collect(),
            network,
        )
        .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    fn sign_sp_inputs(
        &mut self,
        secp: &Secp256k1<secp256k1::All>,
        spend_key: SecretKey
    ) -> Result<()> {
        let sp_inputs_idx: Vec<usize> = self.inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| {
                if let Some(_tweak) = input.sp_tweak {
                    Some(i)
                } else {
                    // not a sp input
                    None
                }
                // TODO must also check the bip32 pubkey to be sure that's our input
            })
            .collect();
        for idx in sp_inputs_idx {
            match self.sign_silent_payment_input(idx, spend_key, secp) {
                Ok(_) => (),
                Err(e) => log::debug!("Failed to sign input {}: {}", idx, e.to_string())
            };
        }
        Ok(())
    }
}
