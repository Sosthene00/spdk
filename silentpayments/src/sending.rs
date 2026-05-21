//! Sending-side output key derivation for Silent Payments.
//!
//! Use [`generate_recipient_pubkeys`] with one or more [`GeneratePubkeysInput`] items.
//! Each item contains:
//! - the recipient scan key,
//! - the ECDH shared secret for that recipient/input set, and
//! - the recipient spend keys to derive output pubkeys for.
//!
//! Using [`generate_recipient_pubkeys`] will require calculating a
//! `ecdh_shared_secret` for each scan key beforehand.

use secp256k1::Signing;
use secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey};
use std::collections::HashMap;

use crate::utils::common::SpVersion;
use crate::utils::common::{calculate_t_n, SILENT_PAYMENT_ADDRESS_BYTE_LEN};
use crate::utils::common::{InputHashApplied, SharedSecret};
use crate::Result;

#[derive(Debug)]
pub struct GeneratePubkeysInput {
    pub scan_key: PublicKey,
    pub ecdh_shared_secret: SharedSecret<InputHashApplied>,
    pub spend_keys: Vec<PublicKey>,
    pub sp_version: SpVersion,
}

/// Create outputs for a given set of silent payment recipients and their corresponding shared secrets.
///
/// When creating transaction outputs, call this function once with all recipients.
///
/// Calling it multiple times for the same transaction can reuse address indexes.
///
/// # Arguments
///
/// * `inputs` - A collection of [`GeneratePubkeysInput`] values. Each value
///   provides the recipient scan key, ECDH shared secret, spend keys, and
///   silent payment version used for derivation.
///
/// # Returns
///
/// Returns a [`HashMap`] from [`[u8: 67]`] (serialization of version, scan_key, spend_key) to derived output
/// [`XOnlyPublicKey`] values for that address.
///
/// # Errors
///
/// This function will return an error if:
///
/// * Edge cases are hit during elliptic curve computation (extremely unlikely).
pub fn generate_recipient_pubkeys<C: Signing>(
    secp: &Secp256k1<C>,
    inputs: Vec<GeneratePubkeysInput>,
) -> Result<HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>>> {
    let mut result: HashMap<[u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN], Vec<XOnlyPublicKey>> =
        HashMap::new();
    for input in inputs {
        let ecdh_shared_secret = &input.ecdh_shared_secret;
        let mut k = 0;
        for spend_key in input.spend_keys {
            let t_n = calculate_t_n(ecdh_shared_secret, k)?;
            let res = t_n.public_key(secp);
            let reskey = res.combine(&spend_key)?;
            let (reskey_xonly, _) = reskey.x_only_public_key();

            let mut key = [0u8; SILENT_PAYMENT_ADDRESS_BYTE_LEN];
            key[0] = input.sp_version.into();
            key[1..34].copy_from_slice(&input.scan_key.serialize());
            key[34..].copy_from_slice(&spend_key.serialize());
            let entry = result.entry(key).or_default();
            entry.push(reskey_xonly);
            k += 1;
        }
    }
    Ok(result)
}
