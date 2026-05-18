//! Silent Payment ECDH Share Aggregation
//!
//! Provides functions for aggregating ECDH shares across PSBT inputs according to BIP-375.
//!
//! # Global vs Per-Input Shares
//!
//! BIP-375 supports two modes of ECDH share distribution:
//!
//! - **Global Shares**: All inputs have the same ECDH share point for a given scan key.
//!   These are stored in PSBT_GLOBAL_SP_ECDH_SHARE (0x07) and should NOT be summed.
//!   Used when one party knows all input private keys.
//!
//! - **Per-Input Shares**: Each input has a unique ECDH share computed from its private key.
//!   These are stored in PSBT_IN_SP_ECDH_SHARE (0x1d) and MUST be summed.
//!   Used in multi-party signing scenarios.
//!
//! This module automatically detects which mode is being used and aggregates accordingly.

use crate::core::utils::is_input_eligible;

use super::{Bip375PsbtExt, Error, Psbt, Result};
use bitcoin::{consensus::serialize, OutPoint};
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::utils::{
    common::{Raw, SharedSecret},
    sending::TypedSecretKey,
};
use std::collections::HashMap;

/// Result of ECDH share aggregation for a single scan key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedShare {
    /// The aggregated ECDH share (single point)
    pub aggregated_share: PublicKey,
    pub is_global: bool,
    /// Number of inputs that contributed shares
    pub num_inputs: usize,
}

/// Collection of aggregated ECDH shares for all scan keys in a PSBT
#[derive(Debug, Clone)]
pub struct AggregatedShares {
    /// Map of scan_key -> aggregated result
    shares: HashMap<PublicKey, AggregatedShare>,
}

impl AggregatedShares {
    /// Get the aggregated share for a specific scan key
    pub fn get(&self, scan_key: &PublicKey) -> Option<&AggregatedShare> {
        self.shares.get(scan_key)
    }

    /// Get the aggregated share point for a specific scan key
    pub fn get_share_point(&self, scan_key: &PublicKey) -> Option<PublicKey> {
        self.shares.get(scan_key).map(|s| s.aggregated_share)
    }

    /// Get all scan keys that have aggregated shares
    pub fn scan_keys(&self) -> Vec<PublicKey> {
        self.shares.keys().copied().collect()
    }

    /// Check if shares exist for a given scan key
    pub fn has_scan_key(&self, scan_key: &PublicKey) -> bool {
        self.shares.contains_key(scan_key)
    }

    /// Get the number of scan keys with aggregated shares
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Check if there are no aggregated shares
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Iterate over all aggregated shares
    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &AggregatedShare)> {
        self.shares.iter()
    }
}

/// Aggregate ECDH shares from all inputs in a PSBT
///
/// This function:
/// 1. Collects all ECDH shares from all inputs, grouped by scan key
/// 2. Detects whether shares are global (all identical) or per-input (unique)
/// 3. For global shares: returns the share without summing
/// 4. For per-input shares: sums all shares using elliptic curve addition
///
/// # Arguments
/// * `psbt` - The PSBT containing ECDH shares
///
/// # Returns
/// * `AggregatedShares` - Collection of aggregated shares for all scan keys
///
/// # Errors
/// * If no inputs exist in the PSBT
/// * If elliptic curve operations fail during aggregation
pub fn aggregate_ecdh_shares(psbt: &Psbt) -> Result<AggregatedShares> {
    let num_inputs = psbt.num_inputs();
    if num_inputs == 0 {
        return Err(Error::Other(
            "Cannot aggregate ECDH shares: no inputs".to_string(),
        ));
    }

    let mut result_shares = HashMap::new();

    // Step 0: Collect explicit Global Shares
    // These are stored in PSBT_GLOBAL_SP_ECDH_SHARE (0x07) and take precedence
    let global_shares = psbt.get_global_ecdh_shares();
    for share in global_shares {
        result_shares.insert(
            share.scan_key,
            AggregatedShare {
                aggregated_share: share.share,
                is_global: true,
                num_inputs, // Global share implicitly covers all inputs
            },
        );
    }

    // Step 1: Collect input shares grouped by scan key
    let mut shares_by_scan_key: HashMap<PublicKey, Vec<PublicKey>> = HashMap::new();

    for input_idx in 0..num_inputs {
        let shares = psbt.get_input_ecdh_shares(input_idx);
        for share in shares {
            shares_by_scan_key
                .entry(share.scan_key)
                .or_default()
                .push(share.share);
        }
    }

    // Step 2: Aggregate per-input shares.
    //
    // Important: only explicit PSBT_GLOBAL_SP_ECDH_SHARE entries are global.
    // Detecting "implicit global" by comparing share point equality is wrong:
    // multiple inputs can legitimately produce identical share points (e.g. reused keys),
    // and those must still be summed.
    for (scan_key, shares) in shares_by_scan_key {
        // If we already have an explicit global share for this key, skip input aggregation
        if result_shares.contains_key(&scan_key) {
            continue;
        }

        // Per-input shares: sum them using elliptic curve addition.
        let aggregated_share =
            PublicKey::combine_keys(shares.iter().collect::<Vec<&PublicKey>>().as_slice())?;

        result_shares.insert(
            scan_key,
            AggregatedShare {
                aggregated_share,
                is_global: false,
                num_inputs: shares.len(),
            },
        );
    }

    Ok(AggregatedShares {
        shares: result_shares,
    })
}

// /// Compute BIP-352 shared secrets from aggregated ECDH shares and PSBT inputs.
// ///
// /// Correctly handles both global and per-input ECDH share modes:
// /// - Global share: sum all eligible input pubkeys
// /// - Per-input shares: sum only the pubkeys of inputs that contributed a share for that scan key
// pub fn compute_sp_shared_secrets(
//     secp: &Secp256k1<secp256k1::All>,
//     psbt: &Psbt,
//     aggregated_shares: &AggregatedShares,
// ) -> Result<HashMap<PublicKey, PublicKey>> {
//     // BIP-352: the smallest outpoint is computed over ALL transaction inputs,
//     // not just BIP-352-eligible ones. Excluding ineligible inputs here would
//     // change the resulting input_hash whenever the smallest outpoint belongs
//     // to an ineligible input (e.g. P2TR script-path with NUMS internal key).
//     let mut outpoints: Vec<[u8; 36]> = Vec::with_capacity(psbt.num_inputs());
//     for input_idx in 0..psbt.num_inputs() {
//         let input = &psbt.inputs[input_idx];
//         let outpoint = OutPoint::new(input.previous_txid, input.spent_output_index);
//         outpoints.push(
//             serialize(&outpoint)
//                 .try_into()
//                 .expect("OutPoint is 36 bytes long"),
//         );
//     }

//     // Build sum of all eligible input pubkeys
//     let mut pubkeys = Vec::new();
//     for input_idx in 0..psbt.num_inputs() {
//         let input = match psbt.inputs.get(input_idx) {
//             Some(i) => i,
//             None => return Err(Error::InvalidInputIndex(input_idx)),
//         };
//         if !is_input_eligible(input).unwrap_or(false) {
//             continue;
//         }
//         if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
//             pubkeys.push(pubkey);
//         }
//     }
//     let summed_pubkeys =
//         PublicKey::combine_keys(pubkeys.iter().collect::<Vec<&PublicKey>>().as_slice())?;

//     for input_idx in 0..psbt.num_inputs() {
//         let shares = psbt.get_input_ecdh_shares(input_idx);
//         for share in &shares {
//             if let Some(entry) = summed_pubkeys.get_mut(&share.scan_key) {
//                 if aggregated_shares
//                     .get(&share.scan_key)
//                     .map(|a| !a.is_global)
//                     .unwrap_or(false)
//                 {
//                     if let Ok(pubkey) = get_input_pubkey(psbt, input_idx) {
//                         *entry = Some(match *entry {
//                             None => pubkey,
//                             Some(existing) => existing.combine(&pubkey).map_err(|e| {
//                                 Error::Other(format!("Failed to sum pubkeys: {}", e))
//                             })?,
//                         });
//                     }
//                 }
//             }
//         }
//     }

//     let mut shared_secrets: HashMap<PublicKey, PublicKey> = HashMap::new();
//     for (scan_key, agg) in aggregated_shares.iter() {
//         let shared_secret = match summed_pubkeys.get(scan_key).and_then(|v| *v) {
//             Some(summed_pubkey) => {
//                 let ecdh_shared_secret = SharedSecret::<Raw>::from_inner(&agg.aggregated_share);
//             }
//             // No pubkeys available: use raw aggregated share (fallback for test contexts
//             // where inputs have no BIP32 derivation data)
//             None => {
//                 return Err(Error::Other(
//                     "Fallback aggregated_shares required".to_string(),
//                 ))
//             }
//         };
//         shared_secrets.insert(*scan_key, shared_secret);
//     }

//     Ok(shared_secrets)
// }
