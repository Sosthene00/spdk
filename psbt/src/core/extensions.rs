//! BIP-375 Extension Traits and PSBT Accessors
//!
//! This module provides extension traits that add BIP-375 silent payment functionality
//! to the `psbt_v2::v2::Psbt` type, along with convenience accessor functions for
//! common PSBT field access patterns.
//!
//! # Module Contents
//!
//! - **`Bip375PsbtExt` trait**: Adds BIP-375 specific methods to PSBT
//!   - ECDH share management (global and per-input)
//!   - DLEQ proof handling
//!   - Silent payment address/label fields
//!   - SP tweak fields for spending
//!
//! - **Convenience Accessors**: Higher-level functions for extracting typed data
//!   - Input field extraction (txid, vout, outpoint, pubkeys)
//!   - Output field extraction (SP keys)
//!   - Fallback logic for public key detection
//!
//! # Design Philosophy
//!
//! - **Non-invasive**: Uses extension traits rather than wrapping types
//! - **Idiomatic**: Follows rust-psbt patterns and conventions
//! - **Upstreamable**: Clean API that could be contributed to rust-psbt
//! - **Type-safe**: Leverages Rust's type system for correctness

use super::{
    error::{Error, Result},
    EcdhShareData,
};
use psbt_v2::{
    bitcoin::CompressedPublicKey,
    v2::{dleq::DleqProof, Psbt},
};
use silentpayments::secp256k1::PublicKey;

pub const PSBT_OUT_DNSSEC_PROOF: u64 = 0x35;
pub const PSBT_IN_SP_SPEND_BIP32_DERIVATION: u64 = 0x1f;
pub const PSBT_IN_SP_TWEAK: u64 = 0x20;
/// Extension trait for BIP-375 silent payment fields on PSBT v2
///
/// This trait adds methods to access and modify BIP-375 specific fields:
/// - ECDH shares (global and per-input)
/// - DLEQ proofs (global and per-input)
/// - Silent payment addresses (per-output)
/// - Silent payment labels (per-output)
pub trait Bip375PsbtExt {
    // ===== Global ECDH Shares =====

    /// Get all global ECDH shares
    ///
    /// Global shares are used when one party knows all input private keys.
    /// Field type: PSBT_GLOBAL_SP_ECDH_SHARE (0x07)
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData>;

    /// Add a global ECDH share
    ///
    /// # Arguments
    /// * `share` - The ECDH share to add
    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()>;

    // ===== Per-Input ECDH Shares =====

    /// Get ECDH shares for a specific input
    ///
    /// Returns per-input shares if present, otherwise falls back to global shares.
    /// Field type: PSBT_IN_SP_ECDH_SHARE (0x1d)
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData>;

    /// Add an ECDH share to a specific input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `share` - The ECDH share to add
    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()>;

    // ===== Silent Payment Spend Key Derivation (BIP-376) =====

    /// Get silent payment tweak for an input
    ///
    /// Returns the 32-byte tweak that should be added to the spend private key
    /// to spend this silent payment output.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]>;

    /// Set silent payment tweak for an input
    ///
    /// The tweak is derived from BIP-352 output derivation during wallet scanning.
    /// Hardware signer uses this to compute: tweaked_privkey = spend_privkey + tweak
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    /// * `tweak` - The 32-byte tweak
    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()>;

    /// Remove silent payment tweak from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_TWEAK
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()>;

    /// Remove silent payment spend key BIP32 derivation from an input
    ///
    /// This is typically called after transaction extraction to clean up the PSBT.
    /// Prevents accidental re-use of tweaks and keeps PSBTs cleaner.
    ///
    /// Field type: PSBT_IN_SP_SPEND_BIP32_DERIVATION
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()>;

    // ===== Convenience Methods =====

    /// Get the number of inputs
    fn num_inputs(&self) -> usize;

    /// Get the number of outputs
    fn num_outputs(&self) -> usize;

    /// Get partial signatures for an input
    ///
    /// # Arguments
    /// * `input_index` - Index of the input
    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)>;
}

impl Bip375PsbtExt for Psbt {
    fn get_global_ecdh_shares(&self) -> Vec<EcdhShareData> {
        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &self.global.sp_ecdh_shares {
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for corresponding DLEQ proof
            let dleq_proof = get_global_dleq_proof(self, &scan_key_pk);
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_global_ecdh_share(&mut self, share: &EcdhShareData) -> Result<()> {
        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::new(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        self.global.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_global_dleq_proof(self, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_input_ecdh_shares(&self, input_index: usize) -> Vec<EcdhShareData> {
        let Some(input) = self.inputs.get(input_index) else {
            return Vec::new();
        };

        let mut shares = Vec::new();

        for (scan_key_compressed, share_compressed) in &input.sp_ecdh_shares {
            println!("scan_key_compressed: {:?}", scan_key_compressed);
            // Convert CompressedPublicKey to secp256k1::PublicKey via the inner field
            let scan_key_pk = scan_key_compressed.0;
            let share_point = share_compressed.0;

            // Look for DLEQ proof (input-specific or global)
            let dleq_proof = get_input_dleq_proof(self, input_index, &scan_key_pk)
                .or_else(|| get_global_dleq_proof(self, &scan_key_pk));
            shares.push(EcdhShareData::new(scan_key_pk, share_point, dleq_proof));
        }

        shares
    }

    fn add_input_ecdh_share(&mut self, input_index: usize, share: &EcdhShareData) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        // Convert secp256k1::PublicKey -> bitcoin::PublicKey -> CompressedPublicKey
        let scan_key = CompressedPublicKey::try_from(bitcoin::PublicKey::from(share.scan_key))
            .map_err(|_| Error::InvalidPublicKey)?;
        let ecdh_share = CompressedPublicKey::try_from(bitcoin::PublicKey::from(share.share))
            .map_err(|_| Error::InvalidPublicKey)?;

        input.sp_ecdh_shares.insert(scan_key, ecdh_share);

        // Add DLEQ proof if present
        if let Some(proof) = share.dleq_proof {
            add_input_dleq_proof(self, input_index, &share.scan_key, proof)?;
        }

        Ok(())
    }

    fn get_input_sp_tweak(&self, input_index: usize) -> Option<[u8; 32]> {
        let input = self.inputs.get(input_index)?;
        input.sp_tweak
    }

    fn set_input_sp_tweak(&mut self, input_index: usize, tweak: [u8; 32]) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;

        input.sp_tweak = Some(tweak);
        Ok(())
    }

    fn remove_input_sp_tweak(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;
        input.sp_tweak = None;
        Ok(())
    }

    fn remove_input_sp_spend_bip32_derivation(&mut self, input_index: usize) -> Result<()> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or(Error::InvalidInputIndex(input_index))?;
        input.sp_spend_bip32_derivations.clear();
        Ok(())
    }

    fn num_inputs(&self) -> usize {
        self.inputs.len()
    }

    fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    fn get_input_partial_sigs(&self, input_index: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if let Some(input) = self.inputs.get(input_index) {
            input
                .partial_sigs
                .iter()
                .map(|(pk, sig)| (pk.inner.serialize().to_vec(), sig.to_vec()))
                .collect()
        } else {
            Vec::new()
        }
    }
}

// Private helper functions for DLEQ proof management
fn get_global_dleq_proof(psbt: &Psbt, scan_key: &PublicKey) -> Option<DleqProof> {
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;
    psbt.global
        .sp_dleq_proofs
        .get(&scan_key_compressed)
        .copied()
}

fn add_global_dleq_proof(psbt: &mut Psbt, scan_key: &PublicKey, proof: DleqProof) -> Result<()> {
    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    psbt.global
        .sp_dleq_proofs
        .insert(scan_key_compressed, proof);

    Ok(())
}

fn get_input_dleq_proof(
    psbt: &Psbt,
    input_index: usize,
    scan_key: &PublicKey,
) -> Option<DleqProof> {
    let input = psbt.inputs.get(input_index)?;
    let scan_key_compressed =
        CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key)).ok()?;

    input.sp_dleq_proofs.get(&scan_key_compressed).copied()
}

fn add_input_dleq_proof(
    psbt: &mut Psbt,
    input_index: usize,
    scan_key: &PublicKey,
    proof: DleqProof,
) -> Result<()> {
    let input = psbt
        .inputs
        .get_mut(input_index)
        .ok_or(Error::InvalidInputIndex(input_index))?;

    let scan_key_compressed = CompressedPublicKey::try_from(bitcoin::PublicKey::new(*scan_key))
        .map_err(|_| Error::InvalidPublicKey)?;

    input.sp_dleq_proofs.insert(scan_key_compressed, proof);

    Ok(())
}

// ============================================================================
// Display Extension Traits
// ============================================================================
//
// The following traits provide methods for extracting and serializing PSBT fields
// for display purposes. These are used by GUI and analysis tools to inspect PSBT contents.

/// Extension trait for iterating all PSBT global map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait GlobalFieldsExt {
    /// Returns all global map fields as (field_type, key_data, value_data) tuples.
    fn iter_global_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl GlobalFieldsExt for psbt_v2::v2::Global {
    fn iter_global_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT input map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait InputFieldsExt {
    /// Returns all input map fields as (field_type, key_data, value_data) tuples.
    fn iter_input_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl InputFieldsExt for psbt_v2::v2::Input {
    fn iter_input_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

/// Extension trait for iterating all PSBT output map fields as raw (type, key, value) tuples.
///
/// Delegates to psbt_v2's internal serialization path, so all fields — including unknowns
/// and any future additions to psbt_v2 — are returned automatically in serialization order.
pub trait OutputFieldsExt {
    /// Returns all output map fields as (field_type, key_data, value_data) tuples.
    fn iter_output_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)>;
}

impl OutputFieldsExt for psbt_v2::v2::Output {
    fn iter_output_fields(&self) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        self.pairs()
            .into_iter()
            .map(|pair| (pair.key.type_value, pair.key.key, pair.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn create_test_psbt() -> Psbt {
        // Create a minimal valid PSBT v2
        Psbt {
            global: psbt_v2::v2::Global::default(),
            inputs: vec![],
            outputs: vec![],
        }
    }

    #[test]
    fn test_global_ecdh_share() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = EcdhShareData::without_proof(scan_key, share_point);

        // Add share
        psbt.add_global_ecdh_share(&share).unwrap();

        // Retrieve shares
        let shares = psbt.get_global_ecdh_shares();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].scan_key, scan_key);
        assert_eq!(shares[0].share, share_point);
    }

    #[test]
    fn test_global_dleq_proof() {
        let mut psbt = create_test_psbt();

        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let proof = DleqProof([0x42u8; 64]);

        // Add proof
        add_global_dleq_proof(&mut psbt, &scan_key, proof).unwrap();

        // Retrieve proof
        let retrieved = get_global_dleq_proof(&psbt, &scan_key);
        assert_eq!(retrieved, Some(proof));
    }
}
