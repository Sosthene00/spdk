//! BIP-352 Silent Payment Cryptography
//!
//! Implements cryptographic primitives for BIP-352 silent payments.

use super::error::{CryptoError, Result};
use bitcoin::key::TapTweak;
use bitcoin::ScriptBuf;
use psbt_v2::v2::Input;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use silentpayments::bitcoin_hashes::Hash as SpHash;
use silentpayments::utils::hash::SharedSecretHash;
use silentpayments::utils::NUMS_H;

/// Derive silent payment output public key
///
/// output_pubkey = spend_key + hash_BIP0352/SharedSecret(ecdh_secret || ser₃₂(k)) * G
pub fn derive_silent_payment_output_pubkey(
    secp: &Secp256k1<secp256k1::All>,
    spend_key: &PublicKey,
    ecdh_secret: &[u8; 33],
    k: u32,
) -> Result<PublicKey> {
    let ecdh_secret_pubkey = PublicKey::from_slice(ecdh_secret)?;
    let tweak_bytes =
        SpHash::to_byte_array(SharedSecretHash::from_ecdh_and_k(&ecdh_secret_pubkey, k));
    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|_| CryptoError::Other("Shared secret hash is invalid scalar".to_string()))?;
    let tweak_key = SecretKey::from_slice(&tweak.to_be_bytes())?;
    let tweak_point = PublicKey::from_secret_key(secp, &tweak_key);

    spend_key
        .combine(&tweak_point)
        .map_err(|e| CryptoError::Other(format!("Failed to derive output pubkey: {}", e)))
}

/// Convert public key to P2WPKH script
///
/// Returns: OP_0 <20-byte-hash>
pub fn pubkey_to_p2wpkh_script(pubkey: &PublicKey) -> ScriptBuf {
    let pubkey_hash = bitcoin::PublicKey::new(*pubkey)
        .wpubkey_hash()
        .expect("Compressed key");

    ScriptBuf::new_p2wpkh(&pubkey_hash)
}

/// Convert an ALREADY-TWEAKED output key to P2TR script
///
/// Use this for Silent Payment outputs where the pubkey is already
/// tweaked via BIP-352 derivation: output_pubkey = spend_key + t_k * G
///
/// The key has already been modified by the Silent Payment protocol,
/// so no additional BIP-341 taproot tweak should be applied.
///
/// Returns: OP_1 <32-byte-xonly-pubkey>
pub fn tweaked_key_to_p2tr_script(tweaked_output_key: &PublicKey) -> ScriptBuf {
    let xonly = tweaked_output_key.x_only_public_key().0;
    ScriptBuf::new_p2tr_tweaked(xonly.dangerous_assume_tweaked())
}

/// Detect script type from ScriptBuf
///
/// Returns a human-readable string identifying the script type.
/// Supports common Bitcoin script types including SegWit v0/v1.
pub fn script_type_string(script: &ScriptBuf) -> &'static str {
    if script.is_p2wpkh() {
        "P2WPKH"
    } else if script.is_p2tr() {
        "P2TR"
    } else if script.is_p2pkh() {
        "P2PKH"
    } else if script.is_p2sh() {
        "P2SH"
    } else if script.is_p2wsh() {
        "P2WSH"
    } else if script.is_op_return() {
        "OP_RETURN"
    } else {
        "Unknown"
    }
}

/// Check if an input is eligible for silent payments (BIP-352)
pub fn is_input_eligible(input: &Input) -> bool {
    // Check if input has witness_utxo
    let witness_utxo = match &input.witness_utxo {
        Some(utxo) => utxo,
        None => return false,
    };

    let script = &witness_utxo.script_pubkey;

    // P2WPKH (SegWit v0) - eligible
    if script.is_p2wpkh() {
        return true;
    }

    // P2TR (Taproot, SegWit v1) - eligible unless internal key is NUMS point (BIP-352)
    if script.is_p2tr() {
        if let Some(internal_key) = &input.tap_internal_key {
            if internal_key.serialize() == NUMS_H {
                return false;
            }
        }
        return true;
    }

    // P2PKH (legacy) - eligible
    if script.is_p2pkh() {
        return true;
    }

    // P2SH - only eligible if it's P2SH-P2WPKH
    if script.is_p2sh() {
        if let Some(redeem_script) = &input.redeem_script {
            return redeem_script.is_p2wpkh();
        }
        return false;
    }

    // All other types are ineligible (multisig, etc.)
    false
}

/// Compute ECDH shared secret
///
/// ecdh_secret = privkey * pubkey
pub fn compute_ecdh_share(
    secp: &Secp256k1<secp256k1::All>,
    privkey: &SecretKey,
    pubkey: &PublicKey,
) -> Result<PublicKey> {
    // Multiply pubkey by privkey scalar
    let scalar: Scalar = (*privkey).into();
    let shared = pubkey.mul_tweak(secp, &scalar)?;
    Ok(shared)
}

/// Apply tweak to spend private key for spending silent payment output
///
/// Computes: tweaked_privkey = spend_privkey + tweak
///
/// This is used by hardware signers to apply the output-specific tweak
/// to the spend private key before signing.
pub fn apply_tweak_to_privkey(spend_privkey: &SecretKey, tweak: &[u8; 32]) -> Result<SecretKey> {
    let tweak_scalar = Scalar::from_be_bytes(*tweak)
        .map_err(|_| CryptoError::Other("Invalid tweak scalar".to_string()))?;

    let mut tweaked = *spend_privkey;
    tweaked = tweaked
        .add_tweak(&tweak_scalar)
        .map_err(|e| CryptoError::Other(format!("Failed to apply tweak: {}", e)))?;

    Ok(tweaked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_tweak() {
        use silentpayments::utils::hash::LabelHash;
        let scan_privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let label = 42u32;

        let tweak = LabelHash::from_b_scan_and_m(scan_privkey, label).to_scalar();
        assert!(tweak.to_be_bytes().len() == 32);
    }

    #[test]
    fn test_shared_secret_tweak() {
        use silentpayments::bitcoin_hashes::Hash as SpHash;
        use silentpayments::utils::hash::SharedSecretHash;
        let ecdh_secret_pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let k = 0u32;

        let tweak_bytes =
            SpHash::to_byte_array(SharedSecretHash::from_ecdh_and_k(&ecdh_secret_pubkey, k));
        assert!(tweak_bytes.len() == 32);
    }

    #[test]
    fn test_ecdh_computation() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let share = compute_ecdh_share(&secp, &privkey, &pubkey).unwrap();
        assert!(share.serialize().len() == 33);
    }

    #[test]
    fn test_p2wpkh_script() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let script = pubkey_to_p2wpkh_script(&pubkey);
        assert_eq!(script.len(), 22); // OP_0 + 20 bytes
    }

    #[test]
    fn test_derive_from_test_vector() {
        let secp = Secp256k1::new();

        // From valid test vector 1
        let spend_key_hex = "024d518353f4bd18d769cf68ff62ef10669b7086246b0a6403fe57bde49211448b";
        let ecdh_secret_hex = "0255164e7926d50d52a09ff990647a5e95c1db1bfc68a616fbc2da213927f98bff";

        let spend_key = PublicKey::from_slice(&hex::decode(spend_key_hex).unwrap()).unwrap();
        let mut ecdh_secret: [u8; 33] = [0; 33];
        ecdh_secret.copy_from_slice(&hex::decode(ecdh_secret_hex).unwrap());

        let output_pubkey =
            derive_silent_payment_output_pubkey(&secp, &spend_key, &ecdh_secret, 0).unwrap();

        let xonly = output_pubkey.x_only_public_key().0;
        let xonly_hex = hex::encode(xonly.serialize());

        println!("Derived x-only: {}", xonly_hex);
        println!(
            "Expected x-only: 2ef9f0e19f3c275d84d98c44912fec626bac45e442af47d02d9b9652ff9a9f0a"
        );

        // This should match the test vector
        assert_eq!(
            xonly_hex,
            "2ef9f0e19f3c275d84d98c44912fec626bac45e442af47d02d9b9652ff9a9f0a"
        );
    }

    #[test]
    fn test_p2tr_script_creation() {
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        let script = tweaked_key_to_p2tr_script(&pubkey);

        // P2TR scripts are 34 bytes: OP_1 (0x51) + PUSH_32 (0x20) + 32-byte x-only key
        assert_eq!(script.len(), 34);
        assert!(script.is_p2tr());

        // Verify script structure
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x51); // OP_1
        assert_eq!(bytes[1], 0x20); // PUSH_32

        // Verify x-only key matches
        let (expected_xonly, _) = pubkey.x_only_public_key();
        assert_eq!(&bytes[2..34], &expected_xonly.serialize()[..]);
    }

    #[test]
    fn test_p2tr_script_compatibility() {
        // Verify that tweaked_key_to_p2tr_script produces identical results
        // to the manual construction previously used in validation.rs and input_finalizer.rs
        let secp = Secp256k1::new();
        let privkey = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &privkey);

        // New method
        let new_script = tweaked_key_to_p2tr_script(&pubkey);

        // Old method (manual construction)
        let (xonly, _parity) = pubkey.x_only_public_key();
        let mut script_bytes = Vec::with_capacity(34);
        script_bytes.push(0x51); // OP_1
        script_bytes.push(0x20); // PUSH_32
        script_bytes.extend_from_slice(&xonly.serialize().as_ref());
        let old_script = ScriptBuf::from_bytes(script_bytes);

        // Should be identical
        assert_eq!(new_script, old_script);
    }
}
