//! BIP-375 Type Definitions
//!
//! Core types for silent payments in PSBTs.

use psbt_v2::v2::dleq::DleqProof;
use secp256k1::PublicKey;

// ============================================================================
// Core BIP-352/BIP-375 Protocol Types
// ============================================================================

/// ECDH share for a silent payment output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdhShareData {
    /// Scan public key this share is for (33 bytes)
    pub scan_key: PublicKey,
    /// ECDH share value (33 bytes compressed public key)
    pub share: PublicKey,
    /// Optional DLEQ proof (64 bytes)
    pub dleq_proof: Option<DleqProof>,
}

impl EcdhShareData {
    /// Create a new ECDH share
    pub fn new(scan_key: PublicKey, share: PublicKey, dleq_proof: Option<DleqProof>) -> Self {
        Self {
            scan_key,
            share,
            dleq_proof,
        }
    }

    /// Create an ECDH share without a DLEQ proof
    pub fn without_proof(scan_key: PublicKey, share: PublicKey) -> Self {
        Self::new(scan_key, share, None)
    }

    /// Serialize share data (scan_key || share)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(66);
        bytes.extend_from_slice(&self.scan_key.serialize());
        bytes.extend_from_slice(&self.share.serialize());
        bytes
    }

    /// Deserialize share data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::Error> {
        if bytes.len() != 66 {
            return Err(super::Error::InvalidEcdhShare(format!(
                "Invalid length: expected 66 bytes, got {}",
                bytes.len()
            )));
        }

        let scan_key = PublicKey::from_slice(&bytes[0..33])
            .map_err(|e| super::Error::InvalidEcdhShare(e.to_string()))?;
        let share = PublicKey::from_slice(&bytes[33..66])
            .map_err(|e| super::Error::InvalidEcdhShare(e.to_string()))?;

        Ok(Self {
            scan_key,
            share,
            dleq_proof: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};
    use silentpayments::{Network, SilentPaymentAddress, SpVersion};

    #[test]
    fn test_silent_payment_address_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let spend_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let addr =
            SilentPaymentAddress::new(scan_key, spend_key, Network::Regtest, SpVersion::ZERO);
        let bytes: Vec<u8> = addr.to_string().into_bytes();
        let decoded = SilentPaymentAddress::try_from(String::from_utf8(bytes).unwrap()).unwrap();

        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_ecdh_share_serialization() {
        let secp = Secp256k1::new();
        let scan_key =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let share = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());

        let ecdh = EcdhShareData::without_proof(scan_key, share);
        let bytes = ecdh.to_bytes();
        let decoded = EcdhShareData::from_bytes(&bytes).unwrap();

        assert_eq!(ecdh.scan_key, decoded.scan_key);
        assert_eq!(ecdh.share, decoded.share);
    }
}
