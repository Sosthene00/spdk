//! Error types for cryptographic operations

use std::fmt;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Cryptographic errors
#[derive(Debug)]
pub enum CryptoError {
    Secp256k1(secp256k1::Error),

    InvalidPrivateKey,

    InvalidPublicKey,

    InvalidSignature,

    DleqGenerationFailed(String),

    DleqVerificationFailed,

    InvalidDleqProofLength(usize),

    InvalidEcdh,

    HashError(String),

    Other(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secp256k1(err) => write!(f, "Secp256k1 error: {err}"),
            Self::InvalidPrivateKey => write!(f, "Invalid private key"),
            Self::InvalidPublicKey => write!(f, "Invalid public key"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::DleqGenerationFailed(err) => write!(f, "DLEQ proof generation failed: {err}"),
            Self::DleqVerificationFailed => write!(f, "DLEQ proof verification failed"),
            Self::InvalidDleqProofLength(len) => {
                write!(f, "Invalid DLEQ proof length: expected 64 bytes, got {len}")
            }
            Self::InvalidEcdh => write!(f, "Invalid ECDH result"),
            Self::HashError(err) => write!(f, "Hash function error: {err}"),
            Self::Other(err) => write!(f, "Other error: {err}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<secp256k1::Error> for CryptoError {
    fn from(value: secp256k1::Error) -> Self {
        Self::Secp256k1(value)
    }
}
