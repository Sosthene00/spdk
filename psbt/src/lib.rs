//! BIP-375 PSBT Module
//!
//! This module contains all BIP-375 PSBT functionality, organized into submodules:
//! - `core`: Core data structures and types
//! - `crypto`: Cryptographic primitives
//! - `helpers`: Helper utilities for display and wallet operations
//! - `roles`: PSBT role implementations (creator, constructor, updater, signer, etc.)

pub mod core;
pub mod crypto;
pub mod roles;

// Re-export commonly used types from core
pub use core::{
    aggregate_ecdh_shares, AggregatedShare, AggregatedShares, Bip375PsbtExt, EcdhShareData, Error,
    GlobalFieldsExt, InputFieldsExt, OutputFieldsExt, Psbt, PsbtKey, Result,
};

// Re-export DleqProof from psbt_v2 (used in EcdhShareData)
pub use psbt_v2::v2::dleq::DleqProof;

// Re-export rust-dleq types and conversion functions from crypto module
pub use crypto::dleq::{from_psbt_v2_proof, to_psbt_v2_proof, DleqError, RustDleqProof};
