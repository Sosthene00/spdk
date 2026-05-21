//! BIP-375 Core Library
//!
//! Core data structures and types for BIP-375 (Sending Silent Payments with PSBTs).
//!
//! This crate provides:
//! - PSBT v2 data structures
//! - Silent payment address types
//! - ECDH share types
//! - UTXO types

pub mod error;
pub mod extensions;
pub mod shares;
pub mod types;
pub mod utils;

pub use error::{Error, Result};
pub use extensions::{Bip375PsbtExt, GlobalFieldsExt, InputFieldsExt, OutputFieldsExt};
pub use psbt_v2::v2::{Global, Input, Output, Psbt};
pub use shares::{aggregate_ecdh_shares, AggregatedShare, AggregatedShares};
pub use types::EcdhShareData;

pub type PsbtKey = psbt_v2::raw::Key;
