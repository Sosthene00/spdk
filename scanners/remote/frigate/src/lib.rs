//! `frigate` — remote silent-payment scanner backend for spdk, speaking the
//! Frigate electrum extension through the electrum streaming client (ESC).
//!
//! See the crate `README.md` for usage and — before pointing this at
//! anything but a trusted server — the trust model: the scan private key is
//! sent to the server.

mod client;
mod scanner;

pub use client::FrigateClient;
pub use scanner::FrigateScanner as Scanner;

/// Re-exported for the integration test in `tests/vectors.rs`, which asserts
/// the crate's scanning math (`process_outputs`) against the canonical BIP-352
/// receive vectors. `#[doc(hidden)]`: deliberately not part of the documented
/// public API — visibility-only plumbing for the regression test, no logic
/// touched.
#[doc(hidden)]
pub use scanner::process_outputs;
