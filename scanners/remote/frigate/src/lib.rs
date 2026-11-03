//! `frigate` — remote silent-payment scanner backend for spdk, speaking the
//! Frigate electrum extension through the electrum streaming client (ESC).
//!
//! The Frigate transport client ([`backend_frigate::FrigateClient`]) lives in
//! the `backend-frigate` crate (mirroring the blindbit layout: the backend
//! crate holds the remote-service client, `scanners/` the scanning logic);
//! this crate holds the scanning logic.
//!
//! See the crate `README.md` for usage and — before pointing this at
//! anything but a trusted server — the trust model: the scan private key is
//! sent to the server.

mod scanner;

pub use scanner::FrigateScanner as Scanner;

/// Re-exported for the integration test in `tests/vectors.rs`, which asserts
/// the crate's scanning math (`process_outputs`) against the canonical BIP-352
/// receive vectors. `#[doc(hidden)]`: deliberately not part of the documented
/// public API — visibility-only plumbing for the regression test, no logic
/// touched.
#[doc(hidden)]
pub use scanner::process_outputs;
