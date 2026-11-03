mod scanner;

pub use scanner::FrigateScanner as Scanner;

/// Re-exported for the integration test in `tests/vectors.rs`, which asserts
/// the crate's scanning math (`process_outputs`) against the canonical BIP-352
/// receive vectors. `#[doc(hidden)]`: deliberately not part of the documented
/// public API — visibility-only plumbing for the regression test, no logic
/// touched.
#[doc(hidden)]
pub use scanner::process_outputs;
