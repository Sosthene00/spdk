//! `backend-frigate` — Frigate electrum transport client for spdk.
//!
//! Wraps the electrum streaming client (ESC) behind [`FrigateClient`]:
//! plain TCP and TLS (`ssl://host:port`) connections, protocol-version
//! negotiation, and typed request wrappers (version / network / tip height /
//! subscribe / unsubscribe / scripthash / header / tx / history). TLS verifies against
//! the webpki-roots public trust store — see the scanner crate README for
//! the trust model (the scan private key crosses the wire).

mod client;

pub use client::{FrigateClient, FrigateError};
