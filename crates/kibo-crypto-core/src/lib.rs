//! The encryption primitives behind the Kibo client SDKs.
//!
//! Scope: AES-256-GCM-SIV authenticated encryption, data keys (DEKs),
//! HKDF-SHA-256 key derivation, the versioned ciphertext format, and the
//! types the client SDKs share.
//!
//! The Kani proofs in this crate check round-trip soundness, tamper
//! detection, AAD binding, key distinctness, and the ciphertext format
//! over a deterministic AEAD model.

#![cfg_attr(not(test), deny(unsafe_code))]

pub mod aead;
pub mod app_container;
pub mod dek;
pub mod envelope;
pub mod kdf;
pub mod types;

/// Bounded-symbolic Kani proofs over the crypto kernel.
///
/// Gated on `#[cfg(kani)]` so the module is skipped under normal
/// `cargo build` / `cargo test`. Compiled + executed only via
/// `cargo kani`. See module docs for the 8-property matrix substance
/// + invocation discipline.
#[cfg(kani)]
mod kani_proofs;

/// Deterministic AEAD contract stubs for the Kani wrapper-tier proofs
/// (P1/P2/P3/P7/P9). Gated `#[cfg(any(kani, test))]` so the model is
/// compiled under both Kani (consumed via `#[kani::stub]`) AND `cargo test`
/// (its own unit tests assert the model is non-vacuous — rejects every
/// key/aad/nonce/tamper mismatch class). NOT a cipher; see module docs.
#[cfg(any(kani, test))]
mod kani_stubs;

pub use types::{KeyVersionRef, Region, WrappedDek};
pub use zeroize::Zeroizing;
