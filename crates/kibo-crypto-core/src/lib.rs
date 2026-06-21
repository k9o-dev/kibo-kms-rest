//! Public raw-crypto primitives for the Kibo vault plane.
//!
//! Scope: AES-256-GCM-SIV authenticated encryption, data-encryption-key
//! (DEK) lifecycle, HKDF-SHA-256 key derivation, the versioned ciphertext
//! envelope format with embedded version routing, and the shared boundary
//! types consumed across the BYOK / HYOK client surface.
//!
//! These primitives are deterministic and side-effect-free at the
//! cryptographic boundary. The bounded-symbolic Kani proof matrix in
//! [`kani_proofs`] verifies round-trip soundness, tamper detection, AAD
//! binding, key distinctness, and envelope wire-format integrity over a
//! deterministic AEAD contract model.

#![cfg_attr(not(test), deny(unsafe_code))]

pub mod aead;
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
