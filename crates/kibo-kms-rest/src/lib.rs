//! Encrypt with your own cloud KMS key directly from the device or client.
//!
//! This crate runs on the device itself (a phone, an IoT gateway, an edge
//! node) and talks **directly** to your KMS over plain HTTPS.
//!
//! It is deliberately minimal:
//!
//! - **No key-encryption key.** At most it holds, briefly, one 32-byte
//!   data key (DEK) and a short-lived federated token you issued.
//! - **No vendor SDKs.** There is no `aws-sdk-kms`, `google-cloud-kms`,
//!   Azure SDK, Smithy, or `tonic` here. The dependencies are a rustls
//!   HTTP client (`reqwest`), `sha2` +
//!   `hmac` (SigV4 signing), `kibo-crypto-core` (envelope framing),
//!   `serde`, `thiserror`, and `zeroize`.
//! - **REST-direct.** Every provider call is a plain HTTPS request that
//!   the device signs itself, so the crate ships into edge targets that
//!   cannot carry a heavyweight cloud SDK.
//!
//! # Provider selection (composable cargo features)
//!
//! Enable one or more of the following features; the provider is chosen at call
//! time from the runtime `provider` field, so a build with several providers
//! compiled in serves them all from one artifact:
//!
//! - `kms-aws`   — AWS KMS REST (SigV4-signed).
//! - `kms-gcp`   — GCP Cloud KMS REST (OAuth bearer).
//! - `kms-azure` — Azure Key Vault REST (OAuth bearer).
//! - `kms-vault` — HashiCorp Vault Transit REST (token auth).
//!
//! A minimal client compiles in just the one provider it uses; a single
//! all-providers artifact compiles in all four. Building with zero providers is
//! a configuration error — every call then finds no matching provider at runtime
//! (`Cargo`'s additive feature model has no portable "at least one" assertion).
//!
//! # Two strategies
//!
//! See [`Strategy`]:
//!
//! - [`Strategy::CustomerKmsOracle`] — the customer KMS encrypts /
//!   decrypts the **data** itself (KMS as an encryption oracle).
//! - [`Strategy::LocalEnvelope`] — the customer KMS only wraps / unwraps
//!   the **32-byte DEK**; the bulk-data AES is performed by `kibo-crypto-core`
//!   on-device, never here.
//!
//! # AAD / `encryptionContext` rule
//!
//! The Additional Authenticated Data binds
//! `{version, strategy, attestation_tier}` together with the
//! caller-supplied `encryptionContext`. The `encryptionContext` is
//! **re-supplied at decrypt time and is NEVER read back from the
//! envelope.** An envelope MAY store a copy of the context, but that copy
//! is for audit / debugging only and is never trusted as a decrypt
//! input. This rule is encoded in the [`provider::KmsRestProvider`] API
//! shape — `decrypt` *requires* the caller to pass the context — and is
//! re-stated at each call site.
//!
//! # Substance boundary
//!
//! This crate carries the **structure + types**; the crypto substance — SigV4 /
//! OAuth signing, the HTTP round-trip, and AAD composition — lives in the
//! provider backends. All four [`provider`] backends
//! (`aws`/`gcp`/`azure`/`vault`) implement REST-direct `encrypt`/`decrypt`
//! against the customer KMS.

#![forbid(unsafe_code)]
// Doc comments name proper nouns + vendor APIs (AWS, KMS, SigV4, JWK, …);
#![allow(clippy::doc_markdown)]

// Provider `kms-*` features are **additive and composable**: a single-provider
// build enables one; a build-all-providers artifact enables all four and the FFI
// layer dispatches on the caller-supplied `provider` at call time (one artifact
// per target serves every provider). A build with zero provider features is a
// configuration error, caught at runtime when a call finds no matching provider
// (an additive model has no portable "at least one feature" assertion).

pub mod auth;
pub mod envelope;
pub mod error;
/// Federation acquisition — exchanging the customer OIDC token
/// for a short-TTL, single-key-scoped [`FederatedToken`] at each provider's
/// workload-identity federation endpoint. Per-provider, feature-gated.
pub mod federation;
pub mod provider;
/// AWS SigV4 request signing — the AWS KMS provider's signing layer.
#[cfg(feature = "kms-aws")]
pub mod sigv4;
pub mod strategy;

pub use auth::FederatedToken;
pub use error::KmsRestError;
pub use strategy::Strategy;
