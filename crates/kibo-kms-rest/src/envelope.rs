//! Thin re-export of the `kibo-crypto-core` PUB envelope framing.
//!
//! The REST-direct edge layer does **not** define its own ciphertext
//! envelope format. It reuses the single canonical framing from
//! [`kibo_crypto_core::envelope`] so that an envelope produced on a device by
//! this crate is byte-compatible with one produced server-side by the
//! data plane (pillar A) or the policy plane (pillar C). **A-/C-produced
//! ciphertexts MUST share this framing** — there is exactly one envelope
//! format across the plane, and edge-produced envelopes round-trip
//! through the server unwrap path unchanged.
//!
//! The constants, header parser, and slice accessors are re-exported as a
//! convenience so downstream edge callers depend only on `kibo-kms-rest`.
//! The actual `build` / `unwrap` AEAD operations remain in `kibo-crypto-core`
//! and are *not* re-exported here, because under
//! [`crate::strategy::Strategy::LocalEnvelope`] the bulk-data AES is the
//! responsibility of `kibo-crypto-core`, invoked by the caller, never by this
//! crate.

pub use kibo_crypto_core::envelope::{
    AEAD_TAG_SIZE, EnvelopeError, FIXED_HEADER_SIZE, FORMAT_VERSION, MAGIC, MAX_DEK_ENVELOPE_SIZE,
    MIN_ENVELOPE_SIZE, NONCE_SIZE_BYTES, ProviderTag,
};

pub use kibo_crypto_core::envelope::{aad_slice, ciphertext_slice, nonce_slice, read_header};
