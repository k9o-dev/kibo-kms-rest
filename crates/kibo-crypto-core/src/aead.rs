//! AES-256-GCM-SIV (nonce-misuse-resistant) authenticated encryption primitive.
//!
//! Wrapper over the RustCrypto `aes-gcm-siv` crate. Pins the algorithm
//! choice at the type level (so the rest of the plane cannot accidentally
//! request a weaker cipher) and enforces internal per-encrypt random
//! 96-bit nonce generation via `OsRng`.
//!
//! **Uses AES-256-GCM-SIV.** SIV is the architectural backbone defeating the
//! nonce-reuse class: random 96-bit nonces are fundamentally unsafe in a confidential
//! VM that can be cloned / snapshot-rolled / horizontally scaled, and SIV
//! degrades a collision to leaking only plaintext-equality rather than
//! catastrophic GHASH-key + plaintext recovery. The `dek.rs` invocation
//! counter (CAS + persistence) lands as defense-in-depth atop this backbone.
//!
//! # Threat model
//!
//! - **Caller MUST NOT supply nonce.** The signature has no nonce
//!   parameter — eliminating the developer loophole where a buggy
//!   upstream caller could pass a repeating or static nonce array,
//!   which would silently catastrophically fail AES-256-GCM (nonce
//!   reuse recovers both the GHASH authentication key and the
//!   plaintext via XOR analysis).
//! - **96-bit nonces only.** Forces the hardware AES path
//!   (AES-NI on Intel Xeon / ARMv8 Cryptographic Extensions on AWS
//!   Graviton) to skip the extra GHASH operation required for
//!   non-96-bit nonces, closing a timing side-channel surface and
//!   matching NIST SP 800-38D §5.2.1.1 recommendation.
//! - **AAD context binding (Header-as-AAD).** Callers pass the
//!   envelope header bytes (`KIBO` magic + version + provider +
//!   key_ver + ext_ref) as `aad` to defend against
//!   envelope-substitution attacks: an adversary who flips the
//!   provider tag or key version in the on-disk envelope cannot
//!   produce a valid GHASH tag without the key.
//! - **Atomic invocation counter (slot 4 `dek.rs`).** This
//!   primitive accepts raw key bytes — the 2³⁰-cap counter discipline
//!   rides at the `DataEncryptionKey` wrapper layer that consumes
//!   this module.
//!
//! # Envelope format (Pattern 1 appended-payload)
//!
//! `seal` returns a single `Vec<u8>` formatted as:
//!
//! ```text
//! [ 12-byte nonce | ciphertext | 16-byte tag ]
//!   bytes 0..12     bytes 12..N   bytes N..N+16
//! ```
//!
//! The caller of `open` must pass the entire returned vector back —
//! `open` extracts the nonce from the prefix internally and verifies
//! the tag at the suffix.
//!
//! # Verification
//!
//! Kani round-trip soundness + tamper detection + AAD
//! binding + key distinctness properties prove over this
//! module's `seal` and `open` functions. The
//! envelope-format byte layout for the cross-provider envelope
//! (`crate::envelope`) is a separate concern; this module's `seal`
//! returns the minimal AEAD envelope.
//!
//! Nonce-distinctness sanity is
//! intentionally NOT proven via Kani — `OsRng` cannot be modeled
//! symbolically without massive unrolling. Routed to `cargo-fuzz`
//! statistical testing.
//!
//! # Declined / redirected items (documented, not actioned)
//!
//! - **Constant-time length checks.** The length comparisons
//!   in [`open`] / [`open_detached`] branch on the *public* envelope /
//!   ciphertext length, not on any secret. A timing difference on a
//!   public quantity is not a secret-dependent side channel; the
//!   secret-dependent comparison that *does* matter — GHASH tag
//!   verification — is performed in constant time inside the vetted
//!   `aes-gcm-siv` crate. No constant-time refactor is warranted.
//! - **NIST SP 800-38D test vectors.** SP 800-38D
//!   vectors are for plain AES-GCM; this module uses AES-256-GCM-**SIV**
//!   (RFC 8452), for which SP 800-38D KATs do not apply. The SIV
//!   primitive's known-answer vectors are exercised in the pinned,
//!   vetted upstream `aes-gcm-siv` crate (`=0.11.1`); our wrapper's
//!   behaviour is covered by the round-trip / tamper / AAD-binding /
//!   key-distinctness / key-commitment tests here plus the Kani proofs.
//!   A bare-cipher RFC 8452 KAT in this suite would re-test the
//!   dependency, not our code, so it is not added.

use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// AES-256-GCM key length in bytes (32 bytes = 256 bits).
pub const AES_256_KEY_SIZE: usize = 32;

/// AES-256-GCM nonce length in bytes (12 bytes = 96 bits).
///
/// 96-bit is the NIST SP 800-38D §5.2.1.1 recommended length and the
/// only length supported by the RustCrypto `aes-gcm` default cipher
/// type. Forces the hardware AES fast path to skip the extra GHASH
/// operation required for non-96-bit nonces.
pub const GCM_NONCE_SIZE: usize = 12;

/// AES-256-GCM authentication tag length in bytes (16 bytes = 128 bits).
pub const GCM_TAG_SIZE: usize = 16;

/// Minimum valid envelope length: nonce + tag, with zero-byte plaintext.
pub const MIN_ENVELOPE_SIZE: usize = GCM_NONCE_SIZE + GCM_TAG_SIZE;

/// Domain separator for the key-commitment hash mixed into the AAD.
/// Versioned so the commitment scheme can evolve without silent
/// ambiguity.
const KEY_COMMITMENT_DOMAIN: &[u8] = b"k9o-aead-key-commitment-v1";

/// Compute the key-commitment tag for `key`: `SHA-256(domain || key)`.
///
/// Standard AES-256-GCM-SIV is *not* key-committing — it is possible to
/// craft one ciphertext that opens to valid plaintext under two
/// different keys (a partitioning attack that could let a malicious
/// tenant's envelope decrypt under another project's key). Mixing
/// `SHA-256(domain || key)` into the authenticated
/// data binds the tag to the specific key: opening with any other key
/// recomputes a different commitment, so the GHASH tag fails. The hash
/// is preimage-resistant, so publishing it in the (authenticated,
/// non-secret) AAD does not leak the key.
fn key_commitment(key: &[u8; AES_256_KEY_SIZE]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_COMMITMENT_DOMAIN);
    hasher.update(key);
    hasher.finalize().into()
}

/// Build the effective AAD = `caller_aad || key_commitment(key)`.
/// Both [`seal`] and [`open`] apply this identically, so round-trips are
/// transparent while a wrong key breaks tag verification. The commitment
/// is recomputed at open from the key — it is never stored on the wire,
/// so the envelope format is unchanged.
fn committed_aad(aad: &[u8], key: &[u8; AES_256_KEY_SIZE]) -> Vec<u8> {
    let commitment = key_commitment(key);
    let mut out = Vec::with_capacity(aad.len() + commitment.len());
    out.extend_from_slice(aad);
    out.extend_from_slice(&commitment);
    out
}

/// Maximum envelope length accepted by [`open`] — 10 MiB hard ceiling.
///
/// Defends against memory-exhaustion DoS: an adversarial multi-gigabyte
/// envelope would otherwise
/// force the in-enclave allocator to provision an equivalent
/// plaintext buffer, triggering an OOM abort that downs the secure
/// instance. DEK-wrap envelopes are tiny (a 32-byte DEK + header);
/// 10 MiB is far above any legitimate wrapped-DEK or small-secret
/// payload while bounding the allocation an attacker can induce.
pub const MAX_ENVELOPE_SIZE: usize = 10 * 1024 * 1024;

/// Errors returned from the AES-256-GCM AEAD primitive.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Sealing (encryption + tag generation) failed; opaque per
    /// RustCrypto upstream. Should not occur with a valid 32-byte key.
    #[error("AEAD seal failed")]
    SealFailed,
    /// Opening (tag verification + decryption) failed — the
    /// ciphertext was tampered, the wrong key was supplied, the AAD
    /// did not match, or the envelope was truncated. The cause is
    /// intentionally not distinguished (fail-uniform per AEAD
    /// security design — distinguishing would create a side-channel
    /// information leak).
    #[error("AEAD open failed (ciphertext tampered, wrong key, wrong AAD, or envelope malformed)")]
    OpenFailed,
    /// Caller supplied a key of incorrect length. AES-256-GCM-SIV
    /// requires exactly 32 bytes.
    #[error("invalid key length (expected 32 bytes for AES-256-GCM-SIV)")]
    InvalidKeyLength,
}

/// Seal `plaintext` under `key` with additional authenticated data `aad`.
///
/// Generates a fresh 96-bit nonce internally via `OsRng`. The caller
/// has no way to influence the nonce — this
/// is by design and is load-bearing for the security claim.
///
/// Returns a single `Vec<u8>` formatted as
/// `[12B nonce || ciphertext || 16B tag]` per Pattern 1 appended-payload.
///
/// The `key` is a fixed-width `&[u8; AES_256_KEY_SIZE]` reference, so a
/// wrong-length key is a compile error rather than a runtime
/// [`AeadError::InvalidKeyLength`] (type-level key-length enforcement).
///
/// # Errors
///
/// - [`AeadError::SealFailed`] if the underlying AES-256-GCM-SIV cipher
///   fails (opaque per RustCrypto upstream; should not occur with a
///   valid 32-byte key).
pub fn seal(
    key: &[u8; AES_256_KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // `key` is a fixed-size array — `new_from_slice` cannot fail on
    // length; the map_err remains as a defensive total-function guard.
    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;

    // Generate the 96-bit random nonce internally — caller cannot
    // influence this. OsRng routes to kernel entropy
    // (RDRAND/RDSEED on x86_64, hardware RNG via `getrandom` on other
    // substrates) for confidential-VM-safe entropy extraction.
    //
    // Under AES-256-GCM-SIV (nonce-misuse-resistant) a nonce
    // collision — e.g. a VM-snapshot/clone replaying OsRng state, or
    // two horizontally-scaled nodes drawing the same bytes before the
    // entropy seed refreshes — degrades only to leaking equality of
    // identical (key, nonce, plaintext, aad) tuples, NOT to the
    // catastrophic GHASH-key + plaintext recovery of plain GCM. The
    // nonce array is wrapped in `Zeroizing` so the transient IV does
    // not linger in unallocated stack frames inside the TEE.
    let mut nonce_bytes = Zeroizing::new([0u8; GCM_NONCE_SIZE]);
    OsRng.fill_bytes(&mut *nonce_bytes);
    let nonce = Nonce::from_slice(&*nonce_bytes);

    // Bind the key into the AAD (key-commitment).
    let aad = committed_aad(aad, key);
    let payload = Payload {
        msg: plaintext,
        aad: &aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| AeadError::SealFailed)?;

    let mut envelope = Vec::with_capacity(GCM_NONCE_SIZE + ciphertext.len());
    envelope.extend_from_slice(&*nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// Open a sealed envelope produced by [`seal`]. Extracts the embedded
/// 12-byte nonce from the prefix and verifies+decrypts the
/// ciphertext+tag payload using `key` and `aad`.
///
/// The `key` is a fixed-width `&[u8; AES_256_KEY_SIZE]` reference
/// (compile-time length enforcement).
///
/// # Tag-failure plaintext hygiene
///
/// This uses the *allocating* `AeadInPlace`/`Aead::decrypt` API, which
/// verifies the GHASH tag and returns `Err` on failure **without
/// handing the caller any plaintext** — the partially-decrypted buffer
/// never escapes the crate. The "in-place decryption plaintext leak"
/// applies to `decrypt_in_place_detached`, a
/// different API we do not call; for the allocating path it is a
/// phantom. The load-bearing mitigation against an
/// *upstream* unpatched-variant regression is the `Cargo.lock` pin to a
/// vetted `aes-gcm-siv` release (`=0.11.1` in the workspace manifest).
/// Wiping the crate-internal transient buffer on the failure path is
/// folded into the zero-copy detached-open path, where we own
/// the buffer; the allocating API gives us nothing to wipe here.
///
/// # Errors
///
/// - [`AeadError::OpenFailed`] if the envelope is shorter than
///   `MIN_ENVELOPE_SIZE`, exceeds `MAX_ENVELOPE_SIZE`, is tampered, or
///   the caller supplied the wrong key/AAD. Fail-uniform per AEAD
///   design (the cause is never distinguished — distinguishing would be
///   a side-channel).
pub fn open(
    key: &[u8; AES_256_KEY_SIZE],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // Explicit bounds-check before slicing to prevent any panicking
    // slice operation on truncated input. Minimum envelope is
    // nonce + zero-byte ciphertext + 16-byte tag = 28 bytes.
    if envelope.len() < MIN_ENVELOPE_SIZE {
        return Err(AeadError::OpenFailed);
    }

    // Upper bound before allocation: reject adversarial multi-GB
    // envelopes that would force the in-enclave allocator to OOM-abort.
    // Fail-uniform as OpenFailed.
    if envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(AeadError::OpenFailed);
    }

    // Split the prefix nonce from the ciphertext+tag and delegate to the
    // detached entry point. The MIN_ENVELOPE_SIZE check above guarantees
    // the 12-byte split is in-bounds, so the try_into is infallible.
    let (nonce_bytes, ciphertext_bytes) = envelope.split_at(GCM_NONCE_SIZE);
    let nonce_arr: &[u8; GCM_NONCE_SIZE] =
        nonce_bytes.try_into().map_err(|_| AeadError::OpenFailed)?;
    open_detached(key, nonce_arr, ciphertext_bytes, aad)
}

/// Open a ciphertext from **detached** nonce + ciphertext+tag slices,
/// without the caller first concatenating them into a single envelope
/// buffer.
///
/// This is the zero-extra-allocation unwrap path: callers that already
/// hold the nonce and ciphertext as separate
/// slices — e.g. [`crate::envelope::unwrap_with_aad`], which parses them
/// out of a wrapped-DEK envelope — pass them straight through instead of
/// allocating and copying a fresh `[nonce || ciphertext]` vector just so
/// [`open`] can re-split it. Eliminating that copy removes the
/// allocation-latency timing oracle. [`open`] itself
/// is now a thin split-then-delegate wrapper over this function.
///
/// `ciphertext` must include the trailing 16-byte AEAD tag. The same
/// key-commitment AAD is applied here.
///
/// # Errors
///
/// - [`AeadError::OpenFailed`] if `ciphertext` is shorter than the tag,
///   exceeds `MAX_ENVELOPE_SIZE`, or fails tag verification (tampered,
///   wrong key, or wrong AAD). Fail-uniform.
pub fn open_detached(
    key: &[u8; AES_256_KEY_SIZE],
    nonce: &[u8; GCM_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // A valid ciphertext slot must carry at least the 16-byte tag, and
    // must stay within the same allocation ceiling open() enforces.
    if ciphertext.len() < GCM_TAG_SIZE || ciphertext.len() > MAX_ENVELOPE_SIZE {
        return Err(AeadError::OpenFailed);
    }

    let cipher = Aes256GcmSiv::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(nonce);

    // Recompute the key-commitment AAD — a wrong key
    // yields a different commitment and the tag fails.
    let aad = committed_aad(aad, key);
    let payload = Payload {
        msg: ciphertext,
        aad: &aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| AeadError::OpenFailed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY_A: &[u8; 32] = &[0x42; 32];
    const KEY_B: &[u8; 32] = &[0x43; 32];

    #[test]
    fn round_trip_minimal() {
        let envelope = seal(KEY_A, b"hello", b"context").unwrap();
        let plaintext = open(KEY_A, &envelope, b"context").unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let envelope = seal(KEY_A, b"", b"context").unwrap();
        let plaintext = open(KEY_A, &envelope, b"context").unwrap();
        assert_eq!(plaintext, b"");
    }

    #[test]
    fn round_trip_empty_aad() {
        let envelope = seal(KEY_A, b"hello", b"").unwrap();
        let plaintext = open(KEY_A, &envelope, b"").unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn round_trip_large_plaintext() {
        let plaintext = vec![0xAA; 8192];
        let envelope = seal(KEY_A, &plaintext, b"context").unwrap();
        let opened = open(KEY_A, &envelope, b"context").unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn envelope_format_nonce_prefix() {
        let envelope = seal(KEY_A, b"hello", b"context").unwrap();
        // Envelope is [12B nonce | 5B ciphertext | 16B tag] = 33 bytes.
        assert_eq!(envelope.len(), GCM_NONCE_SIZE + 5 + GCM_TAG_SIZE);
    }

    #[test]
    fn tamper_detection_ciphertext_byte() {
        let mut envelope = seal(KEY_A, b"hello", b"context").unwrap();
        // Flip a bit in the ciphertext portion (offset 15 = nonce(12) + ct(3)).
        envelope[15] ^= 0x01;
        let err = open(KEY_A, &envelope, b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn tamper_detection_tag_byte() {
        let mut envelope = seal(KEY_A, b"hello", b"context").unwrap();
        // Flip the last bit of the auth tag.
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        let err = open(KEY_A, &envelope, b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn tamper_detection_nonce_byte() {
        let mut envelope = seal(KEY_A, b"hello", b"context").unwrap();
        // Flip a bit in the nonce prefix.
        envelope[0] ^= 0x01;
        let err = open(KEY_A, &envelope, b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn aad_binding_mismatch() {
        let envelope = seal(KEY_A, b"hello", b"context-a").unwrap();
        let err = open(KEY_A, &envelope, b"context-b").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn aad_binding_added() {
        // Seal with empty AAD; open with non-empty AAD — must fail.
        let envelope = seal(KEY_A, b"hello", b"").unwrap();
        let err = open(KEY_A, &envelope, b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn aad_binding_removed() {
        // Seal with non-empty AAD; open with empty AAD — must fail.
        let envelope = seal(KEY_A, b"hello", b"context").unwrap();
        let err = open(KEY_A, &envelope, b"").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn key_distinctness_mismatch() {
        let envelope = seal(KEY_A, b"hello", b"context").unwrap();
        let err = open(KEY_B, &envelope, b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn key_commitment_is_deterministic_and_key_specific() {
        // Same key → same commitment; different key → different
        // commitment (key-commitment).
        assert_eq!(key_commitment(KEY_A), key_commitment(KEY_A));
        assert_ne!(key_commitment(KEY_A), key_commitment(KEY_B));
    }

    #[test]
    fn committed_aad_appends_commitment() {
        // committed_aad = caller_aad || key_commitment(key).
        let aad = b"context";
        let out = committed_aad(aad, KEY_A);
        assert_eq!(out.len(), aad.len() + 32);
        assert_eq!(&out[..aad.len()], aad);
        assert_eq!(&out[aad.len()..], &key_commitment(KEY_A));
    }

    // Wrong-length keys are now rejected at COMPILE time: seal/open take
    // `&[u8; AES_256_KEY_SIZE]`, so the former runtime
    // `invalid_key_length_{short,long}_{seal,open}` tests (which passed
    // 31-/33-byte slices and asserted `InvalidKeyLength`) can no longer
    // be written — the type system is the test.

    #[test]
    fn envelope_truncation_safety_empty() {
        let err = open(KEY_A, &[], b"context").unwrap_err();
        assert!(matches!(err, AeadError::OpenFailed));
    }

    #[test]
    fn envelope_truncation_safety_below_minimum() {
        for len in 0..MIN_ENVELOPE_SIZE {
            let short = vec![0u8; len];
            let err = open(KEY_A, &short, b"context").unwrap_err();
            assert!(
                matches!(err, AeadError::OpenFailed),
                "envelope of {len} bytes should fail-uniform"
            );
        }
    }

    #[test]
    fn nonce_uniqueness_statistical_smoke() {
        // Statistical sanity: two seals with same (key, plaintext, aad) should
        // produce distinct envelopes (different nonces). This is NOT a Kani
        // property (OsRng is not symbolically modelable); the
        // canonical harness for nonce-distinctness is cargo-fuzz. This is a
        // coarse smoke test to catch egregious nonce-reuse regressions.
        let env1 = seal(KEY_A, b"hello", b"context").unwrap();
        let env2 = seal(KEY_A, b"hello", b"context").unwrap();
        assert_ne!(
            env1, env2,
            "two seals must produce distinct envelopes (nonce-distinctness)"
        );
        // Both decrypt to the same plaintext under the same key.
        assert_eq!(open(KEY_A, &env1, b"context").unwrap(), b"hello");
        assert_eq!(open(KEY_A, &env2, b"context").unwrap(), b"hello");
    }
}
