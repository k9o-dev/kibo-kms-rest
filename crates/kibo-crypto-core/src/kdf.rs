//! Key derivation function — HKDF-SHA-256 (RFC 5869).
//!
//! Used for deriving distinct subkeys from a single master secret while
//! preventing cryptographic cross-contamination. The Extract step
//! cryptographically isolates the entropy of the input keying material
//! (IKM); the Expand step produces context-bound subkeys via the `info`
//! parameter for domain separation.
//!
//! # Bounds
//!
//! Per RFC 5869 §2.3, HKDF-SHA-256 has a hard upper bound on output
//! length:
//!
//! ```text
//! Max output length = 255 × HashLen = 255 × 32 = 8160 bytes
//! ```
//!
//! Requesting more bytes than this returns
//! [`KdfError::OutputTooLong`] — the underlying crate would otherwise
//! panic or fail silently depending on its error handling. We enforce
//! the bound explicitly at the API surface.
//!
//! # Two-layer API: RFC primitive vs sovereign gate
//!
//! This module exposes two derivation entry points with deliberately
//! different contracts:
//!
//! - [`hkdf_sha256_raw`] — the **RFC 5869 primitive**. Permits empty
//!   `salt`, empty `info`, and zero-length output, exactly as the RFC
//!   allows. It exists for wire-compatibility and for proving the
//!   standard test vectors (Appendix A.1 / A.3). Application key
//!   derivation should NOT call it directly.
//! - [`derive_subkey`] — the **sovereign-kernel gate**. This is the API
//!   application code derives subkeys through. It enforces the
//!   platform's least-privilege posture by rejecting inputs that the
//!   bare RFC tolerates but that signal a domain-separation bug.
//!
//! # Domain separation discipline
//!
//! The `info` parameter is the **domain-separation key** for derived
//! subkeys. Empty `info` strips domain separation and would allow
//! cross-protocol key reuse if the same master IKM is accidentally used
//! across different parts of the system (a low-stakes key could replay
//! the exact derivation context of a high-stakes one).
//!
//! [`derive_subkey`] closes this two ways. First, it rejects an empty
//! domain. Second — and more importantly — it does NOT accept a
//! pre-flattened `info` byte string built by naive concatenation at the
//! call site. Naive concatenation is ambiguous: the components
//! `("ab", "c")` and `("a", "bc")` both flatten to `abc`, so two
//! distinct identities would derive the *same* subkey, shattering
//! tenant isolation. Instead callers pass **structured domain
//! components** which [`derive_subkey`] canonicalizes internally via
//! [`canonical_info`] (each component length-prefixed), making the
//! encoding injective and collision-resistant. The canonicalization is
//! owned by the module, not left to a call-site convention.
//!
//! [`derive_subkey`] also requires a non-empty `salt`. RFC 5869 §2.2
//! permits an empty salt (Extract still runs `HMAC(0^HashLen, IKM)`, so
//! it is cryptographically safe), but for a sovereign kernel we require
//! an explicit salt as defense-in-depth and to surface caller bugs. We
//! reject rather than silently substituting a platform fallback salt:
//! substitution would mask the bug. Paths that genuinely need RFC empty
//! salt/info semantics use [`hkdf_sha256_raw`] directly.
//!
//! # Memory hygiene
//!
//! The output `Zeroizing<Vec<u8>>` wrapper guarantees that derived
//! subkey material is wiped from heap memory the instant the wrapper
//! drops out of scope. Callers should consume the output into another
//! `Zeroizing` or stack-allocated `Zeroizing<[u8; N]>` wrapper rather
//! than copying into a plain `Vec<u8>` to preserve the boundary.
//!
//! # Verification
//!
//! Kani P8 (KDF determinism) property proves over `hkdf_sha256_raw`:
//! same `(ikm, salt, info, len)` produces identical output across
//! bounded execution scopes.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

/// Hard upper bound on HKDF-SHA-256 output length per RFC 5869 §2.3:
/// `255 × HashLen = 255 × 32 bytes = 8160 bytes`.
pub const HKDF_MAX_OUTPUT_LEN: usize = 8160;

/// Errors returned from the HKDF-SHA-256 KDF.
#[derive(Debug, Error)]
pub enum KdfError {
    /// Input key material was empty. Callers must supply at least one
    /// byte of entropy material; HKDF without IKM defeats the
    /// security claim.
    #[error("invalid input key material length (must be greater than 0 bytes)")]
    InvalidIkm,
    /// Requested output length exceeds the HKDF-SHA-256 maximum
    /// (`255 × 32 = 8160` bytes per RFC 5869 §2.3).
    #[error(
        "requested output length ({requested} bytes) exceeds HKDF-SHA-256 maximum of 8160 bytes"
    )]
    OutputTooLong {
        /// Number of bytes the caller asked for.
        requested: usize,
    },
    /// HKDF Expand step failed; opaque per RustCrypto upstream.
    #[error("HKDF expansion failed")]
    ExpansionFailed,
    /// [`derive_subkey`] was called with no domain-separation
    /// components (or only empty ones). The sovereign gate requires an
    /// explicit, non-empty domain to prevent cross-protocol key reuse.
    #[error("derive_subkey requires a non-empty domain-separation context")]
    MissingDomainSeparation,
    /// [`derive_subkey`] was called with an empty `salt`. The sovereign
    /// gate requires an explicit salt (defense-in-depth); use
    /// [`hkdf_sha256_raw`] if RFC empty-salt semantics are genuinely
    /// required.
    #[error("derive_subkey requires a non-empty salt")]
    EmptySalt,
    /// [`derive_subkey`] was called with `len == 0`. A zero-length
    /// subkey has no cryptographic value and signals a caller bug.
    #[error("derive_subkey requires a non-zero output length")]
    ZeroLength,
}

/// RFC 5869 HKDF-SHA-256 primitive over `ikm`, `salt`, and `info`,
/// producing exactly `len` bytes of output keying material.
///
/// This is the bare RFC primitive: it permits empty `salt`, empty
/// `info`, and `len == 0` exactly as RFC 5869 allows, so the standard
/// test vectors (Appendix A.1 / A.3) and wire-compatibility paths verify
/// against it. **Application key derivation should call
/// [`derive_subkey`] instead** — it enforces the sovereign gate's
/// domain-separation and salt requirements.
///
/// # Parameters
///
/// - `ikm` — input keying material; the master secret being expanded.
///   Must be non-empty.
/// - `salt` — optional salt; may be empty (RFC 5869 §2.2: treated as
///   `HashLen` zero bytes).
/// - `info` — application-specific context bytes for domain separation.
///   May be empty per the RFC.
/// - `len` — desired output length in bytes. Must be in
///   `0 ..= HKDF_MAX_OUTPUT_LEN`.
///
/// # Errors
///
/// - [`KdfError::InvalidIkm`] if `ikm.is_empty()`.
/// - [`KdfError::OutputTooLong`] if `len > HKDF_MAX_OUTPUT_LEN`.
/// - [`KdfError::ExpansionFailed`] on internal expansion failure
///   (should not occur if `len <= HKDF_MAX_OUTPUT_LEN`).
pub fn hkdf_sha256_raw(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, KdfError> {
    if ikm.is_empty() {
        return Err(KdfError::InvalidIkm);
    }
    if len > HKDF_MAX_OUTPUT_LEN {
        return Err(KdfError::OutputTooLong { requested: len });
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    // `vec![0u8; len]` allocates exactly `len` bytes of capacity, and
    // `Hkdf::expand` writes in place into this fixed-length slice — it
    // never re-allocates, so no intermediate subkey remnants are left in
    // stale heap pages. The `Zeroizing` wrapper wipes the buffer on drop.
    let mut okm = Zeroizing::new(vec![0u8; len]);
    hk.expand(info, &mut okm)
        .map_err(|_| KdfError::ExpansionFailed)?;

    Ok(okm)
}

/// Canonically encode domain-separation components into an injective,
/// collision-resistant `info` byte string.
///
/// Each component is serialized as `len_be(u32) || bytes`. The
/// length-prefix makes the encoding prefix-free: distinct component
/// sequences always map to distinct byte strings, so the ambiguous
/// flattening that plain concatenation suffers — `("ab", "c")` and
/// `("a", "bc")` both yielding `abc` — cannot occur. This is the
/// canonical domain-binding used by [`derive_subkey`]; it is exposed so
/// callers that need the raw `info` bytes can build them the same way.
///
/// # Errors
///
/// - [`KdfError::OutputTooLong`] if any single component's length does
///   not fit in a `u32` (a structural impossibility for real domain
///   strings, guarded for completeness).
pub fn canonical_info(components: &[&[u8]]) -> Result<Vec<u8>, KdfError> {
    let mut total: usize = 0;
    for c in components {
        if u32::try_from(c.len()).is_err() {
            return Err(KdfError::OutputTooLong { requested: c.len() });
        }
        total = total
            .checked_add(4)
            .and_then(|t| t.checked_add(c.len()))
            .ok_or(KdfError::OutputTooLong {
                requested: usize::MAX,
            })?;
    }
    let mut out = Vec::with_capacity(total);
    for c in components {
        out.extend_from_slice(&(c.len() as u32).to_be_bytes());
        out.extend_from_slice(c);
    }
    Ok(out)
}

/// Sovereign-kernel subkey derivation gate.
///
/// Derives `len` bytes of subkey material from `ikm` under an explicit
/// `salt` and a structured, non-empty domain. This is the API
/// application code must use to derive subkeys; it enforces the
/// platform's domain-separation posture on top of [`hkdf_sha256_raw`].
///
/// The `domain` components are canonicalized via [`canonical_info`]
/// (length-prefixed) before expansion, so callers cannot accidentally
/// create cross-identity collisions by flattening context strings at the
/// call site.
///
/// # Parameters
///
/// - `ikm` — master secret. Must be non-empty.
/// - `salt` — must be non-empty (see module docs; reject not substitute).
/// - `domain` — domain-separation components, e.g.
///   `&[b"k9o_project_wrap_key_v1", project_id]`. At least one component
///   must carry content.
/// - `len` — output length in bytes. Must be `1 ..= HKDF_MAX_OUTPUT_LEN`.
///
/// # Errors
///
/// - [`KdfError::EmptySalt`] if `salt.is_empty()`.
/// - [`KdfError::MissingDomainSeparation`] if `domain` is empty or every
///   component is empty.
/// - [`KdfError::ZeroLength`] if `len == 0`.
/// - Plus the [`hkdf_sha256_raw`] errors ([`KdfError::InvalidIkm`],
///   [`KdfError::OutputTooLong`], [`KdfError::ExpansionFailed`]).
pub fn derive_subkey(
    ikm: &[u8],
    salt: &[u8],
    domain: &[&[u8]],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, KdfError> {
    if salt.is_empty() {
        return Err(KdfError::EmptySalt);
    }
    if len == 0 {
        return Err(KdfError::ZeroLength);
    }
    if domain.iter().all(|c| c.is_empty()) {
        return Err(KdfError::MissingDomainSeparation);
    }

    let info = canonical_info(domain)?;
    hkdf_sha256_raw(ikm, salt, &info, len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const IKM_A: &[u8] = b"master-secret-material-32-bytes-";
    const IKM_B: &[u8] = b"different-master-secret-material";
    const SALT: &[u8] = b"k9o-salt-v1";
    const INFO_A: &[u8] = b"k9o_project_wrap_key_v1::project-aaa";
    const INFO_B: &[u8] = b"k9o_project_wrap_key_v1::project-bbb";

    #[test]
    fn derives_requested_length_32() {
        let okm = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn derives_requested_length_64() {
        let okm = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 64).unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn derives_requested_length_one() {
        let okm = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 1).unwrap();
        assert_eq!(okm.len(), 1);
    }

    #[test]
    fn raw_permits_zero_length() {
        // The RFC primitive permits zero-byte output; the sovereign
        // gate (derive_subkey) rejects it.
        let okm = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 0).unwrap();
        assert_eq!(okm.len(), 0);
    }

    #[test]
    fn derives_max_length_8160() {
        let okm = hkdf_sha256_raw(IKM_A, SALT, INFO_A, HKDF_MAX_OUTPUT_LEN).unwrap();
        assert_eq!(okm.len(), HKDF_MAX_OUTPUT_LEN);
    }

    #[test]
    fn rejects_length_over_max() {
        let err = hkdf_sha256_raw(IKM_A, SALT, INFO_A, HKDF_MAX_OUTPUT_LEN + 1).unwrap_err();
        assert!(
            matches!(err, KdfError::OutputTooLong { requested } if requested == HKDF_MAX_OUTPUT_LEN + 1)
        );
    }

    #[test]
    fn rejects_empty_ikm() {
        let err = hkdf_sha256_raw(b"", SALT, INFO_A, 32).unwrap_err();
        assert!(matches!(err, KdfError::InvalidIkm));
    }

    #[test]
    fn determinism_same_inputs_same_output() {
        // Kani P8 statistical sanity: identical inputs produce identical
        // outputs across invocations (no internal nondeterminism).
        let okm1 = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 64).unwrap();
        let okm2 = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 64).unwrap();
        assert_eq!(okm1.as_slice(), okm2.as_slice());
    }

    #[test]
    fn ikm_distinctness_different_outputs() {
        // Different IKM under same (salt, info, len) → different output.
        let okm1 = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 32).unwrap();
        let okm2 = hkdf_sha256_raw(IKM_B, SALT, INFO_A, 32).unwrap();
        assert_ne!(okm1.as_slice(), okm2.as_slice());
    }

    #[test]
    fn info_distinctness_different_outputs() {
        // Different info under same (ikm, salt, len) → different output.
        // This is the domain-separation property that protects against
        // cross-protocol key reuse.
        let okm1 = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 32).unwrap();
        let okm2 = hkdf_sha256_raw(IKM_A, SALT, INFO_B, 32).unwrap();
        assert_ne!(okm1.as_slice(), okm2.as_slice());
    }

    #[test]
    fn salt_distinctness_different_outputs() {
        // Different salt under same (ikm, info, len) → different output.
        let salt_b: &[u8] = b"k9o-salt-v2";
        let okm1 = hkdf_sha256_raw(IKM_A, SALT, INFO_A, 32).unwrap();
        let okm2 = hkdf_sha256_raw(IKM_A, salt_b, INFO_A, 32).unwrap();
        assert_ne!(okm1.as_slice(), okm2.as_slice());
    }

    #[test]
    fn raw_accepts_empty_salt() {
        // RFC 5869 permits empty salt (treated as HashLen zero bytes).
        // The sovereign gate rejects it; the raw primitive does not.
        let okm = hkdf_sha256_raw(IKM_A, b"", INFO_A, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn raw_accepts_empty_info() {
        // RFC 5869 permits empty info. The raw primitive does not gate
        // domain separation — derive_subkey does.
        let okm = hkdf_sha256_raw(IKM_A, SALT, b"", 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn rfc5869_test_vector_a1() {
        // RFC 5869 Appendix A.1 Test Case 1 — HKDF-SHA-256 with the
        // canonical test inputs. Confirms our impl is wire-compatible
        // with the standard.
        let ikm = [0x0b; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let okm = hkdf_sha256_raw(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(okm.as_slice(), &expected_okm);
    }

    #[test]
    fn rfc5869_test_vector_a3_empty_salt_and_info() {
        // RFC 5869 Appendix A.3 Test Case 3 — empty salt + empty info
        // path. Confirms RFC 5869 §2.2 "if not provided" semantics
        // (salt treated as HashLen zero bytes; PRK is HMAC(0^HashLen, IKM)).
        let ikm = [0x0b; 22];
        let expected_okm: [u8; 42] = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ];
        let okm = hkdf_sha256_raw(&ikm, b"", b"", 42).unwrap();
        assert_eq!(okm.as_slice(), &expected_okm);
    }

    // --- sovereign gate: derive_subkey + canonical_info ---

    const DOMAIN_A: &[&[u8]] = &[b"k9o_project_wrap_key_v1", b"project-aaa"];
    const DOMAIN_B: &[&[u8]] = &[b"k9o_project_wrap_key_v1", b"project-bbb"];

    #[test]
    fn derive_subkey_happy_path() {
        let okm = derive_subkey(IKM_A, SALT, DOMAIN_A, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn derive_subkey_rejects_empty_salt() {
        let err = derive_subkey(IKM_A, b"", DOMAIN_A, 32).unwrap_err();
        assert!(matches!(err, KdfError::EmptySalt));
    }

    #[test]
    fn derive_subkey_rejects_zero_len() {
        let err = derive_subkey(IKM_A, SALT, DOMAIN_A, 0).unwrap_err();
        assert!(matches!(err, KdfError::ZeroLength));
    }

    #[test]
    fn derive_subkey_rejects_empty_domain() {
        let err = derive_subkey(IKM_A, SALT, &[], 32).unwrap_err();
        assert!(matches!(err, KdfError::MissingDomainSeparation));
        // all-empty components are also rejected
        let err = derive_subkey(IKM_A, SALT, &[b"", b""], 32).unwrap_err();
        assert!(matches!(err, KdfError::MissingDomainSeparation));
    }

    #[test]
    fn derive_subkey_domain_distinctness() {
        // Distinct project domains derive distinct subkeys.
        let a = derive_subkey(IKM_A, SALT, DOMAIN_A, 32).unwrap();
        let b = derive_subkey(IKM_A, SALT, DOMAIN_B, 32).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn derive_subkey_deterministic() {
        let a = derive_subkey(IKM_A, SALT, DOMAIN_A, 48).unwrap();
        let b = derive_subkey(IKM_A, SALT, DOMAIN_A, 48).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn canonical_info_is_collision_resistant() {
        // The classic concatenation ambiguity: ("ab","c") vs ("a","bc")
        // both flatten to "abc" under naive concat. Length-prefixing
        // makes them distinct, so the derived subkeys differ.
        let split1: &[&[u8]] = &[b"ab", b"c"];
        let split2: &[&[u8]] = &[b"a", b"bc"];
        assert_ne!(
            canonical_info(split1).unwrap(),
            canonical_info(split2).unwrap()
        );
        let k1 = derive_subkey(IKM_A, SALT, split1, 32).unwrap();
        let k2 = derive_subkey(IKM_A, SALT, split2, 32).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn canonical_info_encoding_shape() {
        // Each component is len_be(u32) || bytes.
        let enc = canonical_info(&[b"ab", b"c"]).unwrap();
        assert_eq!(enc, vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c']);
    }
}
