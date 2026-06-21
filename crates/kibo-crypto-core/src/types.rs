//! Shared boundary types consumed by `kibo-byok`, `kibo-hyok`, and
//! `kibo-custody`. Centralized here so the adapter crates do not
//! duplicate definitions.
//!
//! # Boundary hardening
//!
//! These structs are the exact interfaces untrusted payloads cross into
//! the enclave, so deserialization is the load-bearing validation point:
//!
//! - `#[serde(deny_unknown_fields)]` on the named structs rejects
//!   duplicate/injected fields (mutation-injection).
//! - [`KeyVersionRef::external_ref`] is length-bounded at deserialize
//!   ([`MAX_EXTERNAL_REF_LEN`]) so an adversarial multi-MB string cannot
//!   be propagated into the envelope/ledger. The
//!   first-line OOM defense is the API-perimeter body limit; this is
//!   the in-kernel backstop.
//! - [`WrappedDek`] derives [`ZeroizeOnDrop`] so the envelope bytes
//!   (and the cleartext metadata they carry) are wiped on drop rather
//!   than left in freed heap pages. We keep the field a
//!   plain `Vec<u8>` (not `Zeroizing<Vec<u8>>`) so the derived
//!   `Serialize`/`Deserialize` and every `WrappedDek { envelope }`
//!   construction site stay source-compatible.
//! - [`Region`] has a private inner field and a validating
//!   [`Region::try_new`] + validating `Deserialize` that reject any byte
//!   outside `[A-Za-z0-9-]`, closing the zero-width/unicode
//!   data-residency jailbreak at the wire boundary. We use
//!   an ASCII charset gate rather than a static registry of region
//!   values: cloud providers add regions continually, and "which
//!   regions exist" is genuinely provider-side — the load-bearing
//!   security property is rejecting the non-printable divergence between
//!   our matching and the provider's parsing, which the charset gate
//!   fully covers.
//!
//! ## Declined finding (documented)
//!
//! The variable-time `Hash` → collision DoS finding is NOT actioned:
//! `std`'s `HashMap` uses `RandomState`/SipHash with a per-map random
//! seed, which already defeats the algorithmic-complexity attack the
//! finding describes (its `O(N²)` claim assumes a non-randomized
//! hasher). Removing the `Hash` derive would break consumers that key
//! maps on these types for no real gain.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Maximum accepted byte length of [`KeyVersionRef::external_ref`].
///
/// Provider key identifiers (AWS ARNs, GCP resource names, Azure key
/// URLs, Vault paths) are all well under this; the bound exists to stop
/// an adversarial oversized string from being deserialized and carried
/// into the envelope/ledger. Comfortably within the envelope wire
/// format's 2-byte `ext_len` field (`u16::MAX`).
pub const MAX_EXTERNAL_REF_LEN: usize = 1024;

/// Maximum accepted byte length of a [`Region`] string.
pub const MAX_REGION_LEN: usize = 64;

/// Errors from boundary-type validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypeError {
    /// A [`Region`] string was empty.
    #[error("region must not be empty")]
    EmptyRegion,
    /// A [`Region`] string exceeded [`MAX_REGION_LEN`] bytes.
    #[error("region exceeds maximum length of {} bytes (got {got})", MAX_REGION_LEN)]
    RegionTooLong {
        /// Actual byte length supplied.
        got: usize,
    },
    /// A [`Region`] string contained a byte outside `[A-Za-z0-9-]` —
    /// rejected to close the zero-width/unicode data-residency jailbreak.
    #[error("region contains characters outside [A-Za-z0-9-]")]
    InvalidRegionFormat,
}

/// Identifies a specific KEK version at the external KMS / HSM
/// (BYOK / HYOK) or a platform-managed key version
/// (PLATFORM_MANAGED / CONFIDENTIAL_WORKLOAD).
///
/// `version` is a numeric monotone that increments across both rotations
/// and custody-mode re-key transitions. It is the project-scoped version of
/// the active KEK across the project's full lifetime, not per-custody-mode.
///
/// `external_ref` is the provider-formatted opaque identifier carried in
/// audit-ledger event payloads so customers can reconcile against their
/// own KMS records (e.g., AWS key ARN, GCP fully-qualified key resource
/// name, Azure versioned key identifier, Vault `<mount>/<key>:<v>`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyVersionRef {
    /// Monotone numeric version increment across all KEK rotations
    /// AND custody-mode re-key transitions. Never resets per custody mode.
    pub version: u64,
    /// Provider-formatted opaque identifier for cross-system reconciliation
    /// (AWS key ARN, GCP fully-qualified key resource name, Azure versioned
    /// key identifier, Vault `<mount>/<key>:<v>`).
    ///
    /// Length-bounded at deserialize to [`MAX_EXTERNAL_REF_LEN`] so an
    /// oversized adversarial string cannot be carried into the envelope
    /// or audit ledger.
    #[serde(deserialize_with = "deserialize_bounded_external_ref")]
    pub external_ref: String,
}

/// Deserialize an `external_ref`, rejecting anything over
/// [`MAX_EXTERNAL_REF_LEN`] bytes.
fn deserialize_bounded_external_ref<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_EXTERNAL_REF_LEN {
        return Err(D::Error::custom(format!(
            "external_ref exceeds maximum of {MAX_EXTERNAL_REF_LEN} bytes (got {})",
            s.len()
        )));
    }
    Ok(s)
}

/// Opaque ciphertext envelope produced by `wrap_dek` / consumed by
/// `unwrap_dek`. Format is provider-aware: a magic header tags which
/// provider produced it, plus the embedded `KeyVersionRef` needed to
/// route unwrap during the dual-version window.
///
/// The envelope is self-describing — the consumer of `unwrap_dek` does
/// not pass `KeyVersionRef` separately. This matches AWS KMS / GCP /
/// Azure / HashiCorp Vault native semantics where ciphertext headers
/// self-describe the version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct WrappedDek {
    /// Self-describing envelope bytes per the [`crate::envelope`] format:
    /// magic + version + provider tag + key-version + external_ref + nonce +
    /// AEAD ciphertext-with-tag.
    ///
    /// Wiped on drop via the struct's [`ZeroizeOnDrop`] derive so the
    /// cleartext header metadata (key version, provider tag,
    /// external_ref) does not linger in freed heap pages. The field
    /// stays a plain `Vec<u8>` (not `Zeroizing<Vec<u8>>`) to preserve
    /// the derived serde impls and source-compatibility with every
    /// `WrappedDek { envelope }` construction site in the adapter crates.
    pub envelope: Vec<u8>,
}

/// Cloud-provider region newtype. Provider-specific region strings
/// (e.g., `us-east-1`, `europe-west1`, `eastus`) flow through this
/// shape; *which* regions exist is validated provider-side, but the
/// **format** is validated here.
///
/// The inner field is private: construction goes through [`Region::new`]
/// (unchecked, for trusted internal callers) or [`Region::try_new`]
/// (validating). Deserialization — the untrusted-input path — always
/// validates via [`Region::try_new`], rejecting any byte outside
/// `[A-Za-z0-9-]`. This closes the zero-width/unicode data-residency
/// jailbreak where a region like `us-east-1\u{200b}` matches one path
/// internally but parses differently provider-side.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Region(String);

impl Region {
    /// Wrap a region string (e.g., `"us-east-1"`) **without validation**.
    ///
    /// For trusted, internal construction from known-good literals only.
    /// Untrusted region strings (provider responses, config, wire
    /// payloads) MUST go through [`Region::try_new`] — deserialization
    /// already does. Kept infallible for source-compatibility with
    /// existing trusted call sites.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Wrap a region string after validating its format.
    ///
    /// # Errors
    ///
    /// - [`TypeError::EmptyRegion`] if empty.
    /// - [`TypeError::RegionTooLong`] if over [`MAX_REGION_LEN`] bytes.
    /// - [`TypeError::InvalidRegionFormat`] if any byte is outside
    ///   `[A-Za-z0-9-]` (rejects zero-width/unicode/control characters).
    pub fn try_new(s: impl Into<String>) -> Result<Self, TypeError> {
        let s = s.into();
        if s.is_empty() {
            return Err(TypeError::EmptyRegion);
        }
        if s.len() > MAX_REGION_LEN {
            return Err(TypeError::RegionTooLong { got: s.len() });
        }
        if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(TypeError::InvalidRegionFormat);
        }
        Ok(Self(s))
    }

    /// Borrow the region as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Region {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Region::try_new(s).map_err(D::Error::custom)
    }
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn key_version_ref_round_trip() {
        let kv = KeyVersionRef {
            version: 7,
            external_ref: "arn:aws:kms:us-east-1:123:key/abc".to_string(),
        };
        let json = serde_json::to_string(&kv).unwrap();
        let back: KeyVersionRef = serde_json::from_str(&json).unwrap();
        assert_eq!(kv, back);
    }

    #[test]
    fn key_version_ref_rejects_unknown_field() {
        let json = r#"{"version":1,"external_ref":"x","injected":"evil"}"#;
        assert!(serde_json::from_str::<KeyVersionRef>(json).is_err());
    }

    #[test]
    fn external_ref_bound_accepts_max_and_rejects_over() {
        let at_max = "a".repeat(MAX_EXTERNAL_REF_LEN);
        let json = format!(r#"{{"version":1,"external_ref":"{at_max}"}}"#);
        assert!(serde_json::from_str::<KeyVersionRef>(&json).is_ok());

        let over = "a".repeat(MAX_EXTERNAL_REF_LEN + 1);
        let json = format!(r#"{{"version":1,"external_ref":"{over}"}}"#);
        assert!(serde_json::from_str::<KeyVersionRef>(&json).is_err());
    }

    #[test]
    fn region_try_new_accepts_valid() {
        assert_eq!(Region::try_new("us-east-1").unwrap().as_str(), "us-east-1");
        assert_eq!(Region::try_new("europe-west1").unwrap().as_str(), "europe-west1");
        assert_eq!(Region::try_new("eastus").unwrap().as_str(), "eastus");
    }

    #[test]
    fn region_try_new_rejects_empty() {
        assert_eq!(Region::try_new(""), Err(TypeError::EmptyRegion));
    }

    #[test]
    fn region_try_new_rejects_too_long() {
        let long = "a".repeat(MAX_REGION_LEN + 1);
        assert_eq!(
            Region::try_new(long),
            Err(TypeError::RegionTooLong { got: MAX_REGION_LEN + 1 })
        );
    }

    #[test]
    fn region_try_new_rejects_unicode_jailbreak() {
        // Zero-width space appended — the data-residency jailbreak.
        assert_eq!(
            Region::try_new("us-east-1\u{200b}"),
            Err(TypeError::InvalidRegionFormat)
        );
        // Other non-allowlisted bytes.
        assert_eq!(Region::try_new("us_east_1"), Err(TypeError::InvalidRegionFormat));
        assert_eq!(Region::try_new("us east 1"), Err(TypeError::InvalidRegionFormat));
    }

    #[test]
    fn region_deserialize_validates() {
        // Valid passes.
        let ok: Region = serde_json::from_str(r#""us-east-1""#).unwrap();
        assert_eq!(ok.as_str(), "us-east-1");
        // Jailbreak rejected at the wire boundary.
        assert!(serde_json::from_str::<Region>(r#""us-east-1​""#).is_err());
    }

    #[test]
    fn region_serialize_is_transparent() {
        let r = Region::new("us-west-2");
        assert_eq!(serde_json::to_string(&r).unwrap(), r#""us-west-2""#);
    }

    #[test]
    fn region_new_is_unchecked_back_compat() {
        // `new` stays infallible for trusted callers; it does NOT validate.
        let r = Region::new("anything-goes");
        assert_eq!(r.as_str(), "anything-goes");
    }

    #[test]
    fn wrapped_dek_round_trip_and_clone() {
        // Confirms ZeroizeOnDrop coexists with the serde + Clone derives.
        let w = WrappedDek { envelope: vec![1, 2, 3, 4] };
        let json = serde_json::to_string(&w).unwrap();
        let back: WrappedDek = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
        let _cloned = w.clone();
    }
}
