//! Error surface for the REST-direct KMS layer.
//!
//! # Error-code mapping
//!
//! Three loci, three dispositions:
//!
//! 1. **Routing / posture decisions** → the **`K9O_CRYPTO_*`** family (the
//!    smart-primitive `CustomerKmsOracle | LocalEnvelope` surface this crate
//!    implements).
//! 2. **AAD / envelope integrity** → the **`K9O_ENVELOPE_*`** family (wrong
//!    `encryptionContext` at decrypt, malformed header).
//! 3. **Raw upstream-KMS transport/auth failure** (the customer's own
//!    AWS/GCP/Azure/Vault KMS returning 4xx/5xx/denied/unreachable) → **NOT a
//!    `K9O_*` catalogue code.** `kibo-kms-rest` is a client-side crate in the
//!    *customer's* trust domain; a vendor-infra failure there is the customer's
//!    error, surfaced as **this crate's own wrapped error** carrying the upstream
//!    status + context — never `K9O_BYOK_*` (those are the *gateway-mediated*
//!    BYOK-attach flow, a different locus). So [`KmsRestError::wire_code`]
//!    returns `None` for these.

use std::fmt;

use kibo_crypto_core::envelope::EnvelopeError;

/// A canonical `K9O_*` wire code this crate maps an error to.
///
/// Only platform-*contract* concepts appear here: crypto-posture routing
/// (`K9O_CRYPTO_*`) and envelope integrity (`K9O_ENVELOPE_*`). Upstream-KMS
/// vendor failures are deliberately absent — they are crate-local (see the
/// module note, rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireCode {
    /// `K9O_CRYPTO_STRATEGY_UNAVAILABLE` (400) — the requested strategy is
    /// structurally impossible for the posture (e.g. `CustomerKmsOracle` on a
    /// Platform-Managed project).
    CryptoStrategyUnavailable,
    /// `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` (403) — a forced strategy/tier sits
    /// below the project's declared posture floor.
    CryptoPostureFloorViolation,
    /// `K9O_CRYPTO_PAYLOAD_EXCEEDS_KMS_LIMIT` (413) — an explicit
    /// `CustomerKmsOracle` payload exceeds the bound key's KMS plaintext ceiling
    /// (AAD counts); honor-or-reject, never silent fallback.
    CryptoPayloadExceedsKmsLimit,
    /// `K9O_CRYPTO_LOCAL_UNAVAILABLE` — the default `LocalEnvelope` strategy is
    /// unreachable on a thin/IoT client.
    CryptoLocalUnavailable,
    /// `K9O_ENVELOPE_INTEGRITY_FAILURE` — AEAD tag or AAD verification failed
    /// (tamper, wrong key, or mismatched `encryptionContext`).
    EnvelopeIntegrityFailure,
    /// `K9O_ENVELOPE_HEADER_MALFORMED` — envelope framing/header parse failure.
    EnvelopeHeaderMalformed,
    /// `K9O_ENVELOPE_KEK_UNAVAILABLE` — the wrapping/unwrapping key was
    /// unavailable for the operation.
    EnvelopeKekUnavailable,
}

impl WireCode {
    /// The exact `K9O_*` wire string for this code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CryptoStrategyUnavailable => "K9O_CRYPTO_STRATEGY_UNAVAILABLE",
            Self::CryptoPostureFloorViolation => "K9O_CRYPTO_POSTURE_FLOOR_VIOLATION",
            Self::CryptoPayloadExceedsKmsLimit => "K9O_CRYPTO_PAYLOAD_EXCEEDS_KMS_LIMIT",
            Self::CryptoLocalUnavailable => "K9O_CRYPTO_LOCAL_UNAVAILABLE",
            Self::EnvelopeIntegrityFailure => "K9O_ENVELOPE_INTEGRITY_FAILURE",
            Self::EnvelopeHeaderMalformed => "K9O_ENVELOPE_HEADER_MALFORMED",
            Self::EnvelopeKekUnavailable => "K9O_ENVELOPE_KEK_UNAVAILABLE",
        }
    }
}

/// Which crypto-posture sub-dial a [`KmsRestError::PostureFloorViolation`] is on
/// — surfaced in the 403 `context.dimension` so the customer sees *which*
/// requirement was breached. The two sub-dials have two shapes: custody is a
/// ladder-floor, oracle-mode an acceptable-set; both compose with the
/// `trust_tier_policy` hardware set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostureDimension {
    /// The custody-posture ladder floor (`PLATFORM_MANAGED < BYOK < HYOK`).
    CustodyPosture,
    /// The oracle-mode acceptable-set (`⊆ {brokered, direct}`).
    OracleMode,
}

impl PostureDimension {
    /// Stable wire token for the 403 `context.dimension`.
    #[must_use]
    pub const fn as_wire_token(self) -> &'static str {
        match self {
            Self::CustodyPosture => "custody_posture",
            Self::OracleMode => "oracle_mode",
        }
    }
}

impl fmt::Display for PostureDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire_token())
    }
}

/// The REST-direct KMS error surface.
///
/// Variants split into the three loci of the module note: routing/posture
/// (→ `K9O_CRYPTO_*`), envelope integrity (→ `K9O_ENVELOPE_*`), and upstream-KMS
/// vendor failures (crate-local; no `K9O_*` code).
#[derive(Debug, thiserror::Error)]
pub enum KmsRestError {
    // ---- Routing / posture (→ K9O_CRYPTO_*) ----
    /// The requested strategy is structurally impossible for the posture.
    #[error("crypto strategy unavailable for this posture")]
    StrategyUnavailable,

    /// A forced posture is outside the project's declared crypto-posture
    /// envelope. `dimension` discriminates which sub-dial failed — the
    /// `custody_posture` ladder floor or the `oracle_mode`
    /// acceptable-set; `requested` is the rejected value's wire token and
    /// `declared` summarises the policy. One `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION`
    /// (403) across both dimensions, dimension-tagged in `context`.
    #[error("crypto posture floor violation ({dimension}): requested {requested}, declared {declared}")]
    PostureFloorViolation {
        /// Which posture sub-dial the violation is on.
        dimension: PostureDimension,
        /// Wire token of the rejected value (e.g. `platform_managed`, `direct`).
        requested: &'static str,
        /// Summary of the declared policy on this dimension (e.g. `min byok`,
        /// `{brokered}`).
        declared: String,
    },

    /// An explicit `CustomerKmsOracle` payload (plaintext **+ AAD**) exceeds the
    /// bound key's KMS plaintext ceiling. Honor-or-reject — never a silent
    /// fallback to `LocalEnvelope` (that would change the sovereignty guarantee).
    /// Carries the size context the customer needs (vendor/`key_type` are added
    /// by the provider layer that knows the bound key).
    #[error(
        "payload+AAD ({payload_bytes}+{aad_bytes} B) exceeds the bound KMS plaintext ceiling ({kms_limit_bytes} B)"
    )]
    PayloadExceedsKmsLimit {
        /// The bound key's KMS plaintext ceiling, in bytes.
        kms_limit_bytes: usize,
        /// The plaintext size, in bytes.
        payload_bytes: usize,
        /// The AAD size, in bytes (counts toward the ceiling — GCP).
        aad_bytes: usize,
    },

    /// The default `LocalEnvelope` strategy is unreachable on a thin client.
    #[error("local-envelope strategy unavailable on this client")]
    LocalUnavailable,

    // ---- Envelope integrity (→ K9O_ENVELOPE_*) ----
    /// AEAD tag or AAD verification failed — e.g. a supplied `encryptionContext`
    /// does not match the one bound at encrypt time (re-supplied at decrypt; the
    /// mismatch surfaces here, never as a silent fallback).
    #[error("envelope integrity verification failed")]
    EnvelopeIntegrity,

    /// The envelope framing/header could not be parsed.
    #[error("envelope header malformed: {0}")]
    EnvelopeHeader(String),

    /// The wrapping/unwrapping key was unavailable for the operation.
    #[error("wrapping key unavailable")]
    KekUnavailable,

    // ---- Upstream-KMS vendor failure (crate-local; NO K9O_* code) ----
    /// The customer's own KMS returned a transport/auth/availability failure
    /// (4xx/5xx/denied/unreachable). This is the **customer's vendor error**, not
    /// a platform code: it carries the upstream HTTP
    /// status (when present) + a non-secret detail string for the customer to act
    /// on. [`KmsRestError::wire_code`] returns `None` for this variant.
    #[error("upstream customer-KMS error ({provider}{}): {detail}", status.map(|s| format!(", status {s}")).unwrap_or_default())]
    UpstreamKms {
        /// The provider whose KMS failed (`aws` | `gcp` | `azure` | `vault`).
        provider: &'static str,
        /// The upstream HTTP status, when the call reached the KMS.
        status: Option<u16>,
        /// The vendor's **non-secret** error text only — the IAM-denial reason,
        /// regional-endpoint timeout, key-state, etc. that the customer needs to
        /// debug *their own* KMS. Preserving the vendor signal is the right
        /// `CustomerKmsOracle` behavior, not a Kibo-flavoured abstraction.
        /// **Discipline:** the signer + REST call MUST NOT thread any
        /// `FederatedToken` (zeroizing), DEK, or plaintext into this field or the
        /// `Display` — only the vendor's sanitized message. KMS vendor errors
        /// don't echo secret inputs; the crate must not *append* secret
        /// request-context here.
        detail: String,
    },
}

impl KmsRestError {
    /// Map this error to its canonical `K9O_*` wire code, or `None` when the
    /// error is crate-local (an upstream-KMS vendor failure or an internal seam)
    /// that must NOT be catalogued as a platform code.
    #[must_use]
    pub fn wire_code(&self) -> Option<WireCode> {
        Some(match self {
            Self::StrategyUnavailable => WireCode::CryptoStrategyUnavailable,
            Self::PostureFloorViolation { .. } => WireCode::CryptoPostureFloorViolation,
            Self::PayloadExceedsKmsLimit { .. } => WireCode::CryptoPayloadExceedsKmsLimit,
            Self::LocalUnavailable => WireCode::CryptoLocalUnavailable,
            Self::EnvelopeIntegrity => WireCode::EnvelopeIntegrityFailure,
            Self::EnvelopeHeader(_) => WireCode::EnvelopeHeaderMalformed,
            Self::KekUnavailable => WireCode::EnvelopeKekUnavailable,
            // Crate-local — the customer's vendor error, not a platform code.
            Self::UpstreamKms { .. } => return None,
        })
    }
}

impl From<EnvelopeError> for KmsRestError {
    /// Maps `kibo-crypto-core` envelope framing errors onto the REST-direct error
    /// surface so callers see a single error type.
    fn from(err: EnvelopeError) -> Self {
        Self::EnvelopeHeader(err.to_string())
    }
}

/// Convenience result alias for the REST-direct KMS layer.
pub type Result<T> = std::result::Result<T, KmsRestError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_errors_map_to_crypto_family() {
        assert_eq!(
            KmsRestError::StrategyUnavailable
                .wire_code()
                .unwrap()
                .as_str(),
            "K9O_CRYPTO_STRATEGY_UNAVAILABLE"
        );
        assert_eq!(
            KmsRestError::PostureFloorViolation {
                dimension: PostureDimension::CustodyPosture,
                requested: "platform_managed",
                declared: "min byok".to_string(),
            }
            .wire_code()
            .unwrap()
            .as_str(),
            "K9O_CRYPTO_POSTURE_FLOOR_VIOLATION"
        );
        assert_eq!(
            KmsRestError::PayloadExceedsKmsLimit {
                kms_limit_bytes: 4096,
                payload_bytes: 5000,
                aad_bytes: 32
            }
            .wire_code()
            .unwrap()
            .as_str(),
            "K9O_CRYPTO_PAYLOAD_EXCEEDS_KMS_LIMIT"
        );
        assert_eq!(
            KmsRestError::LocalUnavailable.wire_code().unwrap().as_str(),
            "K9O_CRYPTO_LOCAL_UNAVAILABLE"
        );
    }

    #[test]
    fn integrity_errors_map_to_envelope_family() {
        assert_eq!(
            KmsRestError::EnvelopeIntegrity
                .wire_code()
                .unwrap()
                .as_str(),
            "K9O_ENVELOPE_INTEGRITY_FAILURE"
        );
        assert_eq!(
            KmsRestError::EnvelopeHeader("x".into())
                .wire_code()
                .unwrap()
                .as_str(),
            "K9O_ENVELOPE_HEADER_MALFORMED"
        );
    }

    #[test]
    fn upstream_kms_is_crate_local_no_platform_code() {
        // The customer's vendor error is NOT a K9O_* code.
        let e = KmsRestError::UpstreamKms {
            provider: "aws",
            status: Some(403),
            detail: "AccessDenied".into(),
        };
        assert!(e.wire_code().is_none());
        // …but it carries the upstream status + context for the customer.
        assert!(e.to_string().contains("status 403"));
        assert!(e.to_string().contains("aws"));
    }

    #[test]
    fn no_byok_codes_remain() {
        // The K9O_BYOK_* mappings were removed (BYOK = gateway-mediated locus).
        for code in [
            WireCode::CryptoStrategyUnavailable,
            WireCode::EnvelopeIntegrityFailure,
        ] {
            assert!(!code.as_str().contains("BYOK"));
        }
    }
}
