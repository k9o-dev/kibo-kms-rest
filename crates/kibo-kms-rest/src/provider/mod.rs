//! REST-direct KMS provider abstraction.
//!
//! A provider is a thin client that performs `Encrypt` / `Decrypt`
//! against a single customer KMS over plain HTTPS. One or more providers
//! are compiled per build via the composable cargo features (`kms-aws`,
//! `kms-gcp`, `kms-azure`, `kms-vault`) and chosen at call time; see the
//! crate root.
//!
//! The trait + per-provider structs define the **shape**. The signing
//! (SigV4 / OAuth / token), the HTTP round-trip, and the AAD composition are
//! the crypto substance: every provider method performs the REST-direct
//! round-trip against the customer KMS.
//!
//! ## wasm target
//! This crate is the WASM-bindable ZK client core. On
//! `wasm32-unknown-unknown` `reqwest` selects its `fetch` backend, whose
//! futures (`JsFuture`) and `Client` are `!Send`. The provider trait therefore
//! drops its `Send` requirements on wasm — via the `#[async_trait(?Send)]`
//! cfg-gate and the [`MaybeSendSync`] supertrait alias — and keeps them on
//! native, with no duplicated trait body.

use crate::auth::FederatedToken;
use crate::error::Result;
use crate::strategy::Strategy;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Marker that is `Send + Sync` on native and unconstrained on wasm. Native
/// providers are shared across the async runtime's worker threads (so the bound
/// is required); the wasm `fetch` backend's `reqwest::Client` wraps non-`Send`
/// JS handles and the SDK runs single-threaded (so the bound is unsatisfiable
/// and unnecessary). Lets [`KmsRestProvider`] keep one trait body on both.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSendSync for T {}
/// wasm variant — no thread-safety bound (see the native variant's docs).
#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSendSync for T {}

/// `reqwest::Error::is_connect` is absent on the wasm `fetch` backend (the
/// browser folds connect failures into the generic transport error). Native
/// keeps the precise category; wasm reports `false` and lands in the generic
/// "transport error" bucket. Non-secret category probe only — see
/// `reqwest_category` in each provider.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn is_connect_error(e: &reqwest::Error) -> bool {
    e.is_connect()
}
/// wasm variant — `is_connect` is not available on the `fetch` backend.
#[cfg(target_arch = "wasm32")]
pub(crate) fn is_connect_error(_e: &reqwest::Error) -> bool {
    false
}

/// The most one KMS call may take, connect to last response byte. A stalled KMS is an error
/// to the caller, never a call that hangs. The KMS's own latency is well under this.
#[cfg(not(test))]
const KMS_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const KMS_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// A bounded POST to a KMS: every provider's one way to make a request.
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-azure",
    feature = "kms-gcp",
    feature = "kms-vault"
))]
pub(crate) fn kms_post(url: &str) -> std::result::Result<reqwest::RequestBuilder, reqwest::Error> {
    Ok(reqwest::Client::builder()
        .build()?
        .post(url)
        .timeout(KMS_CALL_TIMEOUT))
}

#[cfg(feature = "kms-aws")]
pub mod aws;
#[cfg(feature = "kms-azure")]
pub mod azure;
#[cfg(feature = "kms-gcp")]
pub mod gcp;
#[cfg(feature = "kms-vault")]
pub mod vault;

/// Hardware attestation tier of the edge device, bound into the AAD.
///
/// This is a deliberately small local enum so the edge crate does not
/// pull in the server-side `kibo-attestation` dependency. The tier is one
/// of the AAD-bound dimensions (`{version, strategy, attestation_tier,
/// project_id}`).
///
// TODO: reconcile these tokens with the canonical 3-axis attestation taxonomy
// once a shared boundary type is exported from `kibo-crypto-core` / `kibo-attestation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTier {
    /// No hardware attestation available (commodity mobile / IoT).
    Software,
    /// Device-bound key in a secure element / TEE.
    HardwareBacked,
    /// Full confidential-compute attestation chain.
    Confidential,
}

impl AttestationTier {
    /// Stable wire token used in the AAD binding.
    #[must_use]
    pub const fn as_aad_token(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::HardwareBacked => "hardware_backed",
            Self::Confidential => "confidential",
        }
    }
}

/// The authenticated context bound into every REST-direct operation.
///
/// The AAD binds `{version, strategy, attestation_tier, project_id}`
/// together with the caller-supplied [`Self::encryption_context`]. The
/// `encryption_context` is **re-supplied at decrypt time and is never
/// read back from the envelope.** An envelope may store a copy for audit
/// only; that stored copy is never used as a decrypt input. The
/// [`KmsRestProvider::decrypt`] signature enforces this by requiring the
/// caller to pass an `AadContext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AadContext {
    /// Envelope format version (binds the framing generation).
    pub version: u8,
    /// Which strategy produced / consumes the ciphertext.
    pub strategy: Strategy,
    /// Attestation tier of the device.
    pub attestation_tier: AttestationTier,
    /// Caller-supplied key/value encryption context. Re-supplied at
    /// decrypt; never sourced from the envelope.
    pub encryption_context: Vec<(String, String)>,
    /// Reserved tenant-boundary dimension: the owning
    /// project's id, bound as `kibo:project_id`. The value MUST be the canonical
    /// lowercase 8-4-4-4-12 UUID (the caller supplies the canonical form). Like
    /// every dimension it is re-supplied from custody context at BOTH encrypt and
    /// decrypt and is **never** sourced from the envelope; a blob wrapped for
    /// project A fails the AEAD tag when project B's context is re-supplied.
    /// `None` leaves the dimension unbound (the server custody layer always
    /// supplies `Some`; the FFI/SDK input contract threads it through separately).
    pub project_id: Option<String>,
}

/// Reserved AAD-binding keys for the three dimensions, shared by every
/// provider. Part of the envelope-compatibility contract: a ciphertext bound
/// with these can be decrypted only by re-supplying the identical binding. The
/// `kibo:` prefix is reserved — caller `encryption_context` keys must not use
/// it (reserved keys take precedence on collision).
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
pub(crate) const AAD_KEY_VERSION: &str = "kibo:version";
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
pub(crate) const AAD_KEY_STRATEGY: &str = "kibo:strategy";
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
pub(crate) const AAD_KEY_ATTESTATION_TIER: &str = "kibo:attestation_tier";
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
pub(crate) const AAD_KEY_PROJECT_ID: &str = "kibo:project_id";

#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
impl AadContext {
    /// The full set of AAD binding pairs — the caller's `encryption_context`
    /// plus the reserved dimensions (`version`, `strategy`, `attestation_tier`,
    /// and `project_id` when bound; reserved keys win on collision),
    /// sorted for determinism. Every provider binds exactly this logical set,
    /// in its native mechanism: AWS as a KMS `EncryptionContext` map, GCP /
    /// Vault as the single canonical blob from [`Self::binding_blob`].
    pub(crate) fn binding_pairs(&self) -> Vec<(String, String)> {
        let mut map: std::collections::BTreeMap<String, String> =
            self.encryption_context.iter().cloned().collect();
        map.insert(AAD_KEY_VERSION.to_string(), self.version.to_string());
        map.insert(
            AAD_KEY_STRATEGY.to_string(),
            self.strategy.as_aad_token().to_string(),
        );
        map.insert(
            AAD_KEY_ATTESTATION_TIER.to_string(),
            self.attestation_tier.as_aad_token().to_string(),
        );
        // Reserved keys win on collision, so insert after the caller context: a
        // caller cannot smuggle a conflicting `kibo:project_id` via
        // `encryption_context`. Unbound (`None`) omits the dimension entirely.
        if let Some(project_id) = &self.project_id {
            map.insert(AAD_KEY_PROJECT_ID.to_string(), project_id.clone());
        }
        map.into_iter().collect()
    }
}

#[cfg(any(feature = "kms-gcp", feature = "kms-vault", feature = "kms-azure"))]
impl AadContext {
    /// The AAD binding as a single canonical byte blob, for providers whose
    /// AAD is one opaque value (GCP `additionalAuthenticatedData`, Vault
    /// `associated_data`) rather than a key-value map. Uses the injective,
    /// length-prefixed [`kibo_crypto_core::kdf::canonical_info`] encoding over the
    /// sorted `(key, value)` pairs, so the encrypt-time and re-supplied
    /// decrypt-time AAD are byte-identical and unambiguous (the `("ab","c")`
    /// vs `("a","bc")` flattening ambiguity cannot occur).
    ///
    /// # Errors
    /// [`crate::error::KmsRestError::EnvelopeHeader`] if a component exceeds the
    /// canonical encoding's length bound (a structural impossibility for real
    /// context strings).
    pub(crate) fn binding_blob(&self) -> crate::error::Result<Vec<u8>> {
        let pairs = self.binding_pairs();
        let mut components: Vec<&[u8]> = Vec::with_capacity(pairs.len() * 2);
        for (k, v) in &pairs {
            components.push(k.as_bytes());
            components.push(v.as_bytes());
        }
        kibo_crypto_core::kdf::canonical_info(&components).map_err(|_| {
            crate::error::KmsRestError::EnvelopeHeader(
                "additional authenticated data exceeds the canonical encoding limit".to_string(),
            )
        })
    }
}

/// REST-direct KMS provider.
///
/// `encrypt` takes the bytes to protect (either the data, under
/// [`Strategy::CustomerKmsOracle`], or the 32-byte DEK, under
/// [`Strategy::LocalEnvelope`]) plus the [`AadContext`], and returns the
/// provider ciphertext. `decrypt` is the inverse and **requires** the
/// caller to re-supply the `AadContext` — it is never reconstructed from
/// the envelope.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait KmsRestProvider: MaybeSendSync {
    /// REST `Encrypt`: protect `plaintext_or_dek` under the customer KMS,
    /// binding `aad`. Returns the provider ciphertext bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::KmsRestError`] on transport, permission,
    /// or framing failure.
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        aad: &AadContext,
    ) -> Result<Vec<u8>>;

    /// REST `Decrypt`: recover the protected bytes from `ciphertext`,
    /// verifying against the **re-supplied** `aad`. The `aad` (and its
    /// `encryption_context`) MUST come from the caller, never from the
    /// envelope.
    ///
    /// The plaintext is returned in a [`Zeroizing`] buffer so a recovered
    /// DEK or small payload is wiped on drop.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::KmsRestError::EnvelopeIntegrity`] if the
    /// re-supplied context does not match the one bound at encrypt time.
    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

#[cfg(test)]
#[cfg(any(
    feature = "kms-aws",
    feature = "kms-gcp",
    feature = "kms-vault",
    feature = "kms-azure"
))]
mod project_id_aad_tests {
    use super::{AAD_KEY_PROJECT_ID, AadContext, AttestationTier};
    use crate::strategy::Strategy;

    const PID_A: &str = "11111111-1111-1111-1111-111111111111";
    const PID_B: &str = "22222222-2222-2222-2222-222222222222";

    fn ctx(project_id: Option<&str>) -> AadContext {
        AadContext {
            version: 1,
            strategy: Strategy::LocalEnvelope,
            attestation_tier: AttestationTier::HardwareBacked,
            encryption_context: vec![],
            project_id: project_id.map(str::to_string),
        }
    }

    #[test]
    fn project_id_binds_as_reserved_dimension_and_omits_when_unbound() {
        let bound = ctx(Some(PID_A)).binding_pairs();
        assert!(
            bound
                .iter()
                .any(|(k, v)| k == AAD_KEY_PROJECT_ID && v == PID_A),
            "project_id must bind as the reserved kibo:project_id pair"
        );
        let unbound = ctx(None).binding_pairs();
        assert!(
            !unbound.iter().any(|(k, _)| k == AAD_KEY_PROJECT_ID),
            "an unbound (None) project_id must omit the dimension entirely"
        );
    }

    #[test]
    fn distinct_projects_diverge_the_aad_so_a_transplant_fails() {
        // The AAD set is what the AEAD tag covers. Two projects -> two distinct
        // bindings -> a blob wrapped under A cannot be unwrapped with B's
        // re-supplied context (the tenant boundary, cryptographically explicit).
        let a = ctx(Some(PID_A)).binding_pairs();
        let b = ctx(Some(PID_B)).binding_pairs();
        assert_ne!(a, b, "distinct projects must produce distinct AAD bindings");
        // And a legitimate decrypt (same project) re-supplies an identical set.
        assert_eq!(a, ctx(Some(PID_A)).binding_pairs());
    }

    #[test]
    fn reserved_project_id_wins_over_a_caller_context_collision() {
        // A caller must not be able to override the tenant boundary by smuggling
        // a conflicting kibo:project_id through encryption_context.
        let mut c = ctx(Some(PID_A));
        c.encryption_context = vec![(AAD_KEY_PROJECT_ID.to_string(), "spoofed".to_string())];
        let pairs = c.binding_pairs();
        let bound: Vec<&String> = pairs
            .iter()
            .filter(|(k, _)| k == AAD_KEY_PROJECT_ID)
            .map(|(_, v)| v)
            .collect();
        assert_eq!(
            bound,
            vec![PID_A],
            "reserved project_id must win on collision"
        );
    }
}
