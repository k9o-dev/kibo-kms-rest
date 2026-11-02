//! FFI-friendly input, output, and error types for `zk_encrypt`/`zk_decrypt`.

use serde::{Deserialize, Serialize};

/// The customer KMS provider for this call. The engine dispatches on it at call
/// time among the providers compiled into the build (composable `kms-*` Cargo
/// features); a call for a provider whose feature is not compiled in returns
/// `K9O_CRYPTO_STRATEGY_UNAVAILABLE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "kebab-case")]
pub enum KmsProvider {
    AwsKms,
    GcpKms,
    AzureKv,
    HashicorpVault,
}

impl KmsProvider {
    /// Stable wire token used in the ZKFE envelope.
    #[must_use]
    pub const fn as_wire_token(self) -> &'static str {
        match self {
            Self::AwsKms => "aws-kms",
            Self::GcpKms => "gcp-kms",
            Self::AzureKv => "azure-kv",
            Self::HashicorpVault => "hashicorp-vault",
        }
    }
}

/// Custody posture for a `zk_encrypt` call. `PlatformManaged` is deliberately
/// absent — `kibo-kms-rest` is the KEK-free customer-KMS layer; a PM call has
/// no customer KMS to talk to and is structurally impossible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FfiPosture {
    Byok,
    Hyok,
}

/// Explicit strategy pin. `None` selects the posture default (`LocalEnvelope`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FfiStrategy {
    LocalEnvelope,
    CustomerKmsOracle,
}

/// Oracle routing mode. `None` defaults to `Brokered`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FfiOracleMode {
    Brokered,
    Direct,
}

/// Device attestation tier bound into the AAD for every operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FfiAttestationTier {
    Software,
    HardwareBacked,
    Confidential,
}

/// Project-declared crypto-posture floor. Two sub-dials:
/// `min_custody_posture` is a ladder-floor (`PlatformManaged < Byok < Hyok`);
/// `allowed_oracle_modes` is an acceptable-set (`⊆ {brokered, direct}`).
///
/// Default = most permissive (`PlatformManaged` floor + both oracle modes).
/// `min_custody_posture: None` → `PlatformManaged` (admits every posture).
/// `allowed_oracle_modes: None` → both modes allowed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiPosturePolicy {
    /// Minimum custody posture on the sovereignty ladder. `None` = no floor.
    /// Note: `None` and `Some(PlatformManaged)` are equivalent here.
    pub min_custody_posture: Option<FfiMinPosture>,
    /// Permitted oracle modes. `None` = both modes allowed.
    pub allowed_oracle_modes: Option<FfiAllowedOracleModes>,
}

/// The min-custody-posture dial accepts `PlatformManaged` here (unlike
/// `EncryptInput.posture` which only admits Byok/Hyok). A floor of
/// `PlatformManaged` means "no floor — admit every posture including PM", which
/// is the default / most permissive setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "snake_case")]
pub enum FfiMinPosture {
    PlatformManaged,
    Byok,
    Hyok,
}

/// Acceptable oracle-mode set for the allowed_oracle_modes policy dial.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiAllowedOracleModes {
    pub brokered: bool,
    pub direct: bool,
}

/// Short-lived customer KMS credential — the edge device's federated token.
/// Zeroized on drop in the engine (mapped to `FederatedToken`). The `secret`
/// is never logged or returned in any output or error.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiCredential {
    /// Opaque credential value (e.g., STS session token, GCP OAuth bearer,
    /// Vault token). Treated as secret material; zeroized after use.
    pub secret: String,
    /// Absolute expiry as Unix seconds. The caller is responsible for refresh.
    pub expires_at_unix_secs: u64,
}

impl std::fmt::Debug for FfiCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiCredential")
            .field("secret", &"<redacted>")
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .finish()
    }
}

/// Key version reference identifying the customer KMS key. Maps directly to
/// `kibo_crypto_core::types::KeyVersionRef`; `external_ref` format is provider-specific:
/// - AWS: full key ARN (`arn:aws:kms:<region>:<acct>:key/<id>`)
/// - GCP: fully-qualified CryptoKey resource name
/// - Azure: versioned key identifier URL (`https://<vault>.vault.azure.net/keys/<name>/<ver>`)
/// - Vault: `<mount>/<key_name>:<version>` (e.g. `transit/mykey:3`)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiKeyRef {
    /// Monotone version counter across all KEK rotations and re-key transitions.
    pub version: u64,
    /// Provider-formatted opaque identifier (see above).
    pub external_ref: String,
}

/// Provider-specific initialization parameters. Only the field relevant to
/// the compiled-in provider is consulted; others are ignored.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiProviderConfig {
    /// AWS region (e.g. `us-east-1`). Falls back to ARN-extraction from
    /// `key_ref.external_ref` if `None` (ARN format only).
    pub aws_region: Option<String>,
    /// Vault base address (e.g. `https://vault.example.com:8200`). Required
    /// when the compiled-in provider is `kms-vault`.
    pub vault_address: Option<String>,
    /// The Key Vault or Managed HSM DNS suffix of an Azure cloud outside the built-in list
    /// (public, 21Vianet, US Government), e.g. `vault.example.net`. The caller's configuration
    /// only: a key id naming any other host is refused.
    #[serde(default)]
    pub azure_key_host_suffix: Option<String>,
}

/// A single encryption-context key/value pair.
///
/// `Vec<(String, String)>` cannot cross the uniffi boundary (tuples are
/// unsupported); this named record is the wire-compatible replacement.
/// JSON serialization: `{"key": "...", "value": "..."}` (object, not array).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiKvPair {
    pub key: String,
    pub value: String,
}

/// All inputs to `zk_encrypt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct EncryptInput {
    /// The customer KMS provider. Must match the compiled-in provider feature.
    pub provider: KmsProvider,
    /// Custody posture (Byok or Hyok — PlatformManaged excluded).
    pub posture: FfiPosture,
    /// Explicit strategy pin. `None` → `LocalEnvelope` (posture default).
    pub strategy: Option<FfiStrategy>,
    /// Oracle routing mode. `None` → `Brokered` (default).
    pub oracle_mode: Option<FfiOracleMode>,
    /// Customer KMS credential. Customer-issued short-lived token; never
    /// a platform KEK. Zeroized after use.
    pub kms_cred: FfiCredential,
    /// Customer KMS key version reference.
    pub key_ref: FfiKeyRef,
    /// Provider-specific initialization (region for AWS, address for Vault).
    pub provider_config: FfiProviderConfig,
    /// Device attestation tier bound into the AAD.
    pub attestation_tier: FfiAttestationTier,
    /// User-supplied encryption context — key/value pairs bound into the AAD
    /// and re-supplied byte-for-byte at decrypt. `kibo:` prefix is reserved.
    pub encryption_context: Vec<FfiKvPair>,
    /// Plaintext bytes to encrypt.
    pub plaintext: Vec<u8>,
    /// Project-declared crypto-posture floor. `None` = permissive default.
    pub posture_policy: Option<FfiPosturePolicy>,
    /// The keys this application allows, from its own configuration and never from the
    /// platform or a stored envelope. Compared without the key version, so rotation keeps
    /// working. When set, any other key is refused before any token use or network call.
    /// Empty means no pin, and an open then uses whatever key the stored envelope names, so
    /// the SDK's client path must always set this and refuse to call without it.
    #[serde(default)]
    pub expected_key_refs: Vec<String>,
}

/// All inputs to `zk_decrypt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct DecryptInput {
    /// Customer KMS credential. Must be valid for the wrapped-DEK unwrap
    /// (or oracle ciphertext decrypt). Zeroized after use.
    pub kms_cred: FfiCredential,
    /// Provider-specific initialization (region for AWS, address for Vault).
    pub provider_config: FfiProviderConfig,
    /// The canonical (`b"KIBO"`) envelope returned by a prior `zk_encrypt` call.
    pub envelope: Vec<u8>,
    /// Strategy used at encrypt — MUST be re-supplied by the caller. Strategy
    /// is not stored in the canonical envelope header (it is an AAD-bound
    /// dimension in `AadContext`; the KMS verifies it matches at decrypt). The
    /// caller always knows the strategy used at encrypt; it is not inferred from
    /// the envelope bytes.
    pub strategy: FfiStrategy,
    /// Device attestation tier — MUST be re-supplied by the caller; never
    /// stored in or recovered from the envelope. `attestation_tier` is one of
    /// the three reserved AAD dimensions (`kibo:attestation_tier`) bound at
    /// encrypt time; the AEAD tag verification fails if the re-supplied value
    /// differs from the one used at encrypt. Symmetric with `EncryptInput`.
    /// Source from deployment/project config (fixed per deployment, not per-op).
    pub attestation_tier: FfiAttestationTier,
    /// Encryption context — MUST be re-supplied by the caller; never read
    /// from the envelope (anti-envelope-substitution discipline).
    pub encryption_context: Vec<FfiKvPair>,
    /// The keys this application allows, from its own configuration and never from the
    /// platform or a stored envelope. Compared without the key version, so rotation keeps
    /// working. When set, any other key is refused before any token use or network call.
    /// Empty means no pin, and an open then uses whatever key the stored envelope names, so
    /// the SDK's client path must always set this and refuse to call without it.
    #[serde(default)]
    pub expected_key_refs: Vec<String>,
}

/// All inputs to `app_crypto_seal` (the client path of `k9o.crypto.encrypt` on a
/// cloud BYOK/HYOK project). One item; the SDK batches.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct AppSealInput {
    /// The customer KMS provider. Must match a compiled-in provider feature.
    pub provider: KmsProvider,
    /// Byok or Hyok (names the container's provider tag).
    pub posture: FfiPosture,
    /// The federated token for the customer's KMS, scoped to this key. Zeroized after use.
    pub kms_cred: FfiCredential,
    /// The customer KMS key version reference.
    pub key_ref: FfiKeyRef,
    /// Provider-specific initialization (region for AWS, address for Vault).
    pub provider_config: FfiProviderConfig,
    /// The project id, as the platform names it (`proj_…`). Bound into the AAD and the KMS
    /// encryption context.
    pub project_id: String,
    /// The crypt, `[a-z0-9-]{1,64}`. Bound into the AAD and the KMS encryption context.
    pub crypt: String,
    /// Optional caller context, UTF-8, at most 256 bytes. Bound into the AAD only, never
    /// into the KMS encryption context (it may be personal data).
    pub context: Option<String>,
    /// The plaintext.
    pub plaintext: Vec<u8>,
    /// The keys this application allows, from its own configuration and never from the
    /// platform or a stored envelope. Compared without the key version, so rotation keeps
    /// working. When set, any other key is refused before any token use or network call.
    /// Empty means no pin, and an open then uses whatever key the stored envelope names, so
    /// the SDK's client path must always set this and refuse to call without it.
    #[serde(default)]
    pub expected_key_refs: Vec<String>,
}

/// Which customer provider to exchange an identity token with, and how. These values come from
/// the application's own configuration, never from the platform.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Enum))]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum FfiFederationSpec {
    /// AWS STS `AssumeRoleWithWebIdentity`, scoped to the one key.
    Aws {
        /// The role to assume.
        role_arn: String,
        /// Surfaced in CloudTrail.
        session_name: String,
        /// The KMS key's region; selects the STS endpoint.
        region: String,
        /// The one key the session is scoped to.
        key_arn: String,
        /// Requested lifetime, 900 to 43200 seconds.
        duration_secs: u32,
    },
    /// GCP workload identity federation.
    Gcp {
        /// The workload identity pool provider's full resource name.
        audience: String,
    },
    /// Microsoft Entra workload identity federation.
    Azure {
        /// The Entra tenant.
        tenant_id: String,
        /// The app registration whose federated credential trusts the issuer.
        client_id: String,
        /// `https://vault.azure.net/.default` or `https://managedhsm.azure.net/.default`.
        scope: String,
    },
    /// Vault JWT login.
    Vault {
        /// The Vault address, `https` (`http` only on loopback), no trailing slash.
        vault_addr: String,
        /// The JWT auth mount.
        mount: String,
        /// The Vault role.
        role: String,
    },
}

/// All inputs to `acquire_kms_credential`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct FfiFederationInput {
    /// The provider and its configuration.
    pub spec: FfiFederationSpec,
    /// The identity token to exchange. Secret; wiped after use.
    pub identity_token: String,
    /// The host's clock, Unix seconds. The expiry of a GCP, Azure or Vault credential is this
    /// plus the provider's lifetime; AWS states its own.
    pub now_unix_secs: u64,
}

impl std::fmt::Debug for FfiFederationInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiFederationInput")
            .field("spec", &self.spec)
            .field("identity_token", &"<redacted>")
            .field("now_unix_secs", &self.now_unix_secs)
            .finish()
    }
}

/// Output of `app_crypto_seal`: a container v1, opaque to the SDK.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct AppSealOutput {
    /// The container v1 (`0x01 ‖ len ‖ W ‖ D`), the same format the server route emits.
    pub container: Vec<u8>,
}

/// All inputs to `app_crypto_open`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct AppOpenInput {
    /// The federated token for the customer's KMS. Zeroized after use.
    pub kms_cred: FfiCredential,
    /// Provider-specific initialization (region for AWS, address for Vault).
    pub provider_config: FfiProviderConfig,
    /// The project id the container was sealed for.
    pub project_id: String,
    /// The crypt it was sealed under.
    pub crypt: String,
    /// The context it was sealed with.
    pub context: Option<String>,
    /// A container v1 from `app_crypto_seal`.
    pub container: Vec<u8>,
    /// The keys this application allows, from its own configuration and never from the
    /// platform or a stored envelope. Compared without the key version, so rotation keeps
    /// working. When set, any other key is refused before any token use or network call.
    /// Empty means no pin, and an open then uses whatever key the stored envelope names, so
    /// the SDK's client path must always set this and refuse to call without it.
    #[serde(default)]
    pub expected_key_refs: Vec<String>,
}

/// Output of `app_crypto_open`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct AppOpenOutput {
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

/// Output of `zk_encrypt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct EncryptOutput {
    /// ZKFE self-describing envelope. Pass opaque to `zk_decrypt`.
    pub envelope: Vec<u8>,
}

/// Output of `zk_decrypt`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ffi-uniffi", derive(uniffi::Record))]
pub struct DecryptOutput {
    /// Recovered plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Context carried on a `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` (403).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureViolationContext {
    /// Which posture sub-dial failed: `"custody_posture"` or `"oracle_mode"`.
    pub dimension: String,
    /// Wire token of the rejected value.
    pub requested: String,
    /// Summary of the declared policy on this dimension.
    pub declared: String,
}

/// FFI error surface. `code` is the `K9O_*` wire string for platform-contract
/// errors, or `None` for upstream-KMS vendor failures (the customer's own
/// KMS returned a transport/auth error — a vendor failure is not a `K9O_*`
/// code). `context` carries dimension-specific detail for
/// `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION`.
#[derive(Debug)]
pub struct ZkFfiError {
    /// `K9O_*` wire code, or `None` for vendor errors.
    pub code: Option<String>,
    /// Human-readable detail (non-secret). For vendor errors, contains the
    /// upstream status and sanitised message.
    pub message: String,
    /// Present only for `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION`.
    pub context: Option<PostureViolationContext>,
}

impl std::error::Error for ZkFfiError {}

impl std::fmt::Display for ZkFfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code_str = self.code.as_deref().unwrap_or("UPSTREAM_KMS_ERROR");
        write!(f, "{code_str}: {}", self.message)?;
        if let Some(ctx) = &self.context {
            write!(
                f,
                " (dimension: {}, requested: {}, declared: {})",
                ctx.dimension, ctx.requested, ctx.declared
            )?;
        }
        Ok(())
    }
}

/// uniffi-facing error type for `zk_encrypt` / `zk_decrypt` native exports.
///
/// `ZkFfiError` is a struct and cannot directly implement `uniffi::Error`
/// (which requires an enum). This enum flattens the struct into three
/// variants — platform error, upstream KMS error, and posture floor
/// violation — that uniffi-generated Swift/Kotlin/Python code can pattern-match.
/// Converted from `ZkFfiError` at the `ffi_uniffi` boundary.
#[cfg(feature = "ffi-uniffi")]
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZkFfiUniffiError {
    // The text field is `detail`, never `message`: the Kotlin binding makes each variant a
    // subclass of `Exception`, whose own `message` it would clash with, and the binding
    // would not compile.
    /// A platform error with a `K9O_*` wire code.
    #[error("{code}: {detail}")]
    Platform { code: String, detail: String },
    /// The customer's KMS returned an error. No platform code is assigned
    /// (upstream vendor failures are not `K9O_*` codes).
    #[error("upstream KMS error: {detail}")]
    UpstreamKms { detail: String },
    /// The requested posture or oracle mode is below the project-declared
    /// policy floor (`K9O_CRYPTO_POSTURE_FLOOR_VIOLATION`).
    #[error(
        "{code}: {detail} (dimension: {dimension}, requested: {requested}, declared: {declared})"
    )]
    PostureViolation {
        code: String,
        detail: String,
        dimension: String,
        requested: String,
        declared: String,
    },
}

#[cfg(feature = "ffi-uniffi")]
impl From<ZkFfiError> for ZkFfiUniffiError {
    fn from(e: ZkFfiError) -> Self {
        let ZkFfiError {
            code,
            message,
            context,
        } = e;
        match (code, context) {
            (None, _) => Self::UpstreamKms { detail: message },
            (Some(code), Some(ctx)) => Self::PostureViolation {
                code,
                detail: message,
                dimension: ctx.dimension,
                requested: ctx.requested,
                declared: ctx.declared,
            },
            (Some(code), None) => Self::Platform {
                code,
                detail: message,
            },
        }
    }
}

#[cfg(all(test, feature = "ffi-uniffi"))]
mod uniffi_error_tests {
    use super::*;

    /// The binding's text field is `detail` (a Kotlin `Exception` subclass can't declare its
    /// own `message`); the conversion carries the core error's message into it unchanged.
    #[test]
    fn the_uniffi_error_carries_the_message_as_detail() {
        let err = |code: Option<&str>, context| ZkFfiError {
            code: code.map(str::to_owned),
            message: "the text".to_owned(),
            context,
        };
        match ZkFfiUniffiError::from(err(None, None)) {
            ZkFfiUniffiError::UpstreamKms { detail } => assert_eq!(detail, "the text"),
            other => panic!("{other:?}"),
        }
        match ZkFfiUniffiError::from(err(Some("K9O_X"), None)) {
            ZkFfiUniffiError::Platform { code, detail } => {
                assert_eq!((code.as_str(), detail.as_str()), ("K9O_X", "the text"));
            }
            other => panic!("{other:?}"),
        }
        let ctx = PostureViolationContext {
            dimension: "oracle_mode".to_owned(),
            requested: "r".to_owned(),
            declared: "d".to_owned(),
        };
        let e = ZkFfiUniffiError::from(err(Some("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION"), Some(ctx)));
        assert_eq!(
            e.to_string(),
            "K9O_CRYPTO_POSTURE_FLOOR_VIOLATION: the text (dimension: oracle_mode, requested: r, declared: d)"
        );
    }
}
