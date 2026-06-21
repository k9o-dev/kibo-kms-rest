//! Core `zk_encrypt` / `zk_decrypt` logic.
//!
//! Orchestrates the posture-seam resolution → provider dispatch → canonical
//! envelope assembly flow. All ciphertexts use the single `kibo_crypto_core::envelope`
//! (`b"KIBO"`) framing; the prior `b"ZKFE"` private format has been removed.
//!
//! # Canonical envelope layout
//!
//! - `LocalEnvelope`: nonce field = DEK-seal nonce (12B); ciphertext slot =
//!   `[kms_ct_len(4B BE) || kms_ciphertext || data_ct+tag]`.
//! - `CustomerKmsOracle`: nonce field = zero (placeholder; no local AEAD);
//!   ciphertext slot = raw KMS ciphertext.
//!
//! # Strategy re-supply at decrypt
//!
//! Because strategy is not embedded in the canonical envelope header (it is an
//! `AadContext` dimension bound into the KMS AAD), `DecryptInput` carries a
//! required `strategy` field. Wrong re-supply causes KMS AAD mismatch → decrypt
//! fails at the KMS layer.
//!
//! # Strict-ZK invariant
//!
//! `kms_cred` is a customer KMS credential only. This module contains no
//! platform-KEK parameter, no code path that accepts one, and no way to call
//! the provider with anything other than the caller-supplied `FfiCredential`.
//! The `PlatformManaged` posture is structurally absent from `EncryptInput.posture`.

use crate::envelope::parse_local_ciphertext_slot;
use crate::types::{
    DecryptInput, DecryptOutput, EncryptInput, EncryptOutput, FfiAllowedOracleModes,
    FfiAttestationTier, FfiCredential, FfiMinPosture, FfiOracleMode, FfiPosture, FfiPosturePolicy,
    FfiStrategy, KmsProvider, PostureViolationContext, ZkFfiError,
};
use kibo_crypto_core::dek::{DataEncryptionKey, DekError};
use kibo_crypto_core::envelope::{
    EnvelopeError, ProviderTag, NONCE_SIZE_BYTES,
    build as build_canonical_envelope,
};
use kibo_crypto_core::types::KeyVersionRef;
use kibo_kms_rest::auth::FederatedToken;
use kibo_kms_rest::envelope::{aad_slice, ciphertext_slice, nonce_slice, read_header};
use kibo_kms_rest::error::KmsRestError;
use kibo_kms_rest::provider::{AadContext, AttestationTier, KmsRestProvider};
use kibo_kms_rest::strategy::{
    CryptoPosturePolicy, OracleMode, OracleModeSet, PayloadSizing, Posture, Strategy,
    enforce_crypto_posture_floor, resolve_oracle_mode, resolve_strategy,
};

// ── type conversions ────────────────────────────────────────────────────────

fn to_posture(p: FfiPosture) -> Posture {
    match p {
        FfiPosture::Byok => Posture::Byok,
        FfiPosture::Hyok => Posture::Hyok,
    }
}

fn to_strategy(s: FfiStrategy) -> Strategy {
    match s {
        FfiStrategy::LocalEnvelope => Strategy::LocalEnvelope,
        FfiStrategy::CustomerKmsOracle => Strategy::CustomerKmsOracle,
    }
}

fn to_oracle_mode(m: FfiOracleMode) -> OracleMode {
    match m {
        FfiOracleMode::Brokered => OracleMode::Brokered,
        FfiOracleMode::Direct => OracleMode::Direct,
    }
}

fn to_attestation_tier(t: FfiAttestationTier) -> AttestationTier {
    match t {
        FfiAttestationTier::Software => AttestationTier::Software,
        FfiAttestationTier::HardwareBacked => AttestationTier::HardwareBacked,
        FfiAttestationTier::Confidential => AttestationTier::Confidential,
    }
}

fn to_credential(c: FfiCredential) -> FederatedToken {
    FederatedToken::new(c.secret, c.expires_at_unix_secs)
}

fn to_key_version_ref(k: &crate::types::FfiKeyRef) -> Result<KeyVersionRef, ZkFfiError> {
    if k.external_ref.len() > kibo_crypto_core::types::MAX_EXTERNAL_REF_LEN {
        return Err(ZkFfiError {
            code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
            message: format!(
                "external_ref exceeds maximum length of {} bytes",
                kibo_crypto_core::types::MAX_EXTERNAL_REF_LEN
            ),
            context: None,
        });
    }
    Ok(KeyVersionRef {
        version: k.version,
        external_ref: k.external_ref.clone(),
    })
}

fn to_aad_context(
    strategy: Strategy,
    attestation_tier: FfiAttestationTier,
    encryption_context: Vec<crate::types::FfiKvPair>,
) -> AadContext {
    AadContext {
        version: 1,
        strategy,
        attestation_tier: to_attestation_tier(attestation_tier),
        encryption_context: encryption_context.into_iter().map(|p| (p.key, p.value)).collect(),
        // The FFI/SDK input contract does not yet thread the project id, so it is
        // unbound here.
        project_id: None,
    }
}

fn to_posture_policy(policy: Option<FfiPosturePolicy>) -> CryptoPosturePolicy {
    let Some(p) = policy else {
        return CryptoPosturePolicy::default();
    };
    let min_custody_posture = match p.min_custody_posture {
        None | Some(FfiMinPosture::PlatformManaged) => Posture::PlatformManaged,
        Some(FfiMinPosture::Byok) => Posture::Byok,
        Some(FfiMinPosture::Hyok) => Posture::Hyok,
    };
    let allowed_oracle_modes = match p.allowed_oracle_modes {
        None => OracleModeSet::any(),
        Some(FfiAllowedOracleModes { brokered: true, direct: true }) => OracleModeSet::any(),
        Some(FfiAllowedOracleModes { brokered: true, direct: false }) => {
            OracleModeSet::brokered_only()
        }
        Some(FfiAllowedOracleModes { brokered: false, direct: true }) => {
            OracleModeSet::direct_only()
        }
        Some(FfiAllowedOracleModes { brokered: false, direct: false }) => {
            OracleModeSet::brokered_only()
        }
    };
    CryptoPosturePolicy {
        min_custody_posture,
        allowed_oracle_modes,
    }
}

// ── canonical ProviderTag ↔ (FfiPosture, KmsProvider) ───────────────────────

/// Map `(posture, provider)` to the canonical `ProviderTag` used in the
/// `b"KIBO"` envelope header.
///
/// HYOK + HashiCorp Vault has no assigned `ProviderTag` discriminant in
/// `kibo_crypto_core::envelope` yet. Returns `K9O_CRYPTO_STRATEGY_UNAVAILABLE`
/// until that variant is assigned.
fn to_canonical_provider_tag(
    posture: FfiPosture,
    provider: KmsProvider,
) -> Result<ProviderTag, ZkFfiError> {
    match (posture, provider) {
        (FfiPosture::Byok, KmsProvider::AwsKms) => Ok(ProviderTag::BYOKAwsKms),
        (FfiPosture::Byok, KmsProvider::GcpKms) => Ok(ProviderTag::BYOKGcpCloudKms),
        (FfiPosture::Byok, KmsProvider::AzureKv) => Ok(ProviderTag::BYOKAzureKeyVault),
        (FfiPosture::Byok, KmsProvider::HashicorpVault) => Ok(ProviderTag::BYOKHashicorpVault),
        (FfiPosture::Hyok, KmsProvider::AwsKms) => Ok(ProviderTag::HYOKAwsKmsCustomKeyStore),
        (FfiPosture::Hyok, KmsProvider::GcpKms) => Ok(ProviderTag::HYOKGcpCloudKmsHsm),
        (FfiPosture::Hyok, KmsProvider::AzureKv) => Ok(ProviderTag::HYOKAzureManagedHsm),
        (FfiPosture::Hyok, KmsProvider::HashicorpVault) => Err(ZkFfiError {
            code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
            message: "HYOK + HashiCorp Vault Transit has no canonical ProviderTag discriminant \
                      in kibo_crypto_core::envelope yet"
                .to_string(),
            context: None,
        }),
    }
}

/// Derive the `KmsProvider` required at decrypt from the canonical
/// `ProviderTag` embedded in the envelope header.
fn kms_provider_from_tag(tag: ProviderTag) -> Result<KmsProvider, ZkFfiError> {
    match tag {
        ProviderTag::BYOKAwsKms | ProviderTag::HYOKAwsKmsCustomKeyStore => {
            Ok(KmsProvider::AwsKms)
        }
        ProviderTag::BYOKGcpCloudKms | ProviderTag::HYOKGcpCloudKmsHsm => {
            Ok(KmsProvider::GcpKms)
        }
        ProviderTag::BYOKAzureKeyVault | ProviderTag::HYOKAzureManagedHsm => {
            Ok(KmsProvider::AzureKv)
        }
        ProviderTag::BYOKHashicorpVault | ProviderTag::HYOKHashicorpVaultTransit => {
            Ok(KmsProvider::HashicorpVault)
        }
        ProviderTag::PlatformManaged => Err(ZkFfiError {
            code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
            message: "envelope carries PlatformManaged provider tag; \
                      kibo-kms-rest-ffi is ZK-only (strict-ZK invariant)"
                .to_string(),
            context: None,
        }),
    }
}

// ── error mapping ────────────────────────────────────────────────────────────

fn map_kms_error(e: KmsRestError) -> ZkFfiError {
    match &e {
        KmsRestError::PostureFloorViolation {
            dimension,
            requested,
            declared,
        } => ZkFfiError {
            code: Some("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION".to_string()),
            message: e.to_string(),
            context: Some(PostureViolationContext {
                dimension: dimension.as_wire_token().to_string(),
                requested: requested.to_string(),
                declared: declared.clone(),
            }),
        },
        KmsRestError::UpstreamKms { .. } => ZkFfiError {
            code: None,
            message: e.to_string(),
            context: None,
        },
        _ => ZkFfiError {
            code: e.wire_code().map(|c| c.as_str().to_string()),
            message: e.to_string(),
            context: None,
        },
    }
}

fn map_envelope_error(e: EnvelopeError) -> ZkFfiError {
    ZkFfiError {
        code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
        message: e.to_string(),
        context: None,
    }
}

fn map_dek_error(e: DekError) -> ZkFfiError {
    ZkFfiError {
        code: Some("K9O_ENVELOPE_INTEGRITY_FAILURE".to_string()),
        message: e.to_string(),
        context: None,
    }
}

// ── provider dispatch (compile-time feature gate) ───────────────────────────

fn make_provider(
    provider: KmsProvider,
    key_ref: &crate::types::FfiKeyRef,
    config: &crate::types::FfiProviderConfig,
) -> Result<Box<dyn KmsRestProvider>, ZkFfiError> {
    build_provider_impl(provider, key_ref, config)
}

/// `K9O_CRYPTO_STRATEGY_UNAVAILABLE` — the requested provider's `kms-*` feature
/// is not compiled into this build artifact (a single-provider build asked for a
/// different provider). A BUILD-ALL-PROVIDERS artifact never hits this.
fn provider_not_compiled(provider: KmsProvider) -> ZkFfiError {
    ZkFfiError {
        code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
        message: format!(
            "provider `{}` is not compiled into this build artifact",
            provider.as_wire_token()
        ),
        context: None,
    }
}

/// Construct the REST-direct provider for the **runtime-selected** `provider`.
///
/// Each arm is `#[cfg]`-gated on its `kms-*` feature, so a BUILD-ALL-PROVIDERS
/// artifact (all four features) dispatches on the caller-supplied `provider`,
/// while a single-provider build keeps only its one arm and rejects any other
/// provider via the catch-all ([`provider_not_compiled`]).
fn build_provider_impl(
    provider: KmsProvider,
    key_ref: &crate::types::FfiKeyRef,
    config: &crate::types::FfiProviderConfig,
) -> Result<Box<dyn KmsRestProvider>, ZkFfiError> {
    match provider {
        #[cfg(feature = "kms-aws")]
        KmsProvider::AwsKms => {
            use kibo_kms_rest::provider::aws::AwsKmsRest;
            let region = config
                .aws_region
                .clone()
                .or_else(|| aws_region_from_arn(&key_ref.external_ref).map(str::to_owned))
                .ok_or_else(|| ZkFfiError {
                    code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
                    message: "AWS region not provided and not derivable from key_ref.external_ref; \
                        supply FfiProviderConfig.aws_region or use a full ARN"
                        .to_string(),
                    context: None,
                })?;
            Ok(Box::new(AwsKmsRest::new(key_ref.external_ref.clone(), region)))
        }
        #[cfg(feature = "kms-gcp")]
        KmsProvider::GcpKms => {
            use kibo_kms_rest::provider::gcp::GcpKmsRest;
            Ok(Box::new(GcpKmsRest::new(key_ref.external_ref.clone())))
        }
        #[cfg(feature = "kms-azure")]
        KmsProvider::AzureKv => {
            use kibo_kms_rest::provider::azure::AzureKeyVaultRest;
            let (vault_url, key_name, key_version) =
                parse_azure_versioned_key_id(&key_ref.external_ref)?;
            Ok(Box::new(AzureKeyVaultRest::new(
                vault_url.to_owned(),
                key_name.to_owned(),
                key_version.to_owned(),
            )))
        }
        #[cfg(feature = "kms-vault")]
        KmsProvider::HashicorpVault => {
            use kibo_kms_rest::provider::vault::VaultTransitRest;
            let address = config.vault_address.clone().ok_or_else(|| ZkFfiError {
                code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
                message: "FfiProviderConfig.vault_address is required for Vault provider"
                    .to_string(),
                context: None,
            })?;
            let key_name = vault_key_name_from_ref(&key_ref.external_ref);
            Ok(Box::new(VaultTransitRest::new(address, key_name.to_owned())))
        }
        // Any provider whose `kms-*` feature is not compiled into this build.
        #[allow(unreachable_patterns)]
        other => Err(provider_not_compiled(other)),
    }
}

// ── provider-specific reference parsers ─────────────────────────────────────

#[cfg(feature = "kms-aws")]
fn aws_region_from_arn(arn: &str) -> Option<&str> {
    arn.split(':').nth(3).filter(|r| !r.is_empty())
}

#[cfg(feature = "kms-azure")]
fn parse_azure_versioned_key_id(id: &str) -> Result<(&str, &str, &str), ZkFfiError> {
    let bad = || ZkFfiError {
        code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
        message: format!(
            "Azure key_ref.external_ref must be a versioned key URL \
            (`https://<vault>.vault.azure.net/keys/<key>/<ver>`), got: {id}"
        ),
        context: None,
    };
    let path_start = {
        let mut count = 0;
        let mut idx = None;
        for (i, b) in id.bytes().enumerate() {
            if b == b'/' {
                count += 1;
                if count == 3 {
                    idx = Some(i);
                    break;
                }
            }
        }
        idx.ok_or_else(bad)?
    };
    let vault_url = &id[..path_start];
    let path = &id[path_start + 1..];
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() != 3 || parts[0] != "keys" {
        return Err(bad());
    }
    Ok((vault_url, parts[1], parts[2]))
}

#[cfg(feature = "kms-vault")]
fn vault_key_name_from_ref(external_ref: &str) -> &str {
    // Take the segment after the last `/` (or the whole ref if unpathed), then
    // strip any trailing `:version` — applied in both cases so a bare `mykey:3`
    // resolves to `mykey`, not just a path-qualified `transit/mykey:3`.
    let after_slash = external_ref
        .rsplit_once('/')
        .map_or(external_ref, |(_, after)| after);
    after_slash
        .split_once(':')
        .map_or(after_slash, |(key, _)| key)
}

// ── zk_encrypt ──────────────────────────────────────────────────────────────

/// Encrypt `plaintext` under the customer KMS using canonical `b"KIBO"` framing.
///
/// # Posture resolution order
///
/// 1. `resolve_strategy(posture, requested_strategy, sizing)` → effective `Strategy`.
/// 2. `resolve_oracle_mode(posture, requested_oracle_mode)` → effective `OracleMode`.
/// 3. `enforce_crypto_posture_floor(policy, posture, oracle_mode)` — 403
///    `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` if the project's declared floor is
///    breached; carries `{ dimension, requested, declared }`.
/// 4. Provider KMS REST call(s) + canonical envelope assembly.
pub async fn zk_encrypt(input: EncryptInput) -> Result<EncryptOutput, ZkFfiError> {
    let posture = to_posture(input.posture);
    let key_version_ref = to_key_version_ref(&input.key_ref)?;

    let sizing = PayloadSizing {
        payload_bytes: input.plaintext.len(),
        aad_bytes: 0,
        kms_limit_bytes: kms_plaintext_limit(input.provider),
    };
    let resolved_strategy =
        resolve_strategy(posture, input.strategy.map(to_strategy), sizing)
            .map_err(map_kms_error)?;

    let resolved_oracle =
        resolve_oracle_mode(posture, input.oracle_mode.map(to_oracle_mode))
            .map_err(map_kms_error)?;

    let policy = to_posture_policy(input.posture_policy);
    enforce_crypto_posture_floor(&policy, posture, resolved_oracle).map_err(map_kms_error)?;

    let canonical_tag = to_canonical_provider_tag(input.posture, input.provider)?;
    let provider = make_provider(input.provider, &input.key_ref, &input.provider_config)?;
    let token = to_credential(input.kms_cred);
    let aad_ctx = to_aad_context(
        resolved_strategy,
        input.attestation_tier,
        input.encryption_context,
    );

    let envelope_bytes = match resolved_strategy {
        Strategy::LocalEnvelope => {
            encrypt_local_envelope(
                provider.as_ref(),
                &token,
                &aad_ctx,
                canonical_tag,
                &key_version_ref,
                &input.plaintext,
            )
            .await?
        }
        Strategy::CustomerKmsOracle => {
            encrypt_oracle(
                provider.as_ref(),
                &token,
                &aad_ctx,
                canonical_tag,
                &key_version_ref,
                &input.plaintext,
            )
            .await?
        }
    };

    Ok(EncryptOutput { envelope: envelope_bytes })
}

/// `LocalEnvelope` encrypt via the canonical `b"KIBO"` framing.
///
/// 1. Generate 32-byte DEK.
/// 2. Provider wraps the DEK → `kms_ciphertext`.
/// 3. Build a sentinel envelope (empty ciphertext) to derive the header-as-AAD
///    bytes (everything before the nonce: `aad_slice()`).
/// 4. Seal `plaintext` under the DEK with header-as-AAD →
///    `dek_output = [nonce(12B) || ct+tag]`.
/// 5. Assemble canonical envelope: nonce field = first 12 bytes of `dek_output`;
///    ciphertext slot = `[kms_ct_len(4B) || kms_ciphertext || data_ct+tag]`.
async fn encrypt_local_envelope(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    aad_ctx: &AadContext,
    canonical_tag: ProviderTag,
    key_ref: &KeyVersionRef,
    plaintext: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let dek = DataEncryptionKey::generate();

    let kms_ciphertext = provider
        .encrypt(token, dek.key_bytes(), aad_ctx)
        .await
        .map_err(map_kms_error)?;

    // Build a sentinel envelope (zero nonce, empty ciphertext slot) solely to
    // derive the canonical header bytes used as AAD for the DEK seal.
    let sentinel =
        build_canonical_envelope(canonical_tag, key_ref, &[0u8; NONCE_SIZE_BYTES], &[]);
    let header_aad = aad_slice(&sentinel.envelope)
        .map_err(map_envelope_error)?
        .to_vec();

    // dek.encrypt() returns [nonce(12B) || ct+tag].
    let dek_output = dek.encrypt(plaintext, &header_aad).map_err(map_dek_error)?;
    let data_nonce: [u8; NONCE_SIZE_BYTES] = dek_output[..NONCE_SIZE_BYTES]
        .try_into()
        .expect("dek.encrypt() always prepends a 12-byte nonce");
    let data_ct_tag = &dek_output[NONCE_SIZE_BYTES..];

    // Ciphertext slot: kms_ct_len(4B BE) || kms_ciphertext || data_ct+tag.
    let kms_ct_len = (kms_ciphertext.len() as u32).to_be_bytes();
    let mut ciphertext_slot =
        Vec::with_capacity(4 + kms_ciphertext.len() + data_ct_tag.len());
    ciphertext_slot.extend_from_slice(&kms_ct_len);
    ciphertext_slot.extend_from_slice(&kms_ciphertext);
    ciphertext_slot.extend_from_slice(data_ct_tag);

    let wrapped = build_canonical_envelope(canonical_tag, key_ref, &data_nonce, &ciphertext_slot);
    Ok(wrapped.envelope.clone())
}

/// `CustomerKmsOracle` encrypt: provider encrypts the full plaintext.
/// Nonce field in the canonical header = zeros (placeholder; no local AEAD).
async fn encrypt_oracle(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    aad_ctx: &AadContext,
    canonical_tag: ProviderTag,
    key_ref: &KeyVersionRef,
    plaintext: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let kms_ciphertext = provider
        .encrypt(token, plaintext, aad_ctx)
        .await
        .map_err(map_kms_error)?;

    let wrapped = build_canonical_envelope(
        canonical_tag,
        key_ref,
        &[0u8; NONCE_SIZE_BYTES],
        &kms_ciphertext,
    );
    Ok(wrapped.envelope.clone())
}

// ── zk_decrypt ──────────────────────────────────────────────────────────────

/// Decrypt a canonical `b"KIBO"` envelope produced by `zk_encrypt`.
///
/// The `strategy`, `attestation_tier`, and `encryption_context` MUST all be
/// re-supplied by the caller (none are stored in the canonical envelope):
/// - `strategy` — not in envelope header (AAD-bound dimension).
/// - `attestation_tier` — not in envelope (AAD-bound; omit and AEAD decrypt
///   fails).
/// - `encryption_context` — not in envelope (anti-substitution discipline).
pub async fn zk_decrypt(input: DecryptInput) -> Result<DecryptOutput, ZkFfiError> {
    // Parse canonical envelope header → ProviderTag + KeyVersionRef.
    let (envelope_provider_tag, key_ref) =
        read_header(&input.envelope).map_err(map_envelope_error)?;

    // Derive the KmsProvider enum from the envelope's ProviderTag and validate
    // against the compiled-in provider.
    let kms_provider = kms_provider_from_tag(envelope_provider_tag)?;
    let key_ref_ffi = crate::types::FfiKeyRef {
        version: key_ref.version,
        external_ref: key_ref.external_ref.clone(),
    };
    let provider = make_provider(kms_provider, &key_ref_ffi, &input.provider_config)?;
    let token = to_credential(input.kms_cred);

    // AadContext: strategy re-supplied by caller (not embedded in envelope);
    // attestation_tier and encryption_context re-supplied per AAD discipline.
    let aad_ctx = AadContext {
        version: 1,
        strategy: to_strategy(input.strategy),
        attestation_tier: to_attestation_tier(input.attestation_tier),
        encryption_context: input.encryption_context.into_iter().map(|p| (p.key, p.value)).collect(),
        // FFI input does not yet carry the project id.
        project_id: None,
    };

    let plaintext = match input.strategy {
        FfiStrategy::LocalEnvelope => {
            decrypt_local_envelope(
                provider.as_ref(),
                &token,
                &aad_ctx,
                &input.envelope,
            )
            .await?
        }
        FfiStrategy::CustomerKmsOracle => {
            decrypt_oracle(provider.as_ref(), &token, &aad_ctx, &input.envelope).await?
        }
    };

    Ok(DecryptOutput { plaintext })
}

/// `LocalEnvelope` decrypt from a canonical `b"KIBO"` envelope.
///
/// 1. `read_header()` already validated magic/version/provider (called by
///    `zk_decrypt`).
/// 2. `aad_slice()` → header bytes (same as at encrypt).
/// 3. `nonce_slice()` → 12-byte data nonce.
/// 4. `ciphertext_slice()` → `[kms_ct_len || kms_ciphertext || data_ct+tag]`.
/// 5. Provider unwraps `kms_ciphertext` → DEK bytes.
/// 6. Reconstruct `[data_nonce || data_ct+tag]` and `dek.decrypt()` → plaintext.
async fn decrypt_local_envelope(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    aad_ctx: &AadContext,
    envelope: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let header_aad = aad_slice(envelope).map_err(map_envelope_error)?.to_vec();
    let data_nonce = nonce_slice(envelope).map_err(map_envelope_error)?;
    let ciphertext_slot = ciphertext_slice(envelope).map_err(map_envelope_error)?;

    let (kms_ciphertext, data_ct_tag) = parse_local_ciphertext_slot(ciphertext_slot)?;

    let dek_bytes = provider
        .decrypt(token, kms_ciphertext, aad_ctx)
        .await
        .map_err(map_kms_error)?;

    let dek = DataEncryptionKey::from_bytes(&*dek_bytes).map_err(map_dek_error)?;

    // dek.decrypt() expects [nonce(12B) || ct+tag] as the envelope argument.
    let mut dek_envelope = Vec::with_capacity(data_nonce.len() + data_ct_tag.len());
    dek_envelope.extend_from_slice(data_nonce);
    dek_envelope.extend_from_slice(data_ct_tag);

    let plaintext = dek.decrypt(&dek_envelope, &header_aad).map_err(map_dek_error)?;
    Ok(plaintext)
}

/// `CustomerKmsOracle` decrypt: KMS ciphertext is the entire ciphertext slot.
async fn decrypt_oracle(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    aad_ctx: &AadContext,
    envelope: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let kms_ciphertext = ciphertext_slice(envelope).map_err(map_envelope_error)?;
    let plaintext = provider
        .decrypt(token, kms_ciphertext, aad_ctx)
        .await
        .map_err(map_kms_error)?;
    Ok(plaintext.to_vec())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn kms_plaintext_limit(provider: KmsProvider) -> usize {
    match provider {
        KmsProvider::AwsKms => 4096,
        KmsProvider::GcpKms => 64 * 1024,
        KmsProvider::AzureKv => 2048,
        KmsProvider::HashicorpVault => 32 * 1024,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use kibo_kms_rest::error::PostureDimension;

    #[cfg(feature = "kms-aws")]
    #[test]
    fn aws_region_extraction() {
        assert_eq!(
            aws_region_from_arn("arn:aws:kms:us-east-1:123456789:key/abc"),
            Some("us-east-1")
        );
        assert_eq!(
            aws_region_from_arn("arn:aws:kms:eu-west-1:987654321:key/xyz"),
            Some("eu-west-1")
        );
        assert_eq!(aws_region_from_arn("not-an-arn"), None);
    }

    #[cfg(feature = "kms-azure")]
    #[test]
    fn azure_versioned_key_id_parsing() {
        let id = "https://myvault.vault.azure.net/keys/mykey/abc123";
        let (vault_url, key_name, key_version) = parse_azure_versioned_key_id(id).unwrap();
        assert_eq!(vault_url, "https://myvault.vault.azure.net");
        assert_eq!(key_name, "mykey");
        assert_eq!(key_version, "abc123");
    }

    #[cfg(feature = "kms-azure")]
    #[test]
    fn azure_versioned_key_id_invalid() {
        assert!(parse_azure_versioned_key_id("not-a-url").is_err());
        assert!(parse_azure_versioned_key_id("https://vault.azure.net/notkeys/k/v").is_err());
    }

    #[cfg(feature = "kms-vault")]
    #[test]
    fn vault_key_name_extraction() {
        assert_eq!(vault_key_name_from_ref("transit/mykey:3"), "mykey");
        assert_eq!(vault_key_name_from_ref("transit/mykey"), "mykey");
        assert_eq!(vault_key_name_from_ref("mykey:3"), "mykey");
    }

    #[test]
    fn kms_plaintext_limits_are_positive() {
        for p in [
            KmsProvider::AwsKms,
            KmsProvider::GcpKms,
            KmsProvider::AzureKv,
            KmsProvider::HashicorpVault,
        ] {
            assert!(kms_plaintext_limit(p) > 0);
        }
    }

    #[test]
    fn posture_floor_violation_context_propagated() {
        let e = KmsRestError::PostureFloorViolation {
            dimension: PostureDimension::CustodyPosture,
            requested: "byok",
            declared: "min hyok".to_string(),
        };
        let ffi_e = map_kms_error(e);
        assert_eq!(
            ffi_e.code.as_deref(),
            Some("K9O_CRYPTO_POSTURE_FLOOR_VIOLATION")
        );
        let ctx = ffi_e.context.unwrap();
        assert_eq!(ctx.dimension, "custody_posture");
        assert_eq!(ctx.requested, "byok");
        assert_eq!(ctx.declared, "min hyok");
    }

    #[test]
    fn upstream_kms_error_has_no_platform_code() {
        let e = KmsRestError::UpstreamKms {
            provider: "aws",
            status: Some(403),
            detail: "AccessDenied".to_string(),
        };
        let ffi_e = map_kms_error(e);
        assert!(ffi_e.code.is_none());
        assert!(ffi_e.message.contains("AccessDenied"));
    }

    #[test]
    fn canonical_envelope_header_survives_round_trip() {
        use kibo_crypto_core::types::KeyVersionRef;
        let key_ref = KeyVersionRef {
            version: 7,
            external_ref: "arn:aws:kms:us-east-1:123:key/abc".to_string(),
        };
        let nonce = [0xABu8; NONCE_SIZE_BYTES];
        let ciphertext = b"dummy-ciphertext+tag-at-least-16-chars";
        let wrapped = build_canonical_envelope(ProviderTag::BYOKAwsKms, &key_ref, &nonce, ciphertext);
        let (tag, parsed_ref) = read_header(&wrapped.envelope).unwrap();
        assert_eq!(tag, ProviderTag::BYOKAwsKms);
        assert_eq!(parsed_ref.version, 7);
        assert_eq!(parsed_ref.external_ref, "arn:aws:kms:us-east-1:123:key/abc");
    }

    #[test]
    fn canonical_envelope_rejects_non_kibo_magic() {
        use kibo_crypto_core::types::KeyVersionRef;
        let key_ref = KeyVersionRef { version: 1, external_ref: String::new() };
        let mut wrapped =
            build_canonical_envelope(ProviderTag::BYOKAwsKms, &key_ref, &[0u8; 12], &[0u8; 16]);
        wrapped.envelope[0] = b'Z'; // corrupt magic
        let err = read_header(&wrapped.envelope).map_err(map_envelope_error).unwrap_err();
        assert_eq!(err.code.as_deref(), Some("K9O_ENVELOPE_HEADER_MALFORMED"));
    }

    #[test]
    fn byok_vault_maps_to_canonical_tag() {
        let tag =
            to_canonical_provider_tag(FfiPosture::Byok, KmsProvider::HashicorpVault).unwrap();
        assert_eq!(tag, ProviderTag::BYOKHashicorpVault);
    }

    #[test]
    fn hyok_vault_returns_unavailable() {
        let err =
            to_canonical_provider_tag(FfiPosture::Hyok, KmsProvider::HashicorpVault).unwrap_err();
        assert_eq!(err.code.as_deref(), Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE"));
    }

    #[test]
    fn platform_managed_tag_rejected_at_decrypt_routing() {
        let err = kms_provider_from_tag(ProviderTag::PlatformManaged).unwrap_err();
        assert_eq!(err.code.as_deref(), Some("K9O_ENVELOPE_HEADER_MALFORMED"));
    }
}
