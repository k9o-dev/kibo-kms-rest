//! The client path of `k9o.crypto.*`:
//! on a cloud BYOK/HYOK project the SDK seals and opens **in the caller's process**, with a DEK
//! wrapped by the customer's own KMS, and emits the **same container v1** as the server route.
//!
//! - `app_crypto_seal`: a fresh DEK per item; the customer's KMS wraps it (the only remote
//!   call, with the federated token); the data is sealed in-process under the shared AAD
//!   (`kibo_crypto_core::app_container`). The plaintext and the unwrapped DEK never leave.
//! - `app_crypto_open`: the container's wrapped-DEK header names the provider and key version;
//!   the customer's KMS unwraps; the data opens in-process. A platform-tagged container is for
//!   the server route and does not open here.
//! - **The KMS encryption context** binds the project (`kibo:project_id`), the domain and the
//!   crypt, so the customer's KMS refuses a DEK replayed into another project or crypt. The
//!   caller's `context` is bound into the AAD only, never sent to the KMS (it may be personal
//!   data, and KMS logs record the encryption context).
//! - **Same shapes as the server route:** crypt `[a-z0-9-]{1,64}`, context at most 256 bytes,
//!   plaintext at most 64 KiB; every cannot-open is `K9O_ENVELOPE_INTEGRITY_FAILURE`.

use kibo_crypto_core::app_container::{
    AAD_DOMAIN, canonical_aad, context_bytes, frame, open_data, seal_data, unframe, valid_crypt,
};
use kibo_crypto_core::dek::DataEncryptionKey;
use kibo_crypto_core::envelope::{
    NONCE_SIZE_BYTES, ProviderTag, build as build_canonical_envelope,
};
use kibo_crypto_core::types::KeyVersionRef;
use kibo_kms_rest::auth::FederatedToken;
use kibo_kms_rest::envelope::{ciphertext_slice, read_header};
use kibo_kms_rest::provider::{AadContext, AttestationTier, KmsRestProvider};
use kibo_kms_rest::strategy::Strategy;

use crate::engine::{
    azure_open_refused, azure_tag_mismatch, check_azure_seal_route, check_expected_key,
    kms_provider_from_tag, make_provider, map_dek_error, map_envelope_error, map_kms_error,
    to_canonical_provider_tag, to_credential, to_key_version_ref,
};
use crate::types::{
    AppOpenInput, AppOpenOutput, AppSealInput, AppSealOutput, FfiKeyRef, ZkFfiError,
};

/// Plaintext bytes per item: the server route's limit, so the contract is one.
pub const MAX_ITEM_BYTES: usize = 64 * 1024;

fn err(code: &str, message: impl Into<String>) -> ZkFfiError {
    ZkFfiError {
        code: Some(code.to_owned()),
        message: message.into(),
        context: None,
    }
}

fn integrity_failure() -> ZkFfiError {
    err(
        "K9O_ENVELOPE_INTEGRITY_FAILURE",
        "Envelope integrity verification failed.",
    )
}

/// The crypt and context shapes, and the project id present; `context`'s AAD bytes.
fn check_binding<'a>(
    project_id: &str,
    crypt: &str,
    context: Option<&'a str>,
) -> Result<&'a [u8], ZkFfiError> {
    if project_id.is_empty() {
        return Err(err("K9O_INVALID_FIELD_VALUE", "`project_id` is required"));
    }
    if !valid_crypt(crypt) {
        return Err(err(
            "K9O_INVALID_FIELD_VALUE",
            "`crypt` must match ^[a-z0-9-]{1,64}$",
        ));
    }
    context_bytes(context).ok_or_else(|| {
        err(
            "K9O_INVALID_FIELD_VALUE",
            "`context` must be at most 256 bytes",
        )
    })
}

/// The KMS encryption context for the DEK wrap: project, domain and crypt; never `context`.
fn kms_context(project_id: &str, crypt: &str) -> AadContext {
    AadContext {
        version: 1,
        strategy: Strategy::LocalEnvelope,
        attestation_tier: AttestationTier::Software,
        encryption_context: vec![
            (
                "k9o-crypto-domain".to_owned(),
                String::from_utf8_lossy(AAD_DOMAIN).into_owned(),
            ),
            ("k9o-crypto-crypt".to_owned(), crypt.to_owned()),
        ],
        project_id: Some(project_id.to_owned()),
    }
}

/// Seal one item under `provider` (the customer's KMS wraps the DEK). The core of
/// [`app_crypto_seal`], with the provider injected so it is testable without a KMS.
pub(crate) async fn seal_with(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    tag: ProviderTag,
    key_ref: &KeyVersionRef,
    project_id: &str,
    crypt: &str,
    context: Option<&str>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let ctx = check_binding(project_id, crypt, context)?;
    if plaintext.len() > MAX_ITEM_BYTES {
        return Err(err("K9O_PAYLOAD_TOO_LARGE", "At most 64 KiB per item."));
    }
    let dek = DataEncryptionKey::generate();
    let kms_ct = provider
        .encrypt(token, dek.key_bytes(), &kms_context(project_id, crypt))
        .await
        .map_err(map_kms_error)?;
    // W: the canonical envelope whose header names the provider and key version; its
    // ciphertext slot is the customer-KMS-wrapped DEK.
    let w = build_canonical_envelope(tag, key_ref, &[0u8; NONCE_SIZE_BYTES], &kms_ct)
        .envelope
        .clone();
    let aad = canonical_aad(project_id, crypt, ctx);
    let d = seal_data(dek.key_bytes(), &aad, plaintext).map_err(map_dek_error)?;
    Ok(frame(&w, &d))
}

/// The provider tag and key version a container names, with its two parts. A platform-tagged
/// container is the server route's: it does not open here.
pub(crate) fn parse(
    container: &[u8],
) -> Result<(ProviderTag, KeyVersionRef, &[u8], &[u8]), ZkFfiError> {
    let (w, d) = unframe(container).ok_or_else(integrity_failure)?;
    let (tag, kvr) = read_header(w).map_err(|_| integrity_failure())?;
    if matches!(tag, ProviderTag::PlatformManaged) {
        return Err(err(
            "K9O_ENVELOPE_INTEGRITY_FAILURE",
            "This container was sealed under platform custody; open it with the server route.",
        ));
    }
    Ok((tag, kvr, w, d))
}

/// Open one container's parts under `provider`. The core of [`app_crypto_open`].
pub(crate) async fn open_with(
    provider: &dyn KmsRestProvider,
    token: &FederatedToken,
    project_id: &str,
    crypt: &str,
    context: Option<&str>,
    w: &[u8],
    d: &[u8],
) -> Result<Vec<u8>, ZkFfiError> {
    let ctx = check_binding(project_id, crypt, context)?;
    let kms_ct = ciphertext_slice(w).map_err(map_envelope_error)?;
    let dek = provider
        .decrypt(token, kms_ct, &kms_context(project_id, crypt))
        .await
        .map_err(map_kms_error)?;
    open_data(&dek, d, &canonical_aad(project_id, crypt, ctx)).ok_or_else(integrity_failure)
}

/// Seal one item for a cloud BYOK/HYOK project, client-side, into a container v1.
///
/// # Errors
/// `K9O_INVALID_FIELD_VALUE` (project, crypt or context shape), `K9O_PAYLOAD_TOO_LARGE`,
/// `K9O_CRYPTO_STRATEGY_UNAVAILABLE` (a provider/posture pair with no provider tag), or the
/// customer KMS's error.
pub async fn app_crypto_seal(input: AppSealInput) -> Result<AppSealOutput, ZkFfiError> {
    let tag = to_canonical_provider_tag(input.posture, input.provider)?;
    check_expected_key(
        input.provider,
        &input.key_ref.external_ref,
        &input.expected_key_refs,
    )?;
    check_azure_seal_route(tag, &input.key_ref.external_ref)?;
    let key_ref = to_key_version_ref(&input.key_ref)?;
    let provider = make_provider(input.provider, &input.key_ref, &input.provider_config)?;
    let token = to_credential(input.kms_cred);
    let container = seal_with(
        provider.as_ref(),
        &token,
        tag,
        &key_ref,
        &input.project_id,
        &input.crypt,
        input.context.as_deref(),
        &input.plaintext,
    )
    .await?;
    Ok(AppSealOutput { container })
}

/// Open one container v1 sealed client-side, IFF the same project, crypt and context.
///
/// # Errors
/// `K9O_ENVELOPE_INTEGRITY_FAILURE` for every cannot-open (and for a platform-tagged
/// container, which the server route opens); `K9O_INVALID_FIELD_VALUE`; the customer KMS's
/// error (a KMS refusing the encryption context, for another project or crypt, is one).
pub async fn app_crypto_open(input: AppOpenInput) -> Result<AppOpenOutput, ZkFfiError> {
    let (tag, kvr, w, d) = parse(&input.container)?;
    let kms_provider = kms_provider_from_tag(tag)?;
    check_expected_key(kms_provider, &kvr.external_ref, &input.expected_key_refs)?;
    if azure_tag_mismatch(tag, &kvr.external_ref)?.is_some() {
        return Err(azure_open_refused());
    }
    let key_ref = FfiKeyRef {
        version: kvr.version,
        external_ref: kvr.external_ref.clone(),
    };
    let provider = make_provider(kms_provider, &key_ref, &input.provider_config)?;
    let token = to_credential(input.kms_cred);
    let plaintext = open_with(
        provider.as_ref(),
        &token,
        &input.project_id,
        &input.crypt,
        input.context.as_deref(),
        w,
        d,
    )
    .await?;
    Ok(AppOpenOutput { plaintext })
}

// Async tests need tokio, which this crate pulls in only with `ffi-uniffi`:
// `cargo test -p kibo-kms-rest-ffi --features kms-aws,kms-azure,ffi-uniffi`.
#[cfg(all(test, feature = "ffi-uniffi"))]
mod tests {
    use super::*;
    use kibo_kms_rest::error::KmsRestError;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// A fake customer KMS: "wraps" by XOR and refuses a decrypt whose encryption context
    /// differs from the wrap's, as a real KMS does. Records every context it saw.
    #[derive(Default)]
    struct FakeKms {
        seen: Mutex<Vec<String>>,
    }

    fn ctx_key(a: &AadContext) -> String {
        format!("{:?}|{:?}", a.encryption_context, a.project_id)
    }

    #[async_trait::async_trait]
    impl KmsRestProvider for FakeKms {
        async fn encrypt(
            &self,
            _token: &FederatedToken,
            dek: &[u8],
            aad: &AadContext,
        ) -> kibo_kms_rest::error::Result<Vec<u8>> {
            let k = ctx_key(aad);
            self.seen.lock().unwrap().push(k.clone());
            let mut out: Vec<u8> = dek.iter().map(|b| b ^ 0x5a).collect();
            out.extend_from_slice(k.as_bytes());
            Ok(out)
        }
        async fn decrypt(
            &self,
            _token: &FederatedToken,
            ct: &[u8],
            aad: &AadContext,
        ) -> kibo_kms_rest::error::Result<Zeroizing<Vec<u8>>> {
            let k = ctx_key(aad);
            self.seen.lock().unwrap().push(k.clone());
            if ct.len() < 32 || &ct[32..] != k.as_bytes() {
                return Err(KmsRestError::EnvelopeIntegrity);
            }
            Ok(Zeroizing::new(ct[..32].iter().map(|b| b ^ 0x5a).collect()))
        }
    }

    fn token() -> FederatedToken {
        FederatedToken::new("t".to_owned(), u64::MAX)
    }

    fn key() -> KeyVersionRef {
        KeyVersionRef {
            version: 3,
            external_ref: "arn:aws:kms:eu-central-1:123:key/k".to_owned(),
        }
    }

    async fn seal(kms: &FakeKms, project: &str, crypt: &str, ctx: Option<&str>) -> Vec<u8> {
        seal_with(
            kms,
            &token(),
            ProviderTag::BYOKAwsKms,
            &key(),
            project,
            crypt,
            ctx,
            b"hello",
        )
        .await
        .unwrap()
    }

    async fn open(
        kms: &FakeKms,
        c: &[u8],
        project: &str,
        crypt: &str,
        ctx: Option<&str>,
    ) -> Result<Vec<u8>, ZkFfiError> {
        let (_, _, w, d) = parse(c)?;
        open_with(kms, &token(), project, crypt, ctx, w, d).await
    }

    #[tokio::test]
    async fn a_client_container_is_v1_names_its_key_and_round_trips() {
        let kms = FakeKms::default();
        let c = seal(&kms, "proj_a", "pii", Some("user:42")).await;
        assert_eq!(c[0], 0x01);
        let (tag, kvr, _, _) = parse(&c).unwrap();
        assert!(matches!(tag, ProviderTag::BYOKAwsKms));
        assert_eq!(kvr.version, 3);
        assert_eq!(
            open(&kms, &c, "proj_a", "pii", Some("user:42"))
                .await
                .unwrap(),
            b"hello"
        );
    }

    #[tokio::test]
    async fn every_wrong_binding_fails_and_the_context_never_reaches_the_kms() {
        let kms = FakeKms::default();
        let c = seal(&kms, "proj_a", "pii", Some("user:42")).await;
        // Wrong context: the KMS accepts (it never sees the context), the AEAD refuses.
        let e = open(&kms, &c, "proj_a", "pii", Some("user:43"))
            .await
            .unwrap_err();
        assert_eq!(e.code.as_deref(), Some("K9O_ENVELOPE_INTEGRITY_FAILURE"));
        // Wrong crypt or project: the customer's KMS refuses the encryption context.
        assert!(
            open(&kms, &c, "proj_a", "billing", Some("user:42"))
                .await
                .is_err()
        );
        assert!(
            open(&kms, &c, "proj_b", "pii", Some("user:42"))
                .await
                .is_err()
        );
        // Tampered data: the AEAD refuses.
        let mut t = c.clone();
        *t.last_mut().unwrap() ^= 1;
        assert_eq!(
            open(&kms, &t, "proj_a", "pii", Some("user:42"))
                .await
                .unwrap_err()
                .code
                .as_deref(),
            Some("K9O_ENVELOPE_INTEGRITY_FAILURE")
        );
        for seen in kms.seen.lock().unwrap().iter() {
            assert!(
                !seen.contains("user:4"),
                "the context reached the KMS: {seen}"
            );
            assert!(seen.contains("k9o-app-crypto/v1"), "{seen}");
            assert!(
                seen.contains("k9o-crypto-crypt"),
                "the crypt is bound at the KMS: {seen}"
            );
            assert!(
                seen.contains("\"pii\"") || seen.contains("\"billing\""),
                "the crypt's value is bound at the KMS: {seen}"
            );
            assert!(
                seen.contains("Some(\"proj_"),
                "the project is bound at the KMS: {seen}"
            );
        }
    }

    /// The client path's `D` is the server route's format: unwrapped independently (the fake's
    /// XOR) and opened with the shared AAD, not through `open_with`.
    #[tokio::test]
    async fn a_client_container_opens_with_the_shared_aad_alone() {
        let kms = FakeKms::default();
        let c = seal(&kms, "proj_a", "pii", Some("user:42")).await;
        let (_, _, w, d) = parse(&c).unwrap();
        let kms_ct = ciphertext_slice(w).unwrap();
        let dek: Vec<u8> = kms_ct[..32].iter().map(|b| b ^ 0x5a).collect();
        let got = kibo_crypto_core::app_container::open_data(
            &dek,
            d,
            &kibo_crypto_core::app_container::canonical_aad("proj_a", "pii", b"user:42"),
        );
        assert_eq!(got.as_deref(), Some(&b"hello"[..]));
    }

    fn planted_container(tag: ProviderTag, external_ref: String) -> Vec<u8> {
        let kvr = KeyVersionRef {
            version: 1,
            external_ref,
        };
        let w = build_canonical_envelope(tag, &kvr, &[0u8; NONCE_SIZE_BYTES], &[1u8; 40])
            .envelope
            .clone();
        frame(&w, &[0u8; 30])
    }

    fn open_input(container: Vec<u8>) -> AppOpenInput {
        AppOpenInput {
            kms_cred: crate::types::FfiCredential {
                secret: "customer-token".to_owned(),
                expires_at_unix_secs: u64::MAX,
            },
            provider_config: Default::default(),
            project_id: "proj_a".to_owned(),
            crypt: "pii".to_owned(),
            context: None,
            container,
            expected_key_refs: vec![],
        }
    }

    /// What a standard Key Vault gives: the KMS checks no context, so only the AAD can refuse.
    #[derive(Default)]
    struct RsaShapedKms;

    #[async_trait::async_trait]
    impl KmsRestProvider for RsaShapedKms {
        async fn encrypt(
            &self,
            _token: &FederatedToken,
            dek: &[u8],
            _aad: &AadContext,
        ) -> kibo_kms_rest::error::Result<Vec<u8>> {
            Ok(dek.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn decrypt(
            &self,
            _token: &FederatedToken,
            ct: &[u8],
            _aad: &AadContext,
        ) -> kibo_kms_rest::error::Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(ct.iter().map(|b| b ^ 0x5a).collect()))
        }
    }

    /// With no KMS check, the AAD still refuses a container
    /// moved to another project, crypt or context.
    #[tokio::test]
    async fn on_the_rsa_path_the_aad_alone_refuses_a_moved_container() {
        let kms = RsaShapedKms;
        let kvr = KeyVersionRef {
            version: 1,
            external_ref: "https://v.vault.azure.net/keys/k/1".to_owned(),
        };
        let c = seal_with(
            &kms,
            &token(),
            ProviderTag::BYOKAzureKeyVault,
            &kvr,
            "proj_a",
            "pii",
            Some("user:42"),
            b"hello",
        )
        .await
        .unwrap();
        let try_open = |project: &'static str, crypt: &'static str, ctx: &'static str| {
            let c = c.clone();
            async move {
                let (_, _, w, d) = parse(&c)?;
                open_with(&RsaShapedKms, &token(), project, crypt, Some(ctx), w, d).await
            }
        };
        assert_eq!(
            try_open("proj_a", "pii", "user:42").await.unwrap(),
            b"hello"
        );
        for (project, crypt, ctx) in [
            ("proj_b", "pii", "user:42"),
            ("proj_a", "billing", "user:42"),
            ("proj_a", "pii", "user:43"),
        ] {
            let e = try_open(project, crypt, ctx).await.unwrap_err();
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_ENVELOPE_INTEGRITY_FAILURE"),
                "{project} {crypt} {ctx}"
            );
        }
    }

    /// The wrong host for the posture never reaches a KMS on seal, and says what to change.
    #[cfg(feature = "kms-azure")]
    #[tokio::test]
    async fn a_seal_with_the_wrong_host_for_the_posture_is_refused() {
        for (posture, key, words) in [
            (
                crate::types::FfiPosture::Byok,
                "https://h.managedhsm.azure.net/keys/k/1",
                "Azure BYOK takes",
            ),
            (
                crate::types::FfiPosture::Hyok,
                "https://v.vault.azure.net/keys/k/1",
                "Azure HYOK takes",
            ),
        ] {
            let e = app_crypto_seal(AppSealInput {
                provider: crate::types::KmsProvider::AzureKv,
                posture,
                kms_cred: crate::types::FfiCredential {
                    secret: "customer-token".to_owned(),
                    expires_at_unix_secs: u64::MAX,
                },
                key_ref: crate::types::FfiKeyRef {
                    version: 1,
                    external_ref: key.to_owned(),
                },
                provider_config: Default::default(),
                project_id: "proj_a".to_owned(),
                crypt: "pii".to_owned(),
                context: None,
                plaintext: b"hello".to_vec(),
                expected_key_refs: vec![],
            })
            .await
            .err()
            .unwrap();
            assert!(e.message.contains(words), "{}", e.message);
        }
    }

    /// The tag sits outside the data AEAD, so a flipped one has to fail closed, before any
    /// KMS call, on both openers and in both directions.
    #[cfg(feature = "kms-azure")]
    #[tokio::test]
    async fn a_tag_that_disagrees_with_the_host_cannot_open() {
        const KV: &str = "https://v.vault.azure.net/keys/k/1";
        const HSM: &str = "https://h.managedhsm.azure.net/keys/k/1";
        for (tag, key) in [
            (ProviderTag::HYOKAzureManagedHsm, KV),
            (ProviderTag::BYOKAzureKeyVault, HSM),
        ] {
            let c = planted_container(tag, key.to_owned());
            let e = app_crypto_open(open_input(c)).await.err().unwrap();
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_ENVELOPE_INTEGRITY_FAILURE"),
                "{key}"
            );

            let kvr = KeyVersionRef {
                version: 1,
                external_ref: key.to_owned(),
            };
            let envelope =
                build_canonical_envelope(tag, &kvr, &[0u8; NONCE_SIZE_BYTES], &[1u8; 40])
                    .envelope
                    .clone();
            let e = crate::engine::zk_decrypt(crate::types::DecryptInput {
                kms_cred: crate::types::FfiCredential {
                    secret: "customer-token".to_owned(),
                    expires_at_unix_secs: u64::MAX,
                },
                provider_config: Default::default(),
                envelope,
                strategy: crate::types::FfiStrategy::LocalEnvelope,
                attestation_tier: crate::types::FfiAttestationTier::Confidential,
                encryption_context: vec![],
                expected_key_refs: vec![],
            })
            .await
            .err()
            .unwrap();
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_ENVELOPE_INTEGRITY_FAILURE"),
                "{key}"
            );
        }
    }

    /// A row of stored ciphertext is untrusted: a container naming the attacker's host must
    /// not reach it. The host here is a live local listener, so a request would be seen.
    #[cfg(feature = "kms-azure")]
    #[tokio::test]
    async fn a_planted_azure_host_gets_no_request_on_any_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let planted = format!(
            "https://127.0.0.1:{}/keys/k/1",
            listener.local_addr().unwrap().port()
        );

        let c = planted_container(ProviderTag::BYOKAzureKeyVault, planted.clone());
        // Bounded: a client that did reach the silent listener would wait forever for its TLS.
        let bound = std::time::Duration::from_secs(5);
        let e = tokio::time::timeout(bound, app_crypto_open(open_input(c)))
            .await
            .expect("the planted host was dialled")
            .err()
            .unwrap();
        assert_eq!(e.code.as_deref(), Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE"));

        let w = build_canonical_envelope(
            ProviderTag::BYOKAzureKeyVault,
            &KeyVersionRef {
                version: 1,
                external_ref: planted,
            },
            &[0u8; NONCE_SIZE_BYTES],
            &[1u8; 40],
        )
        .envelope
        .clone();
        let decrypt = crate::engine::zk_decrypt(crate::types::DecryptInput {
            kms_cred: crate::types::FfiCredential {
                secret: "customer-token".to_owned(),
                expires_at_unix_secs: u64::MAX,
            },
            provider_config: Default::default(),
            envelope: w,
            strategy: crate::types::FfiStrategy::LocalEnvelope,
            attestation_tier: crate::types::FfiAttestationTier::Software,
            encryption_context: vec![],
            expected_key_refs: vec![],
        });
        let e = tokio::time::timeout(bound, decrypt)
            .await
            .expect("the planted host was dialled")
            .err()
            .unwrap();
        assert_eq!(e.code.as_deref(), Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE"));

        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(std::io::ErrorKind::WouldBlock),
            "the planted host received a connection"
        );
    }

    /// A planted key on a listed host is refused before any call when the application pins
    /// its key: `UNEXPECTED_KEY`, not the KMS's answer. All four entry points.
    #[cfg(all(feature = "kms-aws", feature = "kms-azure"))]
    #[tokio::test]
    async fn a_pinned_application_refuses_a_planted_key_on_every_path() {
        let mine = "arn:aws:kms:eu-central-1:123:key/mine".to_owned();
        let planted = "arn:aws:kms:eu-central-1:666:key/theirs".to_owned();
        let cred = || crate::types::FfiCredential {
            secret: "customer-token".to_owned(),
            expires_at_unix_secs: u64::MAX,
        };
        let unexpected = |e: ZkFfiError| {
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_CRYPTO_UNEXPECTED_KEY"),
                "{}",
                e.message
            );
        };

        let mut open = open_input(planted_container(ProviderTag::BYOKAwsKms, planted.clone()));
        open.expected_key_refs = vec![mine.clone()];
        unexpected(app_crypto_open(open).await.err().unwrap());

        let seal = AppSealInput {
            provider: crate::types::KmsProvider::AwsKms,
            posture: crate::types::FfiPosture::Byok,
            kms_cred: cred(),
            key_ref: FfiKeyRef {
                version: 1,
                external_ref: planted.clone(),
            },
            provider_config: Default::default(),
            project_id: "proj_a".to_owned(),
            crypt: "pii".to_owned(),
            context: None,
            plaintext: b"x".to_vec(),
            expected_key_refs: vec![mine.clone()],
        };
        unexpected(app_crypto_seal(seal).await.err().unwrap());

        let w = build_canonical_envelope(
            ProviderTag::BYOKAwsKms,
            &KeyVersionRef {
                version: 1,
                external_ref: planted.clone(),
            },
            &[0u8; NONCE_SIZE_BYTES],
            &[1u8; 40],
        )
        .envelope
        .clone();
        let decrypt = crate::types::DecryptInput {
            kms_cred: cred(),
            provider_config: Default::default(),
            envelope: w,
            strategy: crate::types::FfiStrategy::LocalEnvelope,
            attestation_tier: crate::types::FfiAttestationTier::Software,
            encryption_context: vec![],
            expected_key_refs: vec![mine.clone()],
        };
        unexpected(crate::engine::zk_decrypt(decrypt).await.err().unwrap());

        let encrypt = crate::types::EncryptInput {
            provider: crate::types::KmsProvider::AwsKms,
            posture: crate::types::FfiPosture::Byok,
            strategy: None,
            oracle_mode: None,
            kms_cred: cred(),
            key_ref: FfiKeyRef {
                version: 1,
                external_ref: planted,
            },
            provider_config: Default::default(),
            attestation_tier: crate::types::FfiAttestationTier::Software,
            encryption_context: vec![],
            plaintext: b"x".to_vec(),
            posture_policy: None,
            expected_key_refs: vec![mine],
        };
        unexpected(crate::engine::zk_encrypt(encrypt).await.err().unwrap());
    }

    /// The region from a planted ARN goes into the KMS host name.
    #[cfg(feature = "kms-aws")]
    #[tokio::test]
    async fn a_planted_aws_region_is_refused_before_any_call() {
        for region in ["evil.example/#", "x@127.0.0.1"] {
            let c = planted_container(
                ProviderTag::BYOKAwsKms,
                format!("arn:aws:kms:{region}:123:key/k"),
            );
            let e = app_crypto_open(open_input(c)).await.err().unwrap();
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE"),
                "{region}"
            );
        }
    }

    #[tokio::test]
    async fn shapes_limits_and_a_platform_container_are_refused() {
        let kms = FakeKms::default();
        let big = vec![0u8; MAX_ITEM_BYTES + 1];
        let e = seal_with(
            &kms,
            &token(),
            ProviderTag::BYOKAwsKms,
            &key(),
            "p",
            "pii",
            None,
            &big,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code.as_deref(), Some("K9O_PAYLOAD_TOO_LARGE"));
        for (p, k, c) in [
            ("", "pii", None),
            ("p", "PII", None),
            ("p", "pii", Some("x".repeat(257))),
        ] {
            let e = seal_with(
                &kms,
                &token(),
                ProviderTag::BYOKAwsKms,
                &key(),
                p,
                k,
                c.as_deref(),
                b"x",
            )
            .await
            .unwrap_err();
            assert_eq!(
                e.code.as_deref(),
                Some("K9O_INVALID_FIELD_VALUE"),
                "{p}/{k}"
            );
        }
        assert!(
            kms.seen.lock().unwrap().is_empty(),
            "nothing reached the KMS"
        );
        // A platform-tagged container is the server route's.
        let w = build_canonical_envelope(
            ProviderTag::PlatformManaged,
            &key(),
            &[0u8; NONCE_SIZE_BYTES],
            &[1u8; 40],
        )
        .envelope
        .clone();
        let e = parse(&frame(&w, &[0u8; 30])).unwrap_err();
        assert_eq!(e.code.as_deref(), Some("K9O_ENVELOPE_INTEGRITY_FAILURE"));
        // Another container version, and the extension route's framing.
        let mut v2 = seal(&kms, "p", "pii", None).await;
        v2[0] = 0x02;
        assert!(parse(&v2).is_err());
        assert!(parse(&v2[1..]).is_err());
    }
}
