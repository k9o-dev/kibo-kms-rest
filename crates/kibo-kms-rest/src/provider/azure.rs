//! Azure Key Vault / Managed HSM REST providers (OAuth bearer), `kms-azure`
//! feature. Plain HTTPS `POST`s with the federated bearer token, no Azure SDK.
//!
//! **Two paths, chosen by the caller from the pinned key's host before any call:**
//!
//! - [`AzureRsaWrapRest`], a standard Key Vault (BYOK): `RSA-OAEP-256` `wrapkey` and
//!   `unwrapkey` of a 32-byte data key, so `LocalEnvelope` only. **It binds nothing at the
//!   KMS**: the project, crypt and context are checked by the container's own AAD. It also
//!   can't confirm who sealed a value, because anyone with the public key can wrap a data
//!   key; accepted for BYOK.
//! - [`AzureKeyVaultRest`], a Managed HSM (HYOK): `A256GCM` `encrypt` and `decrypt` against
//!   an `oct-HSM` key, binding the `{version, strategy, attestation_tier}` + caller context
//!   into the GCM **`aad`** field ([`AadContext::binding_blob`]), so both `LocalEnvelope` and
//!   `CustomerKmsOracle` are supported.
//!
//! **Nonce ownership (grounded, not guessed):** the Azure SDK reference states
//! that for the GCM algorithms *"the nonce will be generated automatically and
//! returned in the EncryptResult after encryption."* So the **service** owns the
//! nonce — the caller never supplies one (no nonce-reuse risk on our side). The
//! encrypt response returns `value` (ciphertext), `iv`, and `tag` as separate
//! fields; we pack `iv ‖ tag ‖ ciphertext` into the opaque provider ciphertext
//! and re-supply them on decrypt. All wire values are **JWK base64url
//! (unpadded)**.

use super::{AadContext, KmsRestProvider};
use crate::auth::FederatedToken;
use crate::error::{KmsRestError, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// AES-256 GCM — the AAD-bearing symmetric algorithm (Managed HSM oct-HSM key).
const ALG: &str = "A256GCM";
/// The only RSA wrap algorithm: never `RSA1_5` or SHA-1 `RSA-OAEP`.
const RSA_ALG: &str = "RSA-OAEP-256";
/// The RSA floor: a 2048-bit modulus (the docs recommend 3072).
const MIN_RSA_MODULUS_BYTES: usize = 256;
/// A data key.
const DEK_BYTES: usize = 32;
/// Key Vault / Managed HSM data-plane API version.
const API_VERSION: &str = "2025-07-01";

/// REST-direct client for Azure Key Vault / Managed HSM.
///
/// Talks to the `<vault>/keys/<key>/<version>/encrypt` and `/decrypt`
/// endpoints over HTTPS, authenticating with the federated OAuth bearer
/// token. No Azure SDK.
#[derive(Clone, Debug)]
pub struct AzureKeyVaultRest {
    /// Base vault / Managed HSM URL (`https://<name>.vault.azure.net` or
    /// `https://<name>.managedhsm.azure.net`).
    vault_url: String,
    /// Key name within the vault.
    key_name: String,
    /// Key version (Key Vault keys are versioned).
    key_version: String,
}

impl AzureKeyVaultRest {
    /// Construct a client for a vault URL, key name, and key version.
    #[must_use]
    pub fn new(vault_url: String, key_name: String, key_version: String) -> Self {
        Self {
            vault_url,
            key_name,
            key_version,
        }
    }

    /// The configured vault base URL.
    #[must_use]
    pub fn vault_url(&self) -> &str {
        &self.vault_url
    }

    /// The configured key name.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// The configured key version.
    #[must_use]
    pub fn key_version(&self) -> &str {
        &self.key_version
    }

    /// POST `body` to the `op` (`encrypt` / `decrypt`) endpoint for the
    /// configured key+version, returning the success body bytes or mapping the
    /// failure.
    async fn invoke(&self, op: &str, token: &FederatedToken, body: &[u8]) -> Result<Vec<u8>> {
        post_key_op(
            &self.vault_url,
            &self.key_name,
            &self.key_version,
            op,
            token,
            body,
        )
        .await
    }
}

/// REST-direct RSA wrap for a standard Key Vault, which can't hold a symmetric key. See the
/// module docs for what this path doesn't bind.
#[derive(Clone, Debug)]
pub struct AzureRsaWrapRest {
    /// Base vault URL (`https://<name>.vault.azure.net`).
    vault_url: String,
    /// Key name within the vault.
    key_name: String,
    /// Key version: wrap and unwrap both name it, and the answer's `kid` must too.
    key_version: String,
}

impl AzureRsaWrapRest {
    /// Construct a client for a vault URL, key name, and key version.
    #[must_use]
    pub fn new(vault_url: String, key_name: String, key_version: String) -> Self {
        Self {
            vault_url,
            key_name,
            key_version,
        }
    }

    /// The Key Vault's answer must name exactly this key and version. Azure's host and key
    /// names aren't case-sensitive; the version is compared as given.
    fn check_kid(&self, kid: &str) -> Result<()> {
        let want_key = format!(
            "{}/keys/{}/",
            self.vault_url.trim_end_matches('/'),
            self.key_name
        );
        let matches = kid.len() == want_key.len() + self.key_version.len()
            && kid.is_char_boundary(want_key.len())
            && kid[..want_key.len()].eq_ignore_ascii_case(&want_key)
            && kid[want_key.len()..] == self.key_version;
        if matches {
            Ok(())
        } else {
            Err(upstream(
                Some(200),
                "the Key Vault answered for a different key",
            ))
        }
    }

    async fn call(
        &self,
        op: &str,
        token: &FederatedToken,
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut request = RsaKeyOpRequest {
            alg: RSA_ALG,
            value: BASE64URL.encode(value),
        };
        let mut body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Key Vault request"))?;
        request.value.zeroize();
        let answer = post_key_op(
            &self.vault_url,
            &self.key_name,
            &self.key_version,
            op,
            token,
            &body,
        )
        .await;
        body.zeroize();
        let mut bytes = answer?;
        let parsed = serde_json::from_slice::<RsaKeyOpResult>(&bytes);
        bytes.zeroize();
        let mut result = parsed
            .map_err(|_| upstream(Some(200), "malformed Key Vault key-operation response"))?;
        self.check_kid(&result.kid)?;
        let decoded = BASE64URL
            .decode(&result.value)
            .map_err(|_| upstream(Some(200), "Key Vault value was not valid base64url"));
        result.value.zeroize();
        decoded.map(Zeroizing::new)
    }
}

/// `wrapkey` and `unwrapkey` take only the algorithm and value: there's no AAD on this path.
#[derive(Serialize)]
struct RsaKeyOpRequest {
    alg: &'static str,
    value: String,
}

/// `KeyOperationResult` for a key wrap: `kid` and base64url `value`.
#[derive(Deserialize)]
struct RsaKeyOpResult {
    kid: String,
    value: String,
}

/// A wrapped key is as long as the RSA modulus, so this refuses a key under the floor.
fn check_wrapped_len(wrapped: &[u8]) -> Result<()> {
    if wrapped.len() < MIN_RSA_MODULUS_BYTES {
        return Err(KmsRestError::EnvelopeHeader(
            "the wrapped key shows an RSA modulus under 2048 bits".to_string(),
        ));
    }
    Ok(())
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl KmsRestProvider for AzureRsaWrapRest {
    /// Wrap a 32-byte data key through the vault, never locally with the public key, so an
    /// honest seal still needs the permission and shows in the customer's logs. `aad` isn't
    /// bound here. Anything but a data key is refused: this path can't be an oracle.
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        _aad: &AadContext,
    ) -> Result<Vec<u8>> {
        if plaintext_or_dek.len() != DEK_BYTES {
            return Err(KmsRestError::StrategyUnavailable);
        }
        let wrapped = self.call("wrapkey", token, plaintext_or_dek).await?;
        check_wrapped_len(&wrapped)?;
        Ok(wrapped.to_vec())
    }

    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        _aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        check_wrapped_len(ciphertext)?;
        let dek = self.call("unwrapkey", token, ciphertext).await?;
        if dek.len() != DEK_BYTES {
            return Err(KmsRestError::EnvelopeHeader(
                "the unwrapped data key is not 32 bytes".to_string(),
            ));
        }
        Ok(dek)
    }
}

/// POST `body` to a key's `op` endpoint at its version.
async fn post_key_op(
    vault_url: &str,
    key_name: &str,
    key_version: &str,
    op: &str,
    token: &FederatedToken,
    body: &[u8],
) -> Result<Vec<u8>> {
    let base = vault_url.trim_end_matches('/');
    let url = format!("{base}/keys/{key_name}/{key_version}/{op}?api-version={API_VERSION}");
    let req =
        super::kms_post(&url).map_err(|_| upstream(None, "failed to build the HTTPS client"))?;
    let resp = req
        .header("authorization", format!("Bearer {}", token.secret()))
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            upstream(
                None,
                &format!("Key Vault request failed ({})", reqwest_category(&e)),
            )
        })?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| upstream(Some(status), "failed to read the Key Vault response body"))?;
    if (200..300).contains(&status) {
        Ok(bytes.to_vec())
    } else {
        Err(map_azure_error(status, &bytes))
    }
}

/// Pack the AES-GCM `{iv, tag, ciphertext}` triple into a single self-describing
/// provider-ciphertext blob: `iv_len(u8) ‖ iv ‖ tag_len(u8) ‖ tag ‖ ciphertext`.
/// The lengths are prefixed (rather than assuming 12-byte iv / 16-byte tag) so
/// the framing survives any nonce/tag sizing the service returns.
fn frame(iv: &[u8], tag: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let iv_len = u8::try_from(iv.len())
        .map_err(|_| upstream(Some(200), "Key Vault iv length out of range"))?;
    let tag_len = u8::try_from(tag.len())
        .map_err(|_| upstream(Some(200), "Key Vault tag length out of range"))?;
    let mut out = Vec::with_capacity(2 + iv.len() + tag.len() + ciphertext.len());
    out.push(iv_len);
    out.extend_from_slice(iv);
    out.push(tag_len);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Inverse of [`frame`]: recover `(iv, tag, ciphertext)` from a provider blob.
fn unframe(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let malformed =
        || KmsRestError::EnvelopeHeader("Azure GCM ciphertext frame is malformed".to_string());
    let mut pos = 0usize;

    let iv_len = *blob.get(pos).ok_or_else(malformed)? as usize;
    pos += 1;
    let iv_end = pos.checked_add(iv_len).ok_or_else(malformed)?;
    let iv = blob.get(pos..iv_end).ok_or_else(malformed)?.to_vec();
    pos = iv_end;

    let tag_len = *blob.get(pos).ok_or_else(malformed)? as usize;
    pos += 1;
    let tag_end = pos.checked_add(tag_len).ok_or_else(malformed)?;
    let tag = blob.get(pos..tag_end).ok_or_else(malformed)?.to_vec();
    pos = tag_end;

    let ciphertext = blob.get(pos..).ok_or_else(malformed)?.to_vec();
    Ok((iv, tag, ciphertext))
}

/// Construct the crate-local upstream error for Azure (no platform `K9O_*` code).
fn upstream(status: Option<u16>, detail: &str) -> KmsRestError {
    KmsRestError::UpstreamKms {
        provider: "azure",
        status,
        detail: detail.to_string(),
    }
}

/// Coarse, non-secret transport-failure category.
fn reqwest_category(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if super::is_connect_error(e) {
        "connection failure"
    } else if e.is_request() {
        "request error"
    } else {
        "transport error"
    }
}

/// Key Vault error body: `{"error": {"code", "message"}}`.
#[derive(Deserialize, Default)]
struct AzureErrorEnvelope {
    error: Option<AzureError>,
}

#[derive(Deserialize, Default)]
struct AzureError {
    code: Option<String>,
    message: Option<String>,
}

/// Map a non-2xx Key Vault response to the crate-local upstream error.
fn map_azure_error(status: u16, body: &[u8]) -> KmsRestError {
    let parsed: AzureErrorEnvelope = serde_json::from_slice(body).unwrap_or_default();
    let detail = match parsed.error {
        Some(AzureError {
            code: Some(c),
            message: Some(m),
        }) => format!("{c}: {m}"),
        Some(AzureError {
            message: Some(m), ..
        }) => m,
        Some(AzureError { code: Some(c), .. }) => c,
        _ => "Key Vault error".to_string(),
    };
    KmsRestError::UpstreamKms {
        provider: "azure",
        status: Some(status),
        detail,
    }
}

/// Encrypt request: `{alg, value, aad}` (JWK base64url; no `iv` — the service
/// generates the GCM nonce and returns it).
#[derive(Serialize)]
struct EncryptRequest {
    alg: &'static str,
    value: String,
    aad: String,
}

/// Encrypt response (`KeyOperationResult`): base64url `value` (ciphertext),
/// `iv`, `tag` (`kid`/`aad` ignored).
#[derive(Deserialize)]
struct EncryptResult {
    value: String,
    iv: String,
    tag: String,
}

/// Decrypt request: `{alg, value, iv, tag, aad}` — all the GCM inputs, JWK
/// base64url. The `aad` is re-supplied from the caller's context, never read
/// from the stored envelope.
#[derive(Serialize)]
struct DecryptRequest {
    alg: &'static str,
    value: String,
    iv: String,
    tag: String,
    aad: String,
}

/// Decrypt response: base64url `value` (plaintext).
#[derive(Deserialize)]
struct DecryptResult {
    value: String,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl KmsRestProvider for AzureKeyVaultRest {
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        aad: &AadContext,
    ) -> Result<Vec<u8>> {
        let aad_blob = aad.binding_blob()?;
        let mut request = EncryptRequest {
            alg: ALG,
            value: BASE64URL.encode(plaintext_or_dek),
            aad: BASE64URL.encode(&aad_blob),
        };
        let mut body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Key Vault encrypt request"))?;
        request.value.zeroize();

        let response_bytes = self.invoke("encrypt", token, &body).await?;
        body.zeroize();
        let result: EncryptResult = serde_json::from_slice(&response_bytes)
            .map_err(|_| upstream(Some(200), "malformed Key Vault encrypt response"))?;
        let iv = BASE64URL
            .decode(&result.iv)
            .map_err(|_| upstream(Some(200), "Key Vault iv was not valid base64url"))?;
        let tag = BASE64URL
            .decode(&result.tag)
            .map_err(|_| upstream(Some(200), "Key Vault tag was not valid base64url"))?;
        let ciphertext = BASE64URL
            .decode(&result.value)
            .map_err(|_| upstream(Some(200), "Key Vault ciphertext was not valid base64url"))?;
        // Pack iv+tag+ciphertext so decrypt can re-supply the GCM inputs.
        frame(&iv, &tag, &ciphertext)
    }

    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (iv, tag, ct) = unframe(ciphertext)?;
        let aad_blob = aad.binding_blob()?;
        let request = DecryptRequest {
            alg: ALG,
            value: BASE64URL.encode(&ct),
            iv: BASE64URL.encode(&iv),
            tag: BASE64URL.encode(&tag),
            aad: BASE64URL.encode(&aad_blob),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Key Vault decrypt request"))?;

        let mut response_bytes = self.invoke("decrypt", token, &body).await?;
        let mut value_b64 = {
            let result: DecryptResult = serde_json::from_slice(&response_bytes)
                .map_err(|_| upstream(Some(200), "malformed Key Vault decrypt response"))?;
            result.value
        };
        response_bytes.zeroize();
        let plaintext = BASE64URL
            .decode(&value_b64)
            .map_err(|_| upstream(Some(200), "Key Vault plaintext was not valid base64url"))?;
        value_b64.zeroize();
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::AttestationTier;
    use crate::strategy::Strategy;

    fn aad() -> AadContext {
        AadContext {
            version: 1,
            strategy: Strategy::CustomerKmsOracle,
            attestation_tier: AttestationTier::Confidential,
            encryption_context: vec![("tenant".to_string(), "acme".to_string())],
            project_id: None,
        }
    }

    #[test]
    fn encrypt_request_is_a256gcm_no_iv_unpadded_base64url() {
        let blob = aad().binding_blob().expect("blob");
        let request = EncryptRequest {
            alg: ALG,
            value: BASE64URL.encode([0xfb, 0xff]),
            aad: BASE64URL.encode(&blob),
        };
        let json = serde_json::to_value(&request).expect("serializable");
        assert_eq!(json["alg"], "A256GCM");
        // No client-supplied iv on encrypt (the service generates it).
        assert!(json.get("iv").is_none());
        // base64url-UNPADDED: 0xfb 0xff -> "-_8" (no '=').
        assert_eq!(json["value"], "-_8");
        assert_eq!(
            BASE64URL
                .decode(json["aad"].as_str().expect("str"))
                .expect("b64url"),
            blob
        );
    }

    fn rsa() -> AzureRsaWrapRest {
        AzureRsaWrapRest::new(
            "https://v.vault.azure.net".to_string(),
            "k".to_string(),
            "ver1".to_string(),
        )
    }

    #[test]
    fn the_rsa_request_is_oaep_256_with_nothing_else() {
        let json = serde_json::to_value(RsaKeyOpRequest {
            alg: RSA_ALG,
            value: "x".to_string(),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "alg": "RSA-OAEP-256", "value": "x" })
        );
    }

    #[test]
    fn the_answer_must_name_the_pinned_key_and_version() {
        let p = rsa();
        assert!(p.check_kid("https://v.vault.azure.net/keys/k/ver1").is_ok());
        assert!(p.check_kid("https://V.VAULT.azure.net/keys/K/ver1").is_ok());
        for wrong in [
            "https://v.vault.azure.net/keys/k/ver2",
            "https://v.vault.azure.net/keys/k/VER1",
            "https://v.vault.azure.net/keys/k/ver1/x",
            "https://v.vault.azure.net/keys/other/ver1",
            "https://other.vault.azure.net/keys/k/ver1",
            "https://v.vault.azure.net/keys/k/",
            "",
        ] {
            assert!(p.check_kid(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn a_modulus_under_2048_bits_is_refused() {
        assert!(check_wrapped_len(&[0u8; 256]).is_ok());
        assert!(check_wrapped_len(&[0u8; 384]).is_ok());
        assert!(check_wrapped_len(&[0u8; 255]).is_err());
        assert!(check_wrapped_len(&[]).is_err());
    }

    /// No token and no network is touched: both refusals come first.
    #[tokio::test]
    async fn it_refuses_to_be_an_oracle_or_to_open_a_short_wrap_before_any_call() {
        let token = crate::auth::FederatedToken::new("t".to_string(), 0);
        let p = rsa();
        let oracle = p.encrypt(&token, &[1u8; 31], &aad()).await.err().unwrap();
        assert!(
            matches!(oracle, KmsRestError::StrategyUnavailable),
            "{oracle}"
        );
        let big = p.encrypt(&token, &[1u8; 33], &aad()).await.err().unwrap();
        assert!(matches!(big, KmsRestError::StrategyUnavailable), "{big}");
        let short = p.decrypt(&token, &[1u8; 255], &aad()).await.err().unwrap();
        assert!(matches!(short, KmsRestError::EnvelopeHeader(_)), "{short}");
    }

    /// One request to a local server: answers from `answer(base_url, body)`, returns the
    /// request line and body it saw.
    fn one_shot(
        answer: impl FnOnce(&str) -> String + Send + 'static,
    ) -> (String, std::thread::JoinHandle<(String, serde_json::Value)>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let url = base.clone();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            let (head_end, length) = loop {
                let n = conn.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&seen).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    break (end + 4, length);
                }
            };
            while seen.len() < head_end + length {
                let n = conn.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            let line = String::from_utf8_lossy(&seen)
                .lines()
                .next()
                .unwrap()
                .to_owned();
            let body = serde_json::from_slice(&seen[head_end..]).unwrap();
            let reply = answer(&base);
            write!(
                conn,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            )
            .unwrap();
            (line, body)
        });
        (url, handle)
    }

    fn rsa_at(url: &str) -> AzureRsaWrapRest {
        AzureRsaWrapRest::new(url.to_string(), "k".to_string(), "ver1".to_string())
    }

    fn rsa_answer(key: &'static str, bytes: Vec<u8>) -> impl FnOnce(&str) -> String + Send {
        move |base| {
            serde_json::json!({
                "kid": format!("{base}/keys/{key}/ver1"),
                "value": BASE64URL.encode(&bytes),
            })
            .to_string()
        }
    }

    fn token() -> crate::auth::FederatedToken {
        crate::auth::FederatedToken::new("t".to_string(), u64::MAX)
    }

    /// RSA goes only through `wrapKey`/`unwrapKey`, AES only
    /// through `encrypt`/`decrypt`, each at the pinned version.
    #[tokio::test]
    async fn each_path_posts_only_its_own_operations() {
        let (url, seen) = one_shot(rsa_answer("k", vec![7u8; 256]));
        let wrapped = rsa_at(&url)
            .encrypt(&token(), &[1u8; 32], &aad())
            .await
            .unwrap();
        assert_eq!(wrapped, vec![7u8; 256]);
        let (line, body) = seen.join().unwrap();
        assert!(line.starts_with("POST /keys/k/ver1/wrapkey?"), "{line}");
        assert_eq!(body["alg"], "RSA-OAEP-256");
        assert!(body.get("aad").is_none(), "{body}");

        let (url, seen) = one_shot(rsa_answer("k", vec![9u8; 32]));
        let dek = rsa_at(&url)
            .decrypt(&token(), &[7u8; 256], &aad())
            .await
            .unwrap();
        assert_eq!(dek.as_slice(), &[9u8; 32]);
        let (line, body) = seen.join().unwrap();
        assert!(line.starts_with("POST /keys/k/ver1/unwrapkey?"), "{line}");
        assert_eq!(body["alg"], "RSA-OAEP-256");

        let aes = |url: &str| {
            AzureKeyVaultRest::new(url.to_string(), "k".to_string(), "ver1".to_string())
        };
        let (url, seen) = one_shot(|_| {
            serde_json::json!({
                "iv": BASE64URL.encode([1u8; 12]),
                "tag": BASE64URL.encode([2u8; 16]),
                "value": BASE64URL.encode([3u8; 32]),
            })
            .to_string()
        });
        let framed = aes(&url)
            .encrypt(&token(), &[1u8; 32], &aad())
            .await
            .unwrap();
        let (line, body) = seen.join().unwrap();
        assert!(line.starts_with("POST /keys/k/ver1/encrypt?"), "{line}");
        assert_eq!(body["alg"], "A256GCM");

        let (url, seen) =
            one_shot(|_| serde_json::json!({ "value": BASE64URL.encode([9u8; 32]) }).to_string());
        aes(&url).decrypt(&token(), &framed, &aad()).await.unwrap();
        let (line, body) = seen.join().unwrap();
        assert!(line.starts_with("POST /keys/k/ver1/decrypt?"), "{line}");
        assert_eq!(body["alg"], "A256GCM");
    }

    #[tokio::test]
    async fn a_wrong_answer_from_the_vault_is_refused() {
        // Another key answered, on both directions.
        let (url, seen) = one_shot(rsa_answer("other", vec![7u8; 256]));
        let e = rsa_at(&url).encrypt(&token(), &[1u8; 32], &aad()).await;
        seen.join().unwrap();
        assert!(e.err().unwrap().to_string().contains("different key"));
        let (url, seen) = one_shot(rsa_answer("other", vec![9u8; 32]));
        let e = rsa_at(&url).decrypt(&token(), &[7u8; 256], &aad()).await;
        seen.join().unwrap();
        assert!(e.err().unwrap().to_string().contains("different key"));
        // A wrap under 2048 bits, on seal.
        let (url, seen) = one_shot(rsa_answer("k", vec![7u8; 128]));
        let e = rsa_at(&url).encrypt(&token(), &[1u8; 32], &aad()).await;
        seen.join().unwrap();
        assert!(e.err().unwrap().to_string().contains("under 2048"));
        // An unwrapped key that isn't 32 bytes.
        for len in [31usize, 33] {
            let (url, seen) = one_shot(rsa_answer("k", vec![9u8; len]));
            let e = rsa_at(&url).decrypt(&token(), &[7u8; 256], &aad()).await;
            seen.join().unwrap();
            assert!(
                e.err().unwrap().to_string().contains("not 32 bytes"),
                "{len}"
            );
        }
    }

    #[test]
    fn frame_unframe_round_trips() {
        let iv = [1u8; 12];
        let tag = [2u8; 16];
        let ct = b"ciphertext-bytes".to_vec();
        let framed = frame(&iv, &tag, &ct).expect("frame");
        let (iv2, tag2, ct2) = unframe(&framed).expect("unframe");
        assert_eq!(iv2, iv);
        assert_eq!(tag2, tag);
        assert_eq!(ct2, ct);
    }

    #[test]
    fn unframe_rejects_truncated_blob() {
        // iv_len says 12 but no bytes follow -> malformed (not a panic).
        let err = unframe(&[12u8]).err().expect("truncated frame must error");
        assert_eq!(
            err.wire_code().unwrap().as_str(),
            "K9O_ENVELOPE_HEADER_MALFORMED"
        );
    }

    #[test]
    fn map_azure_error_extracts_code_and_message_crate_local() {
        let body = br#"{"error":{"code":"Forbidden","message":"caller lacks keys/decrypt"}}"#;
        let err = map_azure_error(403, body);
        assert!(err.wire_code().is_none());
        let rendered = err.to_string();
        assert!(rendered.contains("Forbidden"));
        assert!(rendered.contains("caller lacks keys/decrypt"));
        assert!(rendered.contains("azure"));
        assert!(rendered.contains("status 403"));
    }
}
