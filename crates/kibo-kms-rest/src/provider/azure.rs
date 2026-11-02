//! Azure Key Vault / Managed HSM REST provider (OAuth bearer), `kms-azure`
//! feature.
//!
//! Each operation is a plain HTTPS `POST` to
//! `<hsm-or-vault>/keys/<key>/<version>/encrypt|decrypt`, authenticated with the
//! federated OAuth bearer token (`Authorization: Bearer …`) — no Azure SDK.
//!
//! **Algorithm: `A256GCM`** (AES-256 GCM), against a Managed HSM `oct-HSM`
//! (symmetric AES) key. This keeps Azure **AAD-uniform** with AWS KMS / GCP KMS
//! / Vault: the `{version, strategy, attestation_tier}` + caller context bind
//! into the GCM **`aad`** field (the single canonical blob from
//! [`AadContext::binding_blob`]), so both `LocalEnvelope` and
//! `CustomerKmsOracle` are supported (the AAD is bound at the KMS).
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
        let base = self.vault_url.trim_end_matches('/');
        let url = format!(
            "{base}/keys/{}/{}/{op}?api-version={API_VERSION}",
            self.key_name, self.key_version
        );
        let req = super::kms_post(&url)
            .map_err(|_| upstream(None, "failed to build the HTTPS client"))?;
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
