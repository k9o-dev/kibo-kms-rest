//! HashiCorp Vault Transit REST provider (token auth), `kms-vault` feature.
//!
//! Each operation is a plain HTTPS `POST` to `<address>/v1/transit/encrypt/<key>`
//! or `/decrypt/<key>`, authenticated with the federated Vault token
//! (`X-Vault-Token`) — no `vaultrs` crate. Shapes are grounded in the official
//! Vault Transit API reference:
//!
//! - `plaintext` (request) and `data.plaintext` (response) are **standard**
//!   base64 (padded). The encrypt response `data.ciphertext` is the opaque
//!   `vault:vN:<base64>` token, which is round-tripped back to decrypt verbatim
//!   (returned here as the provider ciphertext bytes).
//! - The AAD binds into **`associated_data`** — the true AEAD additional-data
//!   field (for the `aes256-gcm` / `chacha20-poly1305` key types). It is **not**
//!   the `context` field, which the docs reserve for key-derivation and which
//!   does not feed AEAD authentication. (This corrects the original scaffold
//!   note, which named `context`.) The blob comes from
//!   [`AadContext::binding_blob`] and is re-supplied byte-for-byte at decrypt.

use super::{AadContext, KmsRestProvider};
use crate::auth::FederatedToken;
use crate::error::{KmsRestError, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// REST-direct client for HashiCorp Vault's Transit secrets engine.
///
/// Talks to `<vault>/v1/transit/encrypt/<key>` and
/// `/v1/transit/decrypt/<key>` over HTTPS, authenticating with the
/// federated Vault token (the `X-Vault-Token` header). No `vaultrs`
/// crate.
#[derive(Clone, Debug)]
pub struct VaultTransitRest {
    /// Base Vault address (`https://<vault>:8200`).
    address: String,
    /// Transit key name.
    key_name: String,
}

impl VaultTransitRest {
    /// Construct a client for a Vault address and Transit key name.
    #[must_use]
    pub fn new(address: String, key_name: String) -> Self {
        Self { address, key_name }
    }

    /// The configured Vault base address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The configured Transit key name.
    #[must_use]
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// POST `body` to the Transit `op` (`encrypt` / `decrypt`) endpoint for the
    /// configured key, returning the success body bytes or mapping the failure.
    async fn invoke(&self, op: &str, token: &FederatedToken, body: &[u8]) -> Result<Vec<u8>> {
        let url = format!(
            "{}/v1/transit/{op}/{}",
            self.address.trim_end_matches('/'),
            self.key_name
        );
        let req = super::kms_post(&url)
            .map_err(|_| upstream(None, "failed to build the HTTPS client"))?;
        let resp = req
            .header("x-vault-token", token.secret())
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| {
                upstream(
                    None,
                    &format!("Vault request failed ({})", reqwest_category(&e)),
                )
            })?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| upstream(Some(status), "failed to read the Vault response body"))?;
        if (200..300).contains(&status) {
            Ok(bytes.to_vec())
        } else {
            Err(map_vault_error(status, &bytes))
        }
    }
}

/// Construct the crate-local upstream error for Vault (no platform `K9O_*` code).
fn upstream(status: Option<u16>, detail: &str) -> KmsRestError {
    KmsRestError::UpstreamKms {
        provider: "vault",
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

/// Vault error body: `{"errors": ["...", ...]}`.
#[derive(Deserialize, Default)]
struct VaultErrorBody {
    errors: Option<Vec<String>>,
}

/// Map a non-2xx Vault response to the crate-local upstream error.
fn map_vault_error(status: u16, body: &[u8]) -> KmsRestError {
    let parsed: VaultErrorBody = serde_json::from_slice(body).unwrap_or_default();
    let detail = parsed
        .errors
        .filter(|e| !e.is_empty())
        .map_or_else(|| "Vault Transit error".to_string(), |e| e.join("; "));
    KmsRestError::UpstreamKms {
        provider: "vault",
        status: Some(status),
        detail,
    }
}

/// Encrypt request: standard-base64 `plaintext` + `associated_data` (AEAD AAD).
#[derive(Serialize)]
struct EncryptRequest {
    plaintext: String,
    associated_data: String,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct EncryptResponse {
    data: EncryptData,
}

/// Decrypt request: the `vault:vN:…` ciphertext token + `associated_data`.
#[derive(Serialize)]
struct DecryptRequest {
    ciphertext: String,
    associated_data: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

#[derive(Deserialize)]
struct DecryptResponse {
    data: DecryptData,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl KmsRestProvider for VaultTransitRest {
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        aad: &AadContext,
    ) -> Result<Vec<u8>> {
        let aad_blob = aad.binding_blob()?;
        let mut request = EncryptRequest {
            plaintext: BASE64.encode(plaintext_or_dek),
            associated_data: BASE64.encode(&aad_blob),
        };
        let mut body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Vault encrypt request"))?;
        request.plaintext.zeroize();

        let response_bytes = self.invoke("encrypt", token, &body).await?;
        body.zeroize();
        let response: EncryptResponse = serde_json::from_slice(&response_bytes)
            .map_err(|_| upstream(Some(200), "malformed Vault encrypt response"))?;
        // The `vault:vN:…` token is the provider ciphertext — returned verbatim.
        Ok(response.data.ciphertext.into_bytes())
    }

    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let aad_blob = aad.binding_blob()?;
        let ciphertext_token = std::str::from_utf8(ciphertext).map_err(|_| {
            KmsRestError::EnvelopeHeader("Vault ciphertext token is not valid UTF-8".to_string())
        })?;
        let request = DecryptRequest {
            ciphertext: ciphertext_token.to_string(),
            associated_data: BASE64.encode(&aad_blob),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Vault decrypt request"))?;

        let mut response_bytes = self.invoke("decrypt", token, &body).await?;
        let mut plaintext_b64 = {
            let response: DecryptResponse = serde_json::from_slice(&response_bytes)
                .map_err(|_| upstream(Some(200), "malformed Vault decrypt response"))?;
            response.data.plaintext
        };
        response_bytes.zeroize();
        let plaintext = BASE64
            .decode(&plaintext_b64)
            .map_err(|_| upstream(Some(200), "Vault plaintext was not valid base64"))?;
        plaintext_b64.zeroize();
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
            strategy: Strategy::LocalEnvelope,
            attestation_tier: AttestationTier::Software,
            encryption_context: vec![("tenant".to_string(), "acme".to_string())],
            project_id: None,
        }
    }

    /// A KMS that accepts the connection and never answers is an error, not a hang. The
    /// outer bound is what makes a client with no timeout fail here rather than wait forever.
    #[tokio::test]
    async fn a_stalled_kms_is_a_timeout_not_a_hang() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let provider = VaultTransitRest::new(address, "k".to_owned());
        let token = FederatedToken::new("t".to_owned(), u64::MAX);
        let aad = aad();
        let call = provider.encrypt(&token, b"dek", &aad);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .expect("the KMS call has no timeout");
        let message = outcome
            .err()
            .expect("a stalled KMS is an error")
            .to_string();
        assert!(message.contains("timeout"), "{message}");
    }

    #[test]
    fn encrypt_request_binds_associated_data_not_context() {
        let blob = aad().binding_blob().expect("blob");
        let request = EncryptRequest {
            plaintext: BASE64.encode(b"dek"),
            associated_data: BASE64.encode(&blob),
        };
        let json = serde_json::to_value(&request).expect("serializable");
        // The AAD must ride on `associated_data`, never `context`.
        assert!(json.get("associated_data").is_some());
        assert!(json.get("context").is_none());
        assert_eq!(
            BASE64
                .decode(json["associated_data"].as_str().expect("str"))
                .expect("valid base64"),
            blob
        );
    }

    #[test]
    fn decrypt_request_carries_the_vault_token_verbatim() {
        let token = "vault:v1:abcdef=="; // a representative ciphertext token
        let request = DecryptRequest {
            ciphertext: token.to_string(),
            associated_data: BASE64.encode(aad().binding_blob().expect("blob")),
        };
        let json = serde_json::to_value(&request).expect("serializable");
        assert_eq!(json["ciphertext"], token);
    }

    #[test]
    fn map_vault_error_joins_messages_and_stays_crate_local() {
        let body = br#"{"errors":["permission denied","on key transit/foo"]}"#;
        let err = map_vault_error(403, body);
        assert!(err.wire_code().is_none());
        let rendered = err.to_string();
        assert!(rendered.contains("permission denied"));
        assert!(rendered.contains("vault"));
        assert!(rendered.contains("status 403"));
    }
}
