//! GCP Cloud KMS REST provider (OAuth bearer), `kms-gcp` feature.
//!
//! Each `:encrypt` / `:decrypt` is a plain HTTPS `POST` to
//! `cloudkms.googleapis.com`, authenticated with the federated OAuth bearer
//! token (`Authorization: Bearer …`) — no `google-cloud-kms` gRPC SDK. Shapes
//! are grounded in the official Cloud KMS REST reference:
//!
//! - `plaintext`, `additionalAuthenticatedData`, and `ciphertext` are the
//!   Google `bytes` type in JSON: padded standard base64 in both directions,
//!   per the JSON mapping. A parser of that type takes either alphabet with or
//!   without padding, so [`decode_bytes`] does too.
//! - The AAD `{version, strategy, attestation_tier}` + caller context bind
//!   into the single `additionalAuthenticatedData` blob (see
//!   [`AadContext::binding_blob`]); it must be re-supplied byte-for-byte at
//!   decrypt, and is never read from any envelope.
//!
//! The CRC32C integrity loop is wired (GCP-recommended defence-in-depth): we
//! send `plaintextCrc32c` / `ciphertextCrc32c` and verify GCP's
//! `verified*Crc32c` flag + the returned `*Crc32c` over the bytes we received.
//! TLS plus the KMS AES-GCM tag already cover transport and cryptographic
//! integrity, so a CRC32C mismatch is treated as (retryable) transit
//! corruption, NOT the envelope-integrity (crypto-tamper) contract.

use super::{AadContext, KmsRestProvider};
use crate::auth::FederatedToken;
use crate::error::{KmsRestError, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const EITHER_PADDING: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);

/// Decode a Google `bytes` field from a response.
fn decode_bytes(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    GeneralPurpose::new(&alphabet::STANDARD, EITHER_PADDING)
        .decode(value)
        .or_else(|_| GeneralPurpose::new(&alphabet::URL_SAFE, EITHER_PADDING).decode(value))
}

/// Cloud KMS v1 REST base.
const ENDPOINT_BASE: &str = "https://cloudkms.googleapis.com/v1/";

/// REST-direct client for GCP Cloud KMS.
///
/// Talks to the `cloudkms.googleapis.com` `:encrypt` / `:decrypt`
/// endpoints over HTTPS, authenticating with the federated OAuth bearer
/// token. No `google-cloud-kms` gRPC SDK.
#[derive(Clone, Debug)]
pub struct GcpKmsRest {
    /// Fully-qualified CryptoKey resource name
    /// (`projects/.../locations/.../keyRings/.../cryptoKeys/...`).
    crypto_key: String,
}

impl GcpKmsRest {
    /// Construct a client for a fully-qualified CryptoKey resource name.
    #[must_use]
    pub fn new(crypto_key: String) -> Self {
        Self { crypto_key }
    }

    /// The configured CryptoKey resource name.
    #[must_use]
    pub fn crypto_key(&self) -> &str {
        &self.crypto_key
    }

    /// Sign nothing — bearer auth — and POST `body` to the `op` (`encrypt` /
    /// `decrypt`) endpoint, returning the success body bytes or mapping the
    /// failure.
    async fn invoke(&self, op: &str, token: &FederatedToken, body: &[u8]) -> Result<Vec<u8>> {
        let url = format!("{ENDPOINT_BASE}{}:{op}", self.crypto_key);
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
                    &format!("Cloud KMS request failed ({})", reqwest_category(&e)),
                )
            })?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| upstream(Some(status), "failed to read the Cloud KMS response body"))?;
        if (200..300).contains(&status) {
            Ok(bytes.to_vec())
        } else {
            Err(map_gcp_error(status, &bytes))
        }
    }
}

/// Construct the crate-local upstream error for GCP (no platform `K9O_*` code).
fn upstream(status: Option<u16>, detail: &str) -> KmsRestError {
    KmsRestError::UpstreamKms {
        provider: "gcp",
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

/// Cloud KMS error envelope: `{"error": {"code", "message", "status"}}`.
#[derive(Deserialize, Default)]
struct GcpErrorEnvelope {
    error: Option<GcpError>,
}

#[derive(Deserialize, Default)]
struct GcpError {
    message: Option<String>,
}

/// Map a non-2xx Cloud KMS response to the crate-local upstream error. (Unlike
/// AWS's `InvalidCiphertextException`, the exact GCP AAD-mismatch error signal
/// is not yet pinned, so every failure is surfaced as the vendor error with its
/// non-secret message — a precise integrity mapping is a follow-up.)
fn map_gcp_error(status: u16, body: &[u8]) -> KmsRestError {
    let parsed: GcpErrorEnvelope = serde_json::from_slice(body).unwrap_or_default();
    let detail = parsed
        .error
        .and_then(|e| e.message)
        .unwrap_or_else(|| "Cloud KMS error".to_string());
    KmsRestError::UpstreamKms {
        provider: "gcp",
        status: Some(status),
        detail,
    }
}

/// Software CRC32C (Castagnoli — polynomial `0x1EDC6F41`, the reflected form
/// `0x82F63B78`), matching the checksum Cloud KMS computes. Pure-Rust, table-
/// free bitwise: the KMS integrity-loop volume (one DEK wrap/unwrap per
/// operation) does not warrant a lookup table or SSE intrinsics.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Verify one leg of the Cloud KMS CRC32C integrity loop (GCP-recommended
/// defence-in-depth; encrypt / decrypt). `verified` is GCP's
/// `verified*Crc32c` flag (`false` ⇒ the CRC32C we sent was not delivered
/// intact); `returned` is GCP's `*Crc32c` over the bytes it returned; `bytes`
/// is what we received and recompute over.
///
/// A failure here is **transit corruption** between TLS termination and KMS
/// processing — TLS and the KMS AES-GCM tag still cover transport and
/// cryptographic integrity, so this is mapped to a **retryable upstream**
/// error, deliberately NOT the envelope-integrity (crypto-tamper) contract.
fn check_crc32c(verified: bool, returned: &str, bytes: &[u8]) -> Result<()> {
    if !verified {
        return Err(upstream(
            Some(200),
            "Cloud KMS did not verify the request CRC32C (transit corruption) — retry",
        ));
    }
    let expected: u32 = returned
        .parse()
        .map_err(|_| upstream(Some(200), "Cloud KMS returned a malformed CRC32C"))?;
    if crc32c(bytes) != expected {
        return Err(upstream(
            Some(200),
            "Cloud KMS response CRC32C mismatch (transit corruption) — retry",
        ));
    }
    Ok(())
}

/// Encrypt request: base64 `plaintext` + `additionalAuthenticatedData`, with
/// the `plaintextCrc32c` integrity checksum (Int64Value as a decimal string).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptRequest {
    plaintext: String,
    additional_authenticated_data: String,
    plaintext_crc32c: String,
}

/// Encrypt response: base64 `ciphertext` + the CRC32C integrity fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptResponse {
    ciphertext: String,
    /// CRC32C of the returned ciphertext (Int64Value string).
    ciphertext_crc32c: String,
    /// `false` ⇒ our `plaintextCrc32c` was not delivered intact.
    verified_plaintext_crc32c: bool,
}

/// Decrypt request: base64 `ciphertext` + `additionalAuthenticatedData`, with
/// the `ciphertextCrc32c` integrity checksum.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptRequest {
    ciphertext: String,
    additional_authenticated_data: String,
    ciphertext_crc32c: String,
}

/// Decrypt response: base64 `plaintext` + the CRC32C integrity fields.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptResponse {
    plaintext: String,
    /// CRC32C of the returned plaintext (Int64Value string).
    plaintext_crc32c: String,
    /// `false` ⇒ our `ciphertextCrc32c` was not delivered intact.
    verified_ciphertext_crc32c: bool,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl KmsRestProvider for GcpKmsRest {
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        aad: &AadContext,
    ) -> Result<Vec<u8>> {
        let aad_blob = aad.binding_blob()?;
        let mut request = EncryptRequest {
            plaintext: BASE64.encode(plaintext_or_dek),
            additional_authenticated_data: BASE64.encode(&aad_blob),
            plaintext_crc32c: crc32c(plaintext_or_dek).to_string(),
        };
        let mut body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Cloud KMS encrypt request"))?;
        request.plaintext.zeroize();

        let response_bytes = self.invoke("encrypt", token, &body).await?;
        body.zeroize();
        let response: EncryptResponse = serde_json::from_slice(&response_bytes)
            .map_err(|_| upstream(Some(200), "malformed Cloud KMS encrypt response"))?;
        let ciphertext = decode_bytes(&response.ciphertext)
            .map_err(|_| upstream(Some(200), "Cloud KMS ciphertext was not valid base64"))?;
        // Defence-in-depth integrity loop: GCP confirmed it received our
        // plaintext intact, and the returned ciphertext matches GCP's CRC32C.
        check_crc32c(
            response.verified_plaintext_crc32c,
            &response.ciphertext_crc32c,
            &ciphertext,
        )?;
        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let aad_blob = aad.binding_blob()?;
        let request = DecryptRequest {
            ciphertext: BASE64.encode(ciphertext),
            additional_authenticated_data: BASE64.encode(&aad_blob),
            ciphertext_crc32c: crc32c(ciphertext).to_string(),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the Cloud KMS decrypt request"))?;

        let mut response_bytes = self.invoke("decrypt", token, &body).await?;
        let (mut plaintext_b64, plaintext_crc32c, verified_ciphertext_crc32c) = {
            let response: DecryptResponse = serde_json::from_slice(&response_bytes)
                .map_err(|_| upstream(Some(200), "malformed Cloud KMS decrypt response"))?;
            (
                response.plaintext,
                response.plaintext_crc32c,
                response.verified_ciphertext_crc32c,
            )
        };
        response_bytes.zeroize();
        // Decode into a Zeroizing buffer first so the recovered plaintext is
        // wiped even on the integrity-loop early-return path below.
        let plaintext = Zeroizing::new(
            decode_bytes(&plaintext_b64)
                .map_err(|_| upstream(Some(200), "Cloud KMS plaintext was not valid base64"))?,
        );
        plaintext_b64.zeroize();
        check_crc32c(verified_ciphertext_crc32c, &plaintext_crc32c, &plaintext)?;
        Ok(plaintext)
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
            attestation_tier: AttestationTier::HardwareBacked,
            encryption_context: vec![("tenant".to_string(), "acme".to_string())],
            project_id: None,
        }
    }

    #[test]
    fn encrypt_request_uses_camelcase_and_base64() {
        let blob = aad().binding_blob().expect("blob");
        let request = EncryptRequest {
            plaintext: BASE64.encode(b"hello"),
            additional_authenticated_data: BASE64.encode(&blob),
            plaintext_crc32c: crc32c(b"hello").to_string(),
        };
        let json = serde_json::to_value(&request).expect("serializable");
        assert_eq!(json["plaintext"], "aGVsbG8=");
        assert!(json.get("additionalAuthenticatedData").is_some());
        // The AAD blob round-trips.
        let decoded = decode_bytes(json["additionalAuthenticatedData"].as_str().expect("str"))
            .expect("valid base64");
        assert_eq!(decoded, blob);
    }

    /// A live Cloud KMS answered in the standard alphabet and the strict URL-safe decoder
    /// refused it: every real seal failed. Almost any ciphertext has a `+` or `/`.
    #[test]
    fn a_google_bytes_field_decodes_in_either_alphabet_and_padding() {
        const BYTES: [u8; 2] = [0xfb, 0xff];
        assert_eq!(BASE64.encode(BYTES), "+/8=");
        for form in ["+/8=", "+/8", "-_8=", "-_8"] {
            assert_eq!(decode_bytes(form).unwrap(), BYTES, "{form}");
        }
        for bad in ["+_8=", "*/8=", "+/8=="] {
            assert!(decode_bytes(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn map_gcp_error_extracts_message_and_stays_crate_local() {
        let body =
            br#"{"error":{"code":400,"message":"Decryption failed","status":"INVALID_ARGUMENT"}}"#;
        let err = map_gcp_error(400, body);
        assert!(err.wire_code().is_none());
        let rendered = err.to_string();
        assert!(rendered.contains("Decryption failed"));
        assert!(rendered.contains("gcp"));
        assert!(rendered.contains("status 400"));
    }

    #[test]
    fn crc32c_matches_the_castagnoli_reference_vector() {
        // The canonical CRC32C check value (RFC 3720 / iSCSI) over "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn check_crc32c_round_trips_and_refuses_mismatch_or_unverified() {
        let bytes = b"the returned bytes";
        let good = crc32c(bytes).to_string();
        // Verified + matching CRC over the received bytes → OK.
        assert!(check_crc32c(true, &good, bytes).is_ok());
        // GCP did not verify our sent CRC (transit corruption) → upstream, retryable.
        assert!(check_crc32c(false, &good, bytes).is_err());
        // Returned CRC does not match the bytes we received → upstream.
        assert!(check_crc32c(true, "0", bytes).is_err());
        // Malformed CRC string → upstream, never a panic.
        assert!(check_crc32c(true, "not-a-number", bytes).is_err());
    }
}
