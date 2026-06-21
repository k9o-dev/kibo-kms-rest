//! AWS KMS REST provider (SigV4-signed), `kms-aws` feature.
//!
//! Each `Encrypt` / `Decrypt` is a plain HTTPS `POST /` to
//! `kms.<region>.amazonaws.com`, authenticated with a hand-rolled SigV4
//! signature (see [`crate::sigv4`]) over a federated STS credential — there is
//! no `aws-sdk-kms`. The request/response shapes are grounded in the official
//! AWS KMS API reference (the `awsJson1.1` protocol):
//!
//! - Action dispatch is by the `X-Amz-Target` header (`TrentService.Encrypt` /
//!   `TrentService.Decrypt`), `Content-Type: application/x-amz-json-1.1`.
//! - `Plaintext` (request, Encrypt) and `CiphertextBlob` (response, Encrypt /
//!   request, Decrypt) and `Plaintext` (response, Decrypt) are **base64** in
//!   the JSON body; `KeyId` is the raw key id / ARN.
//! - The AAD `{version, strategy, attestation_tier}` plus the caller's
//!   `encryption_context` bind into the KMS `EncryptionContext` map. On decrypt
//!   the context is re-supplied (never read from the envelope); KMS enforces
//!   the match and returns `InvalidCiphertextException` on a mismatch — which
//!   this crate maps to the envelope-integrity contract.

use super::{AadContext, KmsRestProvider};
use crate::auth::FederatedToken;
use crate::error::{KmsRestError, Result};
use crate::sigv4;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SigV4 service code for AWS KMS — the `kms` segment of the credential scope
/// (`YYYYMMDD/<region>/kms/aws4_request`), as shown verbatim in the KMS API
/// reference request examples.
const KMS_SERVICE: &str = "kms";
/// The `awsJson1.1` content type KMS requires on every request.
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const TARGET_ENCRYPT: &str = "TrentService.Encrypt";
const TARGET_DECRYPT: &str = "TrentService.Decrypt";

/// REST-direct client for AWS KMS.
///
/// Talks to the `kms.<region>.amazonaws.com` `Encrypt` / `Decrypt`
/// targets over HTTPS, authenticating with a SigV4 signature derived from
/// the federated session credential. No `aws-sdk-kms` — the request is
/// hand-rolled.
#[derive(Clone, Debug)]
pub struct AwsKmsRest {
    /// The KMS key ARN / id this client operates on.
    key_id: String,
    /// AWS region the key lives in (also the SigV4 signing region).
    region: String,
}

impl AwsKmsRest {
    /// Construct a client for a given key id and region.
    #[must_use]
    pub fn new(key_id: String, region: String) -> Self {
        Self { key_id, region }
    }

    /// The configured KMS key id / ARN.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The configured signing region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Sign and POST `body` to the KMS endpoint for `target`, returning the
    /// success-response body bytes or mapping the failure (see [`map_kms_error`]).
    /// Shared by `encrypt` and `decrypt`.
    async fn invoke(&self, target: &str, creds: &AwsCredentials, body: &[u8]) -> Result<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (date_stamp, amz_datetime) = sigv4::format_amz_datetime(now);
        let host = format!("kms.{}.amazonaws.com", self.region);
        let url = format!("https://{host}/");
        let authorization =
            sign_kms_post(creds, &self.region, &host, target, body, &amz_datetime, &date_stamp);

        let client = reqwest::Client::builder()
            .build()
            .map_err(|_| upstream(None, "failed to build the HTTPS client"))?;

        // `host` is set automatically by reqwest from the URL and is signed;
        // every other signed header is set explicitly. `authorization` is sent
        // but never itself part of the signature.
        let mut req = client
            .post(&url)
            .header("content-type", CONTENT_TYPE)
            .header("x-amz-target", target)
            .header("x-amz-date", &amz_datetime)
            .header("authorization", authorization)
            .body(body.to_vec());
        if let Some(token) = &creds.session_token {
            req = req.header("x-amz-security-token", token.clone());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| upstream(None, &format!("KMS request failed ({})", reqwest_category(&e))))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| upstream(Some(status), "failed to read the KMS response body"))?;

        if (200..300).contains(&status) {
            Ok(bytes.to_vec())
        } else {
            Err(map_kms_error(status, &bytes))
        }
    }
}

/// AWS STS temporary credential, parsed from the opaque [`FederatedToken`]
/// secret. The field names mirror the STS `Credentials` object verbatim
/// (PascalCase `AccessKeyId` / `SecretAccessKey` / `SessionToken`), so a caller
/// can pass an STS / Cognito credential straight through. `SessionToken` is
/// optional to also admit a long-term credential. The secret material is
/// wiped on drop.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "PascalCase")]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

/// Parse the opaque federated token as an STS credential object.
///
/// On failure the detail is a FIXED non-secret string — the token (and serde's
/// snippet of it) is never echoed into the error.
fn parse_credentials(token: &FederatedToken) -> Result<AwsCredentials> {
    serde_json::from_str::<AwsCredentials>(token.secret())
        .map_err(|_| upstream(None, "federated token is not a valid AWS STS credential object"))
}

/// Build the KMS `EncryptionContext` map from the shared AAD binding pairs
/// (the caller's context plus the three reserved dimensions). Deterministic
/// (`BTreeMap`) so the encrypt-time and re-supplied decrypt-time contexts match.
fn encryption_context(aad: &AadContext) -> BTreeMap<String, String> {
    aad.binding_pairs().into_iter().collect()
}

/// The signed-and-sent header set for a KMS POST, in the order built (the
/// canonicalizer sorts them). `x-amz-security-token` is included only with a
/// temporary credential; per the AWS SigV4 reference it must then appear in the
/// canonical request ("you must add this header in the list of CanonicalHeaders").
fn kms_headers(
    host: &str,
    target: &str,
    amz_datetime: &str,
    session_token: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), amz_datetime.to_string()),
        ("x-amz-target".to_string(), target.to_string()),
        ("content-type".to_string(), CONTENT_TYPE.to_string()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    headers
}

/// Produce the SigV4 `Authorization` header value for a KMS POST. Pure: the
/// datetime and credentials are passed in, so the signing path is unit-testable
/// with no clock or network.
fn sign_kms_post(
    creds: &AwsCredentials,
    region: &str,
    host: &str,
    target: &str,
    body: &[u8],
    amz_datetime: &str,
    date_stamp: &str,
) -> String {
    let payload_hash = sigv4::sha256_hex(body);
    let headers = kms_headers(host, target, amz_datetime, creds.session_token.as_deref());
    let (canonical, signed_headers) =
        sigv4::canonical_request("POST", "/", "", &headers, &payload_hash);
    let scope = sigv4::credential_scope(date_stamp, region, KMS_SERVICE);
    let string_to_sign = sigv4::string_to_sign(amz_datetime, &scope, &canonical);
    let mut signing_key = sigv4::derive_signing_key(&creds.secret_access_key, date_stamp, region, KMS_SERVICE);
    let signature = sigv4::signature_hex(&signing_key, &string_to_sign);
    signing_key.zeroize();
    sigv4::authorization_header(&creds.access_key_id, &scope, &signed_headers, &signature)
}

/// A non-2xx KMS response, parsed for its `awsJson1.1` error discriminator.
#[derive(Deserialize, Default)]
struct KmsErrorBody {
    /// Preferred error-type discriminator (`namespace#Name[:url]`).
    #[serde(rename = "__type", default)]
    type_: Option<String>,
    /// Legacy alternative discriminator field.
    #[serde(default)]
    code: Option<String>,
    /// Human-readable message (lowercase per de-facto AWS convention).
    #[serde(default)]
    message: Option<String>,
    /// Some services capitalise the message field.
    #[serde(rename = "Message", default)]
    message_pascal: Option<String>,
}

/// Reduce an `awsJson1.1` error-type value to its bare shape name: take the
/// segment after the last `#`, then drop any trailing `:url` decoration.
fn sanitize_error_type(raw: &str) -> &str {
    let after_hash = raw.rsplit('#').next().unwrap_or(raw);
    after_hash.split(':').next().unwrap_or(after_hash)
}

/// Map a non-2xx KMS response to the crate error surface.
///
/// `InvalidCiphertextException` — KMS's signal that the ciphertext or its bound
/// `EncryptionContext` (our AAD) is corrupt or mismatched — maps to the
/// envelope-integrity contract (`K9O_ENVELOPE_INTEGRITY_FAILURE`, rule 2). Every
/// other failure is the customer's own KMS error, surfaced crate-local with the
/// non-secret status + vendor message and **no** platform code (rule 3).
fn map_kms_error(status: u16, body: &[u8]) -> KmsRestError {
    let parsed: KmsErrorBody = serde_json::from_slice(body).unwrap_or_default();
    let raw_type = parsed.type_.as_deref().or(parsed.code.as_deref()).unwrap_or("");
    let kind = sanitize_error_type(raw_type);

    if kind == "InvalidCiphertextException" {
        return KmsRestError::EnvelopeIntegrity;
    }

    let message = parsed.message.as_deref().or(parsed.message_pascal.as_deref());
    let detail = match (kind.is_empty(), message) {
        (false, Some(m)) => format!("{kind}: {m}"),
        (false, None) => kind.to_string(),
        (true, Some(m)) => m.to_string(),
        (true, None) => "unrecognized KMS error response".to_string(),
    };
    KmsRestError::UpstreamKms {
        provider: "aws",
        status: Some(status),
        detail,
    }
}

/// Construct the crate-local upstream-KMS error (no platform `K9O_*` code).
fn upstream(status: Option<u16>, detail: &str) -> KmsRestError {
    KmsRestError::UpstreamKms {
        provider: "aws",
        status,
        detail: detail.to_string(),
    }
}

/// A coarse, non-secret category for a transport failure (a reqwest error never
/// carries the request headers, but we surface only the category to be safe).
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

/// Encrypt request body: `KeyId`, base64 `Plaintext`, `EncryptionContext`.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptRequest<'a> {
    key_id: &'a str,
    plaintext: String,
    encryption_context: BTreeMap<String, String>,
}

/// Encrypt response: base64 `CiphertextBlob`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptResponse {
    ciphertext_blob: String,
}

/// Decrypt request body: base64 `CiphertextBlob`, `KeyId`, `EncryptionContext`.
/// `KeyId` is optional for symmetric keys, but we always supply it so KMS
/// asserts the ciphertext was produced by the bound customer key.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptRequest<'a> {
    ciphertext_blob: String,
    key_id: &'a str,
    encryption_context: BTreeMap<String, String>,
}

/// Decrypt response: base64 `Plaintext`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptResponse {
    plaintext: String,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl KmsRestProvider for AwsKmsRest {
    async fn encrypt(
        &self,
        token: &FederatedToken,
        plaintext_or_dek: &[u8],
        aad: &AadContext,
    ) -> Result<Vec<u8>> {
        let creds = parse_credentials(token)?;
        let mut request = EncryptRequest {
            key_id: &self.key_id,
            plaintext: BASE64.encode(plaintext_or_dek),
            encryption_context: encryption_context(aad),
        };
        let mut body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the KMS Encrypt request"))?;
        // Wipe our base64 copies of the plaintext (the caller still owns the
        // original); the reqwest-internal copy of `body` is transient.
        request.plaintext.zeroize();

        let response_bytes = self.invoke(TARGET_ENCRYPT, &creds, &body).await?;
        body.zeroize();
        let response: EncryptResponse = serde_json::from_slice(&response_bytes)
            .map_err(|_| upstream(Some(200), "malformed KMS Encrypt response"))?;
        // CiphertextBlob is not secret; return raw provider ciphertext bytes.
        BASE64
            .decode(response.ciphertext_blob)
            .map_err(|_| upstream(Some(200), "KMS Encrypt response CiphertextBlob was not valid base64"))
    }

    async fn decrypt(
        &self,
        token: &FederatedToken,
        ciphertext: &[u8],
        aad: &AadContext,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let creds = parse_credentials(token)?;
        let request = DecryptRequest {
            ciphertext_blob: BASE64.encode(ciphertext),
            key_id: &self.key_id,
            encryption_context: encryption_context(aad),
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| upstream(None, "failed to serialize the KMS Decrypt request"))?;

        let mut response_bytes = self.invoke(TARGET_DECRYPT, &creds, &body).await?;
        // The response body carries the recovered plaintext (base64) — the
        // most sensitive material this crate handles. Wipe the intermediates.
        let mut plaintext_b64 = {
            let response: DecryptResponse = serde_json::from_slice(&response_bytes)
                .map_err(|_| upstream(Some(200), "malformed KMS Decrypt response"))?;
            response.plaintext
        };
        response_bytes.zeroize();
        let plaintext = BASE64
            .decode(&plaintext_b64)
            .map_err(|_| upstream(Some(200), "KMS Decrypt response Plaintext was not valid base64"))?;
        plaintext_b64.zeroize();
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::AttestationTier;
    use crate::strategy::Strategy;

    // Official aws-sig-v4-test-suite shared credentials (used by the signing
    // core's get-vanilla KAT in `sigv4`); reused here so the credential-scope
    // structure is asserted against known values.
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const ACCESS_KEY: &str = "AKIDEXAMPLE";

    fn test_creds(session: Option<&str>) -> AwsCredentials {
        AwsCredentials {
            access_key_id: ACCESS_KEY.to_string(),
            secret_access_key: SECRET.to_string(),
            session_token: session.map(str::to_string),
        }
    }

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
    fn parse_credentials_reads_pascalcase_sts_shape() {
        let token = FederatedToken::new(
            r#"{"AccessKeyId":"AKID","SecretAccessKey":"sk","SessionToken":"tok","Expiration":"2026-01-01T00:00:00Z"}"#
                .to_string(),
            9_999_999_999,
        );
        let creds = parse_credentials(&token).expect("valid STS JSON");
        assert_eq!(creds.access_key_id, "AKID");
        assert_eq!(creds.secret_access_key, "sk");
        assert_eq!(creds.session_token.as_deref(), Some("tok"));
    }

    #[test]
    fn parse_credentials_allows_long_term_no_session_token() {
        let token = FederatedToken::new(
            r#"{"AccessKeyId":"AKID","SecretAccessKey":"sk"}"#.to_string(),
            9_999_999_999,
        );
        let creds = parse_credentials(&token).expect("valid long-term credential");
        assert!(creds.session_token.is_none());
    }

    #[test]
    fn parse_credentials_failure_never_echoes_the_token() {
        // A malformed token containing a secret-looking value must not leak.
        let token = FederatedToken::new("SUPERSECRETNOTJSON".to_string(), 9_999_999_999);
        // `AwsCredentials` intentionally has no `Debug` (it holds the secret
        // access key), so take the error via `.err()` rather than `unwrap_err`.
        let err = parse_credentials(&token).err().expect("expected a parse failure");
        let rendered = err.to_string();
        assert!(!rendered.contains("SUPERSECRETNOTJSON"), "token leaked into error");
        assert!(err.wire_code().is_none(), "credential parse stays crate-local");
    }

    #[test]
    fn encryption_context_binds_three_reserved_dimensions_plus_caller() {
        let ctx = encryption_context(&aad());
        assert_eq!(ctx.get("kibo:version").map(String::as_str), Some("1"));
        assert_eq!(ctx.get("kibo:strategy").map(String::as_str), Some("local_envelope"));
        assert_eq!(ctx.get("kibo:attestation_tier").map(String::as_str), Some("hardware_backed"));
        assert_eq!(ctx.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(ctx.len(), 4);
    }

    #[test]
    fn encryption_context_reserved_keys_win_on_collision() {
        let mut a = aad();
        // A caller attempting to override a reserved key must not succeed.
        a.encryption_context = vec![("kibo:strategy".to_string(), "forged".to_string())];
        let ctx = encryption_context(&a);
        assert_eq!(ctx.get("kibo:strategy").map(String::as_str), Some("local_envelope"));
    }

    #[test]
    fn encrypt_request_serializes_to_pascalcase_with_base64_plaintext() {
        let request = EncryptRequest {
            key_id: "key-123",
            plaintext: BASE64.encode(b"hello"),
            encryption_context: encryption_context(&aad()),
        };
        let json = serde_json::to_value(&request).expect("serializable");
        assert_eq!(json["KeyId"], "key-123");
        assert_eq!(json["Plaintext"], "aGVsbG8="); // base64("hello")
        assert_eq!(json["EncryptionContext"]["kibo:version"], "1");
        assert_eq!(json["EncryptionContext"]["tenant"], "acme");
    }

    #[test]
    fn canonical_request_signs_security_token_and_sorts_headers() {
        let host = "kms.us-east-1.amazonaws.com";
        let amz = "20150830T123600Z";
        let body = br#"{"KeyId":"k"}"#;
        let payload_hash = sigv4::sha256_hex(body);
        let headers = kms_headers(host, TARGET_ENCRYPT, amz, Some("TESTSESSIONTOKEN"));
        let (creq, signed_headers) =
            sigv4::canonical_request("POST", "/", "", &headers, &payload_hash);

        assert_eq!(
            signed_headers,
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
        );
        let expected = format!(
            "POST\n/\n\n\
             content-type:application/x-amz-json-1.1\n\
             host:kms.us-east-1.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n\
             x-amz-security-token:TESTSESSIONTOKEN\n\
             x-amz-target:TrentService.Encrypt\n\n\
             content-type;host;x-amz-date;x-amz-security-token;x-amz-target\n\
             {payload_hash}"
        );
        assert_eq!(creq, expected);
    }

    #[test]
    fn long_term_credential_omits_security_token_from_signed_set() {
        let headers = kms_headers("kms.us-east-1.amazonaws.com", TARGET_ENCRYPT, "20150830T123600Z", None);
        let (_, signed_headers) = sigv4::canonical_request("POST", "/", "", &headers, &sigv4::sha256_hex(b""));
        assert_eq!(signed_headers, "content-type;host;x-amz-date;x-amz-target");
    }

    #[test]
    fn authorization_header_uses_kms_service_scope() {
        let creds = test_creds(Some("TESTSESSIONTOKEN"));
        let auth = sign_kms_post(
            &creds,
            "us-east-1",
            "kms.us-east-1.amazonaws.com",
            TARGET_ENCRYPT,
            br#"{"KeyId":"k"}"#,
            "20150830T123600Z",
            "20150830",
        );
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/kms/aws4_request,"),
            "scope must name the kms service: {auth}"
        );
        assert!(
            auth.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,"),
            "security token must be signed: {auth}"
        );
        assert!(auth.contains("Signature="));
    }

    #[test]
    fn sanitize_error_type_strips_namespace_and_url() {
        assert_eq!(sanitize_error_type("InvalidCiphertextException"), "InvalidCiphertextException");
        assert_eq!(
            sanitize_error_type("com.amazonaws.kms#InvalidCiphertextException"),
            "InvalidCiphertextException"
        );
        assert_eq!(
            sanitize_error_type("FooError:http://internal.amazon.com/coral/"),
            "FooError"
        );
        assert_eq!(
            sanitize_error_type("smithy.example#FooError:http://x"),
            "FooError"
        );
    }

    #[test]
    fn invalid_ciphertext_maps_to_envelope_integrity() {
        // AAD / context mismatch is the envelope-integrity contract (rule 2).
        let body = br#"{"__type":"com.amazonaws.kms#InvalidCiphertextException","message":"bad ctx"}"#;
        let err = map_kms_error(400, body);
        assert!(matches!(err, KmsRestError::EnvelopeIntegrity));
        assert_eq!(err.wire_code().unwrap().as_str(), "K9O_ENVELOPE_INTEGRITY_FAILURE");
    }

    #[test]
    fn vendor_failure_maps_to_crate_local_upstream() {
        // Permission / availability failures are the customer's vendor error
        // (rule 3): no platform code, status + non-secret message preserved.
        let body = br#"{"__type":"AccessDeniedException","message":"not authorized"}"#;
        let err = map_kms_error(400, body);
        assert!(err.wire_code().is_none());
        let rendered = err.to_string();
        assert!(rendered.contains("AccessDeniedException"));
        assert!(rendered.contains("not authorized"));
        assert!(rendered.contains("status 400"));
    }

    #[test]
    fn unparseable_error_body_still_yields_a_crate_local_error() {
        let err = map_kms_error(503, b"<html>gateway</html>");
        assert!(err.wire_code().is_none());
        assert!(err.to_string().contains("status 503"));
    }
}
