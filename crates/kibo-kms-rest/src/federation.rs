//! Federation acquisition — how the SDK obtains the short-TTL,
//! single-key-scoped [`FederatedToken`] it presents to the customer's KMS/HSM.
//!
//! **The strict-ZK spine:** Kilimanjaro never mints, holds, or
//! proxies a token capable of calling the customer's KMS. The customer's own IdP
//! (or their self-deployed Gate) issues an OIDC/JWT identity token *inside the
//! customer's trust boundary*; the SDK exchanges it **on-device, here** at the
//! provider's standard workload-identity federation endpoint for a credential
//! scoped to the **one** key and the two envelope ops. This module performs that
//! exchange — `reqwest` only (the wasm `fetch` backend), no vendor SDKs.
//!
//! Per-provider and feature-gated, mirroring the composable provider set.
//! Each `acquire_*` returns a [`FederatedToken`] whose `secret` is in exactly the
//! shape the matching [`crate::provider`] backend consumes (e.g. AWS: a PascalCase
//! STS-credentials JSON object for SigV4; GCP/Azure: a raw bearer; Vault: the
//! `client_token`). Acquisition is clock-free — the absolute expiry is read from
//! the **provider's authoritative response**, never a local `SystemTime` (which is
//! unavailable on `wasm32-unknown-unknown`).

/// Parse an RFC 3339 / ISO 8601 UTC instant of the fixed form
/// `YYYY-MM-DDTHH:MM:SSZ` (the AWS STS `Expiration` shape) into a Unix timestamp
/// in seconds. Returns `None` on any structural deviation. Integer-only, no deps,
/// no local clock — the civil→days conversion is Howard Hinnant's
/// `days_from_civil` (the exact inverse of [`crate::sigv4::format_amz_datetime`]'s
/// `civil_from_days`), valid for the proleptic Gregorian calendar.
///
/// (Gated to `kms-aws` while AWS is the only acquirer; broaden the cfg as
/// GCP/Azure/Vault federation lands — every provider's response carries an
/// expiry instant this parses.)
#[cfg(feature = "kms-aws")]
#[must_use]
pub(crate) fn parse_iso8601_z_to_unix(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    // Exactly "YYYY-MM-DDTHH:MM:SSZ" — 20 bytes, fixed separators.
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |start: usize, len: usize| -> Option<i64> {
        let mut v: i64 = 0;
        for &c in &b[start..start + len] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + i64::from(c - b'0');
        }
        Some(v)
    };
    let year = num(0, 4)?;
    let month = num(5, 2)?;
    let day = num(8, 2)?;
    let hour = num(11, 2)?;
    let min = num(14, 2)?;
    let sec = num(17, 2)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // Howard Hinnant's days_from_civil — days since 1970-01-01 (can be negative).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + min * 60 + sec;
    u64::try_from(secs).ok()
}

// ============================================================================
// AWS — STS AssumeRoleWithWebIdentity (query protocol, API version 2011-06-15).
// Grounded against the official STS API reference. The single-key scope is an
// inline SESSION POLICY (`Policy`), intersected with the role's identity policy.
// Ops scoped to `kms:Encrypt` + `kms:Decrypt` — what the `kms-aws` provider
// actually calls (on-device DEK generation + `Encrypt` wrap), NOT
// `GenerateDataKey`.
// ============================================================================
#[cfg(feature = "kms-aws")]
mod aws {
    use super::parse_iso8601_z_to_unix;
    use crate::auth::FederatedToken;
    use crate::error::{KmsRestError, Result};

    /// Inputs for an AWS STS `AssumeRoleWithWebIdentity` federation exchange.
    pub struct AwsStsConfig<'a> {
        /// ARN of the role to assume — its trust policy must accept the
        /// customer's OIDC issuer (the strict-ZK anchor: Kilimanjaro is not in
        /// the trust policy).
        pub role_arn: &'a str,
        /// Session name (`[\w+=,.@-]*`, 2–64 chars) — surfaced in CloudTrail.
        pub session_name: &'a str,
        /// Region of the bound KMS key; also selects the regional STS endpoint.
        pub region: &'a str,
        /// The customer-issued OIDC identity token (secret — never logged).
        pub web_identity_token: &'a str,
        /// Full ARN of the one KMS key the session is scoped to.
        pub key_arn: &'a str,
        /// Requested session lifetime (900–43200; STS clamps to the role max).
        pub duration_secs: u32,
    }

    /// Build the inline session policy that pins the assumed session to the
    /// **one** key and the two envelope ops. This is the strict-ZK scope: even a
    /// role with broader KMS rights yields a session that can only
    /// `Encrypt`/`Decrypt` against `key_arn` (the session ∩ role intersection).
    #[must_use]
    pub(super) fn single_key_session_policy(key_arn: &str) -> String {
        // key_arn is an AWS ARN (`[\w:/-]`-class) — no JSON-special characters,
        // so direct interpolation is safe; assert-free by construction.
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["kms:Encrypt","kms:Decrypt"],"Resource":"{key_arn}"}}]}}"#
        )
    }

    /// Extract the text content of the **first** `<tag>…</tag>` in `xml`.
    /// Minimal + defensive (the STS response is a fixed AWS-generated schema);
    /// returns `None` if the tag is absent or unterminated.
    fn extract_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        Some(&xml[start..end])
    }

    /// The PascalCase STS-credentials JSON written into the [`FederatedToken`]
    /// secret — field names match the `kms-aws` provider's `AwsCredentials`
    /// deserialize exactly, so the wrap/unwrap SigV4 path parses it verbatim.
    #[derive(serde::Serialize)]
    #[serde(rename_all = "PascalCase")]
    struct StsSecret<'a> {
        access_key_id: &'a str,
        secret_access_key: &'a str,
        session_token: &'a str,
    }

    /// A crate-local AWS-federation error (no platform `K9O_*` code — a failure
    /// here is the customer's IdP / role-trust / policy issue, not a platform
    /// fault). The detail is a FIXED non-secret string — the OIDC token is never
    /// echoed.
    fn fed_err(detail: &'static str) -> KmsRestError {
        KmsRestError::UpstreamKms {
            provider: "aws-sts",
            status: None,
            detail: detail.to_string(),
        }
    }

    /// Exchange the customer OIDC token for a single-key-scoped STS session
    /// credential, returned as a [`FederatedToken`] whose secret is the
    /// PascalCase STS-credentials JSON the `kms-aws` provider's SigV4 path parses.
    ///
    /// # Errors
    /// [`KmsRestError::UpstreamKms`] (`provider: "aws-sts"`) on a non-2xx STS
    /// response (expired/invalid token, rejected claim, malformed policy) or an
    /// unparseable credential body — all with fixed, non-secret detail.
    pub async fn acquire_aws_sts(
        client: &reqwest::Client,
        cfg: &AwsStsConfig<'_>,
    ) -> Result<FederatedToken> {
        let endpoint = format!("https://sts.{}.amazonaws.com/", cfg.region);
        let policy = single_key_session_policy(cfg.key_arn);
        let duration = cfg.duration_secs.to_string();
        // reqwest `.form` URL-encodes every value (PascalCase param names per the
        // STS query protocol). POST (not GET) — the OIDC token alone can reach
        // 20 KiB, past any URL limit.
        let params = [
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", cfg.role_arn),
            ("RoleSessionName", cfg.session_name),
            ("WebIdentityToken", cfg.web_identity_token),
            ("Policy", policy.as_str()),
            ("DurationSeconds", duration.as_str()),
        ];

        let resp = client
            .post(&endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|_| fed_err("STS request failed (transport)"))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|_| fed_err("STS response body unreadable"))?;

        if !status.is_success() {
            // Surface only the STS error <Code> (non-secret), never the body.
            let code = extract_tag(&body, "Code").unwrap_or("Unknown");
            let detail: &'static str = match code {
                "ExpiredToken" | "InvalidIdentityToken" => {
                    "STS rejected the web-identity token (expired or invalid)"
                }
                "IDPRejectedClaim" => "STS: identity-provider rejected the claim",
                "MalformedPolicyDocument" => "STS: malformed session policy",
                "AccessDenied" => "STS: role trust policy denied the assumption",
                _ => "STS AssumeRoleWithWebIdentity failed",
            };
            return Err(KmsRestError::UpstreamKms {
                provider: "aws-sts",
                status: Some(status.as_u16()),
                detail: detail.to_string(),
            });
        }

        // Parse the <Credentials> block (PascalCase tags, mirrored straight into
        // the secret JSON the provider expects).
        let creds = extract_tag(&body, "Credentials")
            .ok_or_else(|| fed_err("STS response missing Credentials"))?;
        let access_key_id = extract_tag(creds, "AccessKeyId")
            .ok_or_else(|| fed_err("STS Credentials missing AccessKeyId"))?;
        let secret_access_key = extract_tag(creds, "SecretAccessKey")
            .ok_or_else(|| fed_err("STS Credentials missing SecretAccessKey"))?;
        let session_token = extract_tag(creds, "SessionToken")
            .ok_or_else(|| fed_err("STS Credentials missing SessionToken"))?;
        let expiration = extract_tag(creds, "Expiration")
            .ok_or_else(|| fed_err("STS Credentials missing Expiration"))?;

        let expires_at = parse_iso8601_z_to_unix(expiration)
            .ok_or_else(|| fed_err("STS Expiration not a valid ISO-8601 instant"))?;

        // Build the PascalCase secret via serde (guaranteed field-name parity
        // with the provider's `AwsCredentials` deserialize — no hand JSON).
        let secret = serde_json::to_string(&StsSecret {
            access_key_id,
            secret_access_key,
            session_token,
        })
        .map_err(|_| fed_err("STS credential serialisation failed"))?;

        Ok(FederatedToken::new(secret, expires_at))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // The documented STS sample response (AWS STS API reference).
        const SAMPLE: &str = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <SessionToken>AQoDYXdzEE0aSESSIONTOKEN</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMISECRETKEY</SecretAccessKey>
      <Expiration>2014-10-24T23:00:23Z</Expiration>
      <AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;

        #[test]
        fn session_policy_scopes_to_one_key_and_two_ops() {
            let p = single_key_session_policy("arn:aws:kms:us-east-1:111122223333:key/abcd");
            assert!(p.contains(r#""Resource":"arn:aws:kms:us-east-1:111122223333:key/abcd""#));
            assert!(p.contains(r#""kms:Encrypt""#));
            assert!(p.contains(r#""kms:Decrypt""#));
            // NOT GenerateDataKey, and not a wildcard resource.
            assert!(!p.contains("GenerateDataKey"));
            assert!(!p.contains(r#""Resource":"*""#));
        }

        #[test]
        fn extract_tag_pulls_nested_credentials() {
            let creds = extract_tag(SAMPLE, "Credentials").unwrap();
            assert_eq!(
                extract_tag(creds, "AccessKeyId").unwrap(),
                "ASgeIAIOSFODNN7EXAMPLE"
            );
            assert_eq!(
                extract_tag(creds, "SecretAccessKey").unwrap(),
                "wJalrXUtnFEMISECRETKEY"
            );
            assert_eq!(
                extract_tag(creds, "SessionToken").unwrap(),
                "AQoDYXdzEE0aSESSIONTOKEN"
            );
            assert_eq!(
                extract_tag(creds, "Expiration").unwrap(),
                "2014-10-24T23:00:23Z"
            );
        }

        #[test]
        fn extract_tag_absent_is_none() {
            assert!(extract_tag(SAMPLE, "NoSuchTag").is_none());
            assert!(extract_tag("<Open>no close", "Open").is_none());
        }

        #[test]
        fn sample_expiration_parses_to_unix() {
            // 2014-10-24T23:00:23Z == 1414191623 (verified against a Unix epoch table).
            assert_eq!(
                parse_iso8601_z_to_unix("2014-10-24T23:00:23Z"),
                Some(1_414_191_623)
            );
        }

        #[test]
        fn secret_json_round_trips_through_provider_parse_shape() {
            // The secret must deserialize as the provider's PascalCase AwsCredentials.
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Mirror {
                access_key_id: String,
                secret_access_key: String,
                session_token: Option<String>,
            }
            let secret = serde_json::to_string(&StsSecret {
                access_key_id: "AKID",
                secret_access_key: "SKEY",
                session_token: "STOK",
            })
            .unwrap();
            let parsed: Mirror = serde_json::from_str(&secret).unwrap();
            assert_eq!(parsed.access_key_id, "AKID");
            assert_eq!(parsed.secret_access_key, "SKEY");
            assert_eq!(parsed.session_token.as_deref(), Some("STOK"));
        }
    }
}

#[cfg(feature = "kms-aws")]
pub use aws::{AwsStsConfig, acquire_aws_sts};

// ============================================================================
// GCP — Workload Identity Federation STS token exchange (RFC 8693).
// Grounded against the GCP STS v1 token reference. The single-key scope is
// GCP-IAM-side (`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the one
// `cryptoKey`, granted to the WIF principal) — NOT in the token request, so
// there is no session policy to construct here (cf. AWS). The OAuth `scope` is
// the standard `cloud-platform`; the request body is camelCase JSON, the
// response the snake_case RFC-8693 shape with a RELATIVE `expires_in`.
// ============================================================================
#[cfg(feature = "kms-gcp")]
mod gcp {
    use crate::auth::FederatedToken;
    use crate::error::{KmsRestError, Result};

    /// Inputs for a GCP STS Workload Identity Federation token exchange.
    pub struct GcpWifConfig<'a> {
        /// The WIF provider audience —
        /// `//iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
        pub audience: &'a str,
        /// The customer-issued OIDC identity token (secret — never logged).
        pub subject_token: &'a str,
        /// The subject-token-type URN (e.g.
        /// `urn:ietf:params:oauth:token-type:jwt` for an OIDC JWT).
        pub subject_token_type: &'a str,
        /// The current Unix time in seconds, from the host clock (the binding
        /// supplies it — the crate never reads a local clock, unavailable on
        /// wasm). The absolute expiry is `now + expires_in`.
        pub now_unix_secs: u64,
    }

    /// The standard OAuth scope for Cloud KMS access. The single-key restriction
    /// is the IAM binding on the `cryptoKey`, not this scope.
    const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

    /// camelCase request body (GCP STS v1 token-exchange).
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ExchangeRequest<'a> {
        grant_type: &'a str,
        audience: &'a str,
        scope: &'a str,
        requested_token_type: &'a str,
        subject_token: &'a str,
        subject_token_type: &'a str,
    }

    /// snake_case response body (the RFC 8693 token-exchange shape).
    #[derive(serde::Deserialize)]
    struct ExchangeResponse {
        access_token: String,
        expires_in: u64,
    }

    fn fed_err(detail: &'static str) -> KmsRestError {
        KmsRestError::UpstreamKms {
            provider: "gcp-sts",
            status: None,
            detail: detail.to_string(),
        }
    }

    /// Exchange the customer OIDC token at GCP STS for a short-TTL federated
    /// access token, returned as a [`FederatedToken`] whose secret is the raw
    /// bearer the `kms-gcp` provider sends as `Authorization: Bearer`.
    ///
    /// # Errors
    /// [`KmsRestError::UpstreamKms`] (`provider: "gcp-sts"`) on a non-2xx
    /// exchange (invalid/expired subject token, misconfigured pool) or an
    /// unparseable response — fixed, non-secret detail.
    pub async fn acquire_gcp_wif(
        client: &reqwest::Client,
        cfg: &GcpWifConfig<'_>,
    ) -> Result<FederatedToken> {
        let req = ExchangeRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            audience: cfg.audience,
            scope: CLOUD_PLATFORM_SCOPE,
            requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
            subject_token: cfg.subject_token,
            subject_token_type: cfg.subject_token_type,
        };

        // No Authorization header (per the GCP STS reference).
        let resp = client
            .post("https://sts.googleapis.com/v1/token")
            .json(&req)
            .send()
            .await
            .map_err(|_| fed_err("GCP STS request failed (transport)"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(KmsRestError::UpstreamKms {
                provider: "gcp-sts",
                status: Some(status.as_u16()),
                detail: "GCP STS token exchange rejected the subject token".to_string(),
            });
        }

        let body: ExchangeResponse = resp
            .json()
            .await
            .map_err(|_| fed_err("GCP STS response not a valid token-exchange object"))?;

        let expires_at = cfg.now_unix_secs.saturating_add(body.expires_in);
        Ok(FederatedToken::new(body.access_token, expires_at))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn exchange_request_serializes_camelcase_with_the_rfc8693_urns() {
            let req = ExchangeRequest {
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                audience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/pr",
                scope: CLOUD_PLATFORM_SCOPE,
                requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
                subject_token: "OIDC",
                subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
            };
            let j = serde_json::to_string(&req).unwrap();
            // camelCase field names (GCP STS v1), exact URNs.
            assert!(j.contains(r#""grantType":"urn:ietf:params:oauth:grant-type:token-exchange""#));
            assert!(j.contains(
                r#""requestedTokenType":"urn:ietf:params:oauth:token-type:access_token""#
            ));
            assert!(j.contains(r#""subjectToken":"OIDC""#));
            assert!(j.contains(r#""subjectTokenType":"urn:ietf:params:oauth:token-type:jwt""#));
            assert!(j.contains(r#""scope":"https://www.googleapis.com/auth/cloud-platform""#));
        }

        #[test]
        fn response_parses_snake_case_rfc8693() {
            // The token-exchange RESPONSE is snake_case (RFC 8693), distinct from
            // the camelCase request.
            let body = r#"{"access_token":"ya29.TOKEN","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3599}"#;
            let r: ExchangeResponse = serde_json::from_str(body).unwrap();
            assert_eq!(r.access_token, "ya29.TOKEN");
            assert_eq!(r.expires_in, 3599);
        }

        #[test]
        fn expiry_is_now_plus_relative_expires_in() {
            // now + expires_in (the response carries a relative duration).
            let body: ExchangeResponse =
                serde_json::from_str(r#"{"access_token":"t","expires_in":3600}"#).unwrap();
            let expires_at = 1_000_000_u64.saturating_add(body.expires_in);
            assert_eq!(expires_at, 1_003_600);
        }
    }
}

#[cfg(feature = "kms-gcp")]
pub use gcp::{GcpWifConfig, acquire_gcp_wif};

// ============================================================================
// Azure — Entra Workload Identity Federation (client_credentials + a federated
// `client_assertion`). Grounded against the Microsoft identity platform v2
// client-credentials reference. The app registration's federated credential
// trusts the customer's external IdP; the OIDC token is presented as the
// `client_assertion` (no client secret). The single-key scope is Key-Vault /
// Managed-HSM RBAC-side (`wrapKey`/`unwrapKey` on the one key) — NOT in the
// request; the `scope` is the resource default (caller picks Key Vault vs
// Managed HSM). Form-urlencoded request, JSON response, RELATIVE `expires_in`.
// ============================================================================
#[cfg(feature = "kms-azure")]
mod azure {
    use crate::auth::FederatedToken;
    use crate::error::{KmsRestError, Result};

    /// Inputs for an Azure Entra federated `client_credentials` token request.
    pub struct AzureEntraConfig<'a> {
        /// The Entra tenant ID (the `{tenant}` path segment).
        pub tenant_id: &'a str,
        /// The app-registration client ID whose federated credential trusts the
        /// customer's external IdP.
        pub client_id: &'a str,
        /// The customer-issued OIDC identity token, presented as the
        /// `client_assertion` (secret — never logged).
        pub client_assertion: &'a str,
        /// The resource scope — `https://vault.azure.net/.default` (Key Vault,
        /// BYOK) or `https://managedhsm.azure.net/.default` (Managed HSM, HYOK).
        pub scope: &'a str,
        /// Host Unix time in seconds (the binding supplies it — no local clock).
        /// Absolute expiry is `now + expires_in`.
        pub now_unix_secs: u64,
    }

    /// JSON response (Microsoft identity platform v2 token endpoint).
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: u64,
    }

    fn fed_err(detail: &'static str) -> KmsRestError {
        KmsRestError::UpstreamKms {
            provider: "azure-entra",
            status: None,
            detail: detail.to_string(),
        }
    }

    /// Exchange the customer OIDC token (as a federated `client_assertion`) at
    /// the Entra token endpoint for a short-TTL Key Vault / Managed HSM bearer,
    /// returned as a [`FederatedToken`] the `kms-azure` provider sends as
    /// `Authorization: Bearer`.
    ///
    /// # Errors
    /// [`KmsRestError::UpstreamKms`] (`provider: "azure-entra"`) on a non-2xx
    /// token response (federated-credential trust failure, expired assertion) or
    /// an unparseable body — fixed, non-secret detail.
    pub async fn acquire_azure_entra(
        client: &reqwest::Client,
        cfg: &AzureEntraConfig<'_>,
    ) -> Result<FederatedToken> {
        let endpoint = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            cfg.tenant_id
        );
        // Form-urlencoded; `client_assertion_type` + `client_assertion` replace
        // the client secret (federated-credential flow).
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", cfg.client_id),
            ("scope", cfg.scope),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", cfg.client_assertion),
        ];

        let resp = client
            .post(&endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|_| fed_err("Entra token request failed (transport)"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(KmsRestError::UpstreamKms {
                provider: "azure-entra",
                status: Some(status.as_u16()),
                detail: "Entra rejected the federated client assertion".to_string(),
            });
        }

        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|_| fed_err("Entra response not a valid token object"))?;

        let expires_at = cfg.now_unix_secs.saturating_add(body.expires_in);
        Ok(FederatedToken::new(body.access_token, expires_at))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn token_response_parses() {
            let body = r#"{"token_type":"Bearer","expires_in":3599,"access_token":"eyJ0..."}"#;
            let r: TokenResponse = serde_json::from_str(body).unwrap();
            assert_eq!(r.access_token, "eyJ0...");
            assert_eq!(r.expires_in, 3599);
        }

        #[test]
        fn config_carries_the_jwt_bearer_assertion_and_resource_scope() {
            // Documents the federated-credential shape: client_assertion = the
            // external OIDC token; scope = the KMS resource default.
            let cfg = AzureEntraConfig {
                tenant_id: "tid",
                client_id: "cid",
                client_assertion: "OIDC",
                scope: "https://vault.azure.net/.default",
                now_unix_secs: 1_000_000,
            };
            assert_eq!(cfg.client_assertion, "OIDC");
            assert!(cfg.scope.ends_with("/.default"));
            assert_eq!(cfg.now_unix_secs.saturating_add(3599), 1_003_599);
        }
    }
}

#[cfg(feature = "kms-azure")]
pub use azure::{AzureEntraConfig, acquire_azure_entra};

// ============================================================================
// HashiCorp Vault — JWT/OIDC auth method login. Grounded against the Vault JWT
// auth API. The customer-issued OIDC JWT logs in against a Vault role whose
// bound policy scopes to `transit/encrypt` + `transit/decrypt` on the one
// transit key (policy-side single-key scope, not in the request). JSON request
// + response; the `client_token` is returned with a RELATIVE `lease_duration`.
// ============================================================================
#[cfg(feature = "kms-vault")]
mod vault {
    use crate::auth::FederatedToken;
    use crate::error::{KmsRestError, Result};

    /// Inputs for a Vault JWT/OIDC `login`.
    pub struct VaultJwtConfig<'a> {
        /// The customer's Vault address, e.g. `https://vault.example.com:8200`
        /// (no trailing slash).
        pub vault_addr: &'a str,
        /// The JWT auth-method mount path (default mount is `jwt`; may be a
        /// custom mount such as `oidc`).
        pub mount: &'a str,
        /// The Vault role — its bound policy is the single-key transit scope.
        pub role: &'a str,
        /// The customer-issued OIDC JWT (secret — never logged).
        pub jwt: &'a str,
        /// Host Unix time in seconds (the binding supplies it — no local clock).
        /// Absolute expiry is `now + lease_duration`.
        pub now_unix_secs: u64,
    }

    /// JSON request body for `/auth/<mount>/login`.
    #[derive(serde::Serialize)]
    struct LoginRequest<'a> {
        role: &'a str,
        jwt: &'a str,
    }

    /// The `auth` block of the login response (snake_case).
    #[derive(serde::Deserialize)]
    struct AuthBlock {
        client_token: String,
        lease_duration: u64,
    }

    /// JSON login response — the credential is in `auth.client_token`.
    #[derive(serde::Deserialize)]
    struct LoginResponse {
        auth: AuthBlock,
    }

    fn fed_err(detail: &'static str) -> KmsRestError {
        KmsRestError::UpstreamKms {
            provider: "vault-jwt",
            status: None,
            detail: detail.to_string(),
        }
    }

    /// Log the customer OIDC JWT in at the Vault JWT auth method, returning the
    /// `client_token` as a [`FederatedToken`] the `kms-vault` provider sends as
    /// `X-Vault-Token`.
    ///
    /// # Errors
    /// [`KmsRestError::UpstreamKms`] (`provider: "vault-jwt"`) on a non-2xx login
    /// (role/policy mismatch, expired JWT, bad bound-audience) or an unparseable
    /// response — fixed, non-secret detail.
    pub async fn acquire_vault_jwt(
        client: &reqwest::Client,
        cfg: &VaultJwtConfig<'_>,
    ) -> Result<FederatedToken> {
        let endpoint = format!("{}/v1/auth/{}/login", cfg.vault_addr, cfg.mount);
        let req = LoginRequest {
            role: cfg.role,
            jwt: cfg.jwt,
        };

        let resp = client
            .post(&endpoint)
            .json(&req)
            .send()
            .await
            .map_err(|_| fed_err("Vault login request failed (transport)"))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(KmsRestError::UpstreamKms {
                provider: "vault-jwt",
                status: Some(status.as_u16()),
                detail: "Vault rejected the JWT login (role/policy/audience)".to_string(),
            });
        }

        let body: LoginResponse = resp
            .json()
            .await
            .map_err(|_| fed_err("Vault response not a valid login object"))?;

        let expires_at = cfg.now_unix_secs.saturating_add(body.auth.lease_duration);
        Ok(FederatedToken::new(body.auth.client_token, expires_at))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn login_request_serializes_role_and_jwt() {
            let j = serde_json::to_string(&LoginRequest {
                role: "kibo-transit",
                jwt: "OIDC",
            })
            .unwrap();
            assert_eq!(j, r#"{"role":"kibo-transit","jwt":"OIDC"}"#);
        }

        #[test]
        fn login_response_extracts_client_token_and_lease() {
            let body = r#"{"auth":{"client_token":"hvs.CAESI","lease_duration":2764800,"renewable":true,"policies":["transit-one-key"]}}"#;
            let r: LoginResponse = serde_json::from_str(body).unwrap();
            assert_eq!(r.auth.client_token, "hvs.CAESI");
            assert_eq!(r.auth.lease_duration, 2_764_800);
        }

        #[test]
        fn expiry_is_now_plus_lease_duration() {
            let r: LoginResponse =
                serde_json::from_str(r#"{"auth":{"client_token":"t","lease_duration":3600}}"#)
                    .unwrap();
            assert_eq!(
                1_000_000_u64.saturating_add(r.auth.lease_duration),
                1_003_600
            );
        }
    }
}

#[cfg(feature = "kms-vault")]
pub use vault::{VaultJwtConfig, acquire_vault_jwt};

#[cfg(all(test, feature = "kms-aws"))]
mod tests {
    use super::parse_iso8601_z_to_unix;

    #[test]
    fn iso8601_epoch_and_known_instants() {
        assert_eq!(parse_iso8601_z_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_z_to_unix("2000-01-01T00:00:00Z"),
            Some(946_684_800)
        );
        assert_eq!(
            parse_iso8601_z_to_unix("2024-02-29T12:00:00Z"),
            Some(1_709_208_000)
        );
    }

    #[test]
    fn iso8601_rejects_malformed() {
        assert!(parse_iso8601_z_to_unix("2014-10-24 23:00:23Z").is_none()); // space, not T
        assert!(parse_iso8601_z_to_unix("2014-10-24T23:00:23").is_none()); // no Z
        assert!(parse_iso8601_z_to_unix("2014-13-24T23:00:23Z").is_none()); // month 13
        assert!(parse_iso8601_z_to_unix("not-a-date").is_none());
        assert!(parse_iso8601_z_to_unix("").is_none());
    }
}
