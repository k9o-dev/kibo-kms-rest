//! The client path's exchange: the identity token for a credential the customer's KMS accepts.
//!
//! `kibo_kms_rest::federation` does the exchange; this is that code's one door for the uniffi
//! and wasm SDKs, so no language writes its own. The output goes into `kms_cred`.
//!
//! - **The token goes only to the provider the caller's own configuration names.** Nothing
//!   here comes from the platform. The fields that choose a host or a path are checked first,
//!   so a value can't send the token somewhere else, and Vault must be `https` (plain `http`
//!   only on loopback).
//! - **No redirects, on native builds:** a redirect would re-send the token to a host nobody
//!   configured, so native builds refuse them and stop at 30 seconds. A Vault standby's redirect
//!   therefore fails: point at the active address or a load balancer. In the browser, `fetch`
//!   follows a redirect with the body and has no deadline here, so the JS SDK adds the deadline
//!   and the address must be one the customer trusts.
//! - **The Rust copy of the input token is wiped after use, and it's never logged or returned.**
//!   The language side's string and the returned `secret` stay with the caller.

// A build with no provider refuses every exchange, so the exchange code goes unused there.
#![cfg_attr(
    not(any(
        feature = "kms-aws",
        feature = "kms-gcp",
        feature = "kms-azure",
        feature = "kms-vault"
    )),
    allow(unused)
)]

use kibo_kms_rest::FederatedToken;
use zeroize::Zeroizing;

use crate::engine::map_kms_error;
use crate::types::{FfiCredential, FfiFederationInput, FfiFederationSpec, ZkFfiError};

fn invalid(message: &str) -> ZkFfiError {
    ZkFfiError {
        code: Some("K9O_INVALID_FIELD_VALUE".to_string()),
        message: message.to_string(),
        context: None,
    }
}

#[allow(dead_code)] // unused only when every provider is compiled in
fn not_compiled(provider: &str) -> ZkFfiError {
    ZkFfiError {
        code: Some("K9O_CRYPTO_STRATEGY_UNAVAILABLE".to_string()),
        message: format!("provider `{provider}` is not compiled into this build artifact"),
        context: None,
    }
}

/// A DNS label or dotted name: nothing that can end a host or start a path, and no empty
/// label, so never `.` or `..`.
fn host_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.split('.').any(str::is_empty)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// A Vault mount: path segments, never `..`, no leading or trailing slash.
fn mount_path(s: &str) -> bool {
    !s.is_empty()
        && s.split('/').all(|seg| {
            !seg.is_empty()
                && seg != ".."
                && seg != "."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

/// `https`, or `http` on loopback. No credentials, query or fragment, and no trailing slash.
fn vault_addr_ok(addr: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(addr) else {
        return false;
    };
    let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    (u.scheme() == "https" || (u.scheme() == "http" && loopback))
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && !addr.ends_with('/')
}

fn check_spec(spec: &FfiFederationSpec) -> Result<(), ZkFfiError> {
    match spec {
        FfiFederationSpec::Aws {
            role_arn,
            session_name,
            region,
            key_arn,
            ..
        } => {
            if !host_part(region) {
                return Err(invalid("`region` must be a plain region name"));
            }
            if role_arn.is_empty() || session_name.is_empty() || key_arn.is_empty() {
                return Err(invalid(
                    "`role_arn`, `session_name` and `key_arn` are required",
                ));
            }
        }
        FfiFederationSpec::Gcp { audience } => {
            if audience.is_empty() {
                return Err(invalid("`audience` is required"));
            }
        }
        FfiFederationSpec::Azure {
            tenant_id,
            client_id,
            scope,
        } => {
            if !host_part(tenant_id) {
                return Err(invalid("`tenant_id` must be a plain tenant id"));
            }
            if client_id.is_empty() || scope.is_empty() {
                return Err(invalid("`client_id` and `scope` are required"));
            }
        }
        FfiFederationSpec::Vault {
            vault_addr,
            mount,
            role,
        } => {
            if !vault_addr_ok(vault_addr) {
                return Err(invalid(
                    "`vault_addr` must be https (http only on loopback), with no credentials, query or trailing slash",
                ));
            }
            if !mount_path(mount) {
                return Err(invalid("`mount` must be plain path segments"));
            }
            if role.is_empty() {
                return Err(invalid("`role` is required"));
            }
        }
    }
    Ok(())
}

fn client() -> Result<reqwest::Client, ZkFfiError> {
    let builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30));
    builder.build().map_err(|_| ZkFfiError {
        code: Some("K9O_KEY_SERVICE_UNAVAILABLE".to_string()),
        message: "could not start the HTTP client".to_string(),
        context: None,
    })
}

async fn exchange(
    http: &reqwest::Client,
    spec: &FfiFederationSpec,
    token: &str,
    now_unix_secs: u64,
) -> Result<FederatedToken, ZkFfiError> {
    match spec {
        #[cfg(feature = "kms-aws")]
        FfiFederationSpec::Aws {
            role_arn,
            session_name,
            region,
            key_arn,
            duration_secs,
        } => kibo_kms_rest::federation::acquire_aws_sts(
            http,
            &kibo_kms_rest::federation::AwsStsConfig {
                role_arn,
                session_name,
                region,
                web_identity_token: token,
                key_arn,
                duration_secs: *duration_secs,
            },
        )
        .await
        .map_err(map_kms_error),
        #[cfg(not(feature = "kms-aws"))]
        FfiFederationSpec::Aws { .. } => Err(not_compiled("aws")),
        #[cfg(feature = "kms-gcp")]
        FfiFederationSpec::Gcp { audience } => kibo_kms_rest::federation::acquire_gcp_wif(
            http,
            &kibo_kms_rest::federation::GcpWifConfig {
                audience,
                subject_token: token,
                subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
                now_unix_secs,
            },
        )
        .await
        .map_err(map_kms_error),
        #[cfg(not(feature = "kms-gcp"))]
        FfiFederationSpec::Gcp { .. } => Err(not_compiled("gcp")),
        #[cfg(feature = "kms-azure")]
        FfiFederationSpec::Azure {
            tenant_id,
            client_id,
            scope,
        } => kibo_kms_rest::federation::acquire_azure_entra(
            http,
            &kibo_kms_rest::federation::AzureEntraConfig {
                tenant_id,
                client_id,
                client_assertion: token,
                scope,
                now_unix_secs,
            },
        )
        .await
        .map_err(map_kms_error),
        #[cfg(not(feature = "kms-azure"))]
        FfiFederationSpec::Azure { .. } => Err(not_compiled("azure")),
        #[cfg(feature = "kms-vault")]
        FfiFederationSpec::Vault {
            vault_addr,
            mount,
            role,
        } => kibo_kms_rest::federation::acquire_vault_jwt(
            http,
            &kibo_kms_rest::federation::VaultJwtConfig {
                vault_addr,
                mount,
                role,
                jwt: token,
                now_unix_secs,
            },
        )
        .await
        .map_err(map_kms_error),
        #[cfg(not(feature = "kms-vault"))]
        FfiFederationSpec::Vault { .. } => Err(not_compiled("vault")),
    }
}

/// Exchange an identity token for the customer KMS credential that goes into `kms_cred`.
///
/// # Errors
/// `K9O_INVALID_FIELD_VALUE` for a field that fails its check, before any network call;
/// `K9O_CRYPTO_STRATEGY_UNAVAILABLE` for a provider not in this build; otherwise the provider's
/// refusal or a transport failure. No message carries the token.
pub async fn acquire_kms_credential(
    input: FfiFederationInput,
) -> Result<FfiCredential, ZkFfiError> {
    acquire_with(&client()?, input).await
}

async fn acquire_with(
    http: &reqwest::Client,
    input: FfiFederationInput,
) -> Result<FfiCredential, ZkFfiError> {
    let FfiFederationInput {
        spec,
        identity_token,
        now_unix_secs,
    } = input;
    let token = Zeroizing::new(identity_token);
    if token.is_empty() {
        return Err(invalid("`identity_token` is required"));
    }
    check_spec(&spec)?;
    let credential = exchange(http, &spec, &token, now_unix_secs).await?;
    Ok(FfiCredential {
        secret: credential.secret().to_owned(),
        expires_at_unix_secs: credential.expires_at_unix_secs(),
    })
}

// Async tests need tokio, which this crate pulls in only with `ffi-uniffi`.
#[cfg(all(test, feature = "ffi-uniffi"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    const TOKEN: &str = "eyJ.identity-token-value.sig";

    fn input(spec: FfiFederationSpec) -> FfiFederationInput {
        FfiFederationInput {
            spec,
            identity_token: TOKEN.to_owned(),
            now_unix_secs: 1_000,
        }
    }

    fn vault(addr: &str) -> FfiFederationSpec {
        FfiFederationSpec::Vault {
            vault_addr: addr.to_owned(),
            mount: "jwt".to_owned(),
            role: "kibo-transit".to_owned(),
        }
    }

    /// One local server: answers each connection with `response` and reports the request read.
    fn serve(response: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut seen = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    seen.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&seen);
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if seen.len() >= end + 4 + length {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                stream.write_all(response.as_bytes()).unwrap();
                let _ = tx.send(String::from_utf8_lossy(&seen).into_owned());
            }
        });
        (addr, rx)
    }

    fn json_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn a_vault_login_returns_the_credential_kms_cred_takes() {
        let (addr, seen) = serve(json_response(
            "200 OK",
            r#"{"auth":{"client_token":"hvs.issued","lease_duration":300}}"#,
        ));
        let out = acquire_kms_credential(input(vault(&addr))).await.unwrap();
        assert_eq!(out.secret, "hvs.issued");
        assert_eq!(out.expires_at_unix_secs, 1_300);
        let request = seen.recv().unwrap();
        assert!(request.starts_with("POST /v1/auth/jwt/login"), "{request}");
        assert!(request.contains(TOKEN) && request.contains("kibo-transit"));
    }

    #[tokio::test]
    async fn a_redirect_never_carries_the_token_onward() {
        let (elsewhere, elsewhere_seen) = serve(json_response(
            "200 OK",
            r#"{"auth":{"client_token":"hvs.stolen","lease_duration":300}}"#,
        ));
        let (addr, _seen) = serve(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {elsewhere}/v1/auth/jwt/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        assert!(acquire_kms_credential(input(vault(&addr))).await.is_err());
        assert!(
            elsewhere_seen
                .recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "the token reached the redirect's target"
        );
    }

    #[tokio::test]
    async fn a_refusal_does_not_echo_the_token() {
        let (addr, _seen) = serve(json_response("403 Forbidden", TOKEN));
        let e = acquire_kms_credential(input(vault(&addr)))
            .await
            .unwrap_err();
        assert!(!e.message.contains(TOKEN), "{}", e.message);
    }

    /// Stands in for a fixed provider host: the client's proxy CONNECTs here, then TLS on a
    /// throwaway certificate, then one refusal whose body repeats the token.
    fn refusing_provider() -> (reqwest::Client, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tcp.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let connect = String::from_utf8_lossy(&head).into_owned();
            tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
            let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
            let conn = rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut seen = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = tls.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&seen);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let body = format!("<Error><Code>{TOKEN}</Code><Message>{TOKEN}</Message></Error>");
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(response.as_bytes()).unwrap();
            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tx.send(format!("{connect}{}", String::from_utf8_lossy(&seen)));
        });
        let http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap())
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        (http, rx)
    }

    #[tokio::test]
    async fn a_cloud_refusal_that_repeats_the_token_does_not_reach_the_message() {
        let cases = [
            (
                FfiFederationSpec::Aws {
                    role_arn: "arn:aws:iam::1:role/r".to_owned(),
                    session_name: "kibo".to_owned(),
                    region: "eu-central-1".to_owned(),
                    key_arn: "arn:aws:kms:eu-central-1:1:key/k".to_owned(),
                    duration_secs: 900,
                },
                "CONNECT sts.eu-central-1.amazonaws.com:443",
            ),
            (
                FfiFederationSpec::Gcp {
                    audience: "//iam.googleapis.com/projects/1/x".to_owned(),
                },
                "CONNECT sts.googleapis.com:443",
            ),
            (
                FfiFederationSpec::Azure {
                    tenant_id: "tenant".to_owned(),
                    client_id: "c".to_owned(),
                    scope: "https://vault.azure.net/.default".to_owned(),
                },
                "CONNECT login.microsoftonline.com:443",
            ),
        ];
        for (spec, host) in cases {
            let (http, seen) = refusing_provider();
            let e = acquire_with(&http, input(spec)).await.unwrap_err();
            let request = seen
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert!(request.starts_with(host), "{request}");
            assert!(request.contains(TOKEN), "the token never reached {host}");
            assert!(!e.message.contains(TOKEN), "{host}: {}", e.message);
            assert!(!format!("{e:?}").contains(TOKEN), "{host}: {e:?}");
        }
    }

    #[tokio::test]
    async fn fields_that_could_move_the_token_are_refused_first() {
        let aws = |region: &str| FfiFederationSpec::Aws {
            role_arn: "arn:aws:iam::1:role/r".to_owned(),
            session_name: "kibo".to_owned(),
            region: region.to_owned(),
            key_arn: "arn:aws:kms:eu-central-1:1:key/k".to_owned(),
            duration_secs: 900,
        };
        let azure = |tenant: &str| FfiFederationSpec::Azure {
            tenant_id: tenant.to_owned(),
            client_id: "c".to_owned(),
            scope: "https://vault.azure.net/.default".to_owned(),
        };
        let mount = |m: &str| FfiFederationSpec::Vault {
            vault_addr: "https://vault.example.test".to_owned(),
            mount: m.to_owned(),
            role: "r".to_owned(),
        };
        for spec in [
            aws("evil.test/#"),
            aws("evil.test:443"),
            aws(""),
            azure("t/../../evil"),
            azure("t?x=1"),
            azure(".."),
            azure("."),
            azure("a..b"),
            aws(".."),
            mount("../../sys"),
            mount("jwt/"),
            vault("http://vault.example.test"),
            vault("https://user:pw@vault.example.test"),
            vault("https://vault.example.test/"),
            vault("https://vault.example.test?x=1"),
            vault("not a url"),
        ] {
            let e = acquire_kms_credential(input(spec)).await.unwrap_err();
            assert_eq!(e.code.as_deref(), Some("K9O_INVALID_FIELD_VALUE"));
        }
    }

    #[test]
    fn debug_never_prints_the_token() {
        let printed = format!("{:?}", input(vault("https://vault.example.test")));
        assert!(!printed.contains(TOKEN), "{printed}");
    }

    #[tokio::test]
    async fn an_empty_token_is_refused() {
        let mut i = input(vault("https://vault.example.test"));
        i.identity_token.clear();
        let e = acquire_kms_credential(i).await.unwrap_err();
        assert_eq!(e.code.as_deref(), Some("K9O_INVALID_FIELD_VALUE"));
    }
}
