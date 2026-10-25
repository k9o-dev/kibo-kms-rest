//! Federated short-lived credential used to authenticate REST-direct KMS
//! calls from the edge.
//!
//! The device never holds a long-lived cloud credential. Instead it
//! presents a customer-issued, short-lived **federated token** (e.g. an
//! STS session credential, a GCP/Azure OAuth bearer, or a Vault token).
//! This crate models only the *shape* of that credential — an opaque
//! string plus an expiry. The acquisition / refresh flow and the
//! provider-specific request signing live in the provider backends.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A short-lived federated credential presented on each REST-direct KMS
/// call.
///
/// The secret material is opaque to this crate (its internal structure is
/// provider-specific) and is zeroized on drop. The crate does not parse,
/// validate, or refresh the token — it carries it to the signing seam.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FederatedToken {
    /// The opaque credential value. Treated as secret: never logged, and
    /// zeroized on drop.
    secret: String,

    /// Absolute expiry instant, as a Unix timestamp in seconds. The
    /// caller is responsible for refreshing before this passes; this
    /// crate only exposes the value via [`FederatedToken::is_expired`].
    expires_at_unix_secs: u64,
}

impl FederatedToken {
    /// Construct a federated token from an opaque secret and an absolute
    /// expiry (Unix seconds).
    #[must_use]
    pub fn new(secret: String, expires_at_unix_secs: u64) -> Self {
        Self {
            secret,
            expires_at_unix_secs,
        }
    }

    /// Borrow the opaque secret for use at the signing seam.
    ///
    /// Callers must not log or persist the returned slice.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Absolute expiry as a Unix timestamp in seconds.
    #[must_use]
    pub fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }

    /// Whether the token has expired relative to the supplied `now`.
    ///
    /// Passing `now` explicitly keeps the type clock-agnostic and easy to
    /// test; callers typically derive it from [`SystemTime::now`].
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let now_secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        now_secs >= self.expires_at_unix_secs
    }
}

impl std::fmt::Debug for FederatedToken {
    /// Redacts the secret so a token can never leak through a `Debug`
    /// log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederatedToken")
            .field("secret", &"<redacted>")
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .finish()
    }
}
