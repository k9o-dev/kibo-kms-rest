//! The application-crypto container v1: one format for both paths of
//! `k9o.crypto.*`, so a container written by either opens under the same rules.
//!
//! - The **server route** (`kibo-vault-api` `app_crypto`) seals under a platform-managed
//!   project KEK.
//! - The **client path** (`kibo-kms-rest-ffi` `app_crypto_seal`) seals in the caller's
//!   process with a DEK wrapped by the customer's own KMS (cloud BYOK/HYOK, zero-knowledge).
//!
//! The wrapped DEK's own header (`envelope::read_header`) carries the KEK provider tag and key
//! version, so the provider tag names who can open a container. Nothing here touches a key
//! store: these are the pure, shared pieces both paths call.
//!
//! - **AAD** = `"k9o-app-crypto/v1" ‖ projectId ‖ crypt ‖ context`, each component
//!   `u32-BE(len) ‖ bytes` (injective).
//! - **Container v1** = `0x01 ‖ u32-BE(len(W)) ‖ W ‖ D`, where `W` is the wrapped-DEK envelope
//!   and `D` is the DEK's AEAD output, `nonce(12) ‖ ciphertext ‖ tag(16)` (AES-256-GCM-SIV with
//!   key commitment, [`crate::aead`]).
//! - **Shapes:** `crypt` `[a-z0-9-]{1,64}`; `context` optional UTF-8, at most 256 bytes,
//!   absent meaning empty.

use crate::dek::{DataEncryptionKey, DekError};

/// The AAD domain of `k9o.crypto.*`, distinct from the extension route's `k9o-ext-crypto/v1`.
pub const AAD_DOMAIN: &[u8] = b"k9o-app-crypto/v1";
/// The container format version byte.
pub const CONTAINER_V1: u8 = 0x01;
/// The most `context` bytes.
pub const MAX_CONTEXT_BYTES: usize = 256;

/// `crypt` matches `[a-z0-9-]{1,64}`.
#[must_use]
pub fn valid_crypt(crypt: &str) -> bool {
    (1..=64).contains(&crypt.len())
        && crypt
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The `context` bytes bound into the AAD (absent is empty), or `None` when over the limit.
#[must_use]
pub fn context_bytes(context: Option<&str>) -> Option<&[u8]> {
    let c = context.unwrap_or("").as_bytes();
    (c.len() <= MAX_CONTEXT_BYTES).then_some(c)
}

/// The AAD: domain, project, crypt and context, each `u32-BE(len) ‖ bytes`.
#[must_use]
pub fn canonical_aad(project_id: &str, crypt: &str, context: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(16 + AAD_DOMAIN.len() + project_id.len() + crypt.len() + context.len());
    for comp in [AAD_DOMAIN, project_id.as_bytes(), crypt.as_bytes(), context] {
        out.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        out.extend_from_slice(comp);
    }
    out
}

/// Frame a container v1 from the wrapped-DEK envelope and the data AEAD output.
#[must_use]
pub fn frame(wrapped: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + wrapped.len() + data.len());
    out.push(CONTAINER_V1);
    out.extend_from_slice(&(wrapped.len() as u32).to_be_bytes());
    out.extend_from_slice(wrapped);
    out.extend_from_slice(data);
    out
}

/// `(wrapped, data)` of a container v1, or `None` for another version or a malformed body.
#[must_use]
pub fn unframe(container: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&version, rest) = container.split_first()?;
    if version != CONTAINER_V1 || rest.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let body = &rest[4..];
    (body.len() >= n).then(|| (&body[..n], &body[n..]))
}

/// Seal `plaintext` under `dek` with `aad`: the `D` part of a container.
///
/// # Errors
/// [`DekError`] from the DEK (in practice unreachable for a 32-byte key).
pub fn seal_data(dek: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, DekError> {
    DataEncryptionKey::from_bytes(dek)?.encrypt(plaintext, aad)
}

/// Open the `D` part under `dek` with `aad`. `None` for any cannot-open (wrong key, AAD or
/// bytes): callers answer it as the one opaque integrity failure.
#[must_use]
pub fn open_data(dek: &[u8], data: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    DataEncryptionKey::from_bytes(dek)
        .ok()?
        .decrypt(data, aad)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_aad_is_injective_and_domain_separated() {
        assert_ne!(
            canonical_aad("p", "ab", b"c"),
            canonical_aad("p", "a", b"bc")
        );
        assert!(canonical_aad("p", "k", b"").starts_with(&17u32.to_be_bytes()));
        assert_ne!(AAD_DOMAIN, b"k9o-ext-crypto/v1");
    }

    #[test]
    fn the_container_round_trips_and_refuses_another_version() {
        let c = frame(b"WWW", b"DD");
        assert_eq!(c[0], CONTAINER_V1);
        assert_eq!(unframe(&c), Some((&b"WWW"[..], &b"DD"[..])));
        let mut v2 = c.clone();
        v2[0] = 0x02;
        assert_eq!(unframe(&v2), None);
        assert_eq!(unframe(&[]), None);
        assert_eq!(unframe(&c[..3]), None);
    }

    #[test]
    fn shapes() {
        assert!(valid_crypt("billing-pii-2"));
        for bad in ["", "Upper", "a_b", "a/b", &"k".repeat(65)] {
            assert!(!valid_crypt(bad), "{bad}");
        }
        assert!(context_bytes(Some(&"x".repeat(256))).is_some());
        assert!(context_bytes(Some(&"x".repeat(257))).is_none());
        assert_eq!(context_bytes(None), Some(&b""[..]));
    }

    #[test]
    fn data_opens_only_under_its_own_aad() {
        let dek = [7u8; 32];
        let aad = canonical_aad("proj_a", "pii", b"user:42");
        let d = seal_data(&dek, &aad, b"hello").unwrap();
        assert_eq!(open_data(&dek, &d, &aad).as_deref(), Some(&b"hello"[..]));
        assert!(open_data(&dek, &d, &canonical_aad("proj_a", "pii", b"user:43")).is_none());
        assert!(open_data(&[8u8; 32], &d, &aad).is_none());
    }
}
