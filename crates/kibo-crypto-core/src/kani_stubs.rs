//! Deterministic AEAD contract stubs for the Kani wrapper-tier proofs
//! (P1/P2/P3/P7/P9).
//!
//! These model the `aead::seal` / `aead::open_detached` **contract** —
//! round-trip + key/AAD/nonce binding + whole-message integrity — WITHOUT
//! AES-256-GCM-SIV, SHA-256, or `OsRng`, all three of which are
//! intractable/foreign for CBMC over symbolic inputs. Applied via
//! `#[kani::stub]`, they let the REAL surrounding code run so CBMC can verify
//! OUR logic tractably:
//! - **P9**: real `build_with_aad` / `unwrap_with_aad` (envelope offset +
//!   header-as-AAD wiring) with the AEAD as a black-box contract.
//! - **P1/P2/P3/P7**: real `aead::open` (nonce split + bounds) over the
//!   modeled primitive, asserting the contract-level round-trip / tamper /
//!   AAD-binding / key-distinctness properties.
//!
//! **This is NOT a cipher.** It carries zero cryptographic strength — the
//! real AES-256-GCM-SIV correctness is delegated to the pinned RustCrypto
//! crate + the `aead.rs` known-answer tests. The stub exists only so CBMC can
//! discharge OUR wiring/offset logic; its sole obligation is to model
//! *detection* faithfully (reject every mismatch class) so the proofs are not
//! vacuous. The `#[cfg(test)]` unit tests below assert exactly that, and run
//! under `cargo test` (`#[cfg(any(kani, test))]`) — so the model is validated
//! by the normal suite even though `cargo kani` is toolchain-only.
//!
//! ## Wire layout (model only)
//!
//! ```text
//! env = nonce(12) || ct
//! ct  = nonce_copy(12) || key(32) || aad || plaintext || fold(1)
//! ```
//!
//! `fold` is a 1-byte XOR over `ct[..len-1]` — flipping any single bit in the
//! ciphertext region flips the fold, modeling the AEAD tag's integrity. The
//! stored `nonce_copy` lets open detect a tampered nonce *prefix* that
//! `aead::open` split off before calling `open_detached`.

use crate::aead::{AeadError, AES_256_KEY_SIZE, GCM_NONCE_SIZE};

/// 1-byte XOR integrity fold over `bytes` (models whole-message integrity:
/// any single-bit change to a folded byte flips the result).
fn fold_byte(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Stub for [`crate::aead::seal`]. Deterministic fixed nonce (the proofs do
/// not depend on nonce randomness — that is P6, routed to cargo-fuzz).
pub(crate) fn stub_seal(
    key: &[u8; AES_256_KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let nonce = [0u8; GCM_NONCE_SIZE];
    let mut ct = Vec::with_capacity(GCM_NONCE_SIZE + key.len() + aad.len() + plaintext.len() + 1);
    ct.extend_from_slice(&nonce);
    ct.extend_from_slice(key);
    ct.extend_from_slice(aad);
    ct.extend_from_slice(plaintext);
    ct.push(fold_byte(&ct));

    let mut env = Vec::with_capacity(GCM_NONCE_SIZE + ct.len());
    env.extend_from_slice(&nonce);
    env.extend_from_slice(&ct);
    Ok(env)
}

/// Stub for [`crate::aead::open_detached`]. Recovers the plaintext IFF the
/// embedded nonce + key + aad match the caller's AND the integrity fold
/// verifies; otherwise `OpenFailed` (fail-uniform).
pub(crate) fn stub_open_detached(
    key: &[u8; AES_256_KEY_SIZE],
    nonce: &[u8; GCM_NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let kl = key.len();
    let al = aad.len();
    let min = GCM_NONCE_SIZE + kl + al + 1;
    if ciphertext.len() < min {
        return Err(AeadError::OpenFailed);
    }

    // Integrity: fold over everything but the trailing fold byte. Catches any
    // single-byte tamper in the ciphertext region (incl. the fold byte).
    let body_end = ciphertext.len() - 1;
    if fold_byte(&ciphertext[..body_end]) != ciphertext[body_end] {
        return Err(AeadError::OpenFailed);
    }
    // Nonce binding — catches a tampered nonce prefix split off by `open`.
    if ciphertext[..GCM_NONCE_SIZE] != nonce[..] {
        return Err(AeadError::OpenFailed);
    }
    // Key binding.
    if ciphertext[GCM_NONCE_SIZE..GCM_NONCE_SIZE + kl] != key[..] {
        return Err(AeadError::OpenFailed);
    }
    // AAD binding.
    if ciphertext[GCM_NONCE_SIZE + kl..GCM_NONCE_SIZE + kl + al] != *aad {
        return Err(AeadError::OpenFailed);
    }

    Ok(ciphertext[GCM_NONCE_SIZE + kl + al..body_end].to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const KEY: &[u8; AES_256_KEY_SIZE] = &[0x11; AES_256_KEY_SIZE];
    const KEY2: &[u8; AES_256_KEY_SIZE] = &[0x22; AES_256_KEY_SIZE];

    fn split_env(env: &[u8]) -> ([u8; GCM_NONCE_SIZE], Vec<u8>) {
        let (n, ct) = env.split_at(GCM_NONCE_SIZE);
        (n.try_into().unwrap(), ct.to_vec())
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let env = stub_seal(KEY, b"dek-material", b"header-aad").unwrap();
        let (nonce, ct) = split_env(&env);
        let pt = stub_open_detached(KEY, &nonce, &ct, b"header-aad").unwrap();
        assert_eq!(pt, b"dek-material");
    }

    #[test]
    fn rejects_wrong_key() {
        let env = stub_seal(KEY, b"x", b"aad").unwrap();
        let (nonce, ct) = split_env(&env);
        assert!(matches!(
            stub_open_detached(KEY2, &nonce, &ct, b"aad"),
            Err(AeadError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_wrong_aad() {
        let env = stub_seal(KEY, b"x", b"aad-1").unwrap();
        let (nonce, ct) = split_env(&env);
        assert!(matches!(
            stub_open_detached(KEY, &nonce, &ct, b"aad-2"),
            Err(AeadError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_tampered_nonce_prefix() {
        let mut env = stub_seal(KEY, b"x", b"aad").unwrap();
        env[0] ^= 0x01;
        let (nonce, ct) = split_env(&env);
        assert!(matches!(
            stub_open_detached(KEY, &nonce, &ct, b"aad"),
            Err(AeadError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_tampered_fold_byte() {
        let env = stub_seal(KEY, b"xyz", b"aad").unwrap();
        let (nonce, mut ct) = split_env(&env);
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            stub_open_detached(KEY, &nonce, &ct, b"aad"),
            Err(AeadError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_tampered_payload_byte() {
        let env = stub_seal(KEY, b"xyz", b"aad").unwrap();
        let (nonce, mut ct) = split_env(&env);
        // First payload byte sits at nonce_copy(12) + key(32) + aad(3).
        let idx = GCM_NONCE_SIZE + KEY.len() + 3;
        ct[idx] ^= 0x01;
        assert!(matches!(
            stub_open_detached(KEY, &nonce, &ct, b"aad"),
            Err(AeadError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        assert!(matches!(
            stub_open_detached(KEY, &[0u8; GCM_NONCE_SIZE], &[], b"aad"),
            Err(AeadError::OpenFailed)
        ));
    }
}
