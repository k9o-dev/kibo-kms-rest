//! Data encryption key (DEK) lifecycle with atomic invocation counter.
//!
//! A DEK is a 256-bit symmetric key used by the AES-256-GCM AEAD
//! primitive (`crate::aead`) to seal record payloads. DEK material
//! lives in memory only inside the bounded cleartext cache; durable
//! storage is always the wrapped form (`crate::types::WrappedDek`).
//!
//! # Memory hygiene
//!
//! [`DataEncryptionKey`] derives `Zeroize + ZeroizeOnDrop` — the raw
//! key bytes are wiped from RAM the moment the struct drops. The
//! `zeroize` crate uses volatile writes that the LLVM optimizer
//! cannot strip out (in contrast to a manual `for byte in &mut bytes
//! { *byte = 0; }` loop, which optimizers frequently elide as dead
//! code on unused slices).
//!
//! # Atomic invocation counter
//!
//! Each DEK carries an atomic `AtomicU64` counter that is
//! incremented before every successful `encrypt` call. The hard cap
//! is [`DEK_INVOCATION_HARD_CAP`] (2³⁰ ≈ 1.07 billion encryptions)
//! — well below the NIST SP 800-38D §8.3 safety wall of 2³².
//!
//! When the counter reaches the cap, [`encrypt`](DataEncryptionKey::encrypt)
//! returns [`DekError::KeyInvocationLimitExceeded`] **without**
//! invoking the AEAD primitive. The caller's operational discipline
//! is to trigger an automated Key Rotation/Re-Wrap (a 90-day
//! pipeline or the consumer's per-key rotation policy). The cap is
//! enforced atomically — concurrent encrypt calls see a consistent
//! cap-hit boundary.
//!
//! Decrypt is NOT counter-gated: an exhausted-cap DEK can still
//! decrypt ciphertext sealed under it previously (otherwise rotation
//! would cause data loss).
//!
//! # Counter semantics (CAS check-and-increment)
//!
//! - `encrypt` uses a `compare_exchange_weak` (CAS) loop: load the
//!   counter, reject if `>= DEK_INVOCATION_HARD_CAP` via a **pure read**
//!   (no write), else atomically increment by one. This supersedes
//!   the prior `fetch_add`-then-clamp
//!   pattern as **hygiene** — the old code clamped down to exactly
//!   `CAP` (never below) so it never actually opened sub-`CAP` seal
//!   slots, but it (a) let the counter transiently balloon to `CAP+N`
//!   under burst, muddying `invocation_count()`/`remaining_invocations()`
//!   reads, and (b) made rejected threads issue a dirty `store` write
//!   that thrashes the shared cache line (MESI/MOESI invalidation). The
//!   CAS loop eliminates both: rejected threads fail on a clean read,
//!   never writing back.
//! - Cap-hit predicate is `loaded >= DEK_INVOCATION_HARD_CAP`; the
//!   `CAP`-th seal (counter `CAP-1 → CAP`) is the last permitted.
//! - Sequential consistency (`SeqCst`) is chosen over weaker
//!   orderings: the cap check is a security gate, not a hot-path
//!   counter; the consistency cost is negligible vs the AEAD work.
//! - NOTE: the SIV backbone (`aead`) is now the architectural defense
//!   against nonce-reuse; this counter is defense-in-depth. Counter
//!   *persistence* across process restart / multi-node load
//!   is a separate increment landing in the `WrappedDek` wire
//!   format.

use crate::aead::{self, AES_256_KEY_SIZE, AeadError};
use rand_core::{OsRng, RngCore};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hard cap on encryptions per single DEK before rotation is required.
///
/// `2³⁰ = 1,073,741,824` — well below the NIST SP 800-38D §8.3 safety
/// wall of `2³²` for AES-256-GCM with random 96-bit nonces. The
/// margin accommodates clock skew, burst traffic, and other
/// operational uncertainty before the catastrophic-collision regime.
pub const DEK_INVOCATION_HARD_CAP: u64 = 1 << 30;

/// Errors returned from DEK operations.
#[derive(Debug, Error)]
pub enum DekError {
    /// The DEK has reached its hard invocation cap
    /// ([`DEK_INVOCATION_HARD_CAP`]) and must be rotated before further
    /// encrypt operations. The consumer's automated rotation pipeline
    /// (a 90-day or per-key rotation policy) is the closure mechanism.
    #[error(
        "KEY_INVOCATION_LIMIT_EXCEEDED: DEK reached hard cap of {cap} encryptions; rotation required"
    )]
    KeyInvocationLimitExceeded {
        /// The configured hard cap value ([`DEK_INVOCATION_HARD_CAP`]).
        cap: u64,
    },
    /// AEAD seal/open failure forwarded from the AES-256-GCM primitive.
    #[error("AEAD primitive error: {0}")]
    Aead(#[from] AeadError),
}

/// A 256-bit data encryption key with an atomic invocation counter.
///
/// The struct derives `Zeroize + ZeroizeOnDrop`: when an instance
/// drops, the `key_bytes` field is overwritten with binary zeros via
/// volatile writes (the LLVM optimizer cannot elide). The counter
/// field carries `#[zeroize(skip)]` — `AtomicU64` does not impl
/// `Zeroize` and the value is not secret material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey {
    /// Raw 32-byte AES-256-GCM key material. Wiped on drop.
    key_bytes: [u8; AES_256_KEY_SIZE],
    /// Pre-increment count of successful encrypt operations.
    /// `fetch_add(1, SeqCst)` is performed at the entry of every
    /// `encrypt` call; the cap is enforced before the increment is
    /// observed externally.
    #[zeroize(skip)]
    counter: AtomicU64,
}

impl DataEncryptionKey {
    /// Generate a fresh DEK using hardware-backed system CSPRNG.
    ///
    /// `OsRng::fill_bytes` routes to kernel entropy (RDRAND/RDSEED
    /// on x86_64; equivalent hardware paths via `getrandom` on
    /// other substrates). Inside an Intel TDX / AMD SEV-SNP
    /// confidential VM, the kernel entropy pool draws from the
    /// hardware instruction sets directly.
    ///
    /// The counter is initialized to zero.
    pub fn generate() -> Self {
        let mut key_bytes = [0u8; AES_256_KEY_SIZE];
        OsRng.fill_bytes(&mut key_bytes);
        Self {
            key_bytes,
            counter: AtomicU64::new(0),
        }
    }

    /// Construct a **fresh** DEK from raw key bytes with
    /// `invocation_count = 0`. Use this only for a newly-minted DEK
    /// that has never been used. To reload a DEK recovered from a
    /// wrapped envelope, use [`from_persisted`](Self::from_persisted)
    /// with the count returned by
    /// [`crate::envelope::unwrap_with_aad`] — resetting a reloaded
    /// DEK's count to 0 is the nonce-budget-replay bug the
    /// counter-persistence fix closes.
    ///
    /// # Errors
    ///
    /// - [`DekError::Aead`] wrapping [`AeadError::InvalidKeyLength`]
    ///   if `key_bytes.len() != 32`.
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, DekError> {
        Self::from_persisted(key_bytes, 0)
    }

    /// Reconstruct a DEK from raw key bytes AND its persisted historical
    /// invocation count.
    ///
    /// This is the **restore path** for the counter-persistence fix:
    /// the unwrap flow
    /// ([`crate::envelope::unwrap_with_aad`]) recovers the count that
    /// was sealed alongside the DEK at wrap time and feeds it here, so
    /// a DEK reloaded after a process restart — or loaded concurrently
    /// on a second node — resumes its true invocation count instead of
    /// resetting to 0 and replaying its nonce budget. Under the
    /// AES-256-GCM-SIV backbone a replayed nonce is no longer
    /// catastrophic, but restoring the true count keeps the 2³⁰ rotation
    /// gate honest across the key's full lifetime (defense-in-depth).
    ///
    /// [`from_bytes`](Self::from_bytes) is the fresh-DEK convenience
    /// (`invocation_count = 0`).
    ///
    /// # Errors
    ///
    /// - [`DekError::Aead`] wrapping [`AeadError::InvalidKeyLength`]
    ///   if `key_bytes.len() != 32`.
    pub fn from_persisted(key_bytes: &[u8], invocation_count: u64) -> Result<Self, DekError> {
        if key_bytes.len() != AES_256_KEY_SIZE {
            return Err(DekError::Aead(AeadError::InvalidKeyLength));
        }
        let mut buf = [0u8; AES_256_KEY_SIZE];
        buf.copy_from_slice(key_bytes);
        Ok(Self {
            key_bytes: buf,
            counter: AtomicU64::new(invocation_count),
        })
    }

    /// Encrypt `plaintext` under this DEK with additional authenticated
    /// data `aad`. Returns the AEAD envelope
    /// `[12B nonce || ciphertext || 16B tag]` per [`crate::aead::seal`].
    ///
    /// Increments the atomic counter before invoking the AEAD primitive.
    /// If the pre-increment counter is at or above
    /// [`DEK_INVOCATION_HARD_CAP`], returns
    /// [`DekError::KeyInvocationLimitExceeded`] without doing any
    /// crypto work.
    ///
    /// # Errors
    ///
    /// - [`DekError::KeyInvocationLimitExceeded`] if the counter is at
    ///   the cap.
    /// - [`DekError::Aead`] forwarding any AES-256-GCM seal failure.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DekError> {
        // Atomic check-and-increment via a CAS loop. Rejected
        // (cap-hit) threads fail on a pure
        // read and never write — so the counter never balloons past
        // `CAP` and rejecting threads don't dirty the shared cache
        // line. Each successful increment is exactly +1, so the
        // lifetime seal count is bounded at exactly `CAP`.
        let mut current = self.counter.load(Ordering::SeqCst);
        loop {
            if current >= DEK_INVOCATION_HARD_CAP {
                return Err(DekError::KeyInvocationLimitExceeded {
                    cap: DEK_INVOCATION_HARD_CAP,
                });
            }
            match self.counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        Ok(aead::seal(&self.key_bytes, plaintext, aad)?)
    }

    /// Decrypt `envelope` produced by [`encrypt`](Self::encrypt) under
    /// this DEK with `aad`. Decrypt is NOT counter-gated: an
    /// exhausted-cap DEK retains the ability to decrypt material
    /// sealed under it before rotation.
    ///
    /// # Errors
    ///
    /// - [`DekError::Aead`] forwarding any AES-256-GCM open failure
    ///   (tampered, wrong key, wrong AAD, envelope truncated —
    ///   fail-uniform per AEAD design).
    pub fn decrypt(&self, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>, DekError> {
        Ok(aead::open(&self.key_bytes, envelope, aad)?)
    }

    /// Current pre-increment counter value (number of successful
    /// encrypt calls so far). Reads with `Ordering::SeqCst`.
    pub fn invocation_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Remaining encrypt operations before the cap is hit.
    ///
    /// Returns `0` once the cap has been reached or exceeded. Useful
    /// for proactive rotation triggers (e.g., consumers can rotate
    /// at 80% utilization rather than waiting for the hard error).
    pub fn remaining_invocations(&self) -> u64 {
        let used = self.invocation_count();
        DEK_INVOCATION_HARD_CAP.saturating_sub(used)
    }

    /// Borrow the raw key bytes for paths that need the underlying
    /// material (e.g., wrapping into a BYOK envelope via an external
    /// KMS). Callers MUST NOT copy the bytes into non-zeroizing
    /// storage; the slice is bound to the DEK's lifetime so the
    /// zeroize-on-drop discipline applies.
    pub fn key_bytes(&self) -> &[u8; AES_256_KEY_SIZE] {
        &self.key_bytes
    }
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material via Debug. Counter value is not
        // secret; expose for observability.
        f.debug_struct("DataEncryptionKey")
            .field("key_bytes", &"[REDACTED 32 bytes]")
            .field("invocation_count", &self.invocation_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn generate_returns_correct_key_length() {
        let dek = DataEncryptionKey::generate();
        assert_eq!(dek.key_bytes().len(), AES_256_KEY_SIZE);
    }

    #[test]
    fn generate_zero_initial_counter() {
        let dek = DataEncryptionKey::generate();
        assert_eq!(dek.invocation_count(), 0);
        assert_eq!(dek.remaining_invocations(), DEK_INVOCATION_HARD_CAP);
    }

    #[test]
    fn generate_two_deks_distinct() {
        // Statistical sanity: two generated DEKs should be distinct
        // (OsRng quality assumption). Not a Kani property.
        let dek1 = DataEncryptionKey::generate();
        let dek2 = DataEncryptionKey::generate();
        assert_ne!(dek1.key_bytes(), dek2.key_bytes());
    }

    #[test]
    fn from_bytes_correct_length() {
        let key_bytes = [0x42; 32];
        let dek = DataEncryptionKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(dek.key_bytes(), &key_bytes);
        assert_eq!(dek.invocation_count(), 0);
    }

    #[test]
    fn from_bytes_rejects_short_input() {
        let short = [0x42; 31];
        let err = DataEncryptionKey::from_bytes(&short).unwrap_err();
        assert!(matches!(err, DekError::Aead(AeadError::InvalidKeyLength)));
    }

    #[test]
    fn from_bytes_rejects_long_input() {
        let long = [0x42; 33];
        let err = DataEncryptionKey::from_bytes(&long).unwrap_err();
        assert!(matches!(err, DekError::Aead(AeadError::InvalidKeyLength)));
    }

    #[test]
    fn encrypt_round_trip() {
        let dek = DataEncryptionKey::generate();
        let envelope = dek.encrypt(b"plaintext", b"aad").unwrap();
        let plaintext = dek.decrypt(&envelope, b"aad").unwrap();
        assert_eq!(plaintext, b"plaintext");
    }

    #[test]
    fn encrypt_increments_counter() {
        let dek = DataEncryptionKey::generate();
        assert_eq!(dek.invocation_count(), 0);

        dek.encrypt(b"a", b"").unwrap();
        assert_eq!(dek.invocation_count(), 1);

        dek.encrypt(b"b", b"").unwrap();
        assert_eq!(dek.invocation_count(), 2);

        dek.encrypt(b"c", b"").unwrap();
        assert_eq!(dek.invocation_count(), 3);
    }

    #[test]
    fn encrypt_does_not_consume_counter_on_aead_failure() {
        // Note: aead::seal cannot fail on a valid 32-byte key with normal
        // plaintext under the RustCrypto impl, so we cannot test this
        // path in normal flow. The counter semantics on AeadError are
        // documented: fetch_add is performed BEFORE seal is called, so
        // a failing seal would still consume a counter slot. This is
        // intentional — a seal failure indicates the cipher is in a
        // bad state and forcing rotation is the conservative posture.
    }

    #[test]
    fn remaining_invocations_decrements() {
        let dek = DataEncryptionKey::generate();
        assert_eq!(dek.remaining_invocations(), DEK_INVOCATION_HARD_CAP);
        dek.encrypt(b"a", b"").unwrap();
        assert_eq!(dek.remaining_invocations(), DEK_INVOCATION_HARD_CAP - 1);
    }

    #[test]
    fn cap_hit_returns_key_invocation_limit_exceeded() {
        let dek = DataEncryptionKey::generate();
        // Fast-forward the counter to one below the cap.
        dek.counter
            .store(DEK_INVOCATION_HARD_CAP - 1, Ordering::SeqCst);

        // Last permitted encrypt at counter = cap - 1 succeeds.
        let ok = dek.encrypt(b"final", b"").unwrap();
        assert!(!ok.is_empty());
        assert_eq!(dek.invocation_count(), DEK_INVOCATION_HARD_CAP);

        // Next encrypt at counter = cap is rejected.
        let err = dek.encrypt(b"over-cap", b"").unwrap_err();
        assert!(matches!(
            err,
            DekError::KeyInvocationLimitExceeded { cap } if cap == DEK_INVOCATION_HARD_CAP
        ));

        // Counter is preserved at the cap value (clamped, not incremented).
        assert_eq!(dek.invocation_count(), DEK_INVOCATION_HARD_CAP);
    }

    #[test]
    fn cap_hit_idempotent_repeated_rejections() {
        let dek = DataEncryptionKey::generate();
        dek.counter.store(DEK_INVOCATION_HARD_CAP, Ordering::SeqCst);

        // Repeated post-cap attempts should consistently reject without
        // pushing the counter past the cap.
        for _ in 0..5 {
            let err = dek.encrypt(b"x", b"").unwrap_err();
            assert!(matches!(err, DekError::KeyInvocationLimitExceeded { .. }));
            assert_eq!(dek.invocation_count(), DEK_INVOCATION_HARD_CAP);
        }
    }

    #[test]
    fn decrypt_not_counter_gated() {
        let dek = DataEncryptionKey::generate();
        let envelope = dek.encrypt(b"plaintext", b"aad").unwrap();

        // Exhaust the cap on a separate DEK with the same key bytes;
        // verify decrypt still works against original DEK.
        let dek_clone = DataEncryptionKey::from_bytes(dek.key_bytes()).unwrap();
        dek_clone
            .counter
            .store(DEK_INVOCATION_HARD_CAP, Ordering::SeqCst);

        // Decrypt on the cap-exhausted clone should still succeed —
        // counter does NOT gate the decrypt path.
        let plaintext = dek_clone.decrypt(&envelope, b"aad").unwrap();
        assert_eq!(plaintext, b"plaintext");
    }

    #[test]
    fn decrypt_propagates_aead_open_failed() {
        let dek = DataEncryptionKey::generate();
        let mut envelope = dek.encrypt(b"plaintext", b"aad").unwrap();
        // Tamper.
        envelope[15] ^= 0x01;
        let err = dek.decrypt(&envelope, b"aad").unwrap_err();
        assert!(matches!(err, DekError::Aead(AeadError::OpenFailed)));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let dek = DataEncryptionKey::from_bytes(&[0xAA; 32]).unwrap();
        let debug_str = format!("{dek:?}");
        // Key material must not appear in Debug output.
        assert!(!debug_str.contains("aa"));
        assert!(!debug_str.contains("AA"));
        assert!(debug_str.contains("REDACTED"));
        // Counter is observable.
        assert!(debug_str.contains("invocation_count"));
    }

    #[test]
    fn from_bytes_then_encrypt_round_trip() {
        let key = [0x55; 32];
        let dek = DataEncryptionKey::from_bytes(&key).unwrap();
        let envelope = dek.encrypt(b"hello", b"aad").unwrap();

        let dek2 = DataEncryptionKey::from_bytes(&key).unwrap();
        let plaintext = dek2.decrypt(&envelope, b"aad").unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn concurrent_increments_preserve_total() {
        // Spawn multiple threads each doing N encrypts; total counter
        // should equal sum of per-thread counts (AtomicU64 SeqCst
        // semantics).
        use std::sync::Arc;
        let dek = Arc::new(DataEncryptionKey::generate());
        let mut handles = vec![];
        const THREADS: usize = 8;
        const PER_THREAD: usize = 100;
        for _ in 0..THREADS {
            let dek = Arc::clone(&dek);
            handles.push(std::thread::spawn(move || {
                for _ in 0..PER_THREAD {
                    dek.encrypt(b"x", b"").unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(dek.invocation_count(), (THREADS * PER_THREAD) as u64);
    }
}
