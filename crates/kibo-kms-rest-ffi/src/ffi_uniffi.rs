//! uniffi exports for native-language SDKs (Swift, Kotlin, Python, Go, Ruby, C).
//!
//! Each `zk_*` export is a thin async wrapper that spins a Tokio runtime and
//! delegates to the core engine. uniffi generates the per-language bindings
//! (`uniffi-bindgen generate`) from the proc-macro annotations.
//!
//! # Build
//!
//! Enable the `ffi-uniffi` + one provider feature:
//! ```text
//! cargo build --features ffi-uniffi,kms-aws --release
//! uniffi-bindgen generate --library target/release/libkibo_kms_rest_ffi.a \
//!     --language swift --out-dir bindings/swift
//! ```

use std::sync::OnceLock;

use tokio::runtime::Runtime;

use crate::engine::{zk_decrypt as engine_decrypt, zk_encrypt as engine_encrypt};
use crate::types::{DecryptInput, DecryptOutput, EncryptInput, EncryptOutput, ZkFfiUniffiError};

// `uniffi::setup_scaffolding!()` lives at the crate root (lib.rs) — it must, so
// the `#[uniffi::export]` macros below resolve `crate::UniFfiTag`.

/// uniffi-exported async encrypt. Returns the canonical `b"KIBO"` envelope bytes.
///
/// # Errors
/// [`ZkFfiUniffiError`] on a posture-floor violation, an upstream customer-KMS
/// failure, or a platform error.
#[uniffi::export(async_runtime = "tokio")]
pub async fn zk_encrypt(input: EncryptInput) -> Result<EncryptOutput, ZkFfiUniffiError> {
    engine_encrypt(input).await.map_err(ZkFfiUniffiError::from)
}

/// uniffi-exported async decrypt. Returns the recovered plaintext bytes.
///
/// # Errors
/// [`ZkFfiUniffiError`] on a posture-floor violation, an upstream customer-KMS
/// failure, or a platform error.
#[uniffi::export(async_runtime = "tokio")]
pub async fn zk_decrypt(input: DecryptInput) -> Result<DecryptOutput, ZkFfiUniffiError> {
    engine_decrypt(input).await.map_err(ZkFfiUniffiError::from)
}

// ---- Sync (`_blocking`) exports for the non-async-native uniffi languages ----
// uniffi 0.28 has no async-runtime integration for Ruby/Go/.NET/PHP/Java (the
// generated sync binding receives a `RustFuture` handle it cannot drive), so the
// async exports above are unusable there. These `_blocking` variants drive the
// SAME canonical async op to completion on a process-wide tokio runtime —
// crypto-IDENTICAL — same KMS round-trip, envelope, and AAD; `block_on`
// changes the export shape, not a crypto byte. The async-native langs
// (Python/Swift/Kotlin) keep the async exports; wasm (TS/RN) is unaffected.

/// Process-wide **multi-thread** tokio runtime for the `_blocking` exports. Built
/// once. Multi-thread (not current-thread/per-call) so concurrent `_blocking`
/// callers from multiple host OS threads drive cleanly.
/// `block_on` here is only ever reached from a plain OS thread with no ambient
/// runtime (a non-async-native language) — so it never nests inside a runtime.
fn blocking_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    // A runtime-build failure is unrecoverable (the OS cannot spawn the worker
    // threads) — panic loudly at this once-init rather than thread a fallible
    // result through every `_blocking` export.
    #[allow(clippy::expect_used)]
    RT.get_or_init(|| {
        Runtime::new().expect("kibo-kms-rest-ffi: failed to build the blocking tokio runtime")
    })
}

/// Sync (blocking) encrypt — drives the canonical async `zk_encrypt` to
/// completion. For the non-async-native uniffi languages; crypto-identical.
///
/// # Errors
/// [`ZkFfiUniffiError`] on a posture-floor violation, an upstream customer-KMS
/// failure, or a platform error.
#[uniffi::export]
pub fn zk_encrypt_blocking(input: EncryptInput) -> Result<EncryptOutput, ZkFfiUniffiError> {
    blocking_runtime()
        .block_on(engine_encrypt(input))
        .map_err(ZkFfiUniffiError::from)
}

/// Sync (blocking) decrypt — drives the canonical async `zk_decrypt`.
///
/// # Errors
/// [`ZkFfiUniffiError`] on a posture-floor violation, an upstream customer-KMS
/// failure, or a platform error.
#[uniffi::export]
pub fn zk_decrypt_blocking(input: DecryptInput) -> Result<DecryptOutput, ZkFfiUniffiError> {
    blocking_runtime()
        .block_on(engine_decrypt(input))
        .map_err(ZkFfiUniffiError::from)
}
