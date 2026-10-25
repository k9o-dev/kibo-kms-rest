//! wasm-bindgen exports for the browser and React Native JS SDK.
//!
//! Each exported function accepts a JSON-serialized input struct and returns a
//! JSON-serialized output, using `serde-wasm-bindgen` for the boundary
//! conversion. This keeps the JS/TS surface simple: pass a plain object, get
//! a plain object back.
//!
//! On wasm32 the `reqwest` client uses the browser's `fetch` backend; the
//! `getrandom` crate uses `crypto.getRandomValues`. Both are enabled via the
//! Cargo feature wiring (see `Cargo.toml` target dependencies).
//!
//! # Build
//!
//! Enable the `ffi-wasm` + one provider feature and build for wasm32:
//! ```text
//! cargo build --target wasm32-unknown-unknown --features ffi-wasm,kms-aws
//! wasm-bindgen --target web target/wasm32-unknown-unknown/debug/kibo_kms_rest_ffi.wasm \
//!     --out-dir pkg/
//! ```
//!
//! Or via `wasm-pack`:
//! ```text
//! wasm-pack build --target web -- --features ffi-wasm,kms-aws
//! ```

use wasm_bindgen::prelude::*;

use crate::engine::{zk_decrypt as engine_decrypt, zk_encrypt as engine_encrypt};
use crate::types::{DecryptInput, EncryptInput};

/// Encrypt via the customer KMS (browser / React Native).
///
/// `input_json` — JSON-serialized `EncryptInput`.
/// Returns a `Promise<string>` resolving to JSON-serialized `EncryptOutput`,
/// or rejecting with a `JsValue` error string.
#[wasm_bindgen]
pub async fn zk_encrypt(input_json: JsValue) -> Result<JsValue, JsValue> {
    let input: EncryptInput = serde_wasm_bindgen::from_value(input_json)
        .map_err(|e| JsValue::from_str(&format!("input deserialize error: {e}")))?;
    let output = engine_encrypt(input)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("output serialize error: {e}")))
}

/// Decrypt a ZKFE envelope (browser / React Native).
///
/// `input_json` — JSON-serialized `DecryptInput`.
/// Returns a `Promise<string>` resolving to JSON-serialized `DecryptOutput`.
#[wasm_bindgen]
pub async fn zk_decrypt(input_json: JsValue) -> Result<JsValue, JsValue> {
    let input: DecryptInput = serde_wasm_bindgen::from_value(input_json)
        .map_err(|e| JsValue::from_str(&format!("input deserialize error: {e}")))?;
    let output = engine_decrypt(input)
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("output serialize error: {e}")))
}
