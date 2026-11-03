//! Project-local uniffi-bindgen CLI (version-matched to the crate's `uniffi`
//! dependency). Generates the native-language bindings for the ZK encrypt/decrypt
//! surface from the compiled cdylib. Built behind the bin-only `cli` feature so
//! uniffi's `cli` deps stay out of the library/FFI build:
//!   cargo build -p kibo-kms-rest-ffi --features ffi-uniffi,kms-aws --release
//!   cargo run --bin uniffi-bindgen --features cli -- \
//!     generate --library target/release/libkibo_kms_rest_ffi.dylib \
//!     --language ruby --out-dir bindings/ruby
fn main() {
    uniffi::uniffi_bindgen_main()
}
