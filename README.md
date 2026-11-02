# Kibo ZK SDK

Public, auditable source for the Kibo zero-knowledge client crypto. These are
the crates the Kibo client SDKs (mobile, browser/WASM, and the server-side
bindings) build on to perform envelope encryption where the data-encryption key
is wrapped by a key the customer controls — the platform never holds the
plaintext data key.

This repository is a self-contained Cargo workspace: a clean checkout builds
with `cargo build`, with no dependency on any non-public crate.

## Crates

| Crate | Purpose |
|-------|---------|
| [`kibo-crypto-core`](crates/kibo-crypto-core) | The crypto kernel: AES-256-GCM-SIV authenticated encryption, data-encryption-key (DEK) lifecycle, HKDF-SHA-256 key derivation, the versioned ciphertext envelope format, and the shared boundary types. Includes the bounded-model-checking proof harness. |
| [`kibo-kms-rest`](crates/kibo-kms-rest) | REST-direct KMS client for edge devices (mobile / IoT / WASM): wraps and unwraps the DEK through a cloud or self-hosted KMS over the canonical envelope framing, with no vendor SDK dependency (rustls only). |
| [`kibo-kms-rest-ffi`](crates/kibo-kms-rest-ffi) | The `uniffi` (native: Swift / Kotlin / Python / Go / Ruby / C) and `wasm-bindgen` (browser / React Native) bindings over `kibo-kms-rest`'s `zk_encrypt` / `zk_decrypt`. |

## Building

```sh
cargo build            # builds all three crates
cargo test             # runs the unit + integration test suites
```

The crypto kernel's properties (round-trip soundness, tamper detection, AAD
binding, key distinctness, and envelope integrity) are verified with the
[Kani](https://github.com/model-checking/kani) bounded model checker:

```sh
cargo install --locked kani-verifier
cargo kani setup
cargo kani -p kibo-crypto-core -Z stubbing
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
