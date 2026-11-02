# kibo-crypto-core

The encryption primitives behind the Kibo client SDKs: AES-256-GCM-SIV, data keys, HKDF-SHA-256 and a versioned ciphertext format.

- [Install](#install)
- [Quick start](#quick-start)
- [Modules](#modules)
- [Verification](#verification)

## Install

```toml
[dependencies]
kibo-crypto-core = "0.2"
```

## Quick start

Generate a data key, encrypt, then decrypt with the same authenticated data.

```rust
use kibo_crypto_core::dek::DataEncryptionKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = DataEncryptionKey::generate();

    let sealed = key.encrypt(b"hello", b"order-42")?;
    let opened = key.decrypt(&sealed, b"order-42")?;
    println!("{}", String::from_utf8(opened)?);

    println!("{}", key.decrypt(&sealed, b"order-43").is_err());
    Ok(())
}
```

```text
hello
true
```

The second decrypt fails because the authenticated data doesn't match.

To protect the data key with your own KMS key, use [`kibo-kms-rest`](https://crates.io/crates/kibo-kms-rest).

## Modules

| Module | What it holds |
|---|---|
| `aead` | AES-256-GCM-SIV `seal` and `open` |
| `dek` | `DataEncryptionKey`: generation, encryption and a per-key use limit |
| `kdf` | HKDF-SHA-256 key derivation |
| `envelope` | the versioned ciphertext format |
| `app_container` | the application-crypto container, with known-answer vectors |
| `types` | shared types: `KeyVersionRef`, `Region`, `WrappedDek` |

## Verification

These properties are proven with the [Kani](https://github.com/model-checking/kani) bounded model checker: round-trip soundness, tamper detection, AAD binding, key distinctness and envelope integrity.

```sh
cargo install --locked kani-verifier
cargo kani setup
cargo kani -p kibo-crypto-core -Z stubbing --harness prove_round_trip_soundness
```

The other harnesses are `prove_tamper_detection`, `prove_aad_binding`, `prove_key_distinctness`, `prove_envelope_round_trip`, `prove_envelope_offsets_in_bounds`, `prove_envelope_truncation_safety` and `prove_envelope_header_integrity`.

## License

Apache-2.0
