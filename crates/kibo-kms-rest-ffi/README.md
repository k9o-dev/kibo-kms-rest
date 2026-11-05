# kibo-kms-rest-ffi

Client-side encryption with your own KMS key, for applications and language bindings. It seals and opens data on your side, using a key held in AWS KMS, Google Cloud KMS, Azure Key Vault or HashiCorp Vault, and exchanges an identity token for that key's short-lived credential.

Rust applications can depend on it directly. The same crate builds the native libraries and WebAssembly module that other languages bind.

## Features

Enable the providers you use:

| Feature | Provider |
|---|---|
| `kms-aws` | AWS KMS |
| `kms-gcp` | Google Cloud KMS |
| `kms-azure` | Azure Key Vault |
| `kms-vault` | HashiCorp Vault |

A build with no provider refuses every call at run time.

`ffi-uniffi` and `ffi-wasm` generate the language bindings. A Rust application needs neither.

```toml
[dependencies]
kibo-kms-rest-ffi = { version = "0.4", features = ["kms-aws"] }
```

## Entry points

- `app_crypto_seal` and `app_crypto_open` seal and open a value under your key.
- `federate::acquire_kms_credential` exchanges an identity token for the provider's credential.
- `core_capabilities` lists what this build enforces.

Always set `expected_key_refs` to the keys your application allows, from your own configuration. Any other key is then refused before a token is used or a request is sent.

## License

Apache-2.0
