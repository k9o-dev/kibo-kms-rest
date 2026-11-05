# Changelog

Starts at 0.3.0. Each version builds on the `kibo-kms-rest` version named beside it.

## 0.4.5 (2026-11-05), with kibo-kms-rest 2.16.5

- Fixed: the Windows DLL exported none of the library's functions, so every language binding that loads it failed on the first call.
- Changed: Windows libraries are linked with MinGW GCC. The DLL imports `msvcrt.dll`, and the static library's link flags are listed in the bundle manifest.

## 0.4.4 (2026-11-05), with kibo-kms-rest 2.16.4

- Added: first release on crates.io. The crate also builds as a Rust library, so a Rust application can depend on it directly.

## 0.4.3 (2026-11-04), with kibo-kms-rest 2.16.3

- Fixed: every AWS KMS seal through the Node.js WebAssembly build crashed with `RuntimeError: unreachable`.
- Fixed: the generated C# binding's types are public.
- Changed: HashiCorp Vault can use the platform's federated token. For that token, a Vault token lease over 900 seconds or of 0 is refused, and the login goes over https only.

## 0.4.2 (2026-11-03), with kibo-kms-rest 2.16.2

- Fixed: every Cloud KMS open failed to parse the Decrypt response.

## 0.4.1 (2026-11-03), with kibo-kms-rest 2.16.1

- Fixed: Cloud KMS seals failed on real responses, because of how their base64 fields were read.

## 0.4.0 (2026-11-03), with kibo-kms-rest 2.16.0

- Changed: a standard Azure Key Vault key wraps by RSA, and a Managed HSM key uses AES, chosen by the key's host.
- Removed: `azure_key_host_suffix` from `FfiProviderConfig`.

## 0.3.0 (2026-11-03), with kibo-kms-rest 2.15.0

- Changed: a keyring is now called a crypt.
- Added: `acquire_kms_credential` is reachable from the uniffi and WebAssembly bindings.
