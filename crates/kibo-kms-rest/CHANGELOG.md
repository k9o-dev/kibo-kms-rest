# Changelog

Starts at 2.15.0. Earlier versions aren't listed.

## 2.16.5 (2026-11-05)

No code changes. Released alongside `kibo-kms-rest-ffi` 0.4.5.

## 2.16.4 (2026-11-05)

No code changes. Released alongside `kibo-kms-rest-ffi` 0.4.4.

## 2.16.3 (2026-11-04)

- Fixed: signing an AWS KMS request panicked on `wasm32-unknown-unknown`, because it read `SystemTime::now`. It now reads JavaScript's clock on that target.
- Changed: HashiCorp Vault can use the platform's federated token. For that token, a Vault token lease over 900 seconds or of 0 is refused, and the login goes over https only.

## 2.16.2 (2026-11-03)

- Fixed: every Cloud KMS open failed to parse the response, because the provider required `verifiedCiphertextCrc32c`, which a real Decrypt response doesn't carry. The returned plaintext is still checked against its CRC32C.

## 2.16.1 (2026-11-03)

- Fixed: Cloud KMS seals failed on real responses. Requests now send padded standard base64, and responses are read in either base64 alphabet, with or without padding. The CRC32C check still runs on the decoded bytes.

## 2.16.0 (2026-11-03)

- Changed: on Azure, the key's host now chooses the path, before any token or call. `*.vault.azure.net` wraps by RSA-OAEP-256 through Key Vault, and `*.managedhsm.azure.net` uses AES. Any other host is refused.
- Removed: the Azure key host suffix setting.

## 2.15.0 (2026-11-03)

- Changed: a keyring is now called a crypt.
- Added: the credential exchange is reachable from the language bindings.
