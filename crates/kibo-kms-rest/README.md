# kibo-kms-rest

Encrypt with your own cloud KMS key directly from the device or client, with no vendor SDK.

Each call is one HTTPS request to the KMS, signed on the device. The platform never sees your plaintext or your data key.

- [Install](#install)
- [Quick start](#quick-start)
- [Strategies](#strategies)
- [Getting a token](#getting-a-token)
- [Decrypting](#decrypting)
- [Appendix: features](#appendix-features)

## Install

Enable the provider you use. You can enable several.

```toml
[dependencies]
kibo-kms-rest = { version = "2", features = ["kms-aws"] }
```

There's no default provider, so a build with no `kms-*` feature can't reach a KMS.

## Quick start

Wrap a data key under your AWS KMS key, then unwrap it again.

```rust,no_run
use kibo_kms_rest::provider::aws::AwsKmsRest;
use kibo_kms_rest::provider::{AadContext, AttestationTier, KmsRestProvider};
use kibo_kms_rest::{FederatedToken, KmsRestError, Strategy};

async fn round_trip(token: &FederatedToken) -> Result<(), KmsRestError> {
    let kms = AwsKmsRest::new(
        "arn:aws:kms:eu-central-1:111122223333:key/example".to_string(),
        "eu-central-1".to_string(),
    );
    let aad = AadContext {
        version: 1,
        strategy: Strategy::LocalEnvelope,
        attestation_tier: AttestationTier::Software,
        encryption_context: vec![("tenant".to_string(), "acme".to_string())],
        project_id: None,
    };

    let data_key = [7u8; 32];
    let wrapped = kms.encrypt(token, &data_key, &aad).await?;
    let unwrapped = kms.decrypt(token, &wrapped, &aad).await?;

    println!("{}", unwrapped.as_slice() == data_key.as_slice());
    Ok(())
}
```

```text
true
```

Generate real data keys with [`kibo-crypto-core`](https://crates.io/crates/kibo-crypto-core), which also encrypts the data.

## Strategies

| `Strategy` | The KMS handles | Use it for |
|---|---|---|
| `LocalEnvelope` | a 32-byte data key only | most data: the bulk encryption stays on the device |
| `CustomerKmsOracle` | the data itself | small payloads, when every use should reach the KMS |

The strategy is bound into the authenticated data, so it can't be swapped between encrypt and decrypt.

## Getting a token

A `FederatedToken` is a short-lived credential, scoped to one key and wiped from memory on drop.

Exchange your workload's OIDC token for one in the `federation` module:

| Provider | Function |
|---|---|
| AWS | `acquire_aws_sts` |
| Google Cloud | `acquire_gcp_wif` |
| Azure | `acquire_azure_entra` |
| HashiCorp Vault | `acquire_vault_jwt` |

Refresh the token before it expires. `FederatedToken::is_expired` tells you when.

## Decrypting

Pass the same `encryption_context` you encrypted with, from your own code.

An envelope may hold a copy for audit, but it's never trusted as a decrypt input. A different context fails with `KmsRestError::EnvelopeIntegrity`.

## Appendix: features

| Feature | Provider | Authentication |
|---|---|---|
| `kms-aws` | AWS KMS | SigV4 |
| `kms-gcp` | Google Cloud KMS | OAuth bearer |
| `kms-azure` | Azure Key Vault | OAuth bearer |
| `kms-vault` | HashiCorp Vault Transit | token |

## License

Apache-2.0
