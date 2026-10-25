//! Helpers over the canonical `kibo_crypto_core::envelope` (`b"KIBO"`) framing.
//!
//! This module does NOT define a new envelope format. All ciphertexts use the
//! single canonical framing from `kibo_crypto_core::envelope` (one canonical framing —
//! the prior `b"ZKFE"` private format has been removed).
//!
//! # LocalEnvelope ciphertext-slot layout
//!
//! For `Strategy::LocalEnvelope` the canonical envelope's ciphertext slot
//! (bytes after the nonce: `ciphertext_slice()`) carries:
//!
//! ```text
//! [kms_ct_len: 4B big-endian] [kms_ciphertext: kms_ct_len B] [data_ct_tag: rest]
//! ```
//!
//! The canonical header nonce field (`nonce_slice()`, 12 bytes) holds the
//! nonce extracted from the DEK-seal output (`dek.encrypt()` returns
//! `[nonce(12B) || ct+tag]`; we strip the first 12 bytes into the header
//! and store the remainder as `data_ct_tag`).
//!
//! # CustomerKmsOracle ciphertext-slot layout
//!
//! For `Strategy::CustomerKmsOracle` the ciphertext slot is the raw KMS
//! ciphertext with no length prefix. The nonce field in the header is
//! all zeros (placeholder; no local AEAD is performed in oracle mode).

use crate::types::ZkFfiError;

/// Parse the `LocalEnvelope` ciphertext slot into `(kms_ciphertext, data_ct_tag)`.
///
/// Layout: `[kms_ct_len: 4B BE] [kms_ciphertext: kms_ct_len B] [data_ct_tag: rest]`.
///
/// # Errors
///
/// `K9O_ENVELOPE_HEADER_MALFORMED` if the slot is too short for the length
/// prefix or the declared KMS ciphertext length overruns the buffer.
pub fn parse_local_ciphertext_slot(slot: &[u8]) -> Result<(&[u8], &[u8]), ZkFfiError> {
    if slot.len() < 4 {
        return Err(ZkFfiError {
            code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
            message: format!(
                "LocalEnvelope ciphertext slot too short for length prefix: {} byte(s)",
                slot.len()
            ),
            context: None,
        });
    }
    let kms_ct_len =
        u32::from_be_bytes(slot[..4].try_into().expect("4-byte slice is infallible")) as usize;
    let kms_end = 4usize.checked_add(kms_ct_len).ok_or_else(|| ZkFfiError {
        code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
        message: "LocalEnvelope kms_ct_len overflows offset arithmetic".to_string(),
        context: None,
    })?;
    if slot.len() < kms_end {
        return Err(ZkFfiError {
            code: Some("K9O_ENVELOPE_HEADER_MALFORMED".to_string()),
            message: format!(
                "LocalEnvelope ciphertext slot truncated: kms_ct_len={kms_ct_len} \
                 but only {} bytes available after length prefix",
                slot.len().saturating_sub(4),
            ),
            context: None,
        });
    }
    Ok((&slot[4..kms_end], &slot[kms_end..]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_local_slot_round_trips() {
        let kms_ct = b"wrapped-dek-bytes";
        let data_ct_tag = b"aes-sealed-payload-and-tag";
        let kms_ct_len = (kms_ct.len() as u32).to_be_bytes();
        let mut slot = Vec::new();
        slot.extend_from_slice(&kms_ct_len);
        slot.extend_from_slice(kms_ct);
        slot.extend_from_slice(data_ct_tag);

        let (parsed_kms, parsed_data) = parse_local_ciphertext_slot(&slot).unwrap();
        assert_eq!(parsed_kms, kms_ct.as_slice());
        assert_eq!(parsed_data, data_ct_tag.as_slice());
    }

    #[test]
    fn parse_local_slot_empty_data_ct_is_valid() {
        let kms_ct = b"wrapped-dek";
        let kms_ct_len = (kms_ct.len() as u32).to_be_bytes();
        let mut slot = Vec::new();
        slot.extend_from_slice(&kms_ct_len);
        slot.extend_from_slice(kms_ct);

        let (parsed_kms, parsed_data) = parse_local_ciphertext_slot(&slot).unwrap();
        assert_eq!(parsed_kms, kms_ct.as_slice());
        assert_eq!(parsed_data, b"");
    }

    #[test]
    fn parse_local_slot_rejects_too_short() {
        let err = parse_local_ciphertext_slot(&[0u8; 3]).unwrap_err();
        assert_eq!(err.code.as_deref(), Some("K9O_ENVELOPE_HEADER_MALFORMED"));
    }

    #[test]
    fn parse_local_slot_rejects_overrun_kms_len() {
        let mut slot = Vec::new();
        slot.extend_from_slice(&100u32.to_be_bytes()); // claims 100B but provides none
        let err = parse_local_ciphertext_slot(&slot).unwrap_err();
        assert_eq!(err.code.as_deref(), Some("K9O_ENVELOPE_HEADER_MALFORMED"));
        assert!(err.message.contains("truncated"));
    }
}
