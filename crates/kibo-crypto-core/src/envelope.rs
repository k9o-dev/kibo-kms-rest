//! Ciphertext envelope format for wrapped DEKs.
//!
//! Every [`WrappedDek`](crate::types::WrappedDek) carries a
//! self-describing envelope that lets the unwrap path extract the
//! provider routing + key-version reference without the caller
//! passing them explicitly. This is required for the
//! dual-version window where ciphertexts produced under the old KEK
//! and the new KEK coexist during a re-wrap.
//!
//! # Wire format
//!
//! ```text
//! ┌────────────┬─────────────┬──────────────┬──────────────┬─────────────┐
//! │ Magic (4B) │ Version (1B)│ Provider (1B)│ Key_Ver (8B) │ Ext_Len (2B)│
//! └────────────┴─────────────┴──────────────┴──────────────┴─────────────┘
//!  0            4             5              6              14            16  ← Fixed header (16B)
//! ┌──────────────┬─────────────┬───────────────────────────┐
//! │ Ext_Ref (NB) │ Nonce (12B) │ Ciphertext + tag (MB)     │
//! └──────────────┴─────────────┴───────────────────────────┘
//!  16            16+N           28+N                         28+N+M
//! ```
//!
//! All multi-byte integer fields are **big-endian** (network byte
//! order) — cross-platform compliance with ARM64 ↔ x86_64 mixed
//! substrates.
//!
//! Minimum valid envelope is `28` bytes (16-byte fixed header + 0-byte
//! `ext_ref` + 12-byte nonce). Inputs shorter than this are rejected
//! immediately.
//!
//! # Header-as-AAD binding
//!
//! **The header bytes (everything before the nonce — bytes
//! `0..FIXED_HEADER_SIZE + ext_len`) MUST be passed as the `aad`
//! parameter to [`crate::aead::seal`] and [`crate::aead::open`]
//! when the wrapped DEK ciphertext is sealed/opened.**
//!
//! This binds the ciphertext to its envelope context: an adversary
//! with read/write access to the envelope storage who flips the
//! provider tag, key version, or `external_ref` cannot produce a
//! valid GHASH authentication tag — `open` will return
//! `AeadError::OpenFailed` regardless of whether the underlying DEK
//! material is correct. Defends against the Envelope-Substitution
//! Attack (adversary tries to route a BYOK-AWS-wrapped envelope
//! through the PLATFORM_MANAGED unwrap path, etc.).
//!
//! The helper [`aad_slice`] computes the AAD slice from a parsed
//! envelope (`&envelope_bytes[0..aad_end_offset]`).
//!
//! # Memory-safe zero-copy parsing
//!
//! All slice operations are gated by explicit bounds checks **before**
//! the slice is taken. There are no `.unwrap()` calls on parsing
//! paths and no slicing that could panic on adversarial input.
//! Truncation safety is the load-bearing memory-safety guarantee
//! here — Kani properties P5 and P9 prove this.
//!
//! # Provider tag safety
//!
//! [`ProviderTag::try_from(u8)`] explicitly rejects unknown discriminant
//! values with `EnvelopeError::InvalidProviderTag`. Under
//! `#![forbid(unsafe_code)]` a transmute-based cast would not compile;
//! `TryFrom` provides the explicit error surface in lieu of an
//! `unreachable!` panic.

use thiserror::Error;
use zeroize::Zeroizing;

use crate::types::{KeyVersionRef, WrappedDek};

/// Width of the big-endian invocation-count prefix sealed ahead of the
/// DEK plaintext inside a [`build_with_aad`] envelope (counter
/// persistence across restart /
/// multi-node load). Recovered by [`unwrap_with_aad`] and restored
/// into [`crate::dek::DataEncryptionKey::from_persisted`].
pub const INVOCATION_COUNT_PREFIX_LEN: usize = 8;

/// Envelope magic header — exactly 4 bytes `b"KIBO"`.
pub const MAGIC: &[u8; 4] = b"KIBO";

/// Current envelope format version. Bumped on any breaking envelope change.
pub const FORMAT_VERSION: u8 = 1;

/// Length of the fixed-header prefix (magic + version + provider +
/// key_ver + ext_len) = 16 bytes.
pub const FIXED_HEADER_SIZE: usize = 16;

/// Length of the AES-256-GCM nonce embedded in the envelope = 12 bytes.
/// Matches [`crate::aead::GCM_NONCE_SIZE`].
pub const NONCE_SIZE_BYTES: usize = 12;

/// Length of the AEAD authentication tag (AES-256-GCM-SIV, 128-bit).
/// Matches [`crate::aead::GCM_TAG_SIZE`]; a well-formed envelope's
/// ciphertext slot must hold at least this many bytes.
pub const AEAD_TAG_SIZE: usize = 16;

/// Minimum valid envelope length: fixed header + 0-byte ext_ref + nonce
/// + AEAD tag. Inputs shorter than this cannot carry an authenticated
/// ciphertext and are rejected at parse time (the missing trailing-tag
/// length gate; previously the minimum omitted the 16-byte tag).
pub const MIN_ENVELOPE_SIZE: usize = FIXED_HEADER_SIZE + NONCE_SIZE_BYTES + AEAD_TAG_SIZE;

/// Hard upper bound on a wrapped-DEK envelope, enforced at every parse
/// entry point (unbounded trailing-slice allocation OOM). A real DEK
/// envelope is ~1 KiB (16-byte
/// header + ≤[`crate::types::MAX_EXTERNAL_REF_LEN`] ext_ref + 12-byte
/// nonce + 56-byte sealed `[count || DEK]`); 128 KiB is a generous
/// ceiling that still slams the door on multi-GB adversarial payloads.
pub const MAX_DEK_ENVELOPE_SIZE: usize = 128 * 1024;

/// Offset within the fixed header where the version byte sits.
const VERSION_OFFSET: usize = 4;

/// Offset within the fixed header where the provider tag byte sits.
const PROVIDER_OFFSET: usize = 5;

/// Offset within the fixed header where the 8-byte big-endian
/// `key_ver` field begins.
const KEY_VER_OFFSET: usize = 6;

/// Offset within the fixed header where the 2-byte big-endian
/// `ext_len` field begins.
const EXT_LEN_OFFSET: usize = 14;

/// Errors returned from envelope parsing / construction.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// First 4 bytes are not the `"KIBO"` magic; not a Kibo-format envelope.
    #[error("envelope magic mismatch")]
    MagicMismatch,
    /// Envelope version byte references a format this build doesn't support.
    #[error("unsupported envelope version: {version}")]
    UnsupportedVersion {
        /// The unsupported version byte read from the envelope.
        version: u8,
    },
    /// Envelope bytes ended before the parser expected — corrupt or truncated.
    #[error("envelope truncated at offset {offset}")]
    Truncated {
        /// Byte offset within the envelope where the parser ran out of input.
        offset: usize,
    },
    /// The `external_ref` field bytes were not valid UTF-8.
    #[error("invalid UTF-8 in external_ref")]
    InvalidUtf8,
    /// The provider tag byte does not map to a known [`ProviderTag`] discriminant.
    #[error("invalid provider tag: {tag}")]
    InvalidProviderTag {
        /// The raw u8 value that did not match any known discriminant.
        tag: u8,
    },
    /// The envelope (or its declared `ext_len`) exceeds a hard size
    /// bound — [`MAX_DEK_ENVELOPE_SIZE`] for the whole envelope or
    /// [`crate::types::MAX_EXTERNAL_REF_LEN`] for `ext_len`. Rejected
    /// before allocation to prevent an adversarial-size OOM abort.
    #[error("envelope or ext_len exceeds maximum size (got {got} bytes, max {max})")]
    TooLarge {
        /// The over-budget length read from the input.
        got: usize,
        /// The maximum permitted for the field that was violated.
        max: usize,
    },
}

/// Provider tag carried in the envelope.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProviderTag {
    /// PLATFORM_MANAGED — Kibo holds the wrapped DEK under a platform KEK.
    PlatformManaged = 0,
    /// BYOK — AWS KMS.
    BYOKAwsKms = 1,
    /// BYOK — GCP Cloud KMS.
    BYOKGcpCloudKms = 2,
    /// BYOK — Azure Key Vault.
    BYOKAzureKeyVault = 3,
    /// BYOK — HashiCorp Vault Transit (`shamir` seal type).
    BYOKHashicorpVault = 4,
    /// HYOK — AWS KMS Custom Key Store.
    HYOKAwsKmsCustomKeyStore = 16,
    /// HYOK — GCP Cloud KMS HSM protection level.
    HYOKGcpCloudKmsHsm = 17,
    /// HYOK — Azure Managed HSM.
    HYOKAzureManagedHsm = 18,
    /// HYOK — HashiCorp Vault Transit (HSM-backed auto-unseal seal). Distinct
    /// from `BYOKHashicorpVault` (shamir/software seal): the posture differs, so
    /// the tag must too — this token is bound into the AAD as an anti-substitution
    /// guard, and a BYOK-Vault envelope must not be replayable as HYOK-Vault.
    HYOKHashicorpVaultTransit = 19,
}

impl TryFrom<u8> for ProviderTag {
    type Error = EnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProviderTag::PlatformManaged),
            1 => Ok(ProviderTag::BYOKAwsKms),
            2 => Ok(ProviderTag::BYOKGcpCloudKms),
            3 => Ok(ProviderTag::BYOKAzureKeyVault),
            4 => Ok(ProviderTag::BYOKHashicorpVault),
            16 => Ok(ProviderTag::HYOKAwsKmsCustomKeyStore),
            17 => Ok(ProviderTag::HYOKGcpCloudKmsHsm),
            18 => Ok(ProviderTag::HYOKAzureManagedHsm),
            19 => Ok(ProviderTag::HYOKHashicorpVaultTransit),
            other => Err(EnvelopeError::InvalidProviderTag { tag: other }),
        }
    }
}

/// Parse the envelope header and return the provider tag + key
/// version reference for unwrap-path routing.
///
/// Every slice operation is bounded by an explicit length check
/// **before** the slice is taken — adversarial input cannot trigger
/// a panicking out-of-bounds read.
///
/// # Errors
///
/// - [`EnvelopeError::Truncated`] with the offset at which the
///   parser ran out of input.
/// - [`EnvelopeError::MagicMismatch`] if the first 4 bytes are not
///   `b"KIBO"`.
/// - [`EnvelopeError::UnsupportedVersion`] if the version byte is
///   not [`FORMAT_VERSION`].
/// - [`EnvelopeError::InvalidProviderTag`] if the provider byte does
///   not map to a known [`ProviderTag`].
/// - [`EnvelopeError::InvalidUtf8`] if the `external_ref` bytes are
///   not valid UTF-8.
pub fn read_header(bytes: &[u8]) -> Result<(ProviderTag, KeyVersionRef), EnvelopeError> {
    // 1. Minimum-size check before any slicing. MIN_ENVELOPE_SIZE now
    //    includes the 16-byte AEAD tag, so a header+nonce-only buffer
    //    with no room for an authenticated ciphertext is rejected here.
    if bytes.len() < MIN_ENVELOPE_SIZE {
        return Err(EnvelopeError::Truncated { offset: bytes.len() });
    }

    // 1b. Hard upper bound before any allocation (oversized-envelope OOM).
    if bytes.len() > MAX_DEK_ENVELOPE_SIZE {
        return Err(EnvelopeError::TooLarge {
            got: bytes.len(),
            max: MAX_DEK_ENVELOPE_SIZE,
        });
    }

    // 2. Magic match.
    if &bytes[0..MAGIC.len()] != MAGIC {
        return Err(EnvelopeError::MagicMismatch);
    }

    // 3. Version match.
    let version = bytes[VERSION_OFFSET];
    if version != FORMAT_VERSION {
        return Err(EnvelopeError::UnsupportedVersion { version });
    }

    // 4. Provider tag — TryFrom returns explicit error on rogue bytes.
    let provider = ProviderTag::try_from(bytes[PROVIDER_OFFSET])?;

    // 5. key_ver (8B big-endian). The slice [6..14] is in-bounds by
    //    the MIN_ENVELOPE_SIZE check above (14 <= 28); .try_into()
    //    on the exact-length slice is infallible.
    let key_ver_arr: [u8; 8] = bytes[KEY_VER_OFFSET..KEY_VER_OFFSET + 8]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated {
            offset: KEY_VER_OFFSET,
        })?;
    let version_num = u64::from_be_bytes(key_ver_arr);

    // 6. ext_len (2B big-endian).
    let ext_len_arr: [u8; 2] = bytes[EXT_LEN_OFFSET..FIXED_HEADER_SIZE]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated {
            offset: EXT_LEN_OFFSET,
        })?;
    let ext_len = u16::from_be_bytes(ext_len_arr) as usize;

    // 6b. Reject a declared ext_len beyond the tight identifier bound
    //     before computing offsets (amplification).
    if ext_len > crate::types::MAX_EXTERNAL_REF_LEN {
        return Err(EnvelopeError::TooLarge {
            got: ext_len,
            max: crate::types::MAX_EXTERNAL_REF_LEN,
        });
    }

    // 7. Variable section bounds: ext_ref (ext_len bytes) + nonce (12B)
    //    + AEAD tag (16B). Compute the absolute end offset and check
    //    against input length BEFORE slicing. The trailing tag is part
    //    of the minimum so a ciphertext slot with no room for the tag is
    //    rejected at parse time, not deferred to the AEAD layer.
    let variable_section_end = FIXED_HEADER_SIZE
        .checked_add(ext_len)
        .ok_or(EnvelopeError::Truncated {
            offset: FIXED_HEADER_SIZE,
        })?;
    let nonce_end = variable_section_end
        .checked_add(NONCE_SIZE_BYTES)
        .ok_or(EnvelopeError::Truncated {
            offset: variable_section_end,
        })?;
    let min_ciphertext_end = nonce_end
        .checked_add(AEAD_TAG_SIZE)
        .ok_or(EnvelopeError::Truncated { offset: nonce_end })?;
    if bytes.len() < min_ciphertext_end {
        return Err(EnvelopeError::Truncated {
            offset: variable_section_end,
        });
    }

    // 8. UTF-8 parse the external_ref bytes.
    let external_ref_bytes = &bytes[FIXED_HEADER_SIZE..variable_section_end];
    let external_ref = std::str::from_utf8(external_ref_bytes)
        .map_err(|_| EnvelopeError::InvalidUtf8)?
        .to_string();

    Ok((
        provider,
        KeyVersionRef {
            version: version_num,
            external_ref,
        },
    ))
}

/// Compute the AAD slice for the Header-as-AAD binding.
///
/// This is everything from the start of the envelope up to (but
/// excluding) the nonce — `&envelope[0..FIXED_HEADER_SIZE + ext_len]`.
/// Callers seal/open the wrapped DEK ciphertext under this AAD to
/// bind the envelope context to the AEAD tag.
///
/// # Errors
///
/// Returns [`EnvelopeError::Truncated`] if the envelope is shorter
/// than the fixed header. Performs the same minimum bounds check as
/// [`read_header`] but does NOT verify magic / version / provider —
/// callers that need full validation should call [`read_header`]
/// first.
pub fn aad_slice(envelope: &[u8]) -> Result<&[u8], EnvelopeError> {
    if envelope.len() < FIXED_HEADER_SIZE {
        return Err(EnvelopeError::Truncated {
            offset: envelope.len(),
        });
    }
    let ext_len_arr: [u8; 2] = envelope[EXT_LEN_OFFSET..FIXED_HEADER_SIZE]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated {
            offset: EXT_LEN_OFFSET,
        })?;
    let ext_len = u16::from_be_bytes(ext_len_arr) as usize;
    let aad_end = FIXED_HEADER_SIZE
        .checked_add(ext_len)
        .ok_or(EnvelopeError::Truncated {
            offset: FIXED_HEADER_SIZE,
        })?;
    if envelope.len() < aad_end {
        return Err(EnvelopeError::Truncated { offset: aad_end });
    }
    Ok(&envelope[0..aad_end])
}

/// Extract the nonce slice from a parsed envelope.
///
/// Returns the 12-byte nonce at offset `FIXED_HEADER_SIZE + ext_len`.
///
/// # Errors
///
/// Returns [`EnvelopeError::Truncated`] if the envelope is shorter
/// than the fixed header + nonce.
pub fn nonce_slice(envelope: &[u8]) -> Result<&[u8], EnvelopeError> {
    if envelope.len() < FIXED_HEADER_SIZE {
        return Err(EnvelopeError::Truncated {
            offset: envelope.len(),
        });
    }
    let ext_len_arr: [u8; 2] = envelope[EXT_LEN_OFFSET..FIXED_HEADER_SIZE]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated {
            offset: EXT_LEN_OFFSET,
        })?;
    let ext_len = u16::from_be_bytes(ext_len_arr) as usize;
    let nonce_start = FIXED_HEADER_SIZE
        .checked_add(ext_len)
        .ok_or(EnvelopeError::Truncated {
            offset: FIXED_HEADER_SIZE,
        })?;
    let nonce_end = nonce_start
        .checked_add(NONCE_SIZE_BYTES)
        .ok_or(EnvelopeError::Truncated { offset: nonce_start })?;
    if envelope.len() < nonce_end {
        return Err(EnvelopeError::Truncated { offset: nonce_start });
    }
    Ok(&envelope[nonce_start..nonce_end])
}

/// Extract the ciphertext+tag slice from a parsed envelope.
///
/// Returns the bytes after the nonce — `&envelope[nonce_end..]`.
///
/// # Errors
///
/// Returns [`EnvelopeError::Truncated`] if the envelope is shorter
/// than the fixed header + nonce.
pub fn ciphertext_slice(envelope: &[u8]) -> Result<&[u8], EnvelopeError> {
    if envelope.len() < FIXED_HEADER_SIZE {
        return Err(EnvelopeError::Truncated {
            offset: envelope.len(),
        });
    }
    let ext_len_arr: [u8; 2] = envelope[EXT_LEN_OFFSET..FIXED_HEADER_SIZE]
        .try_into()
        .map_err(|_| EnvelopeError::Truncated {
            offset: EXT_LEN_OFFSET,
        })?;
    let ext_len = u16::from_be_bytes(ext_len_arr) as usize;
    let nonce_start = FIXED_HEADER_SIZE
        .checked_add(ext_len)
        .ok_or(EnvelopeError::Truncated {
            offset: FIXED_HEADER_SIZE,
        })?;
    let nonce_end = nonce_start
        .checked_add(NONCE_SIZE_BYTES)
        .ok_or(EnvelopeError::Truncated { offset: nonce_start })?;
    if envelope.len() < nonce_end {
        return Err(EnvelopeError::Truncated { offset: nonce_start });
    }
    Ok(&envelope[nonce_end..])
}

/// Construct an envelope from the provider tag, key version reference,
/// nonce, and AEAD-sealed DEK ciphertext-with-tag.
///
/// Returns the assembled [`WrappedDek`] suitable for storage. The
/// header bytes (everything before `nonce`) are also what should
/// have been passed as `aad` to [`crate::aead::seal`] when producing
/// `ciphertext_with_tag` — the Header-as-AAD binding.
///
/// The `nonce` is a fixed-width `&[u8; NONCE_SIZE_BYTES]` reference, so
/// a wrong-length nonce is a compile error rather than a malformed wire
/// block.
pub fn build(
    provider: ProviderTag,
    key_version: &KeyVersionRef,
    nonce: &[u8; NONCE_SIZE_BYTES],
    ciphertext_with_tag: &[u8],
) -> WrappedDek {
    let ext_bytes = key_version.external_ref.as_bytes();
    // Cap ext_len at the tight identifier bound.
    // Provider key identifiers are well under this; a caller exceeding
    // it is using the field outside its intended scope, so we cap rather
    // than error to keep build() infallible at the type level. (The
    // bound is also enforced — as a hard reject — at deserialize in
    // types.rs and at parse in read_header.)
    let ext_len = std::cmp::min(ext_bytes.len(), crate::types::MAX_EXTERNAL_REF_LEN);
    let ext_bytes_capped = &ext_bytes[..ext_len];

    // Checked capacity: fall back to a growable Vec on the (unreachable
    // for real in-memory slices) overflow rather than panicking in
    // Vec::with_capacity.
    let mut envelope = match FIXED_HEADER_SIZE
        .checked_add(ext_len)
        .and_then(|a| a.checked_add(NONCE_SIZE_BYTES))
        .and_then(|a| a.checked_add(ciphertext_with_tag.len()))
    {
        Some(cap) => Vec::with_capacity(cap),
        None => Vec::new(),
    };

    // Fixed header.
    envelope.extend_from_slice(MAGIC);
    envelope.push(FORMAT_VERSION);
    envelope.push(provider as u8);
    envelope.extend_from_slice(&key_version.version.to_be_bytes());
    envelope.extend_from_slice(&(ext_len as u16).to_be_bytes());

    // Variable section.
    envelope.extend_from_slice(ext_bytes_capped);
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(ciphertext_with_tag);

    WrappedDek { envelope }
}

/// Build an envelope that round-trips through the AEAD primitive
/// with Header-as-AAD binding: the wrapped DEK ciphertext is produced
/// by sealing `dek_plaintext` under `kek` with the envelope header
/// bytes as AAD. This is the canonical Header-as-AAD construction
/// — a tampered header byte breaks the AEAD tag.
///
/// # Errors
///
/// - [`EnvelopeError`] forwarded from any intermediate failure (none
///   currently surface; placeholder for future bounds-tightening).
///
/// # Panics
///
/// Returns the assembled envelope OR an `aead::AeadError` if the
/// underlying seal fails. The signature funnels both into a single
/// `Result` for ergonomic call-site error handling.
pub fn build_with_aad(
    provider: ProviderTag,
    key_version: &KeyVersionRef,
    kek: &[u8],
    dek_plaintext: &[u8],
    invocation_count: u64,
) -> Result<WrappedDek, crate::aead::AeadError> {
    // Step 1: construct the header bytes that will both serve as AAD
    // and appear at the start of the final envelope. We rebuild the
    // header in a small buffer so the AAD bytes are identical to
    // what `read_header` will see at unwrap time.
    let ext_bytes = key_version.external_ref.as_bytes();
    let ext_len = std::cmp::min(ext_bytes.len(), crate::types::MAX_EXTERNAL_REF_LEN);
    let ext_bytes_capped = &ext_bytes[..ext_len];

    // ext_len <= MAX_EXTERNAL_REF_LEN, so FIXED_HEADER_SIZE + ext_len
    // cannot overflow; with_capacity is safe here.
    let mut header = Vec::with_capacity(FIXED_HEADER_SIZE + ext_len);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(provider as u8);
    header.extend_from_slice(&key_version.version.to_be_bytes());
    header.extend_from_slice(&(ext_len as u16).to_be_bytes());
    header.extend_from_slice(ext_bytes_capped);

    // Step 2: build the inner plaintext as `[count_be(8) || dek]` and
    // seal it under kek with header-as-AAD. Persisting the DEK's
    // invocation count *inside* the sealed (authenticated +
    // confidential) payload means an unwrap on restart / a second
    // node restores the true historical count rather than resetting
    // to 0 — the counter-persistence fix. The inner buffer is
    // `Zeroizing` so the transient DEK plaintext copy is wiped on drop.
    let mut inner = Zeroizing::new(Vec::with_capacity(
        INVOCATION_COUNT_PREFIX_LEN + dek_plaintext.len(),
    ));
    inner.extend_from_slice(&invocation_count.to_be_bytes());
    inner.extend_from_slice(dek_plaintext);

    // aead::seal takes a fixed-width &[u8; 32] key; convert the kek
    // slice once (wrong length → InvalidKeyLength). aead::seal returns
    // [12B nonce || ct+16B tag]; we splice the nonce out and assemble
    // the envelope.
    let kek_arr: &[u8; crate::aead::AES_256_KEY_SIZE] = kek
        .try_into()
        .map_err(|_| crate::aead::AeadError::InvalidKeyLength)?;
    let sealed = crate::aead::seal(kek_arr, &inner, &header)?;
    let (nonce_bytes, ciphertext_with_tag) = sealed.split_at(crate::aead::GCM_NONCE_SIZE);

    // Step 3: assemble the envelope = header || nonce || ct+tag.
    // Checked capacity with a growable fallback.
    let mut envelope = match header
        .len()
        .checked_add(nonce_bytes.len())
        .and_then(|a| a.checked_add(ciphertext_with_tag.len()))
    {
        Some(cap) => Vec::with_capacity(cap),
        None => Vec::new(),
    };
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(nonce_bytes);
    envelope.extend_from_slice(ciphertext_with_tag);

    Ok(WrappedDek { envelope })
}

/// Unwrap a [`WrappedDek`] produced by [`build_with_aad`] under the
/// same `kek`. Returns `(invocation_count, dek_plaintext)` — the
/// persisted historical invocation count (restore into
/// [`crate::dek::DataEncryptionKey::from_persisted`]) plus the
/// original DEK material.
///
/// This is the inverse of [`build_with_aad`] and provides the
/// canonical Header-as-AAD verification: any tampering of the
/// envelope header bytes will cause AEAD-tag verification failure.
///
/// # Errors
///
/// - [`crate::aead::AeadError::OpenFailed`] if the envelope is
///   tampered (header bytes, nonce, ciphertext, or tag), the AAD
///   does not match the embedded header, the `kek` is wrong, the
///   envelope is malformed, or the recovered plaintext is shorter
///   than the [`INVOCATION_COUNT_PREFIX_LEN`] count prefix.
/// - [`crate::aead::AeadError::InvalidKeyLength`] if `kek` is not 32 bytes.
pub fn unwrap_with_aad(
    kek: &[u8],
    envelope: &[u8],
) -> Result<(u64, Zeroizing<Vec<u8>>), crate::aead::AeadError> {
    // Hard size gate BEFORE any slicing/allocation — an oversized
    // envelope with gigabytes of trailing junk cannot drive an OOM
    // abort through the reconstitution copy below. Fail-uniform
    // OpenFailed, consistent with every other
    // malformed-envelope path here.
    if envelope.len() > MAX_DEK_ENVELOPE_SIZE {
        return Err(crate::aead::AeadError::OpenFailed);
    }

    // Compute AAD from the envelope header — this is the same byte
    // range that build_with_aad sealed under.
    let aad = aad_slice(envelope).map_err(|_| crate::aead::AeadError::OpenFailed)?;
    let nonce = nonce_slice(envelope).map_err(|_| crate::aead::AeadError::OpenFailed)?;
    let ciphertext = ciphertext_slice(envelope).map_err(|_| crate::aead::AeadError::OpenFailed)?;

    // Zero-copy unwrap: pass the parsed nonce
    // and ciphertext slices straight to aead::open_detached rather than
    // allocating a fresh [nonce || ciphertext] vector for aead::open to
    // re-split — that copy was the allocation-latency timing oracle.
    let kek_arr: &[u8; crate::aead::AES_256_KEY_SIZE] = kek
        .try_into()
        .map_err(|_| crate::aead::AeadError::InvalidKeyLength)?;
    let nonce_arr: &[u8; crate::aead::GCM_NONCE_SIZE] = nonce
        .try_into()
        .map_err(|_| crate::aead::AeadError::OpenFailed)?;

    // Recovered inner plaintext is `[count_be(8) || dek]`; wrap in
    // Zeroizing so the transient copy is wiped on drop, then split.
    let inner = Zeroizing::new(crate::aead::open_detached(kek_arr, nonce_arr, ciphertext, aad)?);
    if inner.len() < INVOCATION_COUNT_PREFIX_LEN {
        return Err(crate::aead::AeadError::OpenFailed);
    }
    let mut count_arr = [0u8; INVOCATION_COUNT_PREFIX_LEN];
    count_arr.copy_from_slice(&inner[..INVOCATION_COUNT_PREFIX_LEN]);
    let invocation_count = u64::from_be_bytes(count_arr);
    let dek_plaintext = Zeroizing::new(inner[INVOCATION_COUNT_PREFIX_LEN..].to_vec());

    Ok((invocation_count, dek_plaintext))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sample_key_version() -> KeyVersionRef {
        KeyVersionRef {
            version: 0x0102_0304_0506_0708,
            external_ref: "arn:aws:kms:us-east-1:123:key/abcd-1234".to_string(),
        }
    }

    #[test]
    fn provider_tag_try_from_round_trip() {
        for tag in [
            ProviderTag::PlatformManaged,
            ProviderTag::BYOKAwsKms,
            ProviderTag::BYOKGcpCloudKms,
            ProviderTag::BYOKAzureKeyVault,
            ProviderTag::BYOKHashicorpVault,
            ProviderTag::HYOKAwsKmsCustomKeyStore,
            ProviderTag::HYOKGcpCloudKmsHsm,
            ProviderTag::HYOKAzureManagedHsm,
            ProviderTag::HYOKHashicorpVaultTransit,
        ] {
            let byte = tag as u8;
            let parsed = ProviderTag::try_from(byte).unwrap();
            assert_eq!(parsed, tag);
        }
    }

    #[test]
    fn provider_tag_rejects_unknown_discriminants() {
        for value in [5_u8, 6, 7, 15, 20, 21, 99, 255] {
            let err = ProviderTag::try_from(value).unwrap_err();
            assert!(matches!(
                err,
                EnvelopeError::InvalidProviderTag { tag } if tag == value
            ));
        }
    }

    #[test]
    fn build_round_trip_through_read_header() {
        let kv = sample_key_version();
        let nonce = [0xAA; NONCE_SIZE_BYTES];
        let ct_tag = vec![0xBB; 48]; // wrap of 32B DEK + 16B tag
        let wrapped = build(ProviderTag::BYOKAwsKms, &kv, &nonce, &ct_tag);

        let (provider, parsed_kv) = read_header(&wrapped.envelope).unwrap();
        assert_eq!(provider, ProviderTag::BYOKAwsKms);
        assert_eq!(parsed_kv, kv);
    }

    #[test]
    fn build_envelope_total_length() {
        let kv = sample_key_version();
        let nonce = [0xAA; NONCE_SIZE_BYTES];
        let ct_tag = vec![0xBB; 48];
        let wrapped = build(ProviderTag::PlatformManaged, &kv, &nonce, &ct_tag);

        let ext_len = kv.external_ref.len();
        let expected = FIXED_HEADER_SIZE + ext_len + NONCE_SIZE_BYTES + ct_tag.len();
        assert_eq!(wrapped.envelope.len(), expected);
    }

    #[test]
    fn read_header_rejects_empty() {
        let err = read_header(&[]).unwrap_err();
        assert!(matches!(err, EnvelopeError::Truncated { offset: 0 }));
    }

    #[test]
    fn read_header_rejects_short_below_minimum() {
        // MIN_ENVELOPE_SIZE now includes the 16-byte tag (= 44); one
        // byte below it must reject.
        let short = vec![0u8; MIN_ENVELOPE_SIZE - 1];
        let err = read_header(&short).unwrap_err();
        assert!(matches!(
            err,
            EnvelopeError::Truncated { offset } if offset == MIN_ENVELOPE_SIZE - 1
        ));
    }

    #[test]
    fn read_header_rejects_missing_tag_room() {
        // A buffer that has header + nonce but no room for the 16-byte
        // tag in the ciphertext slot is rejected at parse.
        let kv = KeyVersionRef { version: 1, external_ref: String::new() };
        // 15-byte "ciphertext" slot = one short of a bare tag.
        let wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 15]);
        assert!(matches!(
            read_header(&wrapped.envelope),
            Err(EnvelopeError::Truncated { .. })
        ));
    }

    #[test]
    fn read_header_rejects_oversized_ext_len() {
        // Declared ext_len beyond MAX_EXTERNAL_REF_LEN is rejected as
        // TooLarge before offset math.
        let mut envelope = Vec::new();
        envelope.extend_from_slice(MAGIC);
        envelope.push(FORMAT_VERSION);
        envelope.push(ProviderTag::PlatformManaged as u8);
        envelope.extend_from_slice(&1_u64.to_be_bytes());
        envelope.extend_from_slice(&u16::MAX.to_be_bytes()); // 65535 > 1024
        envelope.resize(MIN_ENVELOPE_SIZE + 100, 0u8); // pass the min-size gate
        assert!(matches!(
            read_header(&envelope),
            Err(EnvelopeError::TooLarge { max, .. }) if max == crate::types::MAX_EXTERNAL_REF_LEN
        ));
    }

    #[test]
    fn read_header_rejects_bad_magic() {
        let kv = KeyVersionRef {
            version: 1,
            external_ref: String::new(),
        };
        let mut wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 16]);
        // Flip a magic byte.
        wrapped.envelope[0] = b'X';
        let err = read_header(&wrapped.envelope).unwrap_err();
        assert!(matches!(err, EnvelopeError::MagicMismatch));
    }

    #[test]
    fn read_header_rejects_unsupported_version() {
        let kv = KeyVersionRef {
            version: 1,
            external_ref: String::new(),
        };
        let mut wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 16]);
        wrapped.envelope[VERSION_OFFSET] = 99;
        let err = read_header(&wrapped.envelope).unwrap_err();
        assert!(matches!(
            err,
            EnvelopeError::UnsupportedVersion { version: 99 }
        ));
    }

    #[test]
    fn read_header_rejects_invalid_provider_tag() {
        let kv = KeyVersionRef {
            version: 1,
            external_ref: String::new(),
        };
        let mut wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 16]);
        wrapped.envelope[PROVIDER_OFFSET] = 99;
        let err = read_header(&wrapped.envelope).unwrap_err();
        assert!(matches!(
            err,
            EnvelopeError::InvalidProviderTag { tag: 99 }
        ));
    }

    #[test]
    fn read_header_rejects_truncated_at_variable_section() {
        // Build envelope claiming ext_len = 100 but provide far fewer
        // variable-section bytes. Pad past MIN_ENVELOPE_SIZE so the
        // failure is the variable-section bound, not the min-size gate.
        let mut envelope = Vec::new();
        envelope.extend_from_slice(MAGIC);
        envelope.push(FORMAT_VERSION);
        envelope.push(ProviderTag::PlatformManaged as u8);
        envelope.extend_from_slice(&1_u64.to_be_bytes());
        envelope.extend_from_slice(&100_u16.to_be_bytes()); // claim 100B ext_ref
        envelope.extend_from_slice(&[0u8; 40]); // 40 < 100 + 12 + 16 needed
        let err = read_header(&envelope).unwrap_err();
        assert!(matches!(err, EnvelopeError::Truncated { .. }));
    }

    #[test]
    fn read_header_rejects_invalid_utf8_in_ext_ref() {
        let kv = KeyVersionRef {
            version: 1,
            external_ref: "valid".to_string(),
        };
        let mut wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 16]);
        // Replace ext_ref bytes with invalid UTF-8.
        let ext_start = FIXED_HEADER_SIZE;
        wrapped.envelope[ext_start] = 0xFF;
        wrapped.envelope[ext_start + 1] = 0xFE;
        let err = read_header(&wrapped.envelope).unwrap_err();
        assert!(matches!(err, EnvelopeError::InvalidUtf8));
    }

    #[test]
    fn read_header_empty_external_ref() {
        let kv = KeyVersionRef {
            version: 42,
            external_ref: String::new(),
        };
        let wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &[0u8; 16]);
        let (provider, parsed_kv) = read_header(&wrapped.envelope).unwrap();
        assert_eq!(provider, ProviderTag::PlatformManaged);
        assert_eq!(parsed_kv.version, 42);
        assert_eq!(parsed_kv.external_ref, "");
    }

    #[test]
    fn aad_slice_matches_header_bytes() {
        let kv = sample_key_version();
        let wrapped = build(ProviderTag::BYOKAwsKms, &kv, &[0u8; 12], &[0u8; 16]);
        let aad = aad_slice(&wrapped.envelope).unwrap();
        let expected_len = FIXED_HEADER_SIZE + kv.external_ref.len();
        assert_eq!(aad.len(), expected_len);
        assert_eq!(&aad[0..MAGIC.len()], MAGIC);
        assert_eq!(aad[PROVIDER_OFFSET], ProviderTag::BYOKAwsKms as u8);
    }

    #[test]
    fn nonce_slice_returns_12_bytes() {
        let kv = sample_key_version();
        let nonce_in = [0xAA; NONCE_SIZE_BYTES];
        let wrapped = build(ProviderTag::PlatformManaged, &kv, &nonce_in, &[0u8; 16]);
        let nonce_out = nonce_slice(&wrapped.envelope).unwrap();
        assert_eq!(nonce_out, &nonce_in);
    }

    #[test]
    fn ciphertext_slice_returns_remainder() {
        let kv = sample_key_version();
        let ct_in = vec![0xBB; 48];
        let wrapped = build(ProviderTag::PlatformManaged, &kv, &[0u8; 12], &ct_in);
        let ct_out = ciphertext_slice(&wrapped.envelope).unwrap();
        assert_eq!(ct_out, ct_in.as_slice());
    }

    #[test]
    fn build_with_aad_round_trip() {
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        // Non-zero count to validate counter-persistence round-trips.
        let wrapped =
            build_with_aad(ProviderTag::BYOKAwsKms, &kv, &kek, &dek_plaintext, 500_000).unwrap();
        let (count, recovered) = unwrap_with_aad(&kek, &wrapped.envelope).unwrap();
        assert_eq!(count, 500_000);
        assert_eq!(recovered.as_slice(), &dek_plaintext);
    }

    #[test]
    fn build_with_aad_persists_zero_count() {
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let wrapped =
            build_with_aad(ProviderTag::PlatformManaged, &kv, &kek, &dek_plaintext, 0).unwrap();
        let (count, recovered) = unwrap_with_aad(&kek, &wrapped.envelope).unwrap();
        assert_eq!(count, 0);
        assert_eq!(recovered.as_slice(), &dek_plaintext);
    }

    #[test]
    fn header_as_aad_blocks_envelope_substitution_provider_flip() {
        // Build a BYOK_AWS envelope, tamper the provider byte to
        // PLATFORM_MANAGED, confirm unwrap fails with AEAD OpenFailed.
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let mut wrapped = build_with_aad(ProviderTag::BYOKAwsKms, &kv, &kek, &dek_plaintext, 0).unwrap();
        wrapped.envelope[PROVIDER_OFFSET] = ProviderTag::PlatformManaged as u8;
        let err = unwrap_with_aad(&kek, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn header_as_aad_blocks_envelope_substitution_keyver_flip() {
        // Tamper the key_ver bytes — must break AEAD tag.
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let mut wrapped = build_with_aad(ProviderTag::BYOKAwsKms, &kv, &kek, &dek_plaintext, 0).unwrap();
        wrapped.envelope[KEY_VER_OFFSET] ^= 0x01;
        let err = unwrap_with_aad(&kek, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn header_as_aad_blocks_envelope_substitution_ext_ref_flip() {
        // Tamper the external_ref bytes — must break AEAD tag.
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let mut wrapped = build_with_aad(ProviderTag::BYOKAwsKms, &kv, &kek, &dek_plaintext, 0).unwrap();
        wrapped.envelope[FIXED_HEADER_SIZE] ^= 0x01;
        let err = unwrap_with_aad(&kek, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn header_as_aad_blocks_envelope_substitution_version_flip() {
        // Tamper the version byte — must break AEAD tag. (read_header
        // would catch this with UnsupportedVersion, but if a downstream
        // consumer bypassed read_header and went straight to unwrap,
        // the AAD binding catches it too.)
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let mut wrapped = build_with_aad(ProviderTag::BYOKAwsKms, &kv, &kek, &dek_plaintext, 0).unwrap();
        wrapped.envelope[VERSION_OFFSET] = 99;
        let err = unwrap_with_aad(&kek, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn unwrap_with_aad_rejects_wrong_kek() {
        let kv = sample_key_version();
        let kek_a = [0x42; 32];
        let kek_b = [0x43; 32];
        let dek_plaintext = [0x11; 32];
        let wrapped = build_with_aad(ProviderTag::PlatformManaged, &kv, &kek_a, &dek_plaintext, 0).unwrap();
        let err = unwrap_with_aad(&kek_b, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn unwrap_with_aad_rejects_tampered_ciphertext() {
        let kv = sample_key_version();
        let kek = [0x42; 32];
        let dek_plaintext = [0x11; 32];
        let mut wrapped = build_with_aad(ProviderTag::PlatformManaged, &kv, &kek, &dek_plaintext, 0).unwrap();
        // Flip a byte in the ciphertext region (well past the nonce).
        let ct_offset = FIXED_HEADER_SIZE + kv.external_ref.len() + NONCE_SIZE_BYTES + 5;
        wrapped.envelope[ct_offset] ^= 0x01;
        let err = unwrap_with_aad(&kek, &wrapped.envelope).unwrap_err();
        assert!(matches!(err, crate::aead::AeadError::OpenFailed));
    }

    #[test]
    fn exhaustive_truncation_safety_no_panic() {
        // Exhaustive sub-MIN-size truncation: ensure no slice operation
        // panics on adversarial short input. The parser must return
        // EnvelopeError::Truncated for every 0..MIN_ENVELOPE_SIZE length.
        for len in 0..MIN_ENVELOPE_SIZE {
            let bytes = vec![0u8; len];
            let err = read_header(&bytes).unwrap_err();
            assert!(
                matches!(err, EnvelopeError::Truncated { .. }),
                "len {len} should return Truncated"
            );
        }
    }
}
