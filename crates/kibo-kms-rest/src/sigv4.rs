//! AWS Signature Version 4 (SigV4) request signing — the on-device signing
//! layer for the AWS KMS REST provider ([`crate::provider::aws`]).
//!
//! There is **no `aws-sdk-*`**: the signature is hand-derived with RustCrypto
//! `hmac` + `sha2`, exactly per the AWS SigV4 spec — *canonical request →
//! string-to-sign → signing-key derivation → HMAC-SHA256 signature → the
//! `Authorization` header*. Keeping the algorithm in-crate is what lets the
//! edge stay vendor-SDK-free (the IoT/minimal-deps footprint).
//!
//! **Verified.** Every step is checked, per-step and end-to-end, against the
//! official `aws-sig-v4-test-suite` `get-vanilla` vector (see [`mod@tests`]) —
//! the signing core is not authored from memory.
//!
//! Scope: `canonical_uri` / `canonical_query` are passed pre-normalized by the
//! caller. For the KMS use (`POST /`, action in the `X-Amz-Target` header, no
//! query) those are simply `"/"` and `""`; full RFC-3986 path/query
//! `UriEncode` is not needed here and is deliberately omitted.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The fixed SigV4 algorithm token.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// SHA-256 of `bytes` as lowercase hex (64 chars). Used for the payload hash
/// and the hash of the canonical request.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

/// `HMAC-SHA256(key, data)` → 32 raw bytes. HMAC admits a key of any length,
/// so the keying never fails.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a key of any length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&out);
    key_bytes
}

/// Derive the SigV4 signing key: a succession of `HMAC-SHA256` operations over
/// the date, Region, and service, keyed initially by `"AWS4" + secret`
/// (AWS docs, *Derive a signing key*).
///
/// `date_yyyymmdd` is the date stamp (`YYYYMMDD`), i.e. the date prefix of the
/// credential scope (not the full `X-Amz-Date`).
#[must_use]
pub fn derive_signing_key(
    secret_access_key: &str,
    date_yyyymmdd: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    // The intermediates are derived key material (and `k_secret` carries the
    // secret access key); wipe each as soon as the next stage consumes it. The
    // returned signing key is the caller's to zeroize.
    let mut k_secret = format!("AWS4{secret_access_key}").into_bytes();
    let mut k_date = hmac_sha256(&k_secret, date_yyyymmdd.as_bytes());
    k_secret.zeroize();
    let mut k_region = hmac_sha256(&k_date, region.as_bytes());
    k_date.zeroize();
    let mut k_service = hmac_sha256(&k_region, service.as_bytes());
    k_region.zeroize();
    let signing_key = hmac_sha256(&k_service, b"aws4_request");
    k_service.zeroize();
    signing_key
}

/// Build the SigV4 **canonical request** and the matching **signed-headers**
/// list from a header set.
///
/// Headers are canonicalized: names lowercased, values trimmed of leading and
/// trailing whitespace, then sorted by (lowercased) name. The returned
/// `signed_headers` is the `;`-joined sorted lowercase name list. The caller
/// must include in `headers` every header it will actually send and sign
/// (`host`, `x-amz-date`, and — with temporary credentials —
/// `x-amz-security-token`, plus `content-type`/`x-amz-target` for KMS).
#[must_use]
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    hs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canonical_headers = String::new();
    for (name, value) in &hs {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
    }
    let signed_headers = hs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // `canonical_headers` already carries the trailing `\n` after the last
    // header, so the `\n` before `signed_headers` produces the required blank
    // line between the two sections.
    let creq = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    (creq, signed_headers)
}

/// The credential scope: `YYYYMMDD/region/service/aws4_request`.
#[must_use]
pub fn credential_scope(date_yyyymmdd: &str, region: &str, service: &str) -> String {
    format!("{date_yyyymmdd}/{region}/{service}/aws4_request")
}

/// The SigV4 **string-to-sign** for the given request datetime, credential
/// scope, and canonical request.
#[must_use]
pub fn string_to_sign(
    amz_datetime: &str,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let creq_hash = sha256_hex(canonical_request.as_bytes());
    format!("{ALGORITHM}\n{amz_datetime}\n{credential_scope}\n{creq_hash}")
}

/// The final signature: `HMAC-SHA256(signing_key, string_to_sign)` as
/// lowercase hex.
#[must_use]
pub fn signature_hex(signing_key: &[u8; 32], string_to_sign: &str) -> String {
    hex_lower(&hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

/// The `Authorization` header value for a signed request.
#[must_use]
pub fn authorization_header(
    access_key_id: &str,
    credential_scope: &str,
    signed_headers: &str,
    signature_hex: &str,
) -> String {
    format!(
        "{ALGORITHM} Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature_hex}"
    )
}

/// Lowercase hex of a byte slice (no `hex` crate — minimal-deps edge).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Format a Unix timestamp (seconds, UTC) as the two SigV4 time strings:
/// the **date stamp** (`YYYYMMDD`, used in the credential scope and signing-key
/// derivation) and the **`X-Amz-Date`** value (`YYYYMMDDTHHMMSSZ`).
///
/// The civil date is computed in-crate (Howard Hinnant's `civil_from_days`),
/// so the edge crate needs no `chrono` / `time` dependency — the same
/// minimal-deps stance as the hand-rolled [`hex_lower`] (no `hex` crate). The
/// algorithm is exercised against known epochs, including the 2024 leap-day
/// boundary, in [`mod@tests`].
///
/// Inputs are UTC seconds since the epoch; the formatter assumes a date at or
/// after 1970-01-01 (true for any real device clock).
#[must_use]
pub fn format_amz_datetime(unix_secs: u64) -> (String, String) {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year_civil = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 {
        year_civil + 1
    } else {
        year_civil
    };

    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_datetime = format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z");
    (date_stamp, amz_datetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official `aws-sig-v4-test-suite` shared credentials + the `get-vanilla`
    // case (GET https://example.amazonaws.com/ with Host + X-Amz-Date).
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const ACCESS_KEY: &str = "AKIDEXAMPLE";
    const REGION: &str = "us-east-1";
    const SERVICE: &str = "service";
    const DATE: &str = "20150830";
    const AMZ_DATETIME: &str = "20150830T123600Z";

    const EXPECTED_EMPTY_PAYLOAD_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EXPECTED_CREQ: &str = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EXPECTED_CREQ_HASH: &str =
        "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
    const EXPECTED_STS: &str = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
    const EXPECTED_SIGNATURE: &str =
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";

    fn get_vanilla_headers() -> Vec<(String, String)> {
        vec![
            ("Host".to_string(), "example.amazonaws.com".to_string()),
            ("X-Amz-Date".to_string(), AMZ_DATETIME.to_string()),
        ]
    }

    #[test]
    fn empty_payload_hash_matches_known_value() {
        assert_eq!(sha256_hex(b""), EXPECTED_EMPTY_PAYLOAD_HASH);
    }

    #[test]
    fn canonical_request_matches_get_vanilla() {
        let (creq, signed_headers) =
            canonical_request("GET", "/", "", &get_vanilla_headers(), &sha256_hex(b""));
        assert_eq!(creq, EXPECTED_CREQ);
        assert_eq!(signed_headers, "host;x-amz-date");
        assert_eq!(sha256_hex(creq.as_bytes()), EXPECTED_CREQ_HASH);
    }

    #[test]
    fn canonical_headers_are_sorted_and_normalized() {
        // Reverse + mixed-case + padded — must normalize to the same creq.
        let headers = vec![
            ("X-Amz-Date".to_string(), "  20150830T123600Z  ".to_string()),
            ("HOST".to_string(), "example.amazonaws.com".to_string()),
        ];
        let (creq, signed_headers) = canonical_request("GET", "/", "", &headers, &sha256_hex(b""));
        assert_eq!(creq, EXPECTED_CREQ);
        assert_eq!(signed_headers, "host;x-amz-date");
    }

    #[test]
    fn string_to_sign_matches_get_vanilla() {
        let (creq, _) = canonical_request("GET", "/", "", &get_vanilla_headers(), &sha256_hex(b""));
        let scope = credential_scope(DATE, REGION, SERVICE);
        assert_eq!(scope, "20150830/us-east-1/service/aws4_request");
        assert_eq!(string_to_sign(AMZ_DATETIME, &scope, &creq), EXPECTED_STS);
    }

    #[test]
    fn signature_matches_get_vanilla_end_to_end() {
        let (creq, signed_headers) =
            canonical_request("GET", "/", "", &get_vanilla_headers(), &sha256_hex(b""));
        let scope = credential_scope(DATE, REGION, SERVICE);
        let sts = string_to_sign(AMZ_DATETIME, &scope, &creq);
        let key = derive_signing_key(SECRET, DATE, REGION, SERVICE);
        let sig = signature_hex(&key, &sts);
        assert_eq!(sig, EXPECTED_SIGNATURE);

        let auth = authorization_header(ACCESS_KEY, &scope, &signed_headers, &sig);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn amz_datetime_formatting_matches_known_epochs() {
        // (unix_secs, expected_date_stamp, expected_amz_datetime). Vectors are
        // authoritative (generated with `date -u`); they include the epoch
        // origin, the AWS KMS API-reference example datetime (1463517505 ->
        // 20160517T203825Z), and BOTH sides of the 2024 leap-day boundary.
        let cases = [
            (0u64, "19700101", "19700101T000000Z"),
            (1_000_000_000, "20010909", "20010909T014640Z"),
            (1_234_567_890, "20090213", "20090213T233130Z"),
            (1_463_517_505, "20160517", "20160517T203825Z"),
            (1_709_251_199, "20240229", "20240229T235959Z"),
            (1_709_251_200, "20240301", "20240301T000000Z"),
            (1_719_792_000, "20240701", "20240701T000000Z"),
            (2_147_483_647, "20380119", "20380119T031407Z"),
        ];
        for (secs, date_stamp, amz_datetime) in cases {
            let (ds, dt) = format_amz_datetime(secs);
            assert_eq!(ds, date_stamp, "date stamp for {secs}");
            assert_eq!(dt, amz_datetime, "amz datetime for {secs}");
        }
        // The date stamp is exactly the YYYYMMDD prefix of X-Amz-Date.
        let (ds, dt) = format_amz_datetime(1_463_517_505);
        assert_eq!(&dt[..8], ds);
    }
}
