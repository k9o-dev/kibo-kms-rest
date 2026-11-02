//! Known-answer vectors for the application-crypto container v1, shared by the
//! server route and the client path: `tests/vectors/app-crypto-container-v1.json`.
//!
//! The AEAD nonce is drawn inside `aead::seal` and cannot be injected (by design), so the data
//! vectors run in the OPEN direction: fixed `D` bytes, generated once, open to the fixed
//! plaintext under the fixed DEK and AAD, and fail under any other binding. The AAD and the
//! framing are fully deterministic and pinned byte for byte.
//!
//! Regenerate (only for a deliberate format change, with a new container version):
//! `cargo test -p kibo-crypto-core --test app_container_kat -- --ignored --nocapture`.
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use kibo_crypto_core::app_container::{canonical_aad, frame, open_data, seal_data, unframe};
use serde_json::{Value, json};

const VECTORS: &str = include_str!("vectors/app-crypto-container-v1.json");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ctx(v: &Value) -> Vec<u8> {
    v.as_str().unwrap_or("").as_bytes().to_vec()
}

#[test]
fn the_vectors_hold() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], 1);
    for c in v["aad"].as_array().unwrap() {
        let aad = canonical_aad(
            c["projectId"].as_str().unwrap(),
            c["keyring"].as_str().unwrap(),
            &ctx(&c["context"]),
        );
        assert_eq!(hex(&aad), c["aadHex"], "{c}");
    }
    for c in v["frame"].as_array().unwrap() {
        let (w, d) = (
            unhex(c["wrappedHex"].as_str().unwrap()),
            unhex(c["dataHex"].as_str().unwrap()),
        );
        let container = frame(&w, &d);
        assert_eq!(hex(&container), c["containerHex"], "{c}");
        assert_eq!(unframe(&container), Some((&w[..], &d[..])));
    }
    for c in v["unframeRejects"].as_array().unwrap() {
        assert_eq!(
            unframe(&unhex(c["containerHex"].as_str().unwrap())),
            None,
            "{c}"
        );
    }
    for c in v["open"].as_array().unwrap() {
        let aad = canonical_aad(
            c["projectId"].as_str().unwrap(),
            c["keyring"].as_str().unwrap(),
            &ctx(&c["context"]),
        );
        let got = open_data(
            &unhex(c["dekHex"].as_str().unwrap()),
            &unhex(c["dataHex"].as_str().unwrap()),
            &aad,
        );
        assert_eq!(
            got.map(|p| hex(&p)).as_deref(),
            Some(c["plaintextHex"].as_str().unwrap()),
            "{c}"
        );
    }
    for c in v["openRejects"].as_array().unwrap() {
        let aad = unhex(c["aadHex"].as_str().unwrap());
        let got = open_data(
            &unhex(c["dekHex"].as_str().unwrap()),
            &unhex(c["dataHex"].as_str().unwrap()),
            &aad,
        );
        assert!(got.is_none(), "must not open: {c}");
    }
}

/// Prints a fresh vector file. Run only for a deliberate format change.
#[test]
#[ignore = "generator"]
fn generate() {
    let dek = [0x42u8; 32];
    let p = "proj_2usBGoRQdOWN";
    let aad_cases = [
        (p, "pii", None),
        (p, "pii", Some("user:42")),
        ("p", "ab", Some("c")),
        ("p", "a", Some("bc")),
        (p, "billing-2", Some("na\u{ef}ve \u{1f512}")),
    ];
    let aad: Vec<Value> = aad_cases
        .iter()
        .map(|(pr, k, c)| {
            json!({ "projectId": pr, "keyring": k, "context": c,
                    "aadHex": hex(&canonical_aad(pr, k, c.unwrap_or("").as_bytes())) })
        })
        .collect();
    let frame_cases = [(&b"KIBO-W"[..], &b"D-bytes"[..]), (&b""[..], &b""[..])];
    let frames: Vec<Value> = frame_cases
        .iter()
        .map(|(w, d)| json!({ "wrappedHex": hex(w), "dataHex": hex(d), "containerHex": hex(&frame(w, d)) }))
        .collect();
    let mut v2 = frame(b"W", b"D");
    v2[0] = 0x02;
    let rejects = vec![
        json!({ "why": "another container version", "containerHex": hex(&v2) }),
        json!({ "why": "empty", "containerHex": "" }),
        json!({ "why": "length past the end", "containerHex": hex(&[0x01, 0, 0, 0, 9, 1, 2]) }),
        json!({ "why": "the extension route's framing", "containerHex": hex(&frame(b"W", b"D")[1..]) }),
    ];
    let open_cases = [
        (p, "pii", Some("user:42"), &b"hello"[..]),
        (p, "pii", None, &b""[..]),
    ];
    let mut open = Vec::new();
    let mut open_rejects = Vec::new();
    for (pr, k, c, pt) in open_cases {
        let aad = canonical_aad(pr, k, c.unwrap_or("").as_bytes());
        let d = seal_data(&dek, &aad, pt).unwrap();
        open.push(
            json!({ "dekHex": hex(&dek), "projectId": pr, "keyring": k, "context": c,
                          "dataHex": hex(&d), "plaintextHex": hex(pt) }),
        );
        if c.is_some() {
            for (why, wrong) in [
                ("another context", canonical_aad(pr, k, b"user:43")),
                (
                    "another keyring",
                    canonical_aad(pr, "billing", c.unwrap().as_bytes()),
                ),
                (
                    "another project",
                    canonical_aad("proj_other", k, c.unwrap().as_bytes()),
                ),
            ] {
                open_rejects.push(json!({ "why": why, "dekHex": hex(&dek), "dataHex": hex(&d), "aadHex": hex(&wrong) }));
            }
            open_rejects.push(json!({ "why": "another DEK", "dekHex": hex(&[0x43u8; 32]), "dataHex": hex(&d), "aadHex": hex(&aad) }));
        }
    }
    let out = json!({
        "version": 1,
        "about": "k9o.crypto container v1: AAD = domain || projectId || keyring || context, each u32-BE(len) || bytes, domain \"k9o-app-crypto/v1\"; container = 0x01 || u32-BE(len(W)) || W || D; D = nonce(12) || ct || tag(16), AES-256-GCM-SIV with key commitment. Data vectors are open-direction (the seal nonce is internal).",
        "aad": aad, "frame": frames, "unframeRejects": rejects, "open": open, "openRejects": open_rejects,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
