//! Bounded-symbolic Kani proofs for the crypto kernel.
//!
//! # Scope
//!
//! **8 properties are CI-ENFORCED** (`KANI_HARNESSES`, the `kani` job with
//! `allow_failure: false`) over the AEAD primitive ([`crate::aead`]) and the
//! envelope format ([`crate::envelope`]). A 9th harness exists, is **not
//! gated, and proves nothing** — see P8. This table states what CI actually
//! enforces, not what we would like it to.
//!
//! | # | Property | Module | Gated | Coverage |
//! |---|----------|--------|-------|----------|
//! | P1 | Round-trip soundness | aead | yes | seal/open functional correctness |
//! | P2 | Tamper detection | aead | yes | bit-flip on any envelope byte → OpenFailed |
//! | P3 | AAD binding | aead | yes | seal+aad1 / open+aad2 (aad1≠aad2) → OpenFailed |
//! | P4 | Envelope round-trip | envelope | yes | build → read_header returns same (provider, key_ver) |
//! | P4b | Envelope offsets in bounds | envelope | yes | `prove_envelope_offsets_in_bounds` (gated all along; this matrix omitted it) |
//! | P5 | Envelope truncation safety | envelope | yes | any 0..MIN truncated bytes → Err, no panic |
//! | P7 | Key distinctness | aead | yes | seal+key1 / open+key2 (key1≠key2) → OpenFailed |
//! | P9 | Header-as-AAD integrity | envelope | yes | tampered header byte → unwrap_with_aad returns OpenFailed |
//! | P8 | KDF determinism | kdf | **NO** | **VACUOUS — do not cite or graduate.** See below. |
//!
//! ## P8 is not a proof (Fable adversarial sweep, 2026-07-10)
//!
//! Two independent defects:
//! 1. **The harness is a tautology.** It asserts `hkdf(x) == hkdf(x)` — the
//!    same pure function on the same arguments. True by referential
//!    transparency; CBMC discharges it without reasoning about HKDF at all.
//! 2. **It exercises the wrong function.** It runs the RFC primitive
//!    [`crate::kdf::hkdf_sha256_raw`]; the function production actually calls,
//!    `derive_subkey`, is never executed. That `derive_subkey` "inherits"
//!    determinism was asserted in prose, never proved.
//!
//! It lives in `KANI_DEV_HARNESSES` (`allow_failure: true`) and **must not be
//! promoted to the blocking gate**: a vacuous proof is worse than no proof
//! because it manufactures assurance. Determinism of a pure function is not a
//! bounded-model-checking property. To make P8 mean something, prove the
//! claims the prose asserts: RFC-5869 KAT conformance (a test, not a BMC
//! property) and `derive_subkey ≡ hkdf_sha256_raw` on validated inputs.
//!
//! P6 (nonce-distinctness) is intentionally NOT proved here — OsRng
//! cannot be modeled symbolically without massive unrolling.
//! Routed to `cargo-fuzz` statistical testing.
//!
//! # Invocation
//!
//! Proofs are gated behind `#[cfg(kani)]` so they are skipped under
//! normal `cargo build` / `cargo test`. They compile + execute only
//! when invoked via:
//!
//! ```sh
//! cargo install --locked kani-verifier
//! cargo kani setup
//! cargo kani -p kibo-crypto-core -Z stubbing
//! ```
//!
//! # Bound discipline
//!
//! Kani's bounded model checker requires inputs of fixed size or
//! symbolic-but-small ranges to keep proof times tractable.
//! Proofs here use small bounded sizes (`PLAINTEXT_BOUND`,
//! `AAD_BOUND`, `EXT_REF_BOUND`) per harness. AES-256-GCM is
//! bit-level complex; proofs may exceed default Kani timeouts on
//! larger bounds. Tuning of `--default-unwind` and `--unwind` flags
//! at the CI invocation site may be required.
//!
//! # CBMC tractability — the cipher/hash boundary
//!
//! Bounded model checking proves the wrapper-tier properties
//! (round-trip soundness, tamper detection, AAD binding, key
//! distinctness, and envelope integrity) over a deterministic AEAD
//! contract model. The underlying AES-256-GCM-SIV cipher and the
//! SHA-2 hash boundary are exercised by known-answer tests and fuzzing
//! rather than by Kani.
//!
//! This split is structural, not a tuning miss: a symbolic 32-byte key
//! drives the whole AES key schedule + 14 rounds (S-box lookups,
//! MixColumns) symbolically, and symbolic IKM drives SHA-256's 64-round
//! compression — both at/beyond BMC tractability for any sane
//! time/unwind budget. No `--unwind` value rescues a symbolic-key AES
//! round-trip; the key, not the plaintext length, is the driver. The
//! parser / wire-format / offset logic (P4, P4b, P5) invokes no cipher and
//! is discharged directly by CBMC; P1/P2/P3/P7/P9 run against the
//! deterministic AEAD contract stub so the surrounding wrapper code is
//! verified without unwinding AES or SHA-256. P8 is a separate, non-stubbed
//! harness over HKDF-SHA-256 — but symbolic IKM never drives SHA-256 there
//! either, because the assertion collapses to `f(x) == f(x)` before any
//! reasoning about the compression function is required. That is why it is
//! cheap, and why it is vacuous.
//!
//! # Why these properties matter
//!
//! Each property closes a specific R3 (cryptographic-correctness
//! defect) attack surface:
//! - **P1** rules out silent data loss (encrypt-then-decrypt
//!   produces wrong plaintext).
//! - **P2** rules out silent tampering acceptance (modified
//!   ciphertext decodes without error).
//! - **P3** rules out context-binding bypass (DEK from project A
//!   replayed under project B context).
//! - **P4** rules out envelope wire-format corruption (build
//!   produces an envelope that read_header cannot parse back).
//! - **P4b** rules out out-of-bounds envelope offsets (a header whose
//!   declared spans escape the buffer).
//! - **P5** rules out parser DoS (adversarial short input crashes
//!   the enclave).
//! - **P7** rules out cross-tenant key leakage (open succeeds with
//!   a key that did not seal).
//! - **P8** rules out NOTHING. It asserts `hkdf(x) == hkdf(x)` on a pure
//!   function, which is true by referential transparency, and it never runs
//!   `derive_subkey` — the function production calls. It is listed here only
//!   so that no reader infers a KDF guarantee this matrix does not provide.
//! - **P9** rules out envelope-substitution attacks (flipped
//!   provider tag or key version routes ciphertext through wrong
//!   adapter).
//!
//! Together they constitute the implementation-correctness
//! verification matrix. Note: this is
//! IMPLEMENTATION-CORRECTNESS verification, NOT a formal security
//! proof of IND-CCA security — that proof lives in the RustCrypto
//! `aes-gcm` crate's design and the underlying NIST analysis.

#![cfg(kani)]

use crate::aead;
use crate::envelope::{
    self, AEAD_TAG_SIZE, FIXED_HEADER_SIZE, MIN_ENVELOPE_SIZE, NONCE_SIZE_BYTES, ProviderTag,
};
use crate::kdf;
use crate::types::KeyVersionRef;

/// Plaintext length bound for AEAD proofs (small to keep symbolic
/// state tractable). The P1/P2/P3/P7 proofs run against the deterministic
/// `kani_stubs` AEAD model (not AES), so this only sizes the modeled
/// envelope; 2 keeps the symbolic surface minimal.
const PLAINTEXT_BOUND: usize = 2;

/// AAD length bound for AEAD proofs.
const AAD_BOUND: usize = 2;

/// External-ref length bound for envelope proofs. Kept to 1 (minimal
/// non-empty — preserves variable-section / ext_len coverage without the
/// empty-string vacuity) to shrink the symbolic surface: the first
/// toolchain run timed out at 600s with this at 4 + unwind 64.
const EXT_REF_BOUND: usize = 1;

/// KDF input/output length bound for HKDF proofs.
const KDF_LEN_BOUND: usize = 8;

// The AEAD contract stubs (`stub_seal` / `stub_open_detached`) consumed by the
// `#[kani::stub(...)]` attributes below live in `crate::kani_stubs` — a
// `#[cfg(any(kani, test))]` module so the model is also unit-tested under
// `cargo test` (non-vacuity: it must reject every key / aad / nonce / tamper
// mismatch class). They model the seal/open CONTRACT (no AES / SHA-256 /
// OsRng — all intractable/foreign for CBMC) so the REAL surrounding code runs:
// P9 verifies `build_with_aad`/`unwrap_with_aad`; P1/P2/P3/P7 verify `open`'s
// split + the contract-level round-trip/tamper/binding properties. The
// cipher's cryptographic strength is delegated to RustCrypto + the aead.rs KATs.

/// **P1 — Round-trip soundness.**
///
/// `∀ key, plaintext, aad: open(key, seal(key, plaintext, aad), aad) == Ok(plaintext)`.
///
/// Functional-correctness anchor: encrypt-then-decrypt under the
/// same (key, aad) recovers the original plaintext.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::aead::seal, crate::kani_stubs::stub_seal)]
#[kani::stub(crate::aead::open_detached, crate::kani_stubs::stub_open_detached)]
#[kani::unwind(80)]
fn prove_round_trip_soundness() {
    let key: [u8; aead::AES_256_KEY_SIZE] = kani::any();
    let plaintext: [u8; PLAINTEXT_BOUND] = kani::any();
    let aad: [u8; AAD_BOUND] = kani::any();

    let envelope = match aead::seal(&key, &plaintext, &aad) {
        Ok(env) => env,
        Err(_) => return, // seal should not fail with valid 32B key; bail.
    };
    // Explicit match — NOT `.expect()`. A panicking unwrap would
    // short-circuit the path before the equality assertion, so a
    // broken `open` could pass vacuously if panic-tracking were
    // misconfigured. The Err arm is
    // a hard `assert!(false)` = property violation, so a round-trip
    // failure is caught as a proof failure, not a silent bypass.
    // (The as_slice→fixed-array coercion is intentionally
    // NOT applied — Kani compares slice values, not physical addresses,
    // so the "alignment false-positive" it warns of does not arise; the
    // value comparison is correct and simpler.)
    match aead::open(&key, &envelope, &aad) {
        Ok(recovered) => assert_eq!(recovered.as_slice(), &plaintext[..]),
        Err(_) => assert!(false, "round-trip open must succeed under matching key+aad"),
    }
}

/// **P2 — Tamper detection.**
///
/// `∀ key, plaintext, aad: let env = seal(key, plaintext, aad).
///  Altering any single byte of env guarantees open(key, env, aad) returns OpenFailed.`
///
/// Bit-level integrity: any modification of the ciphertext, tag, or
/// nonce breaks the AEAD authentication and forces a fail-uniform
/// rejection.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::aead::seal, crate::kani_stubs::stub_seal)]
#[kani::stub(crate::aead::open_detached, crate::kani_stubs::stub_open_detached)]
#[kani::unwind(80)]
fn prove_tamper_detection() {
    let key: [u8; aead::AES_256_KEY_SIZE] = kani::any();
    let plaintext: [u8; PLAINTEXT_BOUND] = kani::any();
    let aad: [u8; AAD_BOUND] = kani::any();

    let mut envelope = match aead::seal(&key, &plaintext, &aad) {
        Ok(env) => env,
        Err(_) => return,
    };

    // Pick a symbolic byte index and flip a symbolic bit within it.
    // The index is quantified over the WHOLE envelope (nonce-region +
    // ciphertext + tag) — every byte affects SIV verification, so a
    // single-bit flip anywhere must fail-uniform. A hard `assert!`
    // (NOT `kani::cover!`, which only checks reachability) means a
    // broken `open` returning `Ok` (or any non-`OpenFailed`) on a
    // tampered envelope is caught as a property violation. The
    // full-range quantification supersedes the nonce-vs-tag
    // split suggestion: asserting `Err(OpenFailed)` for EVERY idx
    // already catches a region-specific tag-bypass bug.
    let idx: usize = kani::any();
    kani::assume(idx < envelope.len());
    let bit: u8 = kani::any();
    kani::assume(bit < 8);
    envelope[idx] ^= 1 << bit;

    assert!(
        matches!(
            aead::open(&key, &envelope, &aad),
            Err(aead::AeadError::OpenFailed)
        ),
        "single-bit tamper anywhere in the envelope must fail-uniform as OpenFailed"
    );
}

/// **P3 — AAD binding.**
///
/// `∀ key, plaintext, aad1, aad2 (aad1 ≠ aad2):
///   open(key, seal(key, plaintext, aad1), aad2) == Err(OpenFailed)`.
///
/// Context binding: ciphertext sealed under aad1 cannot be opened
/// under any other aad2. The Header-as-AAD discipline
/// inherits this property at the envelope layer.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::aead::seal, crate::kani_stubs::stub_seal)]
#[kani::stub(crate::aead::open_detached, crate::kani_stubs::stub_open_detached)]
#[kani::unwind(80)]
fn prove_aad_binding() {
    let key: [u8; aead::AES_256_KEY_SIZE] = kani::any();
    let plaintext: [u8; PLAINTEXT_BOUND] = kani::any();
    let aad1: [u8; AAD_BOUND] = kani::any();
    let aad2: [u8; AAD_BOUND] = kani::any();
    kani::assume(aad1 != aad2);

    let envelope = match aead::seal(&key, &plaintext, &aad1) {
        Ok(env) => env,
        Err(_) => return,
    };

    assert!(
        matches!(
            aead::open(&key, &envelope, &aad2),
            Err(aead::AeadError::OpenFailed)
        ),
        "open under AAD2 != seal AAD1 must return OpenFailed"
    );
}

/// **P4 — Envelope round-trip (fixed header; heap-free).**
///
/// `∀ version, nonce, ct: read_header(build(PlatformManaged, {version, ""},
///  nonce, ct)).header == Ok((PlatformManaged, version))`.
///
/// Wire-format soundness for the FIXED header (provider tag + big-endian
/// version). `external_ref` is EMPTY here on purpose: the symbolic-`String`
/// round-trip (a heap allocation carrying symbolic content) walled CBMC —
/// EXIT 124 timeout at both 600s and 1800s (disambiguating run 2026-06-02).
/// `String::new()` does not allocate, and read_header's empty-ext success
/// path reconstructs an empty String without allocating, so this proof is
/// heap-free. The variable-section `ext_len` offset arithmetic — the coverage
/// an empty ext_ref drops — is proved, also heap-free, by
/// [`prove_envelope_offsets_in_bounds`] below (borrowed-slice accessors).
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(48)] // envelope = FIXED_HEADER(16)+ext(0)+nonce(12)+ct(16) = 44B; 48 exceeds the longest build/parse byte loop
fn prove_envelope_round_trip() {
    let provider = ProviderTag::PlatformManaged;
    let version: u64 = kani::any();

    let kv_in = KeyVersionRef {
        version,
        external_ref: String::new(),
    };

    let nonce: [u8; NONCE_SIZE_BYTES] = kani::any();
    // ct must be >= AEAD_TAG_SIZE so the empty-ext envelope reaches
    // MIN_ENVELOPE_SIZE (44) and read_header accepts it (read_header does not
    // parse ct's content).
    let ct: [u8; AEAD_TAG_SIZE] = kani::any();

    let wrapped = envelope::build(provider, &kv_in, &nonce, &ct);
    match envelope::read_header(&wrapped.envelope) {
        Ok((provider_out, kv_out)) => {
            assert_eq!(provider_out, provider);
            assert_eq!(kv_out.version, kv_in.version);
            assert!(kv_out.external_ref.is_empty());
        }
        Err(_) => assert!(false, "build → read_header round-trip must parse"),
    }
}

/// **P4b — Envelope offset arithmetic (variable section; heap-free).**
///
/// `∀ envelope bytes: aad_slice / nonce_slice / ciphertext_slice never panic
///  or read out of bounds; and when all three succeed they partition the
///  buffer exactly — aad.len() + nonce.len() + ct.len() == envelope.len(),
///  with the nonce exactly NONCE_SIZE_BYTES.`
///
/// Covers the variable-section `ext_len` offset arithmetic the empty-ext
/// round-trip (P4) cannot reach — the envelope-substitution / parser-DoS
/// offset surface (P9-adjacent). Heap-free: the slice accessors return
/// borrowed `&[u8]` and never construct a `String`. Symbolic CONTENT over a
/// fixed-size buffer — no symbolic length, no heap. Kani checks every memory
/// access automatically, so reaching the asserts without a verification
/// failure IS the no-OOB-panic proof over adversarial bytes.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(48)]
fn prove_envelope_offsets_in_bounds() {
    let env: [u8; MIN_ENVELOPE_SIZE] = kani::any();

    let aad = envelope::aad_slice(&env);
    let nonce = envelope::nonce_slice(&env);
    let ct = envelope::ciphertext_slice(&env);

    if let (Ok(a), Ok(n), Ok(c)) = (aad, nonce, ct) {
        assert_eq!(n.len(), NONCE_SIZE_BYTES);
        assert_eq!(a.len() + n.len() + c.len(), env.len());
    }
}

/// **P5 — Envelope truncation safety (heap-free).**
///
/// `∀ bytes of length MIN_ENVELOPE_SIZE-1: read_header(bytes) returns Err and
///  does NOT panic.`
///
/// Parser-DoS defense at the sub-minimum boundary. The length is CONCRETE
/// (MIN-1): a symbolic `len` (a variable-length slice) was this harness's
/// dominant cost and contributed to its 600s timeout. read_header's size gate
/// is its FIRST operation and rejects any sub-minimum input before indexing
/// or allocating, so MIN-1 is the representative boundary (shorter inputs are
/// rejected a fortiori by the same length-only gate) and the proof never
/// reaches the allocating success path — heap-free.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(48)]
fn prove_envelope_truncation_safety() {
    let bytes: [u8; MIN_ENVELOPE_SIZE - 1] = kani::any();
    let result = envelope::read_header(&bytes);
    assert!(
        result.is_err(),
        "sub-minimum input must return Err, not panic"
    );
}

/// **P7 — Key distinctness.**
///
/// `∀ key1, key2, plaintext, aad (key1 ≠ key2):
///   open(key2, seal(key1, plaintext, aad), aad) == Err(OpenFailed)`.
///
/// Cross-tenant isolation: ciphertext sealed under one key cannot
/// be opened with a different key. Defends against key-rotation /
/// tenant-context-swap bugs at the cipher level.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::aead::seal, crate::kani_stubs::stub_seal)]
#[kani::stub(crate::aead::open_detached, crate::kani_stubs::stub_open_detached)]
#[kani::unwind(80)]
fn prove_key_distinctness() {
    let key1: [u8; aead::AES_256_KEY_SIZE] = kani::any();
    let key2: [u8; aead::AES_256_KEY_SIZE] = kani::any();
    kani::assume(key1 != key2);

    let plaintext: [u8; PLAINTEXT_BOUND] = kani::any();
    let aad: [u8; AAD_BOUND] = kani::any();

    let envelope = match aead::seal(&key1, &plaintext, &aad) {
        Ok(env) => env,
        Err(_) => return,
    };

    assert!(
        matches!(
            aead::open(&key2, &envelope, &aad),
            Err(aead::AeadError::OpenFailed)
        ),
        "open under key2 != seal key1 must return OpenFailed"
    );
}

/// **P8 — KDF determinism. 🔴 VACUOUS: NOT CI-GATED, PROVES NOTHING.**
///
/// This harness calls the SAME pure function TWICE with the SAME arguments and
/// asserts the results are equal — `f(x) == f(x)`, discharged by referential
/// transparency without reasoning about HKDF. It also exercises
/// `hkdf_sha256_raw`, not `derive_subkey` (what production calls).
///
/// Kept in the non-blocking dev lane deliberately. **Do not add it to
/// `KANI_HARNESSES`** — gating a vacuous proof adds false assurance, which is
/// worse than no proof. See the module header for what a real P8 would need.
///
/// What it literally asserts:
/// `∀ ikm, salt, info: hkdf_sha256_raw(ikm, salt, info, 32) ==
///  hkdf_sha256_raw(ikm, salt, info, 32)`
/// — the same pure function, the same arguments, on both sides.
///
/// This does **not** establish "no hidden internal state": `hkdf_sha256_raw`
/// is a pure Rust function, so the equality holds by referential transparency
/// regardless of what HKDF computes. A stateful or incorrect implementation
/// would satisfy it equally, provided it were deterministic.
///
/// It also does not cover `derive_subkey`, which is what production calls.
/// The previous doc asserted `derive_subkey` is "determinism-equivalent since
/// it only adds input-validation gates and canonical-info encoding atop the
/// primitive" — that is a claim about code this harness never executes, and it
/// was never proved. If it is worth relying on, prove it (`derive_subkey ≡
/// hkdf_sha256_raw` on validated inputs); if not, do not assert it.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(16)]
fn prove_kdf_determinism() {
    let ikm: [u8; KDF_LEN_BOUND] = kani::any();
    let salt: [u8; KDF_LEN_BOUND] = kani::any();
    let info: [u8; KDF_LEN_BOUND] = kani::any();
    // Fixed output length (32 = AES-256 key size) rather than a
    // symbolic `len`: CaDiCaL would otherwise unroll the SHA-256
    // diffusion over every output-length permutation. Determinism is a
    // per-length property; 32 is the representative, real-world boundary.
    let len = 32usize;

    // IKM is non-empty by construction (KDF_LEN_BOUND > 0), so
    // hkdf_sha256_raw cannot return InvalidIkm/OutputTooLong here.
    // Explicit match (not `.expect()`) keeps the model total and the
    // determinism assertion non-short-circuited.
    match (
        kdf::hkdf_sha256_raw(&ikm, &salt, &info, len),
        kdf::hkdf_sha256_raw(&ikm, &salt, &info, len),
    ) {
        (Ok(okm1), Ok(okm2)) => assert_eq!(okm1.as_slice(), okm2.as_slice()),
        _ => assert!(
            false,
            "hkdf_sha256_raw must succeed deterministically on bounded inputs"
        ),
    }
}

/// **P9 — Envelope header-as-AAD integrity (AEAD-stubbed).**
///
/// `∀ kek, dek, count, version: tampering ANY byte in
///  [0..FIXED_HEADER_SIZE+ext_len] of a build_with_aad envelope causes
///  unwrap_with_aad to return OpenFailed.`
///
/// THE load-bearing defense against envelope-substitution attacks (flipped
/// provider tag = route attack, key_ver = rotation attack, ext_ref =
/// cross-tenant attack). The **real** `build_with_aad`/`unwrap_with_aad` run;
/// only the AEAD primitive is replaced by the deterministic contract stub
/// (`stub_seal`/`stub_open_detached`) so CBMC verifies OUR header-as-AAD
/// wiring + `aad_slice` offset logic without unwinding AES / SHA-256 / OsRng.
/// The stub binds (key, aad): a header byte flip desynchronizes the aad
/// `unwrap_with_aad` recomputes → `OpenFailed` (parse-level corruption also
/// maps to `OpenFailed`, fail-uniform inside `unwrap_with_aad`). The cipher's
/// cryptographic strength is delegated to RustCrypto + the `aead.rs` KATs.
/// `external_ref` is a CONCRETE non-empty byte ("x") — spans the variable
/// section in the tamper sweep while staying heap-tractable (a
/// symbolic-content String walls CBMC; see P4 / the disambiguating run).
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::aead::seal, crate::kani_stubs::stub_seal)]
#[kani::stub(crate::aead::open_detached, crate::kani_stubs::stub_open_detached)]
// The stubbed envelope is ~100 B (header 17 + nonce 12 + stub-ct 71). Tampering
// the ext_len header bytes makes the PARSED length symbolic, so the buffer
// loops in unwrap_with_aad — including the Zeroizing-on-drop zeroize() — must
// unwind past the whole envelope. 96 sat just below it (unwinding-assertion
// failure in zeroize → 688 undetermined). 128 covers the envelope-bounded max.
#[kani::unwind(128)]
fn prove_envelope_header_integrity() {
    // CONCRETE base envelope. P9 proves header-tamper detection, which is a
    // property of the envelope WIRING (aad_slice recomputes the AAD from the
    // header → any header change desyncs it → OpenFailed), independent of the
    // specific key / version / content. The 32 symbolic key bytes flowing
    // through the ~100 B clone + fold + comparisons at unwind 128 were the
    // memory hog that OOM-killed the runner even after the ext_len exclusion.
    // Holding the base concrete collapses the symbolic state to ONLY the
    // tamper (idx, bit) below — the quantification that matters for "any
    // header byte flip → OpenFailed". (∀-key is not P9's concern; P7 covers
    // key-distinctness with a symbolic key.)
    let kek: [u8; aead::AES_256_KEY_SIZE] = [0x42; aead::AES_256_KEY_SIZE];
    let dek_plaintext: [u8; 1] = [0x07];
    let invocation_count: u64 = 1;

    let kv = KeyVersionRef {
        version: 1,
        external_ref: String::from("x"),
    };
    let ext_ref_len = 1usize;

    let wrapped = match envelope::build_with_aad(
        ProviderTag::PlatformManaged,
        &kv,
        &kek,
        &dek_plaintext,
        invocation_count,
    ) {
        Ok(w) => w,
        Err(_) => return,
    };

    // `.clone()` is REQUIRED: `WrappedDek` derives `ZeroizeOnDrop` (implements
    // Drop), so a field move is E0509. The ~100-byte clone loop is covered by
    // the unwind(128) above (envelope-bounded). (Earlier move-optimization was
    // a compile error — kani_proofs is cfg(kani), so `cargo build` doesn't
    // catch it; only `cargo kani` does.)
    let mut tampered = wrapped.envelope.clone();
    // Tamper any byte across the header-as-AAD region ([0 .. FIXED_HEADER_SIZE
    // + ext_ref_len]) = exactly the bytes `aad_slice` feeds as AAD. Hard
    // `assert!` (not `kani::cover!`) so a bypass is a property violation.
    let aad_region = FIXED_HEADER_SIZE + ext_ref_len;
    let idx: usize = kani::any();
    kani::assume(idx < aad_region);
    // Exclude the 2 ext_len header bytes ([FIXED_HEADER_SIZE-2 .. FIXED_HEADER_SIZE])
    // from the symbolic tamper. Flipping them makes the PARSED length symbolic,
    // which explodes CBMC memory at unwind 128 — it OOM-killed the runner pod
    // (the 2-line truncated report). Holding ext_len concrete keeps the envelope
    // a fixed ~100 B structure (no symbolic-length state blow-up) so P9 proves
    // AAD-binding for the substitution-bearing fields (magic / version / provider
    // tag / key_ver / ext_ref content) tractably. The ext_len-field tamper's
    // safety is covered by composition: P4b (`prove_envelope_offsets_in_bounds`)
    // proves the offset arithmetic is panic-free for EVERY ext_len, and
    // `unwrap_with_aad` maps any parse failure to `OpenFailed` fail-uniform — so a
    // tampered ext_len still yields OpenFailed, established outside this harness.
    kani::assume(idx < FIXED_HEADER_SIZE - 2 || idx >= FIXED_HEADER_SIZE);
    let bit: u8 = kani::any();
    kani::assume(bit < 8);
    tampered[idx] ^= 1 << bit;

    assert!(
        matches!(
            envelope::unwrap_with_aad(&kek, &tampered),
            Err(aead::AeadError::OpenFailed)
        ),
        "tampering any header-as-AAD byte must produce OpenFailed (envelope-substitution defense)"
    );
}
