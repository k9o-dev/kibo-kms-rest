//! The two REST-direct encryption strategies this crate serves, and the
//! posture-first routing that selects between them (the EaaS smart-primitives
//! model).
//!
//! `kibo-kms-rest` executes the **two client-side** strategies — `LocalEnvelope`
//! and `CustomerKmsOracle`. The third SDK strategy, `KIBO_VAULT_ORACLE`, is
//! gateway-routed (server-side Kibo Vault) and is **not** this crate's concern.

use serde::{Deserialize, Serialize};

use crate::error::{KmsRestError, PostureDimension};

/// Which thing the customer KMS REST call operates on.
///
/// The strategy is part of the AAD binding (alongside `version` and
/// `attestation_tier`), so it cannot be silently swapped between encrypt
/// and decrypt without an integrity failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    /// The customer KMS acts as an encryption **oracle** over the data
    /// itself: the plaintext is sent to the KMS REST `Encrypt` endpoint
    /// and the ciphertext comes back from the KMS. The device performs no
    /// bulk AES of its own in this mode.
    ///
    /// Appropriate for small payloads where a per-call KMS round-trip is
    /// acceptable and the customer wants the KMS to be the sole point of
    /// data en/decryption.
    CustomerKmsOracle,

    /// The customer KMS only wraps / unwraps the **32-byte DEK**. The
    /// device generates (or holds) a DEK, has the KMS REST `Encrypt`
    /// endpoint wrap it, and performs the bulk-data AES locally via
    /// `kibo-crypto-core`. Decrypt unwraps the DEK through the KMS, then
    /// `kibo-crypto-core` does the data AES.
    ///
    /// This is the envelope-encryption pattern and the default for any
    /// payload large enough that round-tripping the whole plaintext
    /// through the KMS would be wasteful. The AES of the data is **never**
    /// performed in this crate.
    LocalEnvelope,
}

impl Strategy {
    /// Stable wire token for this strategy, used in the AAD binding.
    ///
    /// The token is part of the authenticated context; changing it is a
    /// breaking change to envelope compatibility.
    #[must_use]
    pub const fn as_aad_token(self) -> &'static str {
        match self {
            Self::CustomerKmsOracle => "customer_kms_oracle",
            Self::LocalEnvelope => "local_envelope",
        }
    }
}

/// The project's custody posture — the **first** routing axis (route on trust
/// posture first, size second; a size-only switch would silently change the
/// sovereignty guarantee).
///
/// The variant declaration order **is** the custody-sovereignty ladder
/// (`PlatformManaged < Byok < Hyok`): who-holds-the-KEK is a clean total order
/// (customer-HSM keys are unambiguously more sovereign than platform-held), so
/// the derived `Ord` is the ladder the `min_custody_posture` floor compares on.
/// **Do not reorder the variants** —
/// the ordering is load-bearing, not cosmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Posture {
    /// Platform-Managed — no customer KMS exists, so `CustomerKmsOracle` is
    /// structurally impossible here.
    PlatformManaged,
    /// BYOK — a customer-owned KMS key is attached.
    Byok,
    /// HYOK — a customer-resident HSM/KMS is attached.
    Hyok,
}

impl Posture {
    /// `true` if a customer KMS exists to act as an oracle (BYOK/HYOK).
    #[must_use]
    pub fn has_customer_kms(self) -> bool {
        matches!(self, Self::Byok | Self::Hyok)
    }

    /// Stable wire token — the custody dial's value in the posture-floor
    /// `context` (`requested` / `declared`).
    #[must_use]
    pub const fn as_custody_token(self) -> &'static str {
        match self {
            Self::PlatformManaged => "platform_managed",
            Self::Byok => "byok",
            Self::Hyok => "hyok",
        }
    }
}

/// The `oracle: brokered | direct` sub-mode — **how** a
/// customer-KMS wrap/unwrap is routed, independent of *which* [`Strategy`]
/// runs. It is a routing / authorization axis, **not** a cryptographic one:
/// `OracleMode` is deliberately **NOT** part of the AAD binding (that is
/// `strategy` + `version` + `attestation_tier`, see [`Strategy::as_aad_token`]),
/// so a brokered and a direct wrap of the same DEK produce interchangeable
/// envelopes. Adding it to the AAD would be a correctness error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleMode {
    /// **Default.** The wrap/unwrap routes through Kibo's authorization path:
    /// Kibo retains a signed *authorization* event plus the opaque-blob
    /// store/fetch (the brokered-C default — partial custody audit retained,
    /// **never plaintext**). The pragmatic ZK path.
    #[default]
    Brokered,

    /// The max-sovereignty opt-in: the SDK calls the customer KMS directly and
    /// Kibo sees only the stored [`crate::WrappedDek`] — no authorization event,
    /// no brokered round-trip. Meaningful only where a customer KMS exists
    /// (BYOK/HYOK); structurally impossible under Platform-Managed.
    Direct,
}

impl OracleMode {
    /// Stable wire token. Unlike [`Strategy::as_aad_token`] this is **not** an
    /// AAD element — it is a routing label only (config + audit-routing).
    #[must_use]
    pub const fn as_wire_token(self) -> &'static str {
        match self {
            Self::Brokered => "brokered",
            Self::Direct => "direct",
        }
    }
}

/// A non-empty subset of [`OracleMode`] — the project's `allowed_oracle_modes`
/// policy. Oracle-mode is an
/// **acceptable-set, not a floor**: `brokered` ⇄ `direct` is a
/// sovereignty-vs-auditability trade-off, not a rank — an audit-compliance
/// project must be able to *require* `brokered` (forbid `direct`) for a complete
/// authorization trail, which a one-directional floor cannot express. The set is
/// enforced by membership, never by "≥".
///
/// Construction guarantees the set is **non-empty** (an empty allow-set would
/// reject every operation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleModeSet {
    brokered: bool,
    direct: bool,
}

impl OracleModeSet {
    /// Both modes permitted — the most permissive policy (the project default,
    /// matching the per-operation `OracleMode::Brokered` default).
    #[must_use]
    pub const fn any() -> Self {
        Self {
            brokered: true,
            direct: true,
        }
    }

    /// `{brokered}` only — the audit-compliance policy (a complete Kibo
    /// authorization trail; `direct` forbidden).
    #[must_use]
    pub const fn brokered_only() -> Self {
        Self {
            brokered: true,
            direct: false,
        }
    }

    /// `{direct}` only — the max-sovereignty / air-gap policy (Kibo never in the
    /// token path; `brokered` forbidden).
    #[must_use]
    pub const fn direct_only() -> Self {
        Self {
            brokered: false,
            direct: true,
        }
    }

    /// `true` if `mode` is a member of the allowed set.
    #[must_use]
    pub const fn contains(self, mode: OracleMode) -> bool {
        match mode {
            OracleMode::Brokered => self.brokered,
            OracleMode::Direct => self.direct,
        }
    }

    /// A `{token,…}` summary for the violation `declared` context.
    #[must_use]
    fn summary(self) -> String {
        let mut modes = Vec::with_capacity(2);
        if self.brokered {
            modes.push(OracleMode::Brokered.as_wire_token());
        }
        if self.direct {
            modes.push(OracleMode::Direct.as_wire_token());
        }
        format!("{{{}}}", modes.join(","))
    }
}

impl Default for OracleModeSet {
    /// The permissive default — both modes allowed (the project does not
    /// constrain oracle-mode until it declares a policy).
    fn default() -> Self {
        Self::any()
    }
}

/// A project's declared **crypto-posture policy** — the floor the SDK respects
/// and the gateway enforces. Two sub-dials, two shapes:
/// [`min_custody_posture`](Self::min_custody_posture) is a ladder-floor
/// (`PlatformManaged < Byok < Hyok`); `allowed_oracle_modes` is an
/// acceptable-set. This crate enforces these two crypto sub-dials; the
/// `trust_tier_policy` hardware set composes at the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoPosturePolicy {
    /// The minimum custody posture on the sovereignty ladder; an effective
    /// posture **below** this is rejected.
    pub min_custody_posture: Posture,
    /// The set of permitted oracle modes; an effective mode **outside** this set
    /// is rejected.
    pub allowed_oracle_modes: OracleModeSet,
}

impl Default for CryptoPosturePolicy {
    /// The most permissive policy — `PlatformManaged` floor (admits everything)
    /// + both oracle modes. A project with no declared crypto posture floor.
    fn default() -> Self {
        Self {
            min_custody_posture: Posture::PlatformManaged,
            allowed_oracle_modes: OracleModeSet::any(),
        }
    }
}

/// The size inputs for the `CustomerKmsOracle` plaintext-ceiling check. The KMS
/// limit is **per-provider AND per-key-type** and **AAD counts** (GCP) — derive
/// `kms_limit_bytes` from the bound key, and budget `payload_bytes + aad_bytes`.
#[derive(Clone, Copy, Debug)]
pub struct PayloadSizing {
    /// Plaintext size, bytes.
    pub payload_bytes: usize,
    /// AAD size, bytes (counts toward the ceiling).
    pub aad_bytes: usize,
    /// The bound key's KMS plaintext ceiling, bytes.
    pub kms_limit_bytes: usize,
}

impl PayloadSizing {
    /// `true` if plaintext + AAD fits under the KMS ceiling.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.payload_bytes.saturating_add(self.aad_bytes) <= self.kms_limit_bytes
    }
}

/// Resolve which client-side strategy to execute, posture-first.
///
/// - **Platform-Managed:** default `LocalEnvelope`; explicit `CustomerKmsOracle`
///   is structurally impossible → `K9O_CRYPTO_STRATEGY_UNAVAILABLE` (400).
/// - **BYOK/HYOK:** default `LocalEnvelope`; explicit `CustomerKmsOracle` is the
///   max-sovereignty opt-in and is **honor-or-reject** — over the KMS ceiling it
///   is `K9O_CRYPTO_PAYLOAD_EXCEEDS_KMS_LIMIT` (413), **never** a silent fallback
///   to `LocalEnvelope` (the asymmetry: only a *default* may auto-adapt C→A
///   within the safe band).
///
/// `requested == None` selects the posture default. `requested == Some(s)` is an
/// explicit pin (honor-or-reject).
///
/// **Resolved elsewhere** (not decided here): (a) the posture-floor check
/// (`K9O_CRYPTO_POSTURE_FLOOR_VIOLATION`, 403) — needs the project's declared
/// floor + the sovereignty ordering over strategies/tiers; (b) the
/// `oracle: brokered | direct` sub-mode (default brokered); (c) the
/// *band-default* size-route (C-tiny / A-larger with C→A auto-adapt) for a
/// caller who opts into the C band without pinning the exact strategy. This fn
/// implements the structural posture→strategy core those compose with.
///
/// # Errors
///
/// `StrategyUnavailable` (Platform-Managed + explicit-C) or
/// `PayloadExceedsKmsLimit` (BYOK/HYOK + explicit-C over the ceiling).
pub fn resolve_strategy(
    posture: Posture,
    requested: Option<Strategy>,
    sizing: PayloadSizing,
) -> Result<Strategy, KmsRestError> {
    match (posture, requested) {
        // Defaults — every posture defaults to LocalEnvelope (Kibo-attestable).
        (_, None) | (_, Some(Strategy::LocalEnvelope)) => Ok(Strategy::LocalEnvelope),

        // Explicit CustomerKmsOracle on Platform-Managed: no customer KMS exists.
        (Posture::PlatformManaged, Some(Strategy::CustomerKmsOracle)) => {
            Err(KmsRestError::StrategyUnavailable)
        }

        // Explicit CustomerKmsOracle on BYOK/HYOK: honor-or-reject on size.
        (Posture::Byok | Posture::Hyok, Some(Strategy::CustomerKmsOracle)) => {
            if sizing.fits() {
                Ok(Strategy::CustomerKmsOracle)
            } else {
                Err(KmsRestError::PayloadExceedsKmsLimit {
                    kms_limit_bytes: sizing.kms_limit_bytes,
                    payload_bytes: sizing.payload_bytes,
                    aad_bytes: sizing.aad_bytes,
                })
            }
        }
    }
}

/// Resolve the `oracle` sub-mode, posture-aware. Sibling to
/// [`resolve_strategy`]: that picks *which* strategy runs (size/posture-driven
/// crypto axis); this picks *how* a customer-KMS call is routed (the sovereignty
/// routing axis). The SDK / FFI binding composes the two — `resolve_strategy`
/// gives the [`Strategy`], `resolve_oracle_mode` the [`OracleMode`], and
/// [`enforce_crypto_posture_floor`] composes the declared floor over both.
///
/// - `requested == None` → [`OracleMode::Brokered`] (the default, every posture).
/// - **Platform-Managed + explicit `Direct`** → `K9O_CRYPTO_STRATEGY_UNAVAILABLE`
///   (400): there is no customer KMS to call directly, so `direct` is
///   structurally impossible (mirrors the `CustomerKmsOracle`-on-PM rule in
///   [`resolve_strategy`] — honor-or-reject, never a silent coercion to brokered).
/// - **BYOK/HYOK + explicit mode** → that mode (honored; `direct` is the
///   max-sovereignty opt-in).
///
/// # Errors
///
/// [`KmsRestError::StrategyUnavailable`] for Platform-Managed + explicit `Direct`.
pub fn resolve_oracle_mode(
    posture: Posture,
    requested: Option<OracleMode>,
) -> Result<OracleMode, KmsRestError> {
    match (posture, requested) {
        // Default — brokered everywhere (the pragmatic ZK path).
        (_, None) | (_, Some(OracleMode::Brokered)) => Ok(OracleMode::Brokered),
        // Direct requires a customer KMS to call; none under Platform-Managed.
        (Posture::PlatformManaged, Some(OracleMode::Direct)) => {
            Err(KmsRestError::StrategyUnavailable)
        }
        // BYOK/HYOK: honor the max-sovereignty opt-in.
        (Posture::Byok | Posture::Hyok, Some(OracleMode::Direct)) => Ok(OracleMode::Direct),
    }
}

/// Enforce the project's declared crypto-posture floor over the resolved
/// `(posture, oracle_mode)` of an operation. Two sub-dials, two shapes:
///
/// - **custody** — `effective_posture` must be `>=` `policy.min_custody_posture`
///   on the sovereignty ladder (`PlatformManaged < Byok < Hyok`). A *floor*:
///   more sovereignty is always acceptable, so only "below" is rejected.
/// - **oracle** — `effective_oracle` must be a *member* of
///   `policy.allowed_oracle_modes`. A *set*, not a floor: `brokered`/`direct` is
///   a sovereignty-vs-auditability trade-off, so an out-of-set mode is rejected
///   in **either** direction (the audit-compliance project forbids `direct`; the
///   air-gap project forbids `brokered`).
///
/// Custody is checked first (the primary sovereignty axis). Both compose with —
/// never replace — [`resolve_strategy`]'s strategy/tier floor and the gateway's
/// `trust_tier_policy` hardware set; a single
/// `K9O_CRYPTO_POSTURE_FLOOR_VIOLATION` (403) carries the failing
/// [`PostureDimension`] so the caller sees which requirement was breached.
///
/// # Errors
///
/// [`KmsRestError::PostureFloorViolation`] — `dimension: CustodyPosture` when the
/// posture is below the floor, `dimension: OracleMode` when the mode is outside
/// the allowed set.
pub fn enforce_crypto_posture_floor(
    policy: &CryptoPosturePolicy,
    effective_posture: Posture,
    effective_oracle: OracleMode,
) -> Result<(), KmsRestError> {
    if effective_posture < policy.min_custody_posture {
        return Err(KmsRestError::PostureFloorViolation {
            dimension: PostureDimension::CustodyPosture,
            requested: effective_posture.as_custody_token(),
            declared: format!("min {}", policy.min_custody_posture.as_custody_token()),
        });
    }
    if !policy.allowed_oracle_modes.contains(effective_oracle) {
        return Err(KmsRestError::PostureFloorViolation {
            dimension: PostureDimension::OracleMode,
            requested: effective_oracle.as_wire_token(),
            declared: policy.allowed_oracle_modes.summary(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> PayloadSizing {
        PayloadSizing {
            payload_bytes: 16,
            aad_bytes: 32,
            kms_limit_bytes: 4096,
        }
    }
    fn oversized() -> PayloadSizing {
        PayloadSizing {
            payload_bytes: 5000,
            aad_bytes: 32,
            kms_limit_bytes: 4096,
        }
    }

    #[test]
    fn every_posture_defaults_to_local_envelope() {
        for p in [Posture::PlatformManaged, Posture::Byok, Posture::Hyok] {
            assert_eq!(
                resolve_strategy(p, None, tiny()).unwrap(),
                Strategy::LocalEnvelope
            );
        }
    }

    #[test]
    fn explicit_local_envelope_is_honored_everywhere() {
        for p in [Posture::PlatformManaged, Posture::Byok, Posture::Hyok] {
            assert_eq!(
                resolve_strategy(p, Some(Strategy::LocalEnvelope), tiny()).unwrap(),
                Strategy::LocalEnvelope
            );
        }
    }

    #[test]
    fn customer_oracle_on_platform_managed_is_unavailable() {
        let err = resolve_strategy(
            Posture::PlatformManaged,
            Some(Strategy::CustomerKmsOracle),
            tiny(),
        )
        .unwrap_err();
        assert_eq!(
            err.wire_code().unwrap().as_str(),
            "K9O_CRYPTO_STRATEGY_UNAVAILABLE"
        );
    }

    #[test]
    fn explicit_customer_oracle_honored_on_byok_within_ceiling() {
        for p in [Posture::Byok, Posture::Hyok] {
            assert_eq!(
                resolve_strategy(p, Some(Strategy::CustomerKmsOracle), tiny()).unwrap(),
                Strategy::CustomerKmsOracle
            );
        }
    }

    #[test]
    fn explicit_customer_oracle_rejected_over_ceiling_no_fallback() {
        // Honor-or-reject: NEVER a silent fallback to LocalEnvelope.
        let err = resolve_strategy(
            Posture::Byok,
            Some(Strategy::CustomerKmsOracle),
            oversized(),
        )
        .unwrap_err();
        assert_eq!(
            err.wire_code().unwrap().as_str(),
            "K9O_CRYPTO_PAYLOAD_EXCEEDS_KMS_LIMIT"
        );
        // The error carries the size context.
        assert!(err.to_string().contains("4096"));
    }

    #[test]
    fn sizing_counts_aad_toward_the_ceiling() {
        // payload alone fits, but payload + AAD does not (GCP semantics).
        let s = PayloadSizing {
            payload_bytes: 4080,
            aad_bytes: 32,
            kms_limit_bytes: 4096,
        };
        assert!(!s.fits());
    }

    #[test]
    fn oracle_mode_defaults_to_brokered_everywhere() {
        assert_eq!(OracleMode::default(), OracleMode::Brokered);
        for p in [Posture::PlatformManaged, Posture::Byok, Posture::Hyok] {
            assert_eq!(resolve_oracle_mode(p, None).unwrap(), OracleMode::Brokered);
        }
    }

    #[test]
    fn explicit_brokered_is_honored_everywhere() {
        for p in [Posture::PlatformManaged, Posture::Byok, Posture::Hyok] {
            assert_eq!(
                resolve_oracle_mode(p, Some(OracleMode::Brokered)).unwrap(),
                OracleMode::Brokered
            );
        }
    }

    #[test]
    fn direct_is_honored_on_byok_and_hyok() {
        for p in [Posture::Byok, Posture::Hyok] {
            assert_eq!(
                resolve_oracle_mode(p, Some(OracleMode::Direct)).unwrap(),
                OracleMode::Direct
            );
        }
    }

    #[test]
    fn direct_on_platform_managed_is_unavailable() {
        // No customer KMS to call directly → honor-or-reject, never coerced
        // silently to brokered.
        let err =
            resolve_oracle_mode(Posture::PlatformManaged, Some(OracleMode::Direct)).unwrap_err();
        assert_eq!(
            err.wire_code().unwrap().as_str(),
            "K9O_CRYPTO_STRATEGY_UNAVAILABLE"
        );
    }

    #[test]
    fn oracle_mode_wire_tokens_are_stable() {
        assert_eq!(OracleMode::Brokered.as_wire_token(), "brokered");
        assert_eq!(OracleMode::Direct.as_wire_token(), "direct");
    }

    // ---- posture-floor enforcement ----

    #[test]
    fn custody_posture_is_a_sovereignty_ladder() {
        assert!(Posture::PlatformManaged < Posture::Byok);
        assert!(Posture::Byok < Posture::Hyok);
    }

    #[test]
    fn floor_admits_at_or_above_the_min_custody_posture() {
        let policy = CryptoPosturePolicy {
            min_custody_posture: Posture::Byok,
            allowed_oracle_modes: OracleModeSet::any(),
        };
        // At the floor and above it pass.
        assert!(enforce_crypto_posture_floor(&policy, Posture::Byok, OracleMode::Brokered).is_ok());
        assert!(enforce_crypto_posture_floor(&policy, Posture::Hyok, OracleMode::Brokered).is_ok());
    }

    #[test]
    fn floor_rejects_below_the_min_custody_posture() {
        let policy = CryptoPosturePolicy {
            min_custody_posture: Posture::Hyok,
            allowed_oracle_modes: OracleModeSet::any(),
        };
        let err = enforce_crypto_posture_floor(&policy, Posture::Byok, OracleMode::Brokered)
            .unwrap_err();
        assert_eq!(
            err.wire_code().unwrap().as_str(),
            "K9O_CRYPTO_POSTURE_FLOOR_VIOLATION"
        );
        // Dimension-tagged + carries the requested/declared context.
        assert!(matches!(
            err,
            KmsRestError::PostureFloorViolation {
                dimension: PostureDimension::CustodyPosture,
                requested: "byok",
                ref declared,
            } if declared == "min hyok"
        ));
    }

    #[test]
    fn oracle_set_membership_is_two_directional_not_a_floor() {
        // Audit-compliance project: require brokered, FORBID direct (a complete
        // authorization trail) — a floor could not express this.
        let audit = CryptoPosturePolicy {
            min_custody_posture: Posture::Byok,
            allowed_oracle_modes: OracleModeSet::brokered_only(),
        };
        assert!(enforce_crypto_posture_floor(&audit, Posture::Byok, OracleMode::Brokered).is_ok());
        let err =
            enforce_crypto_posture_floor(&audit, Posture::Byok, OracleMode::Direct).unwrap_err();
        assert!(matches!(
            err,
            KmsRestError::PostureFloorViolation {
                dimension: PostureDimension::OracleMode,
                requested: "direct",
                ..
            }
        ));

        // Air-gap project: the reverse — require direct, forbid brokered.
        let airgap = CryptoPosturePolicy {
            min_custody_posture: Posture::Hyok,
            allowed_oracle_modes: OracleModeSet::direct_only(),
        };
        assert!(enforce_crypto_posture_floor(&airgap, Posture::Hyok, OracleMode::Direct).is_ok());
        assert!(enforce_crypto_posture_floor(&airgap, Posture::Hyok, OracleMode::Brokered).is_err());
    }

    #[test]
    fn custody_checked_before_oracle() {
        // Both dials violated → the custody (primary sovereignty) dimension wins.
        let policy = CryptoPosturePolicy {
            min_custody_posture: Posture::Hyok,
            allowed_oracle_modes: OracleModeSet::direct_only(),
        };
        let err = enforce_crypto_posture_floor(&policy, Posture::Byok, OracleMode::Brokered)
            .unwrap_err();
        assert!(matches!(
            err,
            KmsRestError::PostureFloorViolation {
                dimension: PostureDimension::CustodyPosture,
                ..
            }
        ));
    }

    #[test]
    fn default_policy_admits_everything() {
        let policy = CryptoPosturePolicy::default();
        for p in [Posture::PlatformManaged, Posture::Byok, Posture::Hyok] {
            for m in [OracleMode::Brokered, OracleMode::Direct] {
                assert!(enforce_crypto_posture_floor(&policy, p, m).is_ok());
            }
        }
    }
}
