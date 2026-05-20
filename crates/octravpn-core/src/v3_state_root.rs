//! OctraVPN v3 — canonical `state-root.json` schema.
//!
//! Each operator circle holds a sealed asset at
//! `oct://<circle_id>/state-root.json`. The chain stores
//! `circle_state_root[circle] = sha256_hex(state-root.json)` as a 64-char
//! hex anchor (see `program/main-v3.aml`'s `register_circle` /
//! `update_circle_state` entrypoints). Off-chain verifiers fetch the
//! JSON, recompute the SHA-256, and compare against the on-chain anchor.
//!
//! The chain does NOT decode or validate the JSON itself — integrity is
//! enforced entirely by the commit/recompute cycle. That means the JSON
//! must serialise **deterministically**: two clients producing the
//! semantically identical `StateRoot` must emit identical bytes, or the
//! anchor will not round-trip.
//!
//! # Canonical encoding rules
//!
//! 1. Object keys are emitted in lexicographic (byte-wise on UTF-8)
//!    order. Insertion order is NOT preserved — `serde_json`'s default
//!    behaviour is overridden by re-walking the `Value` tree.
//! 2. No whitespace anywhere. Tokens are concatenated directly; `,` and
//!    `:` are the only structural separators.
//! 3. Integer fields are emitted as bare decimal digits, no leading
//!    zeros, no `+`/`-` sign for unsigned values, no scientific
//!    notation. `serde_json`'s default integer formatting already
//!    matches this.
//! 4. Optional fields that are `None` are omitted entirely; they do
//!    NOT appear as `"field":null`. This keeps the canonical bytes
//!    stable as we add nullable fields over time.
//! 5. The output is UTF-8. All fields in v1 are ASCII; future fields
//!    that admit non-ASCII strings MUST document their unicode
//!    normalisation form (NFC).
//!
//! # Hashing
//!
//! `anchor_hex()` returns the lowercase 64-char hex SHA-256 of
//! `canonical_bytes()`. This is the value committed on chain.
//!
//! # Versioning
//!
//! The `v` field is the schema version. v1 is the initial release. Adding
//! an optional field that defaults to `None`/absent does NOT require
//! bumping `v` — old verifiers will silently ignore unknown keys and
//! recompute a different hash, which is fine because the chain anchor
//! was written by the new encoder. Bumping `v` is reserved for breaking
//! changes (field removal, field rename, semantics shift).
//!
//! Unknown fields encountered during decode are preserved verbatim
//! (`#[serde(flatten)]` into a `BTreeMap`) and round-trip through
//! `canonical_bytes()` so a verifier built against v1 can still verify
//! a v2 anchor produced by a newer encoder.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical schema version emitted by encoders in this crate.
pub const SCHEMA_VERSION_V1: u32 = 1;
/// v2 — adds the optional `enc_anchor_hash` field for the HFHE-2
/// shadow-blob commitment. See `StateRoot::new_v2` for the canonical
/// constructor.
pub const SCHEMA_VERSION_V2: u32 = 2;

/// Length of a SHA-256 hex digest produced by AML's `sha256()` builtin
/// and required by every `state_root` / `members_root` argument in
/// `main-v3.aml`. The chain enforces `len(arg) == HEX_HASH_LEN`.
pub const HEX_HASH_LEN: usize = 64;

/// Errors surfaced by the v3 `StateRoot` encoder/decoder.
#[derive(Debug, thiserror::Error)]
pub enum StateRootError {
    #[error("schema version unsupported: got {got}, this build understands {supported}")]
    UnsupportedVersion { got: u32, supported: u32 },
    #[error("hex hash field {field} has length {len}, expected {HEX_HASH_LEN}")]
    BadHashLength { field: &'static str, len: usize },
    #[error("hex hash field {field} contains non-hex character")]
    BadHashEncoding { field: &'static str },
    #[error("circle_id is empty")]
    EmptyCircleId,
    #[error("region is empty")]
    EmptyRegion,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Canonical operator-circle state commitment.
///
/// One of these is produced by the operator-side daemon each time the
/// operator wants to rotate the on-chain commitment (policy change, ACL
/// change, attestation refresh, member-count refresh, …). It is sealed
/// into the operator's circle at `oct://<circle_id>/state-root.json`,
/// and `sha256_hex(canonical_bytes())` is sent to main-v3's
/// `update_circle_state(circle, new_state_root)`.
///
/// # Field semantics
///
/// All hash fields are lowercase hex SHA-256 digests (length 64). Hex,
/// not raw bytes, because the AML runtime treats every `bytes` parameter
/// as a UTF-8 string at the RPC boundary (see the encoding note at the
/// top of `docs/v3-circle-resident-architecture.md`).
///
/// `unknown` carries any fields a newer encoder added that this version
/// doesn't recognise. They are preserved verbatim through encode → decode
/// → re-encode so the anchor remains stable for upgraded peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRoot {
    /// Schema version. Starts at 1. See module-level doc for bump policy.
    pub v: u32,

    /// `oct…` display address of the operator circle this commitment is
    /// for. Self-binding: a verifier that fetches `state-root.json` from
    /// circle X and finds `circle_id != X` MUST reject it. Without this
    /// field a malicious operator could host another operator's
    /// state-root.json and pass the anchor check.
    pub circle_id: String,

    /// SHA-256 of the sealed `oct://<circle_id>/policy.json`. The policy
    /// JSON itself carries encrypted endpoint URL, WG pubkey ciphertext,
    /// price tiers — its plaintext format is operator-defined and out of
    /// scope here. Anchoring its hash here lets verifiers detect policy
    /// drift between what the operator advertised and what they're
    /// actually serving.
    pub policy_hash: String,

    /// SHA-256 of the operator's WireGuard public key in its raw 32-byte
    /// form (NOT base64). Pinned separately from `policy_hash` because
    /// the WG pubkey is the operator's network identity — a verifier
    /// who learns the pubkey out-of-band (e.g. from a peer's prior
    /// session) can validate it without decrypting the policy.
    pub wg_pubkey_hash: String,

    /// SHA-256 of the sealed `oct://<circle_id>/attestation.json`.
    /// `None` for operators who do not advertise remote attestation
    /// (most devnet operators today). When `None` the field is OMITTED
    /// from canonical JSON, not emitted as `null`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation_hash: Option<String>,

    /// Freeform region tag (e.g. `"us-east-1"`, `"eu-west"`,
    /// `"home-server"`). Surfaced to clients picking exits by latency
    /// pool; not load-bearing for security. Must be non-empty.
    pub region: String,

    /// Cached count of the tailnet members this operator serves. Purely
    /// observability — authoritative member set lives in the
    /// tailnet-owner circle's `members.json`. Two operators that share
    /// a tailnet may report different values during reconciliation
    /// windows; verifiers must treat divergence as a soft warning,
    /// not a hard reject.
    pub member_count: u32,

    /// Chain epoch at which this state was committed. Monotonic per
    /// circle. Verifiers reject `update_circle_state` rotations whose
    /// `epoch` is less than the previously-seen value.
    pub epoch: u64,

    /// Wall-clock timestamp at the operator (UNIX seconds). Strictly
    /// informational — the chain has its own epoch counter. Skew across
    /// operators is expected and NOT a verifier reject condition.
    pub timestamp_secs: u64,

    /// HFHE-2 shadow-blob commitment: a 64-char lowercase hex
    /// SHA-256 digest folded over the sealed `oct://<circle_id>/
    /// enc-receipts.json` (or equivalent operator-managed manifest
    /// of `(session_id, seq) -> { enc_bytes_used, enc_net,
    /// pvac_zero_proof }`). Anchoring its hash here means an
    /// on-chain anchor rotation is *evidence* of encrypted-blob
    /// change — verifiers detect when an operator silently rotates
    /// the shadow set out from under previously-emitted receipts.
    ///
    /// `None` for v1 anchors and for v2 operators who choose not to
    /// commit a shadow set. When `None` the field is OMITTED from
    /// canonical JSON (not emitted as `null`) so v1 anchors remain
    /// byte-identical across the schema bump.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enc_anchor_hash: Option<String>,

    /// Forward-compatibility bucket. Any JSON keys not recognised by
    /// this decoder land here, and are re-emitted verbatim by
    /// `canonical_bytes()` so the SHA-256 round-trips for v(N+1) data
    /// running through a v(N) verifier. Internal — operators should
    /// not write directly into this map.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Value>,
}

impl StateRoot {
    /// Build a v1 `StateRoot`. Performs no field validation — call
    /// `validate()` before sealing.
    pub fn new_v1(
        circle_id: impl Into<String>,
        policy_hash: impl Into<String>,
        wg_pubkey_hash: impl Into<String>,
        attestation_hash: Option<String>,
        region: impl Into<String>,
        member_count: u32,
        epoch: u64,
        timestamp_secs: u64,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION_V1,
            circle_id: circle_id.into(),
            policy_hash: policy_hash.into(),
            wg_pubkey_hash: wg_pubkey_hash.into(),
            attestation_hash,
            region: region.into(),
            member_count,
            epoch,
            timestamp_secs,
            enc_anchor_hash: None,
            unknown: BTreeMap::new(),
        }
    }

    /// Build a v2 `StateRoot` carrying an optional HFHE-2 shadow
    /// anchor. Sets `v = SCHEMA_VERSION_V2`. If `enc_anchor_hash` is
    /// `None` the canonical bytes are *byte-identical* to a v1 with
    /// the same other fields except for the bumped `"v":2`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v2(
        circle_id: impl Into<String>,
        policy_hash: impl Into<String>,
        wg_pubkey_hash: impl Into<String>,
        attestation_hash: Option<String>,
        region: impl Into<String>,
        member_count: u32,
        epoch: u64,
        timestamp_secs: u64,
        enc_anchor_hash: Option<String>,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION_V2,
            circle_id: circle_id.into(),
            policy_hash: policy_hash.into(),
            wg_pubkey_hash: wg_pubkey_hash.into(),
            attestation_hash,
            region: region.into(),
            member_count,
            epoch,
            timestamp_secs,
            enc_anchor_hash,
            unknown: BTreeMap::new(),
        }
    }

    /// Encode to canonical bytes: sorted-key JSON, no whitespace, UTF-8.
    /// Two `StateRoot` values that compare `Eq` MUST produce identical
    /// bytes. This is the input to `anchor_hex()`.
    ///
    /// # Errors
    ///
    /// Returns `StateRootError::Serde` if `serde_json` cannot represent
    /// the struct — in practice this is unreachable for the v1 shape.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StateRootError> {
        let value = serde_json::to_value(self)?;
        let mut out = Vec::with_capacity(256);
        crate::v3_canonical::canonical_write(&value, &mut out);
        Ok(out)
    }

    /// SHA-256 of `canonical_bytes()`, rendered as lowercase 64-char
    /// hex. This is the exact value committed on chain.
    pub fn anchor_hex(&self) -> Result<String, StateRootError> {
        let bytes = self.canonical_bytes()?;
        let digest = Sha256::digest(&bytes);
        Ok(hex::encode(digest))
    }

    /// Decode + validate a canonical JSON blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, StateRootError> {
        let sr: Self = serde_json::from_slice(bytes)?;
        sr.validate()?;
        Ok(sr)
    }

    /// Field-level invariants. Accepts both v1 and v2 schemas; v2
    /// additionally validates the optional `enc_anchor_hash` hex.
    pub fn validate(&self) -> Result<(), StateRootError> {
        if self.v != SCHEMA_VERSION_V1 && self.v != SCHEMA_VERSION_V2 {
            return Err(StateRootError::UnsupportedVersion {
                got: self.v,
                supported: SCHEMA_VERSION_V2,
            });
        }
        if self.circle_id.is_empty() {
            return Err(StateRootError::EmptyCircleId);
        }
        if self.region.is_empty() {
            return Err(StateRootError::EmptyRegion);
        }
        check_hash("policy_hash", &self.policy_hash)?;
        check_hash("wg_pubkey_hash", &self.wg_pubkey_hash)?;
        if let Some(h) = &self.attestation_hash {
            check_hash("attestation_hash", h)?;
        }
        if let Some(h) = &self.enc_anchor_hash {
            check_hash("enc_anchor_hash", h)?;
        }
        Ok(())
    }

    /// Decode without enforcing schema-version equality. Verifiers
    /// running against a future `v` use this path to keep the anchor
    /// computation working even when they don't understand new
    /// semantic fields. Hash-level invariants on the known fields
    /// are still checked.
    pub fn decode_lenient(bytes: &[u8]) -> Result<Self, StateRootError> {
        let sr: Self = serde_json::from_slice(bytes)?;
        if sr.circle_id.is_empty() {
            return Err(StateRootError::EmptyCircleId);
        }
        if sr.region.is_empty() {
            return Err(StateRootError::EmptyRegion);
        }
        check_hash("policy_hash", &sr.policy_hash)?;
        check_hash("wg_pubkey_hash", &sr.wg_pubkey_hash)?;
        if let Some(h) = &sr.attestation_hash {
            check_hash("attestation_hash", h)?;
        }
        if let Some(h) = &sr.enc_anchor_hash {
            check_hash("enc_anchor_hash", h)?;
        }
        Ok(sr)
    }
}

fn check_hash(field: &'static str, value: &str) -> Result<(), StateRootError> {
    let len = value.len();
    crate::v3_canonical::check_hash(value, || {
        if len == crate::v3_canonical::HEX_HASH_LEN {
            StateRootError::BadHashEncoding { field }
        } else {
            StateRootError::BadHashLength { field, len }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn h(byte: u8) -> String {
        // Helper: build a 64-char lowercase hex string of `byte` repeated.
        use std::fmt::Write as _;
        let mut s = String::with_capacity(HEX_HASH_LEN);
        for _ in 0..32 {
            write!(s, "{byte:02x}").expect("write to String is infallible");
        }
        s
    }

    fn sample() -> StateRoot {
        StateRoot::new_v1(
            "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
            h(0xab),
            h(0xcd),
            Some(h(0xef)),
            "us-east-1",
            42,
            12345,
            1_705_000_000,
        )
    }

    #[test]
    fn validate_accepts_sample() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn round_trip_through_canonical_bytes() {
        let sr = sample();
        let bytes = sr.canonical_bytes().expect("encode");
        let back = StateRoot::decode(&bytes).expect("decode");
        assert_eq!(sr, back);
    }

    #[test]
    fn determinism_same_struct_same_bytes() {
        let a = sample().canonical_bytes().unwrap();
        let b = sample().canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn determinism_field_reorder_in_input_doesnt_change_anchor() {
        // Encode the canonical form, then deserialize through a generic
        // Value, shuffle the top-level keys, re-canonicalise, and
        // confirm the SHA matches. This is the *load-bearing* property:
        // a verifier that gets handed a non-canonical JSON shape will
        // still recompute the same anchor as the original committer,
        // because `canonical_bytes()` re-sorts everything.
        let original_anchor = sample().anchor_hex().unwrap();

        // Round-trip the canonical bytes through serde_json::Value with
        // a deliberately-different key order (we rebuild the Map by
        // inserting keys in reverse).
        let bytes = sample().canonical_bytes().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let Value::Object(map) = value else { panic!("top-level not an object") };

        let mut reversed: Map<String, Value> = Map::new();
        let mut entries: Vec<_> = map.into_iter().collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0)); // reverse-lex order
        for (k, v) in entries {
            reversed.insert(k, v);
        }
        let shuffled_bytes = serde_json::to_vec(&Value::Object(reversed)).unwrap();

        let reparsed: StateRoot = serde_json::from_slice(&shuffled_bytes).unwrap();
        let recomputed_anchor = reparsed.anchor_hex().unwrap();
        assert_eq!(original_anchor, recomputed_anchor);
    }

    #[test]
    fn canonical_bytes_have_no_whitespace() {
        let bytes = sample().canonical_bytes().unwrap();
        for b in &bytes {
            assert!(
                !b" \n\r\t".contains(b),
                "whitespace byte 0x{b:02x} leaked into canonical encoding"
            );
        }
    }

    #[test]
    fn canonical_bytes_have_sorted_top_level_keys() {
        let bytes = sample().canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Naive scan: collect the key positions of the top-level keys.
        // The shape is `{"attestation_hash":...,"circle_id":...,...}`.
        let expected_order = [
            "attestation_hash",
            "circle_id",
            "epoch",
            "member_count",
            "policy_hash",
            "region",
            "timestamp_secs",
            "v",
            "wg_pubkey_hash",
        ];
        let mut cursor = 0;
        for key in expected_order {
            let needle = format!("\"{key}\"");
            let idx = s[cursor..]
                .find(&needle)
                .unwrap_or_else(|| panic!("key {key} missing or out of order"));
            cursor += idx + needle.len();
        }
    }

    #[test]
    fn omits_attestation_hash_when_none() {
        let mut sr = sample();
        sr.attestation_hash = None;
        let bytes = sr.canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !s.contains("attestation_hash"),
            "None fields must be omitted, not serialized as null. got: {s}"
        );
        assert!(!s.contains("null"));
    }

    #[test]
    fn bad_hash_length_rejected() {
        let mut sr = sample();
        sr.policy_hash = "deadbeef".to_string();
        match sr.validate() {
            Err(StateRootError::BadHashLength { field, .. }) => {
                assert_eq!(field, "policy_hash");
            }
            other => panic!("expected BadHashLength, got {other:?}"),
        }
    }

    #[test]
    fn uppercase_hex_rejected() {
        let mut sr = sample();
        sr.policy_hash = sr.policy_hash.to_uppercase();
        assert!(matches!(
            sr.validate(),
            Err(StateRootError::BadHashEncoding { .. })
        ));
    }

    #[test]
    fn empty_circle_id_rejected() {
        let mut sr = sample();
        sr.circle_id = String::new();
        assert!(matches!(
            sr.validate(),
            Err(StateRootError::EmptyCircleId)
        ));
    }

    #[test]
    fn unknown_future_fields_preserved_through_round_trip() {
        // Encode a "v99" blob (extra field `policy_url`) and verify
        // forward-compat. We use v=99 (not v=2) because HFHE-2 made
        // v=2 a real, supported schema — v=99 stands in for a
        // hypothetical future version this build doesn't understand.
        let bytes_v1 = sample().canonical_bytes().unwrap();
        let mut value: Value = serde_json::from_slice(&bytes_v1).unwrap();
        if let Value::Object(map) = &mut value {
            map.insert(
                "policy_url".to_string(),
                Value::String("https://op.example/policy".to_string()),
            );
            map.insert("v".to_string(), Value::from(99u32));
        }
        let bytes_v2 = serde_json::to_vec(&value).unwrap();

        // Strict decode rejects v=99.
        assert!(matches!(
            StateRoot::decode(&bytes_v2),
            Err(StateRootError::UnsupportedVersion { got: 99, .. })
        ));

        // Lenient decode succeeds and preserves the extra key.
        let sr = StateRoot::decode_lenient(&bytes_v2).expect("lenient decode");
        assert!(sr.unknown.contains_key("policy_url"));

        // Re-encoding emits the unknown field in lex order; the anchor
        // is stable across encode → decode_lenient → encode.
        let re_encoded = sr.canonical_bytes().unwrap();
        let anchor_a = hex::encode(Sha256::digest(&re_encoded));
        let canonical_v2 = {
            // Independent reference: canonical_write the original Value.
            let mut out = Vec::new();
            crate::v3_canonical::canonical_write(&value, &mut out);
            out
        };
        let anchor_b = hex::encode(Sha256::digest(&canonical_v2));
        assert_eq!(anchor_a, anchor_b);
    }

    /// Cross-check: hash a hand-built fixture string and confirm both
    /// `canonical_bytes()` and `anchor_hex()` agree with an independent
    /// `Sha256::digest` call. Catches regressions in either the
    /// canonicalisation walker or the hex encoding step.
    #[test]
    fn cross_check_anchor_matches_independent_sha256() {
        let sr = sample();
        let bytes = sr.canonical_bytes().unwrap();
        let expected = hex::encode(Sha256::digest(&bytes));
        let got = sr.anchor_hex().unwrap();
        assert_eq!(expected, got);
        assert_eq!(expected.len(), HEX_HASH_LEN);
    }

    /// Fixed-string cross-check: hash a tiny known JSON literal and
    /// confirm SHA-256 matches a precomputed digest. This is the
    /// "did sha2 / hex even link correctly" tripwire — independent of
    /// any StateRoot logic.
    #[test]
    fn cross_check_known_fixture_sha256() {
        // "octra" — well-known short input, easy to recompute by hand:
        //   echo -n 'octra' | sha256sum
        //   => 5d4fbcb50d4c97f25c50b4e6c7bbfd92cf69c2b14ed1f4f0d4a8b6f55c1a... [truncated]
        // We compute it inline here against sha2 directly so the test
        // exercises the same crate the StateRoot encoder uses.
        let input = b"octra";
        let expected = hex::encode(Sha256::digest(input));
        // Recomputed via `printf 'octra' | shasum -a 256` on 2026-05-18:
        let golden = "5ce2bc74acf79bc4fb5685f0633f010818b5f09331eb68a51784a76b964d5bbb";
        assert_eq!(expected, golden, "sha2 crate produced unexpected digest");
    }

    // -----------------------------------------------------------------
    // Property-based tests. Probe the StateRoot encoder against a broad
    // strategy space and pin down: determinism, reorder-invariance,
    // hash stability, and a weak form of injectivity. Goal: surface any
    // one-byte canonicalisation drift before it ships.
    // -----------------------------------------------------------------
    use proptest::collection::btree_map;
    use proptest::prelude::*;

    /// Build a 64-char lowercase-hex string from a 32-byte seed.
    fn hex_from(bytes: &[u8; 32]) -> String {
        hex::encode(bytes)
    }

    /// Strategy producing arbitrary, well-formed `StateRoot`s. All
    /// validation invariants (hex hash discipline, non-empty
    /// circle_id/region, v=1, no `unknown`-vs-declared-field collisions)
    /// are satisfied by construction.
    fn arb_state_root() -> impl Strategy<Value = StateRoot> {
        (
            ".{1,32}",                                 // circle_id (non-empty)
            any::<[u8; 32]>(),                         // policy_hash seed
            any::<[u8; 32]>(),                         // wg_pubkey_hash seed
            proptest::option::of(any::<[u8; 32]>()),   // attestation_hash seed
            ".{1,16}",                                 // region (non-empty)
            any::<u32>(),                              // member_count
            any::<u64>(),                              // epoch
            any::<u64>(),                              // timestamp_secs
            // `unknown` bucket — prefix keys with `x_` to guarantee
            // disjointness with declared field names. Values are JSON
            // primitives so we don't tangle with nested-Value Map order.
            btree_map(
                "x_[a-z]{1,8}",
                prop_oneof![
                    Just(Value::Null),
                    any::<bool>().prop_map(Value::Bool),
                    any::<i64>().prop_map(Value::from),
                    ".{0,16}".prop_map(Value::String),
                ],
                0..4,
            ),
        )
            .prop_map(
                |(cid, ph, wgh, attest, region, mc, ep, ts, unknown_map)| {
                    let mut sr = StateRoot::new_v1(
                        cid,
                        hex_from(&ph),
                        hex_from(&wgh),
                        attest.map(|a| hex_from(&a)),
                        region,
                        mc,
                        ep,
                        ts,
                    );
                    let bt: BTreeMap<String, Value> = unknown_map.into_iter().collect();
                    sr.unknown = bt;
                    sr
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        /// **Determinism.** Two `canonical_bytes()` calls on the same
        /// `StateRoot` produce identical bytes.
        #[test]
        fn prop_canonical_bytes_deterministic(sr in arb_state_root()) {
            let a = sr.canonical_bytes().expect("encode a");
            let b = sr.canonical_bytes().expect("encode b");
            prop_assert_eq!(a, b);
        }

        /// **Encode → decode → encode round-trip is byte-identical.**
        /// Two encoders that disagree by even one byte would fail this.
        #[test]
        fn prop_round_trip_through_canonical_bytes(sr in arb_state_root()) {
            sr.validate().expect("constructed StateRoot must validate");
            let bytes_a = sr.canonical_bytes().expect("encode");
            let decoded = StateRoot::decode(&bytes_a).expect("decode");
            let bytes_b = decoded.canonical_bytes().expect("re-encode");
            prop_assert_eq!(bytes_a, bytes_b);
        }

        /// **Field-reorder invariance.** Shuffling the top-level
        /// `serde_json::Map` insertion order of the encoded form yields
        /// the same anchor when fed back through `canonical_bytes()`.
        #[test]
        fn prop_field_reorder_invariance(sr in arb_state_root()) {
            let original_anchor = sr.anchor_hex().expect("anchor");
            let bytes = sr.canonical_bytes().expect("encode");
            let Value::Object(map) = serde_json::from_slice::<Value>(&bytes)
                .expect("reparse") else {
                    return Err(TestCaseError::fail("not an object"));
                };
            let mut reversed = Map::new();
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| b.0.cmp(&a.0));
            for (k, v) in entries {
                reversed.insert(k, v);
            }
            let shuffled = serde_json::to_vec(&Value::Object(reversed))
                .expect("encode shuffled");
            let reparsed = StateRoot::decode_lenient(&shuffled)
                .expect("lenient decode of reordered");
            let recomputed = reparsed.anchor_hex().expect("recompute anchor");
            prop_assert_eq!(original_anchor, recomputed);
        }

        /// **Hash output stability.** `anchor_hex()` is deterministic
        /// and always 64 lowercase hex chars.
        #[test]
        fn prop_anchor_hex_is_stable_and_well_formed(sr in arb_state_root()) {
            let h1 = sr.anchor_hex().expect("anchor 1");
            let h2 = sr.anchor_hex().expect("anchor 2");
            prop_assert_eq!(&h1, &h2);
            prop_assert_eq!(h1.len(), HEX_HASH_LEN);
            prop_assert!(h1.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }

        /// **Weak injectivity.** Two `StateRoot`s that differ in a
        /// structurally-relevant field (`epoch`) produce distinct
        /// canonical bytes and distinct anchors.
        #[test]
        fn prop_injectivity_on_distinct_epochs(
            mut sr in arb_state_root(),
            epoch_a in any::<u64>(),
            epoch_b in any::<u64>(),
        ) {
            prop_assume!(epoch_a != epoch_b);
            sr.epoch = epoch_a;
            let bytes_a = sr.canonical_bytes().expect("encode a");
            let anchor_a = sr.anchor_hex().expect("anchor a");
            sr.epoch = epoch_b;
            let bytes_b = sr.canonical_bytes().expect("encode b");
            let anchor_b = sr.anchor_hex().expect("anchor b");
            prop_assert_ne!(bytes_a, bytes_b);
            prop_assert_ne!(anchor_a, anchor_b);
        }

        /// Cross-field non-aliasing: swapping `policy_hash` and
        /// `wg_pubkey_hash` produces a different anchor. Catches
        /// regression where the encoder collapses two hex fields.
        #[test]
        fn prop_policy_hash_and_wg_hash_do_not_alias(
            mut sr in arb_state_root(),
            ph in any::<[u8; 32]>(),
            wgh in any::<[u8; 32]>(),
        ) {
            prop_assume!(ph != wgh);
            sr.policy_hash = hex::encode(ph);
            sr.wg_pubkey_hash = hex::encode(wgh);
            let anchor_a = sr.anchor_hex().expect("anchor a");
            sr.policy_hash = hex::encode(wgh);
            sr.wg_pubkey_hash = hex::encode(ph);
            let anchor_b = sr.anchor_hex().expect("anchor b");
            prop_assert_ne!(anchor_a, anchor_b);
        }

        /// Cross-field non-aliasing: changing `circle_id` while keeping
        /// every other field constant changes the anchor (a verifier
        /// that fetches state-root.json from circle X and finds
        /// `circle_id != X` MUST reject — anchor MUST cover it).
        #[test]
        fn prop_circle_id_changes_anchor(
            mut sr in arb_state_root(),
            cid_a in "[a-z]{4,16}",
            cid_b in "[a-z]{4,16}",
        ) {
            prop_assume!(cid_a != cid_b);
            sr.circle_id = cid_a;
            let a = sr.anchor_hex().expect("anchor a");
            sr.circle_id = cid_b;
            let b = sr.anchor_hex().expect("anchor b");
            prop_assert_ne!(a, b);
        }

        /// Cross-field non-aliasing: `member_count` changes the anchor
        /// (defends "unused fields aren't in the hash" regression).
        #[test]
        fn prop_member_count_in_anchor(
            mut sr in arb_state_root(),
            a in any::<u32>(),
            b in any::<u32>(),
        ) {
            prop_assume!(a != b);
            sr.member_count = a;
            let h_a = sr.anchor_hex().expect("h a");
            sr.member_count = b;
            let h_b = sr.anchor_hex().expect("h b");
            prop_assert_ne!(h_a, h_b);
        }

        /// Cross-field non-aliasing: `timestamp_secs` changes the
        /// anchor. Together with the epoch invariant this nails down
        /// that observers can't replace the observed time silently.
        #[test]
        fn prop_timestamp_in_anchor(
            mut sr in arb_state_root(),
            a in any::<u64>(),
            b in any::<u64>(),
        ) {
            prop_assume!(a != b);
            sr.timestamp_secs = a;
            let h_a = sr.anchor_hex().expect("h a");
            sr.timestamp_secs = b;
            let h_b = sr.anchor_hex().expect("h b");
            prop_assert_ne!(h_a, h_b);
        }

        /// `attestation_hash = None` produces a distinct anchor from
        /// `Some(any hex)`. Otherwise None could collide with
        /// `Some([0;32])`.
        #[test]
        fn prop_attestation_none_distinct_from_some(
            mut sr in arb_state_root(),
            h in any::<[u8; 32]>(),
        ) {
            sr.attestation_hash = None;
            let none_anchor = sr.anchor_hex().expect("none anchor");
            sr.attestation_hash = Some(hex::encode(h));
            let some_anchor = sr.anchor_hex().expect("some anchor");
            prop_assert_ne!(none_anchor, some_anchor);
        }
    }

    // -----------------------------------------------------------------
    // HFHE-2: v2 schema + `enc_anchor_hash` tests.
    // -----------------------------------------------------------------

    fn sample_v2_with_anchor() -> StateRoot {
        StateRoot::new_v2(
            "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
            h(0xab),
            h(0xcd),
            Some(h(0xef)),
            "us-east-1",
            42,
            12345,
            1_705_000_000,
            Some(h(0xa5)),
        )
    }

    #[test]
    fn v2_state_root_validates() {
        assert!(sample_v2_with_anchor().validate().is_ok());
    }

    #[test]
    fn v2_state_root_round_trips_through_canonical_bytes() {
        let sr = sample_v2_with_anchor();
        let bytes = sr.canonical_bytes().expect("encode");
        let back = StateRoot::decode(&bytes).expect("decode");
        assert_eq!(sr, back);
    }

    #[test]
    fn v1_anchor_unchanged_by_v2_schema_bump() {
        let v1 = sample();
        let bytes = v1.canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("enc_anchor_hash"));
        let anchor = v1.anchor_hex().unwrap();
        assert_eq!(anchor.len(), HEX_HASH_LEN);
    }

    #[test]
    fn v2_without_enc_anchor_differs_from_v1_only_in_v_field() {
        let v1 = sample();
        let v2_no_anchor = StateRoot::new_v2(
            v1.circle_id.clone(),
            v1.policy_hash.clone(),
            v1.wg_pubkey_hash.clone(),
            v1.attestation_hash.clone(),
            v1.region.clone(),
            v1.member_count,
            v1.epoch,
            v1.timestamp_secs,
            None,
        );
        let v1_bytes = v1.canonical_bytes().unwrap();
        let v2_bytes = v2_no_anchor.canonical_bytes().unwrap();
        let v1_s = std::str::from_utf8(&v1_bytes).unwrap();
        let v2_s = std::str::from_utf8(&v2_bytes).unwrap();
        assert!(v1_s.contains("\"v\":1"));
        assert!(v2_s.contains("\"v\":2"));
        let mended = v1_s.replace("\"v\":1", "\"v\":2");
        assert_eq!(mended, v2_s);
    }

    #[test]
    fn v2_enc_anchor_changes_anchor() {
        let v2_no = StateRoot::new_v2(
            "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
            h(0xab),
            h(0xcd),
            None,
            "us-east-1",
            1,
            1,
            1,
            None,
        );
        let v2_with = StateRoot::new_v2(
            "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
            h(0xab),
            h(0xcd),
            None,
            "us-east-1",
            1,
            1,
            1,
            Some(h(0x77)),
        );
        let a = v2_no.anchor_hex().unwrap();
        let b = v2_with.anchor_hex().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn v2_bad_enc_anchor_hash_rejected() {
        let mut sr = sample_v2_with_anchor();
        sr.enc_anchor_hash = Some("not-hex".into());
        match sr.validate() {
            Err(StateRootError::BadHashLength { field, .. }) => {
                assert_eq!(field, "enc_anchor_hash");
            }
            other => panic!("expected BadHashLength, got {other:?}"),
        }
    }

    #[test]
    fn unknown_version_rejected_by_validate() {
        let mut sr = sample_v2_with_anchor();
        sr.v = 99;
        match sr.validate() {
            Err(StateRootError::UnsupportedVersion { got: 99, .. }) => {}
            other => panic!("expected UnsupportedVersion(99), got {other:?}"),
        }
    }

    #[test]
    fn worked_example_anchor_is_stable() {
        // Lock down the worked example used in the schema doc. If
        // anything in canonical_write changes, this test will trip and
        // the doc fixture must be updated in lockstep.
        let sr = StateRoot::new_v1(
            "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3",
            // 64-char hex digests chosen to be visually distinct.
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            Some("3333333333333333333333333333333333333333333333333333333333333333".to_string()),
            "us-east-1",
            42,
            12345,
            1_705_000_000,
        );
        let bytes = sr.canonical_bytes().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        // The exact canonical form (sorted keys, no whitespace):
        let expected = concat!(
            "{",
            "\"attestation_hash\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
            "\"circle_id\":\"oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3\",",
            "\"epoch\":12345,",
            "\"member_count\":42,",
            "\"policy_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"region\":\"us-east-1\",",
            "\"timestamp_secs\":1705000000,",
            "\"v\":1,",
            "\"wg_pubkey_hash\":\"2222222222222222222222222222222222222222222222222222222222222222\"",
            "}",
        );
        assert_eq!(json, expected);
        // And the corresponding anchor — locked verbatim against the
        // value documented in `docs/v3-state-root-schema.md` §6. If you
        // changed canonical_write and this trips, the doc fixture is
        // also wrong: update BOTH in lockstep, never just the test.
        let anchor = sr.anchor_hex().unwrap();
        assert_eq!(
            anchor,
            "6dc60d262d2f232b3b90d260e789ee5a0b6b00f35637153665b61eadc64a2700",
            "worked-example anchor drifted from docs/v3-state-root-schema.md"
        );
        // Sanity: also matches an independent Sha256::digest call.
        let recomputed = hex::encode(Sha256::digest(expected.as_bytes()));
        assert_eq!(anchor, recomputed);
        // Also assert AML's 64-char invariant.
        assert_eq!(anchor.len(), HEX_HASH_LEN);
    }
}
