//! OctraVPN v3 — canonical `policy.json` schema.
//!
//! Each operator circle holds a sealed asset at
//! `oct://<circle_id>/policy.json`. Clients fetch it to learn how to
//! dial the operator's WireGuard endpoint and how much that operator
//! charges. The `state-root.json` sibling (see `v3_state_root.rs`)
//! commits a 64-char lowercase hex SHA-256 of this file's canonical
//! bytes into its `policy_hash` field; the chain then anchors that
//! state-root hash via `update_circle_state`.
//!
//! Concretely:
//!
//! ```text
//! state_root.policy_hash == sha256_hex(canonical_bytes(policy.json))
//! circle_state_root[circle] == sha256_hex(canonical_bytes(state-root.json))
//! ```
//!
//! As with `state-root.json`, integrity is enforced entirely by the
//! commit/recompute cycle. The chain does NOT decode or interpret
//! `policy.json` — so two clients producing semantically identical
//! `OperatorPolicy` values MUST emit byte-identical canonical bytes.
//!
//! # Canonical encoding rules
//!
//! These mirror `v3_state_root.rs` exactly — both files MUST canonicalise
//! the same way so the same `canonical_write` discipline can be re-used
//! between them by anyone re-implementing the schema:
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
//! 5. The output is UTF-8. v1 ASCII fields (`endpoint`, `wg_pubkey_b64`)
//!    have their character set further constrained by `validate()`.
//!    Freeform string fields (`region`) admit non-ASCII text; future
//!    producers SHOULD NFC-normalise before sealing so distinct
//!    operators agree on the byte form.
//!
//! # Hashing
//!
//! `hash_hex()` returns the lowercase 64-char hex SHA-256 of
//! `canonical_bytes()`. This is the value that flows into
//! `state-root.json`'s `policy_hash` field.
//!
//! # Versioning
//!
//! The `v` field is the schema version. v1 is the initial release.
//! Adding an optional field that defaults to `None`/absent does NOT
//! require bumping `v` — old verifiers will silently ignore unknown
//! keys and recompute a different hash, which is fine because the
//! `state-root.json` `policy_hash` was written by the new encoder.
//! Bumping `v` is reserved for breaking changes (field removal,
//! field rename, semantics shift).
//!
//! Unknown fields encountered during decode are preserved verbatim
//! (`#[serde(flatten)]` into a `BTreeMap`) and round-trip through
//! `canonical_bytes()` so a verifier built against v1 can still
//! compute the correct `policy_hash` for v2+ data.
//!
//! # Field-set rationale
//!
//! `wg_pubkey_b64` carries the operator's WireGuard public key in raw
//! base64 (the form `wg` and `boringtun` expect on the wire), NOT a
//! hex hash of the key. Clients have to actually dial WireGuard with
//! the key, so it must be the real key. `state-root.json` carries a
//! separate `wg_pubkey_hash` that lets verifiers pin which key the
//! operator has committed to without having to fetch the (potentially
//! larger) policy file first.

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical schema version emitted by encoders in this crate.
pub const SCHEMA_VERSION_V1: u32 = 1;

/// Length of a SHA-256 hex digest. Matches AML's `sha256()` builtin
/// and the `HEX_HASH_LEN` constant in `v3_state_root.rs`.
pub const HEX_HASH_LEN: usize = 64;

/// Expected character length of a base64-encoded 32-byte WireGuard
/// public key. 32 bytes → ceil(32/3)*4 == 44 characters, including
/// one `=` pad byte. `boringtun` and `wg` both emit/accept this form.
pub const WG_PUBKEY_B64_LEN: usize = 44;

/// Expected decoded length of a WireGuard public key, in bytes.
pub const WG_PUBKEY_RAW_LEN: usize = 32;

/// Errors surfaced by the v3 `OperatorPolicy` encoder/decoder.
#[derive(Debug, thiserror::Error)]
pub enum V3PolicyError {
    #[error("schema version unsupported: got {got}, this build understands {supported}")]
    UnsupportedVersion { got: u32, supported: u32 },
    #[error(
        "wg_pubkey_b64 length is {len}, expected {WG_PUBKEY_B64_LEN} (base64 of 32 bytes)"
    )]
    BadWgPubkeyLength { len: usize },
    #[error("wg_pubkey_b64 is not valid base64: {0}")]
    BadWgPubkeyEncoding(String),
    #[error(
        "wg_pubkey_b64 decodes to {got} bytes, expected {WG_PUBKEY_RAW_LEN}"
    )]
    BadWgPubkeyDecodedLength { got: usize },
    #[error("endpoint is empty")]
    EmptyEndpoint,
    #[error("region is empty")]
    EmptyRegion,
    #[error("hex hash field {field} has length {len}, expected {HEX_HASH_LEN}")]
    BadHashLength { field: &'static str, len: usize },
    #[error("hex hash field {field} contains non-hex character or uppercase")]
    BadHashEncoding { field: &'static str },
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Canonical operator-circle policy.
///
/// One of these is produced by the operator-side daemon each time the
/// operator wants to advertise updated policy (price change, endpoint
/// rotation, attestation evidence change, …). It is sealed into the
/// operator's circle at `oct://<circle_id>/policy.json`, and
/// `sha256_hex(canonical_bytes())` flows into `state-root.json`'s
/// `policy_hash` field — which is what the chain ultimately anchors.
///
/// # Field semantics
///
/// `endpoint` is the dial target the client should use (e.g.
/// `"wg://relay.example:51820"`). It is plaintext in v1 — privacy of
/// the endpoint URL is a future feature behind HFHE / hidden-exit v2.
///
/// `wg_pubkey_b64` is the operator's WireGuard public key, in standard
/// base64 (32 bytes → 44 chars, one `=` pad). NOT a hash — clients
/// need the raw key bytes to bring up the tunnel.
///
/// Price fields are plaintext OU-per-MB tiers; `shared` is the rate
/// charged to ad-hoc dial-ins, `internal` to members of the same
/// tailnet (typically lower, sometimes zero).
///
/// `attestation_url` is an optional pointer at a remote-attestation
/// bundle so clients can verify the operator's host before opening a
/// session. When present, its content is committed separately via
/// `state-root.json`'s `attestation_hash`. When `None` the field is
/// OMITTED from canonical JSON, not emitted as `null`.
///
/// `unknown` carries any fields a newer encoder added that this version
/// doesn't recognise. They are preserved verbatim through encode →
/// decode → re-encode so the policy hash remains stable for upgraded
/// peers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorPolicy {
    /// Schema version. Starts at 1. See module-level doc for bump policy.
    pub v: u32,

    /// Public endpoint URL the client should dial (e.g.
    /// `"wg://relay.example:51820"`). Non-empty. Freeform string; the
    /// scheme convention is operator-defined, but `wg://host:port`
    /// is the documented norm for WireGuard exits.
    pub endpoint: String,

    /// Base64-encoded WireGuard public key (32 bytes raw → 44 base64
    /// chars). Validation enforces both the textual length and that
    /// it decodes cleanly to exactly 32 bytes.
    pub wg_pubkey_b64: String,

    /// Freeform region tag (e.g. `"us-east-1"`, `"eu-west"`,
    /// `"home-server"`). Surfaced to clients picking exits by latency
    /// pool; not load-bearing for security. Must be non-empty.
    /// Unicode is permitted — producers SHOULD NFC-normalise.
    pub region: String,

    /// Per-MB price (in the program's accounting unit) charged to
    /// clients NOT on a tailnet shared with this operator.
    pub price_per_mb_shared: u64,

    /// Per-MB price charged to clients on the same tailnet as this
    /// operator (typically lower, often zero).
    pub price_per_mb_internal: u64,

    /// Chain epoch at which the operator began serving this policy.
    /// Monotonic per circle. Clients use this to detect stale policy
    /// blobs left over from a prior epoch.
    pub effective_epoch: u64,

    /// Wall-clock timestamp at the operator (UNIX seconds). Strictly
    /// informational — the chain has its own epoch counter. Skew
    /// across operators is expected and NOT a validation reject.
    pub timestamp_secs: u64,

    /// Optional URL pointing at a remote-attestation bundle the
    /// operator publishes for its host. `None` for operators who do
    /// not advertise attestation (most devnet operators today). When
    /// `None` the field is OMITTED from canonical JSON, not emitted
    /// as `null`. The bundle's SHA-256 is separately committed by
    /// `state-root.json`'s `attestation_hash`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation_url: Option<String>,

    /// Forward-compatibility bucket. Any JSON keys not recognised by
    /// this decoder land here, and are re-emitted verbatim by
    /// `canonical_bytes()` so the SHA-256 round-trips for v(N+1) data
    /// running through a v(N) verifier. Internal — operators should
    /// not write directly into this map.
    #[serde(flatten)]
    pub unknown: BTreeMap<String, Value>,
}

impl OperatorPolicy {
    /// Build a v1 `OperatorPolicy`. Performs no field validation — call
    /// `validate()` before sealing.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v1(
        endpoint: impl Into<String>,
        wg_pubkey_b64: impl Into<String>,
        region: impl Into<String>,
        price_per_mb_shared: u64,
        price_per_mb_internal: u64,
        effective_epoch: u64,
        timestamp_secs: u64,
        attestation_url: Option<String>,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION_V1,
            endpoint: endpoint.into(),
            wg_pubkey_b64: wg_pubkey_b64.into(),
            region: region.into(),
            price_per_mb_shared,
            price_per_mb_internal,
            effective_epoch,
            timestamp_secs,
            attestation_url,
            unknown: BTreeMap::new(),
        }
    }

    /// Encode to canonical bytes: sorted-key JSON, no whitespace, UTF-8.
    /// Two `OperatorPolicy` values that compare `Eq` MUST produce
    /// identical bytes. This is the input to `hash_hex()`.
    ///
    /// # Errors
    ///
    /// Returns `V3PolicyError::Serde` if `serde_json` cannot represent
    /// the struct — in practice this is unreachable for the v1 shape.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, V3PolicyError> {
        let value = serde_json::to_value(self)?;
        let mut out = Vec::with_capacity(256);
        crate::v3_canonical::canonical_write(&value, &mut out);
        Ok(out)
    }

    /// SHA-256 of `canonical_bytes()`, rendered as lowercase 64-char
    /// hex. This is the exact value that flows into
    /// `state-root.json`'s `policy_hash`.
    pub fn hash_hex(&self) -> Result<String, V3PolicyError> {
        let bytes = self.canonical_bytes()?;
        let digest = Sha256::digest(&bytes);
        Ok(hex::encode(digest))
    }

    /// Decode + validate a canonical JSON blob.
    pub fn decode(bytes: &[u8]) -> Result<Self, V3PolicyError> {
        let p: Self = serde_json::from_slice(bytes)?;
        p.validate()?;
        Ok(p)
    }

    /// Field-level invariants. Run on every encode and decode that
    /// touches untrusted data.
    pub fn validate(&self) -> Result<(), V3PolicyError> {
        if self.v != SCHEMA_VERSION_V1 {
            // v1 is the only version this build understands. We do NOT
            // reject higher versions outright at decode time when called
            // through the forward-compat path — see `decode_lenient`.
            return Err(V3PolicyError::UnsupportedVersion {
                got: self.v,
                supported: SCHEMA_VERSION_V1,
            });
        }
        validate_common(self)?;
        Ok(())
    }

    /// Decode without enforcing schema-version equality. Verifiers
    /// running against a future `v` use this path to keep the policy
    /// hash computation working even when they don't understand new
    /// semantic fields. Field-level invariants on the known fields
    /// are still checked.
    pub fn decode_lenient(bytes: &[u8]) -> Result<Self, V3PolicyError> {
        let p: Self = serde_json::from_slice(bytes)?;
        validate_common(&p)?;
        Ok(p)
    }
}

/// Shared field-level invariants used by both strict `validate()` and
/// `decode_lenient()`. Does NOT check the `v` field — callers decide
/// whether to reject unknown versions.
fn validate_common(p: &OperatorPolicy) -> Result<(), V3PolicyError> {
    if p.endpoint.is_empty() {
        return Err(V3PolicyError::EmptyEndpoint);
    }
    if p.region.is_empty() {
        return Err(V3PolicyError::EmptyRegion);
    }
    check_wg_pubkey(&p.wg_pubkey_b64)?;
    Ok(())
}

/// Validate a base64 WireGuard public key string. Checks the textual
/// length, the base64 alphabet, and the decoded byte length.
fn check_wg_pubkey(value: &str) -> Result<(), V3PolicyError> {
    if value.len() != WG_PUBKEY_B64_LEN {
        return Err(V3PolicyError::BadWgPubkeyLength { len: value.len() });
    }
    let raw = BASE64_STD
        .decode(value.as_bytes())
        .map_err(|e| V3PolicyError::BadWgPubkeyEncoding(e.to_string()))?;
    if raw.len() != WG_PUBKEY_RAW_LEN {
        return Err(V3PolicyError::BadWgPubkeyDecodedLength { got: raw.len() });
    }
    Ok(())
}

/// Validate a lowercase-hex SHA-256 digest. Currently unused by v1
/// (the only hash field, `policy_hash`, lives over in
/// `state-root.json`), but exported so a future v2 field that embeds
/// a hash inline can call this without re-deriving the rules.
#[allow(dead_code)]
fn check_hash(field: &'static str, value: &str) -> Result<(), V3PolicyError> {
    let len = value.len();
    crate::v3_canonical::check_hash(value, || {
        if len == crate::v3_canonical::HEX_HASH_LEN {
            V3PolicyError::BadHashEncoding { field }
        } else {
            V3PolicyError::BadHashLength { field, len }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    /// 32 base64-encoded bytes (44 chars). Built from a fixed pattern
    /// so test fixtures are stable across runs without pulling in a
    /// real WG keypair generator.
    fn sample_wg_pubkey_b64() -> String {
        let raw = [0xAB_u8; WG_PUBKEY_RAW_LEN];
        BASE64_STD.encode(raw)
    }

    fn sample() -> OperatorPolicy {
        OperatorPolicy::new_v1(
            "wg://relay.example:51820",
            sample_wg_pubkey_b64(),
            "us-east-1",
            1000,
            0,
            12345,
            1_705_000_000,
            Some("https://op.example/attestation".to_string()),
        )
    }

    #[test]
    fn validate_accepts_sample() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn round_trip_through_canonical_bytes() {
        let p = sample();
        let bytes = p.canonical_bytes().expect("encode");
        let back = OperatorPolicy::decode(&bytes).expect("decode");
        assert_eq!(p, back);
    }

    #[test]
    fn determinism_same_struct_same_bytes() {
        let a = sample().canonical_bytes().unwrap();
        let b = sample().canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn determinism_field_reorder_in_input_doesnt_change_hash() {
        // Encode the canonical form, then deserialize through a generic
        // Value, shuffle the top-level keys, re-canonicalise, and
        // confirm the SHA matches. This is the *load-bearing* property:
        // a verifier that gets handed a non-canonical JSON shape will
        // still recompute the same hash as the original committer,
        // because `canonical_bytes()` re-sorts everything.
        let original_hash = sample().hash_hex().unwrap();

        let bytes = sample().canonical_bytes().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let Value::Object(map) = value else {
            panic!("top-level not an object");
        };

        let mut reversed: Map<String, Value> = Map::new();
        let mut entries: Vec<_> = map.into_iter().collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0)); // reverse-lex order
        for (k, v) in entries {
            reversed.insert(k, v);
        }
        let shuffled_bytes = serde_json::to_vec(&Value::Object(reversed)).unwrap();

        let reparsed: OperatorPolicy = serde_json::from_slice(&shuffled_bytes).unwrap();
        let recomputed_hash = reparsed.hash_hex().unwrap();
        assert_eq!(original_hash, recomputed_hash);
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
        let expected_order = [
            "attestation_url",
            "effective_epoch",
            "endpoint",
            "price_per_mb_internal",
            "price_per_mb_shared",
            "region",
            "timestamp_secs",
            "v",
            "wg_pubkey_b64",
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
    fn omits_attestation_url_when_none() {
        let mut p = sample();
        p.attestation_url = None;
        let bytes = p.canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !s.contains("attestation_url"),
            "None fields must be omitted, not serialized as null. got: {s}"
        );
        assert!(!s.contains("null"));
    }

    #[test]
    fn bad_wg_pubkey_length_rejected() {
        let mut p = sample();
        p.wg_pubkey_b64 = "too-short".to_string();
        assert!(matches!(
            p.validate(),
            Err(V3PolicyError::BadWgPubkeyLength { .. })
        ));
    }

    #[test]
    fn bad_wg_pubkey_encoding_rejected() {
        let mut p = sample();
        // 44 chars but with non-base64 characters.
        p.wg_pubkey_b64 = "!".repeat(WG_PUBKEY_B64_LEN);
        match p.validate() {
            Err(V3PolicyError::BadWgPubkeyEncoding(_)) => {}
            other => panic!("expected BadWgPubkeyEncoding, got {other:?}"),
        }
    }

    #[test]
    fn bad_wg_pubkey_decoded_length_rejected() {
        // 44 chars, valid base64, but decodes to a wrong number of
        // bytes. The only way to hit BadWgPubkeyDecodedLength while
        // staying at 44 chars is base64 of a 33-byte string padded out
        // — but that requires 44 chars to round-trip, which forces 32
        // bytes. So we exercise the post-length check by injecting a
        // shorter raw value and padding up the b64 string manually.
        //
        // Simpler path: bypass `validate()` and call `check_wg_pubkey`
        // directly on a 44-char string of all `A` (which decodes to
        // 33 raw bytes when the trailing chars are mis-padded). To
        // keep this hermetic we just test the helper directly with a
        // deliberately-crafted decoded length error.
        // 44 chars of "A" decodes to 33 bytes — wait, base64 of 33
        // bytes is 44 chars (no pad), and base64 of 32 bytes is 44
        // chars WITH one '=' pad. "A" repeated 44 times is valid b64
        // alphabet but decodes to a 33-byte buffer of zeros. That
        // hits the decoded-length branch.
        let mut p = sample();
        p.wg_pubkey_b64 = "A".repeat(WG_PUBKEY_B64_LEN);
        match p.validate() {
            Err(V3PolicyError::BadWgPubkeyDecodedLength { got }) => {
                assert_eq!(got, 33);
            }
            other => panic!("expected BadWgPubkeyDecodedLength, got {other:?}"),
        }
    }

    #[test]
    fn empty_endpoint_rejected() {
        let mut p = sample();
        p.endpoint = String::new();
        assert!(matches!(p.validate(), Err(V3PolicyError::EmptyEndpoint)));
    }

    #[test]
    fn empty_region_rejected() {
        let mut p = sample();
        p.region = String::new();
        assert!(matches!(p.validate(), Err(V3PolicyError::EmptyRegion)));
    }

    #[test]
    fn check_hash_enforces_lowercase_hex() {
        // Even though no v1 field is a hex hash, the helper is
        // exported for future use and must keep the same lowercase-
        // hex discipline as `v3_state_root::check_hash`.
        let lower = "a".repeat(HEX_HASH_LEN);
        assert!(check_hash("test", &lower).is_ok());
        let upper = "A".repeat(HEX_HASH_LEN);
        assert!(matches!(
            check_hash("test", &upper),
            Err(V3PolicyError::BadHashEncoding { .. })
        ));
        let bad_len = "a".repeat(HEX_HASH_LEN - 1);
        assert!(matches!(
            check_hash("test", &bad_len),
            Err(V3PolicyError::BadHashLength { .. })
        ));
    }

    #[test]
    fn unknown_future_fields_preserved_through_round_trip() {
        // Encode a "v2" blob (extra field `hfhe_pubkey_hash`) and
        // verify that a v1 decoder both preserves the extra field AND
        // recomputes the same hash when re-encoded.
        let bytes_v1 = sample().canonical_bytes().unwrap();
        let mut value: Value = serde_json::from_slice(&bytes_v1).unwrap();
        if let Value::Object(map) = &mut value {
            map.insert(
                "hfhe_pubkey_hash".to_string(),
                Value::String("a".repeat(HEX_HASH_LEN)),
            );
            // Pretend the producer bumped the schema version.
            map.insert("v".to_string(), Value::from(2u32));
        }
        let bytes_v2 = serde_json::to_vec(&value).unwrap();

        // Strict decode rejects v=2.
        assert!(matches!(
            OperatorPolicy::decode(&bytes_v2),
            Err(V3PolicyError::UnsupportedVersion { got: 2, .. })
        ));

        // Lenient decode succeeds and preserves the extra key.
        let p = OperatorPolicy::decode_lenient(&bytes_v2).expect("lenient decode");
        assert!(p.unknown.contains_key("hfhe_pubkey_hash"));

        // Re-encoding emits the unknown field in lex order; the hash
        // is stable across encode → decode_lenient → encode.
        let re_encoded = p.canonical_bytes().unwrap();
        let hash_a = hex::encode(Sha256::digest(&re_encoded));
        let canonical_v2 = {
            // Independent reference: canonical_write the original Value.
            let mut out = Vec::new();
            crate::v3_canonical::canonical_write(&value, &mut out);
            out
        };
        let hash_b = hex::encode(Sha256::digest(&canonical_v2));
        assert_eq!(hash_a, hash_b);
    }

    /// Cross-check: hash a hand-built fixture struct and confirm both
    /// `canonical_bytes()` and `hash_hex()` agree with an independent
    /// `Sha256::digest` call. Catches regressions in either the
    /// canonicalisation walker or the hex encoding step.
    #[test]
    fn cross_check_hash_matches_independent_sha256() {
        let p = sample();
        let bytes = p.canonical_bytes().unwrap();
        let expected = hex::encode(Sha256::digest(&bytes));
        let got = p.hash_hex().unwrap();
        assert_eq!(expected, got);
        assert_eq!(expected.len(), HEX_HASH_LEN);
    }

    #[test]
    fn unicode_region_round_trips_byte_identical() {
        // Freeform `region` admits non-ASCII strings. Confirm we don't
        // mangle them and that two encoders feeding the same NFC-form
        // input produce byte-identical canonical bytes.
        let mut p = sample();
        // "Zürich" + an em-dash + a CJK ideograph. ASCII-only escape
        // form in JSON: serde_json does NOT escape non-ASCII by default
        // — it emits the UTF-8 bytes directly inside the string. That
        // matches the canonicalisation contract (UTF-8 output).
        p.region = "Zürich—北京".to_string();
        let bytes_a = p.canonical_bytes().unwrap();
        let bytes_b = p.canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);

        // Re-decode and re-encode → identical bytes again.
        let decoded = OperatorPolicy::decode(&bytes_a).unwrap();
        let bytes_c = decoded.canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_c);

        // And the raw UTF-8 ideograph is present in the canonical
        // bytes (i.e. not \u-escaped).
        let s = std::str::from_utf8(&bytes_a).unwrap();
        assert!(s.contains("Zürich—北京"), "unicode mangled: {s}");
    }

    // -----------------------------------------------------------------
    // Property-based tests. Probe the encoder against a broad strategy
    // space: determinism, reorder-invariance, hash stability, and a
    // weak form of injectivity.
    // -----------------------------------------------------------------
    use proptest::collection::btree_map;
    use proptest::prelude::*;

    /// 32-byte WG pubkey from a seed → 44-char base64 (always valid).
    fn wg_b64_from(seed: &[u8; 32]) -> String {
        BASE64_STD.encode(seed)
    }

    /// Strategy producing arbitrary, well-formed `OperatorPolicy`s.
    fn arb_policy() -> impl Strategy<Value = OperatorPolicy> {
        (
            ".{1,32}",                            // endpoint
            any::<[u8; 32]>(),                    // wg_pubkey seed
            ".{1,16}",                            // region
            any::<u64>(),                         // price_per_mb_shared
            any::<u64>(),                         // price_per_mb_internal
            any::<u64>(),                         // effective_epoch
            any::<u64>(),                         // timestamp_secs
            proptest::option::of(".{0,32}"),      // attestation_url
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
                |(endpoint, wg, region, shared, internal, ep, ts, attest, unknown_map)| {
                    let mut p = OperatorPolicy::new_v1(
                        endpoint,
                        wg_b64_from(&wg),
                        region,
                        shared,
                        internal,
                        ep,
                        ts,
                        attest,
                    );
                    let bt: BTreeMap<String, Value> = unknown_map.into_iter().collect();
                    p.unknown = bt;
                    p
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        /// **Determinism.** Two `canonical_bytes()` calls on the same
        /// `OperatorPolicy` produce identical bytes.
        #[test]
        fn prop_canonical_bytes_deterministic(p in arb_policy()) {
            let a = p.canonical_bytes().expect("encode a");
            let b = p.canonical_bytes().expect("encode b");
            prop_assert_eq!(a, b);
        }

        /// **Encode → decode → encode round-trip is byte-identical.**
        #[test]
        fn prop_round_trip_through_canonical_bytes(p in arb_policy()) {
            p.validate().expect("constructed policy must validate");
            let bytes_a = p.canonical_bytes().expect("encode");
            let decoded = OperatorPolicy::decode(&bytes_a).expect("decode");
            let bytes_b = decoded.canonical_bytes().expect("re-encode");
            prop_assert_eq!(bytes_a, bytes_b);
        }

        /// **Field-reorder invariance.** Shuffling the top-level
        /// `Map` insertion order of the encoded form yields the same
        /// hash when fed back through `canonical_bytes()`.
        #[test]
        fn prop_field_reorder_invariance(p in arb_policy()) {
            let original_hash = p.hash_hex().expect("hash");
            let bytes = p.canonical_bytes().expect("encode");
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
            let reparsed = OperatorPolicy::decode_lenient(&shuffled)
                .expect("lenient decode of reordered");
            let recomputed = reparsed.hash_hex().expect("recompute hash");
            prop_assert_eq!(original_hash, recomputed);
        }

        /// **Hash output stability.** `hash_hex()` is deterministic
        /// and always 64 lowercase hex chars.
        #[test]
        fn prop_hash_hex_is_stable_and_well_formed(p in arb_policy()) {
            let h1 = p.hash_hex().expect("hash 1");
            let h2 = p.hash_hex().expect("hash 2");
            prop_assert_eq!(&h1, &h2);
            prop_assert_eq!(h1.len(), HEX_HASH_LEN);
            prop_assert!(h1.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }

        /// **Weak injectivity.** Two policies that differ in a
        /// structurally-relevant field (`effective_epoch`) produce
        /// distinct canonical bytes and distinct hashes.
        #[test]
        fn prop_injectivity_on_distinct_epochs(
            mut p in arb_policy(),
            ep_a in any::<u64>(),
            ep_b in any::<u64>(),
        ) {
            prop_assume!(ep_a != ep_b);
            p.effective_epoch = ep_a;
            let bytes_a = p.canonical_bytes().expect("encode a");
            let hash_a = p.hash_hex().expect("hash a");
            p.effective_epoch = ep_b;
            let bytes_b = p.canonical_bytes().expect("encode b");
            let hash_b = p.hash_hex().expect("hash b");
            prop_assert_ne!(bytes_a, bytes_b);
            prop_assert_ne!(hash_a, hash_b);
        }

        /// Cross-field non-aliasing: swapping `price_per_mb_shared`
        /// and `price_per_mb_internal` yields a different hash —
        /// defends against the chain charging the wrong tier silently.
        #[test]
        fn prop_price_tiers_do_not_alias(
            mut p in arb_policy(),
            shared in any::<u64>(),
            internal in any::<u64>(),
        ) {
            prop_assume!(shared != internal);
            p.price_per_mb_shared = shared;
            p.price_per_mb_internal = internal;
            let h1 = p.hash_hex().expect("h1");
            p.price_per_mb_shared = internal;
            p.price_per_mb_internal = shared;
            let h2 = p.hash_hex().expect("h2");
            prop_assert_ne!(h1, h2);
        }

        /// Cross-field non-aliasing: changing `endpoint` changes the
        /// hash. Otherwise an operator could rotate the dial target
        /// without anchor proof.
        #[test]
        fn prop_endpoint_in_hash(
            mut p in arb_policy(),
            a in "[a-z]{4,16}",
            b in "[a-z]{4,16}",
        ) {
            prop_assume!(a != b);
            p.endpoint = a;
            let h_a = p.hash_hex().expect("ha");
            p.endpoint = b;
            let h_b = p.hash_hex().expect("hb");
            prop_assert_ne!(h_a, h_b);
        }

        /// Cross-field non-aliasing: two distinct WG keys with
        /// otherwise identical policy MUST produce distinct hashes —
        /// the chain's only path to detect WG key rotation.
        #[test]
        fn prop_wg_pubkey_in_hash(
            mut p in arb_policy(),
            ka in any::<[u8; 32]>(),
            kb in any::<[u8; 32]>(),
        ) {
            prop_assume!(ka != kb);
            p.wg_pubkey_b64 = wg_b64_from(&ka);
            let h_a = p.hash_hex().expect("ha");
            p.wg_pubkey_b64 = wg_b64_from(&kb);
            let h_b = p.hash_hex().expect("hb");
            prop_assert_ne!(h_a, h_b);
        }

        /// `attestation_url = None` MUST be distinct from
        /// `Some(non-empty)`. Otherwise None collides with `Some("")`.
        #[test]
        fn prop_attestation_none_distinct_from_some(
            mut p in arb_policy(),
            url in ".{1,32}",
        ) {
            p.attestation_url = None;
            let none_h = p.hash_hex().expect("none");
            p.attestation_url = Some(url);
            let some_h = p.hash_hex().expect("some");
            prop_assert_ne!(none_h, some_h);
        }
    }

    #[test]
    fn worked_example_hash_is_stable() {
        // Lock down the worked example used in the schema doc. If
        // anything in canonical_write changes, this test will trip and
        // the doc fixture must be updated in lockstep.
        //
        // Fixed WG pubkey: 32 bytes of 0x11 → known base64. This makes
        // the canonical form fully deterministic across machines.
        let raw_key = [0x11_u8; WG_PUBKEY_RAW_LEN];
        let wg = BASE64_STD.encode(raw_key);
        // Sanity: this is exactly 44 chars.
        assert_eq!(wg.len(), WG_PUBKEY_B64_LEN);

        let p = OperatorPolicy::new_v1(
            "wg://relay.example:51820",
            wg.clone(),
            "us-east-1",
            1000,
            0,
            12345,
            1_705_000_000,
            Some("https://op.example/attestation".to_string()),
        );
        let bytes = p.canonical_bytes().unwrap();
        let json = std::str::from_utf8(&bytes).unwrap();
        // The exact canonical form (sorted keys, no whitespace):
        let expected = format!(
            concat!(
                "{{",
                "\"attestation_url\":\"https://op.example/attestation\",",
                "\"effective_epoch\":12345,",
                "\"endpoint\":\"wg://relay.example:51820\",",
                "\"price_per_mb_internal\":0,",
                "\"price_per_mb_shared\":1000,",
                "\"region\":\"us-east-1\",",
                "\"timestamp_secs\":1705000000,",
                "\"v\":1,",
                "\"wg_pubkey_b64\":\"{wg}\"",
                "}}",
            ),
            wg = wg
        );
        assert_eq!(json, expected);

        let hash = p.hash_hex().unwrap();
        // Cross-check against an independent Sha256::digest call.
        let recomputed = hex::encode(Sha256::digest(expected.as_bytes()));
        assert_eq!(hash, recomputed);
        // AML's 64-char invariant.
        assert_eq!(hash.len(), HEX_HASH_LEN);

        // Locked anchor — mirrored verbatim into
        // `docs/v3-policy-schema.md` §6. If you changed canonical_write
        // and this trips, the doc fixture is also wrong: update BOTH
        // in lockstep, never just the test.
        assert_eq!(
            hash,
            "d24ee1b8b9fc41071ffa16fa747626b5e3827ef8a6921eb2108520e1af9ad04f",
            "worked-example hash drifted from docs/v3-policy-schema.md"
        );
    }
}
