//! Canonical-JSON encoder shared by the v3 anchor schemas
//! (`v3_state_root`, `v3_policy`, `v3_members`).
//!
//! Each v3 schema commits a sha256 over canonical bytes onto chain;
//! verifiers re-derive the bytes from the off-chain JSON and compare.
//! A one-byte canonicalization deviation between sender + verifier =
//! silent on-chain-anchor desync. ONE encoder owns that surface.
//!
//! Rules (locked):
//!
//!   1. JSON object keys are sorted lexicographically by UTF-8 byte
//!      order. `serde_json::Map` preserves insertion order, so this
//!      module's `canonical_write` re-sorts on every object.
//!   2. No whitespace anywhere. No leading-zero numbers. Strings escape
//!      via `serde_json`'s standard escape rules so the output is what
//!      every JSON ecosystem produces.
//!   3. `Value::Null` / `Value::Bool` / `Value::Number` / `Value::String`
//!      / `Value::Array` / `Value::Object` are emitted exactly as
//!      RFC 8259 says, modulo (1) + (2).
//!   4. Hash fields in callers are 64-char lowercase hex sha256 digests
//!      — `check_hash` enforces that shape so a mixed-case anchor never
//!      escapes the producer side.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Length of an SHA-256 digest expressed as lowercase hex.
pub const HEX_HASH_LEN: usize = 64;

/// Lowercase-hex sha256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Validate that `value` is a 64-char lowercase-hex sha256. Caller-owned
/// error type — see `v3_state_root::StateRootError::BadHash` etc.
///
/// # Errors
/// Returns the caller's `not_hex` if `value` isn't exactly
/// `HEX_HASH_LEN` characters or contains a non-`[0-9a-f]` byte.
pub fn check_hash<E>(value: &str, not_hex: impl FnOnce() -> E) -> Result<(), E> {
    if value.len() != HEX_HASH_LEN {
        return Err(not_hex());
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(not_hex());
    }
    Ok(())
}

/// Write `v` to `out` in canonical-JSON form.
///
/// Tree-walk: objects emit their keys in sorted UTF-8 byte order; arrays
/// preserve input order; primitives delegate to `serde_json`. Recursive
/// but the v3 schemas are shallow — deepest nesting is ~3 levels.
pub fn canonical_write(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_write(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // `serde_json::Map` preserves insertion order. We MUST
            // re-sort: callers may declare struct fields in any order,
            // and the `#[serde(flatten)] unknown` bucket holds arbitrary
            // future-version fields whose order we don't control.
            let sorted: Map<String, Value> = {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
            out.push(b'{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(k, out);
                out.push(b':');
                canonical_write(val, out);
            }
            out.push(b'}');
        }
    }
}

/// Emit a JSON string literal. Delegates to `serde_json`'s escape table
/// — the canonical form matches what every JSON ecosystem produces.
fn write_json_string(s: &str, out: &mut Vec<u8>) {
    let encoded = serde_json::to_string(&Value::String(s.to_owned()))
        .expect("serialising a String to JSON cannot fail except on OOM");
    out.extend_from_slice(encoded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_top_level_keys_by_utf8_bytes() {
        let v = json!({"b": 1, "a": 2, "c": 3});
        let mut out = Vec::new();
        canonical_write(&v, &mut out);
        assert_eq!(out, br#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn sorts_nested_keys() {
        let v = json!({"outer": {"z": 1, "a": 2}});
        let mut out = Vec::new();
        canonical_write(&v, &mut out);
        assert_eq!(out, br#"{"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn preserves_array_order() {
        let v = json!([3, 1, 2]);
        let mut out = Vec::new();
        canonical_write(&v, &mut out);
        assert_eq!(out, br"[3,1,2]");
    }

    #[test]
    fn no_whitespace() {
        let v = json!({"k": "v", "n": 1, "a": [1, 2]});
        let mut out = Vec::new();
        canonical_write(&v, &mut out);
        assert!(!out.contains(&b' '));
        assert!(!out.contains(&b'\n'));
    }

    #[test]
    fn check_hash_accepts_lowercase_64_hex() {
        let h = "a".repeat(64);
        check_hash::<()>(&h, || ()).unwrap();
    }

    #[test]
    fn check_hash_rejects_short() {
        let h = "a".repeat(63);
        assert!(check_hash::<()>(&h, || ()).is_err());
    }

    #[test]
    fn check_hash_rejects_uppercase() {
        let mut h = "a".repeat(63);
        h.push('A');
        assert!(check_hash::<()>(&h, || ()).is_err());
    }

    #[test]
    fn check_hash_rejects_non_hex_char() {
        let mut h = "a".repeat(63);
        h.push('g');
        assert!(check_hash::<()>(&h, || ()).is_err());
    }

    #[test]
    fn unicode_strings_are_serde_json_compatible() {
        // Cross-check vs `serde_json::to_string` directly.
        let v = json!({"name": "日本語"});
        let mut out = Vec::new();
        canonical_write(&v, &mut out);
        // serde_json::to_string emits raw UTF-8 (no \uXXXX escapes) for
        // BMP chars >= 0x80. Match that.
        let expected = r#"{"name":"日本語"}"#;
        assert_eq!(out, expected.as_bytes());
    }

    #[test]
    fn sha256_hex_matches_independent() {
        let bytes = b"hello world";
        let mine = sha256_hex(bytes);
        let mut h = Sha256::new();
        h.update(bytes);
        let theirs = hex::encode(h.finalize());
        assert_eq!(mine, theirs);
    }

    // -----------------------------------------------------------------
    // Property-based tests. The canonical encoder is the single piece
    // of code that owns the on-chain anchor format; a one-byte
    // deviation silently desyncs verifiers from producers. We use
    // proptest to probe a broad strategy space of JSON shapes.
    //
    // To keep these fast we cap the case count and bound the
    // arbitrary-JSON tree depth: deepest realistic v3 nesting is 3,
    // so depth 4 is plenty of headroom without exploding generation
    // time.
    // -----------------------------------------------------------------
    use proptest::collection::{btree_map, vec as pvec};
    use proptest::prelude::*;

    /// A proptest strategy over arbitrary `serde_json::Value` trees.
    ///
    /// Leaves: null, bool, signed integer numbers (we deliberately
    /// avoid `f64` here — `Value` does not implement `Eq` for `NaN`
    /// and `serde_json::Number` itself rejects `NaN`/`Inf`), and
    /// arbitrary unicode strings. Branches: arrays and objects,
    /// depth-bounded.
    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i64>().prop_map(Value::from),
            ".{0,32}".prop_map(Value::String),
        ];
        leaf.prop_recursive(
            4,  // max depth
            32, // max total nodes
            8,  // max items per array/object
            |inner| {
                prop_oneof![
                    pvec(inner.clone(), 0..6).prop_map(Value::Array),
                    btree_map(".{1,12}", inner, 0..6).prop_map(|m| {
                        let mut map = Map::new();
                        for (k, v) in m {
                            map.insert(k, v);
                        }
                        Value::Object(map)
                    }),
                ]
            },
        )
    }

    /// Wrap a `Value` in a top-level object so the root is always an
    /// Object (matches the v3 schemas' shape — they all emit `{ ... }`).
    fn arb_object() -> impl Strategy<Value = Value> {
        btree_map(".{1,12}", arb_value(), 0..6).prop_map(|m| {
            let mut map = Map::new();
            for (k, v) in m {
                map.insert(k, v);
            }
            Value::Object(map)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        /// **Idempotence (sort stability).** Applying `canonical_write`
        /// to its own output (after re-parsing into a `Value`) yields
        /// identical bytes. Load-bearing: if canonicalisation isn't a
        /// fixed point, two verifiers can reach different anchors by
        /// canonicalising at different stages of a pipeline.
        #[test]
        fn canonical_write_is_idempotent(v in arb_value()) {
            let mut bytes_a = Vec::new();
            canonical_write(&v, &mut bytes_a);
            let reparsed: Value = serde_json::from_slice(&bytes_a)
                .expect("canonical output must reparse");
            let mut bytes_b = Vec::new();
            canonical_write(&reparsed, &mut bytes_b);
            prop_assert_eq!(bytes_a, bytes_b);
        }

        /// **Determinism.** Encoding the same `Value` twice produces
        /// identical bytes.
        #[test]
        fn canonical_write_is_deterministic(v in arb_value()) {
            let mut a = Vec::new();
            canonical_write(&v, &mut a);
            let mut b = Vec::new();
            canonical_write(&v, &mut b);
            prop_assert_eq!(a, b);
        }

        /// **Reorder-invariance at the Value level.** Two objects with
        /// the same `(key, value)` content but different
        /// `serde_json::Map` insertion order produce identical
        /// canonical bytes.
        #[test]
        fn object_key_reorder_invariant(
            entries in pvec((".{1,8}", arb_value()), 0..8),
        ) {
            let mut seen = std::collections::BTreeSet::new();
            let entries: Vec<_> = entries
                .into_iter()
                .filter(|(k, _)| seen.insert(k.clone()))
                .collect();
            let mut forward = Map::new();
            for (k, v) in &entries {
                forward.insert(k.clone(), v.clone());
            }
            let mut reversed = Map::new();
            for (k, v) in entries.iter().rev() {
                reversed.insert(k.clone(), v.clone());
            }
            let mut a = Vec::new();
            canonical_write(&Value::Object(forward), &mut a);
            let mut b = Vec::new();
            canonical_write(&Value::Object(reversed), &mut b);
            prop_assert_eq!(a, b);
        }

        /// **No whitespace OUTSIDE quoted string literals.** Walk the
        /// canonical bytes toggling an in-string flag on unescaped `"`.
        #[test]
        fn no_whitespace_outside_strings(v in arb_value()) {
            let mut out = Vec::new();
            canonical_write(&v, &mut out);
            let mut in_string = false;
            let mut escaped = false;
            for &b in &out {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        in_string = false;
                    }
                } else if b == b'"' {
                    in_string = true;
                } else {
                    prop_assert!(
                        !b" \n\r\t".contains(&b),
                        "structural whitespace byte 0x{:02x} leaked",
                        b
                    );
                }
            }
        }

        /// **`sha256_hex` over canonical bytes is stable + well-formed.**
        /// Same input → same output → 64 lowercase hex chars.
        #[test]
        fn sha256_hex_canonical_is_stable(v in arb_value()) {
            let mut bytes = Vec::new();
            canonical_write(&v, &mut bytes);
            let h1 = sha256_hex(&bytes);
            let h2 = sha256_hex(&bytes);
            prop_assert_eq!(&h1, &h2);
            prop_assert_eq!(h1.len(), HEX_HASH_LEN);
            prop_assert!(h1.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }

        /// **Top-level object keys are sorted in canonical output.**
        /// Lex-byte order. A regression where we forgot to re-sort
        /// after a `Map` mutation would trip this.
        #[test]
        fn top_level_object_keys_are_sorted(obj in arb_object()) {
            let mut bytes = Vec::new();
            canonical_write(&obj, &mut bytes);
            let v: Value = serde_json::from_slice(&bytes)
                .expect("must reparse");
            if let Value::Object(map) = v {
                let keys: Vec<&String> = map.keys().collect();
                for w in keys.windows(2) {
                    prop_assert!(
                        w[0].as_bytes() <= w[1].as_bytes(),
                        "keys not in lex-byte order: {:?} then {:?}", w[0], w[1]
                    );
                }
            }
        }

        /// **`check_hash` accepts every 64-char lowercase-hex string.**
        /// This is the rule the AML side relies on: chain rejects an
        /// anchor argument that isn't exactly `HEX_HASH_LEN` lowercase
        /// hex.
        #[test]
        fn check_hash_round_trip(
            good_chars in pvec(prop_oneof![
                0_u8..10_u8,
                10_u8..16_u8,
            ], HEX_HASH_LEN..=HEX_HASH_LEN),
        ) {
            let s: String = good_chars
                .iter()
                .map(|&n| {
                    if n < 10 {
                        char::from(b'0' + n)
                    } else {
                        char::from(b'a' + (n - 10))
                    }
                })
                .collect();
            prop_assert!(check_hash::<()>(&s, || ()).is_ok());
        }

        /// **`check_hash` rejects any uppercase letter at any
        /// position.** Mirrors the AML invariant; mixed-case anchors
        /// must never round-trip.
        #[test]
        fn check_hash_rejects_uppercase_anywhere(
            pos in 0_usize..HEX_HASH_LEN,
        ) {
            let mut chars: Vec<u8> = vec![b'a'; HEX_HASH_LEN];
            chars[pos] = b'A';
            let s = String::from_utf8(chars).expect("ascii is valid utf8");
            prop_assert!(check_hash::<()>(&s, || ()).is_err());
        }
    }
}
