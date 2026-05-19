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
    if !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
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
}
