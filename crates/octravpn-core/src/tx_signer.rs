//! Canonical Octra tx signing preimage + tx hash — byte-exact port of the
//! node's serializer. **This module is the authoritative signer** for
//! anything submitted to a real Octra node; `octra_core::tx` (the foundry
//! v1/v2 `chain_id` format) remains only for the mock-rpc/foundry harness
//! and for verifying receipts already signed under that scheme. Migrating
//! the existing call sites onto this module is tracked separately.
//!
//! Ground truth (upstream `octra-labs/lite_node`, public since 2026-08):
//!
//!   - Signing preimage: `lib/core/transaction.ml:309-326`
//!     (`serialize_for_signing`). Compact Yojson `Assoc` in this EXACT
//!     insertion order — `from`, `to_`, `amount` (string), `nonce` (int),
//!     `ou` (string), `timestamp` (float), `op_type` (string), then
//!     `encrypted_data` and `message`, each appended ONLY when present.
//!     ed25519 over the JSON text; signature base64
//!     (`transaction.ml:328-333`).
//!   - Node-side verification re-serializes the parsed tx through the
//!     same function (`node_runtime/tx_view.ml:1140-1148` →
//!     `Transaction.verify`, `transaction.ml:335-341`), so one byte of
//!     drift in our rendering = code 101 "invalid signature".
//!   - Tx hash: `transaction.ml:482-497` — a DIFFERENT, 11-field JSON
//!     (adds `signature` after `timestamp`, then `public_key` /
//!     `message` / `encrypted_data` as trailing `null`-able fields),
//!     sha256, lowercase hex. Never reuse the signing preimage for it.
//!   - Reference client: `webcli/lib/tx_builder.hpp:78-106`
//!     (`canonical_json` / `sign_transaction` / `build_tx_json`).
//!
//! **There is NO `chain_id` in the preimage.** The chain's serializer has
//! no such field — our own foundry v2 "chain_id in canonical bytes"
//! format (`octra_core::tx::to_canonical_json`) is a workspace invention
//! that a real node rejects with code 101. See
//! `docs/octra-upstream-delta-2026-08-17.md` §5.1. Replay protection on
//! the real chain comes from the per-account nonce + ±300s timestamp
//! window, not from a chain-id binding.
//!
//! Float rendering is pinned to yojson 3.0.0 (`octra_node.opam.locked:115`;
//! `yojson/lib/write.ml:90-119` `write_float`): `%.16g`, falling back to
//! `%.17g` when 16 significant digits don't round-trip, then `".0"`
//! appended when the result contains only digits/`-` (so integral floats
//! render `"1755446400.0"`, large magnitudes `"1e+21"`). String escaping
//! is yojson's (`write.ml:27-47`): short escapes for `"` `\` `\b` `\f`
//! `\n` `\r` `\t`, and `\u00XX` (lowercase hex) for remaining control
//! bytes **including 0x7F** — serde_json does not escape 0x7F, which is
//! why this module hand-writes the JSON instead of going through
//! `serde_json::to_string`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::sig::KeyPair;

// Native op_type strings accepted by the node (`transaction.ml:199-239`,
// `op_type_of_string`). An UNRECOGNIZED op_type is a hard error at parse;
// a MISSING one silently falls back to `Standard` (`transaction.ml:295-296`)
// — that silent fallback is what turned our early relay ops into bogus
// "amount must be positive" rejections, so always set one of these
// explicitly. Only the ops this workspace actually submits are listed;
// extend from the upstream match as needed.
pub const OP_STANDARD: &str = "standard";
pub const OP_CALL: &str = "call";
pub const OP_DEPLOY_CIRCLE: &str = "deploy_circle";
pub const OP_CIRCLE_CALL: &str = "circle_call";
pub const OP_CIRCLE_OUTBOX_OPEN: &str = "circle_outbox_open";
pub const OP_CIRCLE_RELAY_CLAIM: &str = "circle_relay_claim";
pub const OP_CIRCLE_RELAY_CANCEL: &str = "circle_relay_cancel";
pub const OP_CIRCLE_INGRESS_COMMIT: &str = "circle_ingress_commit";

/// A transaction in the node's own field layout (`transaction.ml:241-253`),
/// minus the signature-side fields (`signature`, `public_key`) which are
/// appended after signing and never participate in the preimage.
///
/// `amount` / `ou` are `Z.t` (arbitrary-precision, non-negative) upstream
/// and serialize as decimal strings; `u64` covers the entire OCT supply
/// (1e8 OCT × 1e6 OU = 1e14 ≪ 2^64) so we keep the workspace's existing
/// integer convention. `nonce` is an OCaml 63-bit int on the wire.
///
/// Optional fields follow the node exactly: present iff `Some` — note
/// `Some("")` and `None` produce DIFFERENT preimages (the node includes an
/// empty string if the submitted JSON carried one; webcli simply never
/// sends empty strings).
#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalTx {
    pub from: String,
    /// Recipient. Wire key is `"to_"` — trailing underscore, always.
    pub to: String,
    /// OU, integer. Rendered as a quoted decimal string.
    pub amount: u64,
    pub nonce: u64,
    /// Fee in OU, integer. Rendered as a quoted decimal string.
    pub ou: u64,
    /// Wall-clock seconds as a float. Must land within ±300s of the
    /// node's clock (`tx_view.ml:1125-1129`) or the tx is rejected 105.
    pub timestamp: f64,
    /// One of the `OP_*` constants. Empty is treated as [`OP_STANDARD`],
    /// matching webcli (`tx_builder.hpp:85`).
    pub op_type: String,
    pub encrypted_data: Option<String>,
    pub message: Option<String>,
}

impl CanonicalTx {
    /// The exact UTF-8 bytes the node verifies the ed25519 signature
    /// over — byte-for-byte `serialize_for_signing`
    /// (`transaction.ml:309-326`).
    #[must_use]
    pub fn signing_preimage(&self) -> String {
        let mut s = String::with_capacity(192);
        s.push('{');
        push_kv_str(&mut s, "from", &self.from, true);
        push_kv_str(&mut s, "to_", &self.to, false);
        push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
        push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        push_kv_str(&mut s, "op_type", op, false);
        // NO chain_id here, ever: the chain's preimage has no such field
        // (docs/octra-upstream-delta-2026-08-17.md §5.1). Optional tail,
        // in this order: encrypted_data THEN message.
        if let Some(ed) = &self.encrypted_data {
            push_kv_str(&mut s, "encrypted_data", ed, false);
        }
        if let Some(m) = &self.message {
            push_kv_str(&mut s, "message", m, false);
        }
        s.push('}');
        s
    }

    /// Sign the preimage; returns the base64-encoded 64-byte ed25519
    /// signature (`transaction.ml:328-333` encodes with `Base64.encode`).
    #[must_use]
    pub fn sign_b64(&self, kp: &KeyPair) -> String {
        B64.encode(kp.sign(self.signing_preimage().as_bytes()).0)
    }

    /// Full wire envelope for `octra_submit`: the tx fields plus
    /// `signature` and `public_key` (both base64), mirroring webcli's
    /// `build_tx_json` (`tx_builder.hpp:114-128`). The node re-parses by
    /// key name (`transaction.ml:273-307`), so envelope key ORDER and
    /// float rendering on the wire are immaterial — only the values must
    /// parse back to what we signed over, which `serde_json`'s
    /// round-trippable float output guarantees.
    #[must_use]
    pub fn signed_envelope(&self, kp: &KeyPair) -> Value {
        let mut obj = serde_json::Map::with_capacity(11);
        obj.insert("from".into(), json!(self.from));
        obj.insert("to_".into(), json!(self.to));
        obj.insert("amount".into(), json!(self.amount.to_string()));
        obj.insert("nonce".into(), json!(self.nonce));
        obj.insert("ou".into(), json!(self.ou.to_string()));
        obj.insert("timestamp".into(), json!(self.timestamp));
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        obj.insert("op_type".into(), json!(op));
        obj.insert("signature".into(), json!(self.sign_b64(kp)));
        obj.insert("public_key".into(), json!(B64.encode(kp.public.0)));
        if let Some(ed) = &self.encrypted_data {
            obj.insert("encrypted_data".into(), json!(ed));
        }
        if let Some(m) = &self.message {
            obj.insert("message".into(), json!(m));
        }
        Value::Object(obj)
    }

    /// The chain's tx hash (`transaction.ml:482-497`): sha256 (lowercase
    /// hex) of an 11-field JSON that is NOT the signing preimage —
    /// `signature` slots in between `timestamp` and `op_type`, and the
    /// three optional fields appear unconditionally at the tail as
    /// `public_key`, `message`, `encrypted_data`, rendering `null` when
    /// absent.
    #[must_use]
    pub fn tx_hash(&self, signature_b64: &str, public_key_b64: Option<&str>) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        push_kv_str(&mut s, "from", &self.from, true);
        push_kv_str(&mut s, "to_", &self.to, false);
        push_kv_str(&mut s, "amount", &self.amount.to_string(), false);
        push_kv_raw(&mut s, "nonce", &self.nonce.to_string(), false);
        push_kv_str(&mut s, "ou", &self.ou.to_string(), false);
        push_kv_raw(&mut s, "timestamp", &yojson_float(self.timestamp), false);
        push_kv_str(&mut s, "signature", signature_b64, false);
        let op = if self.op_type.is_empty() {
            OP_STANDARD
        } else {
            &self.op_type
        };
        push_kv_str(&mut s, "op_type", op, false);
        push_kv_opt(&mut s, "public_key", public_key_b64);
        push_kv_opt(&mut s, "message", self.message.as_deref());
        push_kv_opt(&mut s, "encrypted_data", self.encrypted_data.as_deref());
        s.push('}');
        hex::encode(Sha256::digest(s.as_bytes()))
    }
}

fn push_kv_raw(out: &mut String, k: &str, v: &str, first: bool) {
    if !first {
        out.push(',');
    }
    out.push('"');
    out.push_str(k);
    out.push_str("\":");
    out.push_str(v);
}

fn push_kv_str(out: &mut String, k: &str, v: &str, first: bool) {
    push_kv_raw(out, k, "\"", first);
    push_yojson_string(out, v);
    out.push('"');
}

/// `opt_json` (`transaction.ml:480`): string when present, `null` when not.
fn push_kv_opt(out: &mut String, k: &str, v: Option<&str>) {
    match v {
        Some(v) => push_kv_str(out, k, v, false),
        None => push_kv_raw(out, k, "null", false),
    }
}

/// Yojson's string-body escaping (`yojson/lib/write.ml:27-47`,
/// `write_string_body`). Byte-oriented upstream; multi-byte UTF-8 passes
/// through untouched, so char-wise iteration here is equivalent.
fn push_yojson_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Yojson escapes 0x00-0x1F AND 0x7F, lowercase hex.
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                let _ = write!(out, "\\u00{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Render a float exactly as `Yojson.Safe.to_string` does
/// (`yojson/lib/write.ml:90-119`): C `%.16g`, retried at `%.17g` when 16
/// significant digits don't parse back to the same double, with `".0"`
/// appended when the result is bare digits (`float_needs_period`). OCaml's
/// `Printf "%.16g"` delegates to the platform C library, which rounds
/// correctly (nearest, ties-to-even) — as does Rust's fixed-precision
/// formatter — so the two agree on every finite double.
#[must_use]
pub fn yojson_float(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_string();
    }
    if x.is_infinite() {
        return (if x > 0.0 { "Infinity" } else { "-Infinity" }).to_string();
    }
    let s16 = format_g(x, 16);
    let s = if s16.parse::<f64>().map(f64::to_bits) == Ok(x.to_bits()) {
        s16
    } else {
        format_g(x, 17)
    };
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        s + ".0"
    } else {
        s
    }
}

/// C `printf("%.Pg", x)` for finite `x` and `P >= 1`: round to `P`
/// significant digits; render `%e`-style when the decimal exponent `E`
/// of the rounded value falls outside `-4 <= E < P`, `%f`-style with
/// `P-1-E` fractional digits otherwise; strip trailing fractional zeros
/// (and a bare trailing point) in both styles; `%e` exponents carry a
/// sign and at least two digits.
fn format_g(x: f64, p: i32) -> String {
    debug_assert!(p >= 1);
    let sig = usize::try_from(p - 1).expect("p >= 1");
    // Learn E from the value AFTER rounding to P significant digits (a
    // carry can bump it: 9.99e5 at P=2 is "1.0e+06"). Rust's `{:.*e}`
    // is exactly that rounding.
    let e_form = format!("{x:.sig$e}");
    let e_at = e_form.rfind('e').expect("exponential form has an 'e'");
    let exp: i32 = e_form[e_at + 1..].parse().expect("exponent is an int");
    if exp < -4 || exp >= p {
        let mantissa = strip_trailing_fraction_zeros(&e_form[..e_at]);
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exp.abs())
    } else {
        let frac = usize::try_from(p - 1 - exp).expect("exp < p in this branch");
        let f_form = format!("{x:.frac$}");
        strip_trailing_fraction_zeros(&f_form).to_string()
    }
}

fn strip_trailing_fraction_zeros(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn fixture() -> CanonicalTx {
        CanonicalTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 100,
            nonce: 7,
            ou: 1000,
            timestamp: 1_755_446_400.0,
            op_type: OP_CIRCLE_RELAY_CLAIM.into(),
            encrypted_data: Some("payload".into()),
            message: Some("hi".into()),
        }
    }

    /// Golden bytes for the full preimage, optional tail included —
    /// integral timestamp MUST render with the trailing ".0" and the
    /// optional order is encrypted_data THEN message
    /// (`transaction.ml:318-325`).
    #[test]
    fn golden_preimage_bytes_full() {
        assert_eq!(
            fixture().signing_preimage(),
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"100\",\
             \"nonce\":7,\"ou\":\"1000\",\"timestamp\":1755446400.0,\
             \"op_type\":\"circle_relay_claim\",\
             \"encrypted_data\":\"payload\",\"message\":\"hi\"}"
        );
    }

    /// Golden bytes for the minimal (no optional fields) preimage with a
    /// fractional timestamp.
    #[test]
    fn golden_preimage_bytes_minimal() {
        let tx = CanonicalTx {
            from: "octFROM".into(),
            to: "octTO".into(),
            amount: 0,
            nonce: 1,
            ou: 3000,
            timestamp: 1_700_000_000.5,
            op_type: OP_STANDARD.into(),
            encrypted_data: None,
            message: None,
        };
        assert_eq!(
            tx.signing_preimage(),
            "{\"from\":\"octFROM\",\"to_\":\"octTO\",\"amount\":\"0\",\
             \"nonce\":1,\"ou\":\"3000\",\"timestamp\":1700000000.5,\
             \"op_type\":\"standard\"}"
        );
    }

    /// The chain's preimage carries NO chain_id — the foundry v2
    /// "chain_id in canonical bytes" format (`octra_core::tx`) is NOT
    /// what a real node verifies against and earns a code 101. See
    /// docs/octra-upstream-delta-2026-08-17.md §5.1 and
    /// `transaction.ml:309-326`, which has no such field to serialize.
    #[test]
    fn preimage_has_no_chain_id() {
        assert!(!fixture().signing_preimage().contains("chain_id"));
        assert!(!fixture().tx_hash("sig", Some("pk")).contains("chain_id"));
    }

    /// `Some("")` is a present-but-empty field upstream, distinct from
    /// `None` (`transaction.ml:318-325` appends whenever `Some`).
    #[test]
    fn empty_string_optional_differs_from_absent() {
        let mut tx = fixture();
        tx.encrypted_data = Some(String::new());
        tx.message = None;
        assert!(tx.signing_preimage().ends_with("\"encrypted_data\":\"\"}"));
        tx.encrypted_data = None;
        assert!(!tx.signing_preimage().contains("encrypted_data"));
    }

    /// Empty op_type falls back to "standard" like webcli
    /// (`tx_builder.hpp:85`); the node would otherwise treat a missing
    /// op_type as Standard silently, and we never send an empty string
    /// (hard parse error upstream, `transaction.ml:239`).
    #[test]
    fn empty_op_type_renders_standard() {
        let mut tx = fixture();
        tx.op_type = String::new();
        assert!(tx.signing_preimage().contains("\"op_type\":\"standard\""));
    }

    /// Escaping matches yojson (`write.ml:27-47`): short escapes, plus
    /// `\u00XX` lowercase for other control bytes INCLUDING 0x7F (which
    /// serde_json leaves raw — the reason this module hand-renders).
    #[test]
    fn yojson_string_escaping() {
        let mut out = String::new();
        push_yojson_string(&mut out, "a\"b\\c\u{08}\u{0C}\n\r\t\u{01}\u{7F}é");
        assert_eq!(out, "a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u007fé");
    }

    /// Float goldens, cross-checked against C `%.16g`/`%.17g` (glibc and
    /// CPython's correctly-rounded formatter agree) with yojson's
    /// fallback + ".0" rules applied.
    #[test]
    fn yojson_float_goldens() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1.23, "1.23"),
            (0.5, "0.5"),
            (-2.5, "-2.5"),
            (1_755_446_400.0, "1755446400.0"),
            (1_755_446_400.123, "1755446400.123"),
            (1_700_000_000.5, "1700000000.5"),
            // 0.1 + 0.2 needs all 17 digits (16 round down to 0.3).
            (0.1 + 0.2, "0.30000000000000004"),
            // 2^70 also needs the %.17g fallback.
            (2f64.powi(70), "1.1805916207174113e+21"),
            (1e-5, "1e-05"),
            (1e-4, "0.0001"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1e21, "1e+21"),
            (1e300, "1e+300"),
            (5e-324, "4.940656458412465e-324"),
            (9_007_199_254_740_992.0, "9007199254740992.0"),
            (std::f64::consts::PI, "3.141592653589793"),
        ];
        for (x, want) in cases {
            assert_eq!(yojson_float(*x), *want, "for {x:?}");
        }
    }

    #[test]
    fn yojson_float_nonfinite() {
        // yojson's non-std writer (`write.ml:105-110`); we never submit
        // these, but the renderer must not panic or lie.
        assert_eq!(yojson_float(f64::NAN), "NaN");
        assert_eq!(yojson_float(f64::INFINITY), "Infinity");
        assert_eq!(yojson_float(f64::NEG_INFINITY), "-Infinity");
    }

    /// Differential test against the platform C library's `%g` via
    /// printf(1) — the same code path OCaml's `Printf.sprintf "%.16g"`
    /// bottoms out in. Replays yojson's exact pipeline on the C output
    /// and compares whole strings. Skips silently when printf(1) is
    /// unavailable or non-conforming (the pinned goldens above still
    /// gate correctness).
    #[test]
    #[cfg(unix)]
    fn yojson_float_matches_c_printf() {
        let mut vals: Vec<f64> = vec![
            0.0,
            -0.0,
            1.0,
            0.1 + 0.2,
            1e15,
            1e16,
            1e21,
            5e-324,
            2f64.powi(70),
            1_755_446_400.0,
        ];
        // Deterministic pseudo-random doubles across the full bit space.
        let mut seed = 0x243F_6A88_85A3_08D3_u64;
        while vals.len() < 300 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let x = f64::from_bits(seed);
            if x.is_finite() {
                vals.push(x);
            }
        }
        let c_g = |p: u32| -> Option<Vec<String>> {
            // `{:e}` with no precision is Rust's shortest round-trip
            // form; strtod inside printf(1) recovers the exact double.
            let args: Vec<String> = vals.iter().map(|v| format!("{v:e}")).collect();
            let out = std::process::Command::new("printf")
                .arg(format!("%.{p}g\n"))
                .args(&args)
                .output()
                .ok()?;
            // NOT gated on exit status: BSD printf(1) exits 1 with
            // "Result too large" (strtod ERANGE) on subnormal operands
            // while still printing the correctly-rounded value. The
            // line-count check below is the real gate.
            let lines: Vec<String> = String::from_utf8(out.stdout)
                .ok()?
                .lines()
                .map(str::to_string)
                .collect();
            (lines.len() == vals.len()).then_some(lines)
        };
        let (Some(g16), Some(g17)) = (c_g(16), c_g(17)) else {
            eprintln!("printf(1) unavailable; skipping differential");
            return;
        };
        for (i, x) in vals.iter().enumerate() {
            let s = if g16[i].parse::<f64>().map(f64::to_bits) == Ok(x.to_bits()) {
                g16[i].clone()
            } else {
                g17[i].clone()
            };
            let expected = if s.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                s + ".0"
            } else {
                s
            };
            assert_eq!(
                yojson_float(*x),
                expected,
                "for {x:?} (bits {:#x})",
                x.to_bits()
            );
        }
    }

    /// Golden tx hash: sha256 over the 11-field hash JSON
    /// (`transaction.ml:482-497`), which inserts `signature` after
    /// `timestamp` and renders absent optionals as `null`.
    #[test]
    fn golden_tx_hash() {
        // sha256 of:
        // {"from":"octFROM","to_":"octTO","amount":"100","nonce":7,
        //  "ou":"1000","timestamp":1755446400.0,"signature":"SIGB64",
        //  "op_type":"circle_relay_claim","public_key":null,
        //  "message":"hi","encrypted_data":"payload"}
        assert_eq!(
            fixture().tx_hash("SIGB64", None),
            "f61cb29e9eb60e7181548ccdb00eb8f798504e9b6d211db0c2a8c5a586b5a216"
        );
    }

    /// The hash JSON is NOT the signing preimage — conflating them is the
    /// exact bug the task warns about.
    #[test]
    fn tx_hash_differs_from_sha_of_preimage() {
        let tx = fixture();
        let sha_pre = hex::encode(Sha256::digest(tx.signing_preimage().as_bytes()));
        assert_ne!(tx.tx_hash("SIGB64", None), sha_pre);
    }

    /// Sign then verify over the preimage bytes — the same check the node
    /// runs in `signature_admission` (`tx_view.ml:1140-1148`).
    #[test]
    fn sign_then_verify_preimage() {
        let kp = KeyPair::generate();
        let tx = fixture();
        let sig_b64 = tx.sign_b64(&kp);
        let sig = B64.decode(&sig_b64).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        crate::sig::verify(
            &kp.public,
            tx.signing_preimage().as_bytes(),
            &crate::sig::Signature(sig_arr),
        )
        .expect("signature must verify over the canonical preimage");
    }

    /// The wire envelope carries base64 `signature` + `public_key` and its
    /// signature verifies over the preimage.
    #[test]
    fn signed_envelope_shape_and_signature() {
        let kp = KeyPair::generate();
        let tx = fixture();
        let env = tx.signed_envelope(&kp);
        let obj = env.as_object().unwrap();
        for k in [
            "from",
            "to_",
            "amount",
            "nonce",
            "ou",
            "timestamp",
            "op_type",
            "signature",
            "public_key",
            "encrypted_data",
            "message",
        ] {
            assert!(obj.contains_key(k), "missing {k}: {env}");
        }
        assert_eq!(obj["amount"], json!("100"));
        assert_eq!(obj["ou"], json!("1000"));
        assert_eq!(obj["nonce"], json!(7));
        let sig = B64.decode(obj["signature"].as_str().unwrap()).unwrap();
        let pk = B64.decode(obj["public_key"].as_str().unwrap()).unwrap();
        assert_eq!((sig.len(), pk.len()), (64, 32));
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        crate::sig::verify(
            &kp.public,
            tx.signing_preimage().as_bytes(),
            &crate::sig::Signature(sig_arr),
        )
        .unwrap();
    }

    proptest! {
        /// Reversibility — the property yojson's writer is built around
        /// (`write.ml:101-104`): every finite double parses back to the
        /// exact same bits from our rendering.
        #[test]
        fn prop_yojson_float_round_trips(bits in any::<u64>()) {
            let x = f64::from_bits(bits);
            prop_assume!(x.is_finite());
            let s = yojson_float(x);
            let back: f64 = s.parse().unwrap();
            prop_assert_eq!(back.to_bits(), x.to_bits(), "rendered {}", s);
        }

        /// The renderer prefers 16 significant digits and only widens to
        /// 17 when forced, mirroring the upstream fallback order.
        #[test]
        fn prop_yojson_float_prefers_16_digits(bits in any::<u64>()) {
            let x = f64::from_bits(bits);
            prop_assume!(x.is_finite());
            let s16 = format_g(x, 16);
            if s16.parse::<f64>().map(f64::to_bits) == Ok(x.to_bits()) {
                let s = yojson_float(x);
                let stripped = s.strip_suffix(".0").unwrap_or(&s);
                prop_assert_eq!(stripped, s16);
            }
        }

        /// Preimage stability: same tx, same bytes — and the preimage is
        /// always parseable JSON whose timestamp survives a serde
        /// round-trip (what the node's parse-then-reserialize does).
        #[test]
        fn prop_preimage_parse_reserialize_fixpoint(
            amount in any::<u64>(),
            nonce in any::<u64>(),
            ou in any::<u64>(),
            // Wall-clock-ish range plus sub-second fractions.
            ts_ms in 0_u64..4_102_444_800_000,
            msg in proptest::option::of("[ -~]{0,32}"),
        ) {
            #[allow(clippy::cast_precision_loss)]
            let timestamp = ts_ms as f64 / 1000.0;
            let tx = CanonicalTx {
                from: "octFROM".into(),
                to: "octTO".into(),
                amount, nonce, ou, timestamp,
                op_type: OP_CIRCLE_CALL.into(),
                encrypted_data: None,
                message: msg,
            };
            let pre = tx.signing_preimage();
            prop_assert_eq!(&pre, &tx.signing_preimage());
            // The node parses our JSON then re-renders it with the same
            // writer; our rendering must be that writer's fixpoint.
            let parsed: serde_json::Value = serde_json::from_str(&pre).unwrap();
            let ts_back = parsed["timestamp"].as_f64().unwrap();
            prop_assert_eq!(ts_back.to_bits(), timestamp.to_bits());
            prop_assert_eq!(yojson_float(ts_back), yojson_float(timestamp));
        }
    }
}
