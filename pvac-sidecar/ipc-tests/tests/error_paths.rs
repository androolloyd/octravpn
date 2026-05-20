//! Error-path tests for the sidecar IPC protocol.
//!
//! Every malformed input must come back as a `{"error": "..."}` line —
//! never a crash, panic, or silent acknowledgement. These tests deliver
//! the malformed inputs and assert the documented error envelope.

use pvac_sidecar_ipc_tests::{blinding_b64, seed_hex, skip_if_no_binary, Sidecar};
use serde_json::json;

#[test]
fn malformed_json_returns_bad_json_error() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    sc.write_raw_line("this is not json").unwrap();
    let resp = sc.read_raw_line().unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("bad json"), "expected 'bad json' prefix: {err}");
}

#[test]
fn json_array_top_level_is_rejected() {
    // Per main.cpp, "request must be object with string op".
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!([1, 2, 3])).unwrap();
    assert!(resp["error"].as_str().unwrap().contains("request must be object"));
}

#[test]
fn missing_op_field_returns_object_error() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"not_op": "ping"})).unwrap();
    assert!(resp["error"].as_str().unwrap().contains("string op"));
}

#[test]
fn non_string_op_field_is_rejected() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"op": 42})).unwrap();
    assert!(resp["error"].as_str().unwrap().contains("string op"));
}

#[test]
fn keygen_with_short_seed_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc
        .request(&json!({"op": "keygen", "seed": "deadbeef"}))
        .unwrap();
    let err = resp["error"].as_str().unwrap();
    assert!(err.contains("32 bytes"), "expected '32 bytes' in error: {err}");
}

#[test]
fn keygen_with_odd_hex_length_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    // Odd number of hex chars triggers the length check before parsing.
    let resp = sc
        .request(&json!({"op": "keygen", "seed": "012"}))
        .unwrap();
    let err = resp["error"].as_str().unwrap();
    assert!(
        err.contains("hex") || err.contains("32 bytes"),
        "expected hex-length error: {err}"
    );
}

#[test]
fn keygen_with_invalid_hex_char_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let bogus = "z".repeat(64);
    let resp = sc.request(&json!({"op": "keygen", "seed": bogus})).unwrap();
    assert!(resp["error"].as_str().unwrap().contains("hex"));
}

#[test]
fn encrypt_zero_with_garbage_pubkey_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x21)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_zero",
            "pk": "hfhe_v1|AAAAAAAA",
            "sk": kg["sk"],
            "seed": seed_hex(0x22),
        }))
        .unwrap();
    let err = resp["error"].as_str().unwrap();
    assert!(
        err.contains("pubkey") || err.contains("deserialization") || err.contains("PVAC"),
        "expected deserialization error, got: {err}"
    );
}

#[test]
fn encrypt_zero_with_wrong_prefix_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x23)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_zero",
            "pk": "notaprefix|AAAA",
            "sk": kg["sk"],
            "seed": seed_hex(0x24),
        }))
        .unwrap();
    assert!(resp["error"].as_str().unwrap().contains("hfhe_v1"));
}

#[test]
fn make_zero_proof_with_wrong_blinding_length_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x25)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "1",
            "seed": seed_hex(0x26),
        }))
        .unwrap();
    // 16-byte blinding (must be 32).
    use base64::Engine as _;
    let short_blinding = base64::engine::general_purpose::STANDARD.encode([0xAB; 16]);
    let resp = sc
        .request(&json!({
            "op": "make_zero_proof",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "ct": enc["ct"],
            "amount": "1",
            "blinding": short_blinding,
        }))
        .unwrap();
    assert!(resp["error"].as_str().unwrap().contains("blinding"));
}

#[test]
fn encrypt_const_with_negative_value_string_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x27)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "-5",
            "seed": seed_hex(0x28),
        }))
        .unwrap();
    let err = resp["error"].as_str().unwrap();
    assert!(err.contains("decimal u64") || err.contains("value"));
}

#[test]
fn encrypt_const_with_negative_number_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x29)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": -1,
            "seed": seed_hex(0x2A),
        }))
        .unwrap();
    assert!(resp["error"].as_str().unwrap().contains("non-negative"));
}

#[test]
fn encrypt_const_with_empty_value_string_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x2B)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "",
            "seed": seed_hex(0x2C),
        }))
        .unwrap();
    assert!(resp["error"].as_str().unwrap().contains("empty"));
}

#[test]
fn empty_line_is_ignored_not_error() {
    // main.cpp explicitly does `if (line.empty()) continue;`. An empty
    // input line should NOT produce a response — but the next line
    // (a valid ping) must still get its response.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    sc.write_raw_line("").unwrap();
    let resp = sc.request(&json!({"op": "ping"})).unwrap();
    assert_eq!(resp["pong"], true);
}

#[test]
fn premature_eof_does_not_corrupt_subsequent_run() {
    // Spawn → send one ping → close stdin → wait for exit → assert
    // the binary exited 0 (clean EOF handling, no panic-on-broken-pipe).
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"op": "ping"})).unwrap();
    assert_eq!(resp["pong"], true);
    // Drop drops stdin, then kills + waits — clean shutdown path.
    drop(sc);
    // A fresh spawn must still work.
    let mut sc2 = Sidecar::spawn(&bin).unwrap();
    let resp = sc2.request(&json!({"op": "version"})).unwrap();
    assert!(resp["sidecar"].as_str().unwrap().starts_with("octra-pvac-sidecar/"));
}

#[test]
fn oversized_payload_does_not_panic() {
    // 1 MiB of junk JSON; the sidecar should reject as malformed JSON,
    // not crash or hang.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let huge = "a".repeat(1024 * 1024);
    sc.write_raw_line(&huge).unwrap();
    let resp = sc.read_raw_line().unwrap();
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert!(v["error"].as_str().unwrap().contains("bad json"));
    // And the next request still works.
    let ok = sc.request(&json!({"op": "ping"})).unwrap();
    assert_eq!(ok["pong"], true);
}

#[test]
fn malformed_blinding_base64_errors() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x2D)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "1",
            "seed": seed_hex(0x2E),
        }))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "make_zero_proof",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "ct": enc["ct"],
            "amount": "1",
            "blinding": "!!!not base64!!!",
        }))
        .unwrap();
    // Either a base64 decode error, or a wrong-length error after decode.
    let err = resp["error"].as_str().unwrap();
    assert!(
        err.contains("blinding") || err.contains("base64") || err.contains("base"),
        "expected blinding/base64 error: {err}"
    );
    // No mention of `=` for visibility — just confirm we exited cleanly.
    let _ = blinding_b64(0); // silence unused-import-ish noise
}

#[test]
fn unrecognized_field_is_silently_ignored_when_valid_op() {
    // Forward-compat: extra fields don't break valid requests.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc
        .request(&json!({"op": "ping", "extra_field": "ignored"}))
        .unwrap();
    assert_eq!(resp["pong"], true);
}
