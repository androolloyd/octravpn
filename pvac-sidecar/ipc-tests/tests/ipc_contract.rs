//! JSON IPC contract round-trip tests.
//!
//! For every documented op (`ping`, `version`, `aes_kat`, `keygen`,
//! `encrypt_zero`, `encrypt_const`, `make_zero_proof`, `add`), assert
//! that:
//!
//!   1. A request constructed per the README parses cleanly.
//!   2. The response shape matches the documented schema (right field
//!      names, right value types, right prefix tags on the blob).
//!
//! These tests don't validate the cryptographic content — only the
//! wire protocol's structure.

use pvac_sidecar_ipc_tests::{
    blinding_b64, seed_hex, sidecar_binary, skip_if_no_binary, split_prefixed, Sidecar,
};
use serde_json::json;

#[test]
fn ping_returns_pong_true() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"op": "ping"})).unwrap();
    assert_eq!(resp["pong"], true);
    // No spurious fields.
    let obj = resp.as_object().unwrap();
    assert_eq!(obj.len(), 1, "ping response has stray fields: {resp}");
}

#[test]
fn version_returns_sidecar_identity_string() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"op": "version"})).unwrap();
    let s = resp["sidecar"].as_str().unwrap();
    assert!(s.starts_with("octra-pvac-sidecar/"), "got: {s}");
}

#[test]
fn aes_kat_returns_32_char_hex() {
    // The aes_kat op is what `octra_registerPvacPubkey` checks on chain;
    // this is the chain-compatibility ground truth — see
    // `pvac-sidecar/src/main.cpp::aes_kat`.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc.request(&json!({"op": "aes_kat"})).unwrap();
    let kat = resp["kat_hex"].as_str().unwrap();
    assert_eq!(kat.len(), 32, "aes_kat hex length wrong: {kat}");
    assert!(kat.chars().all(|c| c.is_ascii_hexdigit()), "non-hex chars: {kat}");
    // Determinism: a second call returns the same hex.
    let resp2 = sc.request(&json!({"op": "aes_kat"})).unwrap();
    assert_eq!(resp2["kat_hex"], kat);
}

#[test]
fn keygen_returns_hfhe_v1_pk_and_sk() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x01)}))
        .unwrap();
    let pk = resp["pk"].as_str().unwrap();
    let sk = resp["sk"].as_str().unwrap();
    assert!(pk.starts_with("hfhe_v1|"));
    assert!(sk.starts_with("hfhe_v1|"));
    // Base64 portion must decode cleanly.
    let (pk_pre, pk_bytes) = split_prefixed(pk).unwrap();
    let (sk_pre, sk_bytes) = split_prefixed(sk).unwrap();
    assert_eq!(pk_pre, "hfhe_v1");
    assert_eq!(sk_pre, "hfhe_v1");
    // Reality check: pubkey is the big compressed blob, sk is much
    // smaller. Don't pin exact sizes (they're crypto-impl-defined) but
    // pk should be at least a few KiB and sk at most a few KiB.
    assert!(pk_bytes.len() > 10_000, "pk unexpectedly small: {}", pk_bytes.len());
    assert!(sk_bytes.len() < 10_000, "sk unexpectedly large: {}", sk_bytes.len());
}

#[test]
fn keygen_response_contains_no_extra_fields() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x42)}))
        .unwrap();
    let obj = resp.as_object().unwrap();
    assert_eq!(obj.len(), 2, "keygen response has stray fields: {resp:?}");
    assert!(obj.contains_key("pk"));
    assert!(obj.contains_key("sk"));
}

#[test]
fn encrypt_zero_returns_ct_with_hfhe_v1_prefix() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x02)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_zero",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "seed": seed_hex(0x77),
        }))
        .unwrap();
    let ct = resp["ct"].as_str().unwrap();
    assert!(ct.starts_with("hfhe_v1|"));
    let (_, bytes) = split_prefixed(ct).unwrap();
    assert!(bytes.len() > 32);
}

#[test]
fn encrypt_const_accepts_decimal_string_value() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x03)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "1000000000",
            "seed": seed_hex(0x55),
        }))
        .unwrap();
    let ct = resp["ct"].as_str().unwrap();
    assert!(ct.starts_with("hfhe_v1|"));
}

#[test]
fn encrypt_const_accepts_unsigned_number_too() {
    // The README documents string-only to dodge JS 53-bit limits, but
    // the sidecar also accepts JSON numbers for u64-safe values.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x04)}))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": 100u64,
            "seed": seed_hex(0x44),
        }))
        .unwrap();
    assert!(resp["ct"].as_str().unwrap().starts_with("hfhe_v1|"));
}

#[test]
fn make_zero_proof_returns_zkzp_v2_blob() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x05)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "12345",
            "seed": seed_hex(0x66),
        }))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "make_zero_proof",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "ct": enc["ct"],
            "amount": "12345",
            "blinding": blinding_b64(0xAB),
        }))
        .unwrap();
    let proof = resp["proof"].as_str().unwrap();
    assert!(proof.starts_with("zkzp_v2|"), "got prefix: {proof}");
    let (pre, bytes) = split_prefixed(proof).unwrap();
    assert_eq!(pre, "zkzp_v2");
    assert!(bytes.len() > 32);
}

#[test]
fn add_homomorphic_returns_ct_blob() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x06)}))
        .unwrap();
    let a = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "7",
            "seed": seed_hex(0x11),
        }))
        .unwrap();
    let b = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "13",
            "seed": seed_hex(0x12),
        }))
        .unwrap();
    let resp = sc
        .request(&json!({
            "op": "add",
            "pk": kg["pk"],
            "a": a["ct"],
            "b": b["ct"],
        }))
        .unwrap();
    let ct = resp["ct"].as_str().unwrap();
    assert!(ct.starts_with("hfhe_v1|"));
}

#[test]
fn sidecar_handles_back_to_back_round_trips() {
    // A tight loop of mixed ops on one process — proves the
    // line-buffered loop doesn't desync.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x07)}))
        .unwrap();
    for i in 0u8..10 {
        let ping = sc.request(&json!({"op": "ping"})).unwrap();
        assert_eq!(ping["pong"], true);
        let v = sc
            .request(&json!({
                "op": "encrypt_const",
                "pk": kg["pk"],
                "sk": kg["sk"],
                "value": (i as u64 + 1).to_string(),
                "seed": seed_hex(0x10 + i),
            }))
            .unwrap();
        assert!(v["ct"].as_str().unwrap().starts_with("hfhe_v1|"));
        let kat = sc.request(&json!({"op": "aes_kat"})).unwrap();
        assert_eq!(kat["kat_hex"].as_str().unwrap().len(), 32);
    }
}

#[test]
fn unknown_op_returns_error_object() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let resp = sc
        .request(&json!({"op": "definitely-not-a-real-op"}))
        .unwrap();
    let err = resp["error"].as_str().unwrap();
    assert!(err.contains("unknown op"), "expected 'unknown op' in: {err}");
}

#[test]
fn binary_discovery_smoke_test() {
    // Sanity: in CI/dev, the discovery function returns a real path or
    // None — never a malformed PathBuf.
    if let Some(p) = sidecar_binary() {
        assert!(p.is_absolute() || p.exists());
        assert!(p.is_file());
    }
}
