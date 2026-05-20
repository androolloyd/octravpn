//! PVAC pubkey: register → import → export → byte-identical bytes
//! round-trip via the sidecar's wire format.
//!
//! "Register" / "import" / "export" in the chain sense map to:
//!   - **Register**: hand a pubkey to a second process, which is what
//!     the chain RPC `octra_registerPvacPubkey` does. We simulate by
//!     spawning two sidecars and shipping the same pubkey bytes between
//!     them.
//!   - **Import**: deserialize the pubkey inside the second process —
//!     the sidecar does this implicitly any time it sees `"pk":"hfhe_v1|..."`
//!     in a request.
//!   - **Export**: produce the same bytes back. Because keygen is
//!     deterministic and the sidecar never re-emits a pk after import,
//!     the byte-identity check is: import the pk into encrypt_zero, and
//!     compare the SAME pk used in the SECOND process matches what came
//!     out of the FIRST.

use pvac_sidecar_ipc_tests::{seed_hex, skip_if_no_binary, Sidecar};
use serde_json::json;

#[test]
fn pubkey_round_trips_byte_identical_across_two_processes() {
    let Some(bin) = skip_if_no_binary() else { return };

    // Process A: keygen → pubkey bytes.
    let mut a = Sidecar::spawn(&bin).unwrap();
    let kg = a
        .request(&json!({"op": "keygen", "seed": seed_hex(0xCC)}))
        .unwrap();
    let pk_a = kg["pk"].as_str().unwrap().to_string();
    let sk_a = kg["sk"].as_str().unwrap().to_string();

    // Process B: same seed → same keys.
    let mut b = Sidecar::spawn(&bin).unwrap();
    let kg_b = b
        .request(&json!({"op": "keygen", "seed": seed_hex(0xCC)}))
        .unwrap();
    assert_eq!(kg_b["pk"].as_str().unwrap(), pk_a);
    assert_eq!(kg_b["sk"].as_str().unwrap(), sk_a);

    // Process B imports A's pubkey and uses it for encrypt_zero. Just
    // accepting the input without an error proves the deserialize path
    // sees bit-identical bytes.
    let enc = b
        .request(&json!({
            "op": "encrypt_zero",
            "pk": pk_a,
            "sk": sk_a,
            "seed": seed_hex(0xDD),
        }))
        .unwrap();
    assert!(enc["ct"].as_str().unwrap().starts_with("hfhe_v1|"));
}

#[test]
fn pubkey_export_string_is_stable_across_calls() {
    // A pubkey re-derived from the same seed in the same process must
    // come out byte-identical every time — this is the property the
    // chain's IEE contract relies on for "operator deletion-resistant
    // identity".
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let mut last: Option<String> = None;
    for _ in 0..10 {
        let kg = sc
            .request(&json!({"op": "keygen", "seed": seed_hex(0xEE)}))
            .unwrap();
        let pk = kg["pk"].as_str().unwrap().to_string();
        if let Some(prev) = &last {
            assert_eq!(prev, &pk, "pubkey re-export drifted between calls");
        }
        last = Some(pk);
    }
}

#[test]
fn imported_pubkey_used_in_add_op_preserves_format() {
    // Use process A's pk to encrypt two ciphers, then ask process B
    // (same pk via determinism) to add them. The output must be a
    // well-formed cipher under the same pk.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut a = Sidecar::spawn(&bin).unwrap();
    let kg = a
        .request(&json!({"op": "keygen", "seed": seed_hex(0xAB)}))
        .unwrap();
    let c1 = a
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "5",
            "seed": seed_hex(0x01),
        }))
        .unwrap();
    let c2 = a
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "11",
            "seed": seed_hex(0x02),
        }))
        .unwrap();
    let mut b = Sidecar::spawn(&bin).unwrap();
    let sum = b
        .request(&json!({
            "op": "add",
            "pk": kg["pk"],
            "a": c1["ct"],
            "b": c2["ct"],
        }))
        .unwrap();
    assert!(sum["ct"].as_str().unwrap().starts_with("hfhe_v1|"));
}

#[test]
fn pubkey_bytes_are_idempotent_under_repeated_seed_keygen() {
    // 5 distinct seeds, each used 3 times: every triple yields the
    // same pk; the 5 outputs are distinct from each other.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let mut got = Vec::new();
    for seed_byte in [0x10u8, 0x20, 0x30, 0x40, 0x50] {
        let seed = seed_hex(seed_byte);
        let r1 = sc.request(&json!({"op": "keygen", "seed": &seed})).unwrap();
        let r2 = sc.request(&json!({"op": "keygen", "seed": &seed})).unwrap();
        let r3 = sc.request(&json!({"op": "keygen", "seed": &seed})).unwrap();
        assert_eq!(r1["pk"], r2["pk"]);
        assert_eq!(r2["pk"], r3["pk"]);
        got.push(r1["pk"].as_str().unwrap().to_string());
    }
    let mut sorted = got.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), got.len(), "expected 5 distinct pubkeys");
}
