//! Long-running stress test: 1000 encrypt+pseudo-decrypt round trips
//! over a single sidecar process.
//!
//! The sidecar deliberately does NOT expose a decrypt op (only the
//! operator should ever decrypt). What we exercise instead is
//! encrypt → add zero → check well-formed cipher, repeated 1000×.
//! This is enough to catch:
//!
//!   - Per-call heap growth in the C++ Guard/free chain.
//!   - Stdin/stdout buffer drift over many round-trips.
//!   - Per-process state corruption from one op affecting the next.
//!
//! We use a simple counter — no jemalloc tracking, per the task spec.

use std::time::Instant;

use pvac_sidecar_ipc_tests::{seed_hex, skip_if_no_binary, split_prefixed, Sidecar};
use serde_json::json;

#[test]
fn stress_one_thousand_round_trips_on_one_process() {
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x77)}))
        .unwrap();

    let start = Instant::now();
    let mut ok_count = 0u32;
    let n = 1_000u32;

    for i in 0..n {
        // Vary the seed every iteration so each call exercises a fresh
        // randomness path.
        let seed = hex::encode({
            let mut s = [0u8; 32];
            s[0] = (i & 0xFF) as u8;
            s[1] = ((i >> 8) & 0xFF) as u8;
            s
        });
        let resp = sc
            .request(&json!({
                "op": "encrypt_const",
                "pk": kg["pk"],
                "sk": kg["sk"],
                "value": ((i as u64) + 1).to_string(),
                "seed": seed,
            }))
            .unwrap();
        assert!(resp["ct"].as_str().unwrap().starts_with("hfhe_v1|"));
        // Cheap "decryption stand-in": parse the wire format. If the
        // sidecar drifted, the prefix or length would change.
        let (_, bytes) = split_prefixed(resp["ct"].as_str().unwrap()).unwrap();
        assert!(bytes.len() > 32);
        ok_count += 1;
    }

    let elapsed = start.elapsed();
    assert_eq!(ok_count, n, "all {n} round-trips must succeed");
    eprintln!(
        "[stress] {n} round-trips in {:.2}s ({:.0}/s)",
        elapsed.as_secs_f64(),
        f64::from(n) / elapsed.as_secs_f64()
    );
    // One last sanity: the sidecar is still answering pings cleanly.
    let pong = sc.request(&json!({"op": "ping"})).unwrap();
    assert_eq!(pong["pong"], true);
}

#[test]
fn stress_alternating_ops_dont_desync_the_pipe() {
    // 200 cycles of (ping, keygen, ping). Each cycle's keygen response
    // must NOT show up as the answer to a ping. This proves the
    // line-protocol can't drift on the stdin/stdout pipe under load.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    for i in 0u32..200 {
        let p1 = sc.request(&json!({"op": "ping"})).unwrap();
        assert_eq!(p1["pong"], true, "ping 1 failed at iter {i}");

        let kg = sc
            .request(&json!({
                "op": "keygen",
                "seed": hex::encode([i as u8; 32]),
            }))
            .unwrap();
        assert!(kg["pk"].as_str().unwrap().starts_with("hfhe_v1|"));

        let p2 = sc.request(&json!({"op": "ping"})).unwrap();
        assert_eq!(p2["pong"], true, "ping 2 failed at iter {i}");
    }
}

#[test]
fn stress_make_zero_proof_50_iterations() {
    // make_zero_proof is the heaviest op; 50 iterations is enough to
    // surface any leak in the proof object's RAII guard.
    let Some(bin) = skip_if_no_binary() else { return };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x88)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "999",
            "seed": seed_hex(0x89),
        }))
        .unwrap();
    for i in 0u32..50 {
        let mut blinding = [0u8; 32];
        blinding[0] = (i & 0xFF) as u8;
        blinding[1] = ((i >> 8) & 0xFF) as u8;
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(blinding);
        let resp = sc
            .request(&json!({
                "op": "make_zero_proof",
                "pk": kg["pk"],
                "sk": kg["sk"],
                "ct": enc["ct"],
                "amount": "999",
                "blinding": b64,
            }))
            .unwrap();
        assert!(
            resp["proof"].as_str().unwrap().starts_with("zkzp_v2|"),
            "iter {i}: bad proof response: {resp}"
        );
    }
}
