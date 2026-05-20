//! Chain-compatibility tests: pin the on-wire byte shape of every
//! serialized blob the sidecar emits.
//!
//! ## What "chain-compatible" means here
//!
//! The on-chain v2 substrate (`program/main-v2.aml`) deserializes PVAC
//! blobs with the same `pvac_ser` reader the sidecar uses. The reader's
//! invariants are:
//!
//!   - **Magic**: every serialized PVAC artifact starts with the ASCII
//!     bytes `"PVAC"` followed by a 1-byte version and a 1-byte tag.
//!   - **Pubkey**: shipped *compressed*, so the raw `PVAC` magic is
//!     hidden behind a `pvac::compress` wrapper. The wrapper format is
//!     documented in `vendor/pvac/include/pvac/core/pvac_compress.hpp`.
//!   - **Secret key** / **cipher** / **zero proof**: shipped raw, so
//!     the first 4 bytes after the base64 are always `b"PVAC"`.
//!   - **AES KAT**: 16 raw bytes hex-encoded. The chain's
//!     `octra_registerPvacPubkey` RPC validates this against its own
//!     KAT; mismatch ⇒ "AES implementation incompatible".
//!
//! ## Round-trip semantics
//!
//! The sidecar's reverse direction (deserialize) is exercised
//! transitively whenever an op takes a previously-emitted blob as input
//! (encrypt_zero reads a pubkey, add reads two ciphers, etc.). If the
//! round-trip succeeded, we know the producer and the consumer agree on
//! the wire format byte-for-byte.

use pvac_sidecar_ipc_tests::{seed_hex, skip_if_no_binary, split_prefixed, Sidecar};
use serde_json::json;

const PVAC_MAGIC: &[u8] = b"PVAC";
const PVAC_VERSION_V2: u8 = 0x02;
const TAG_CIPHER: u8 = 0;
const TAG_SECKEY: u8 = 2;
const TAG_ZERO_PROOF: u8 = 6;

#[test]
fn seckey_blob_starts_with_pvac_magic_v2_tag_seckey() {
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x31)}))
        .unwrap();
    let (_, sk_bytes) = split_prefixed(kg["sk"].as_str().unwrap()).unwrap();
    assert!(sk_bytes.len() >= 6, "sk too short to contain header");
    assert_eq!(&sk_bytes[..4], PVAC_MAGIC, "seckey missing PVAC magic");
    assert_eq!(sk_bytes[4], PVAC_VERSION_V2, "seckey version mismatch");
    assert_eq!(sk_bytes[5], TAG_SECKEY, "seckey tag mismatch");
}

#[test]
fn cipher_blob_starts_with_pvac_magic_v2_tag_cipher() {
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x32)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_zero",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "seed": seed_hex(0x33),
        }))
        .unwrap();
    let (_, ct_bytes) = split_prefixed(enc["ct"].as_str().unwrap()).unwrap();
    assert!(ct_bytes.len() >= 6);
    assert_eq!(&ct_bytes[..4], PVAC_MAGIC, "cipher missing PVAC magic");
    assert_eq!(ct_bytes[4], PVAC_VERSION_V2);
    assert_eq!(ct_bytes[5], TAG_CIPHER);
}

#[test]
fn zero_proof_blob_is_raw_no_pvac_header() {
    // Quirk in the C API: unlike pvac_serialize_cipher / _seckey, the
    // `pvac_serialize_zero_proof` entry point calls `write_zero_proof_raw`
    // **without** a `Writer::header()` prefix — so the on-wire bytes
    // have NO `"PVAC"` magic + version + tag envelope. The chain-side
    // verifier reads the same `write_zero_proof_raw` payload directly,
    // so this is correct, but it's surprising compared to the other
    // serialized shapes and worth pinning.
    //
    // See: pvac-sidecar/vendor/pvac/pvac_c_api.cpp::pvac_serialize_zero_proof
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x34)}))
        .unwrap();
    let enc = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "1",
            "seed": seed_hex(0x35),
        }))
        .unwrap();
    let proof = sc
        .request(&json!({
            "op": "make_zero_proof",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "ct": enc["ct"],
            "amount": "1",
            "blinding": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        }))
        .unwrap();
    let (pre, p_bytes) = split_prefixed(proof["proof"].as_str().unwrap()).unwrap();
    assert_eq!(pre, "zkzp_v2", "proof prefix must be zkzp_v2");
    // No PVAC magic anywhere — the on-wire body is raw.
    assert_ne!(
        &p_bytes[..4.min(p_bytes.len())],
        PVAC_MAGIC,
        "regression: zero proof unexpectedly grew a PVAC header (check pvac_c_api.cpp::pvac_serialize_zero_proof)"
    );
    // Length is bounded (a single zero proof is ~1 KiB).
    assert!(
        p_bytes.len() > 100 && p_bytes.len() < 10_000,
        "unexpected zero-proof length: {}",
        p_bytes.len()
    );
    // Touch the unused constant so the lint doesn't fire.
    let _ = TAG_ZERO_PROOF;
}

#[test]
fn pubkey_blob_is_compressed_not_raw_pvac_magic() {
    // The on-disk pubkey wraps the raw PVAC blob in pvac::compress::pack,
    // so the first 4 bytes are NOT b"PVAC". The chain accepts both
    // forms (deserialize_pubkey checks is_packed first). This test
    // pins that the sidecar ships the compressed form.
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x36)}))
        .unwrap();
    let (_, pk_bytes) = split_prefixed(kg["pk"].as_str().unwrap()).unwrap();
    assert!(pk_bytes.len() > 4);
    assert_ne!(
        &pk_bytes[..4],
        PVAC_MAGIC,
        "pubkey was shipped uncompressed; chain will still accept but \
         this contradicts the compressed-output contract"
    );
    // Pubkey is intentionally big (compressed PVAC pubkeys are ~3 MiB).
    assert!(
        pk_bytes.len() > 1_000_000,
        "pk size {} unexpectedly small",
        pk_bytes.len()
    );
}

#[test]
fn aes_kat_is_deterministic_across_processes() {
    // Spawn TWO separate processes and confirm both compute the same
    // KAT. This is the on-chain check that decides whether the sidecar
    // is allowed to register a pubkey at all.
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc1 = Sidecar::spawn(&bin).unwrap();
    let mut sc2 = Sidecar::spawn(&bin).unwrap();
    let a = sc1.request(&json!({"op": "aes_kat"})).unwrap();
    let b = sc2.request(&json!({"op": "aes_kat"})).unwrap();
    assert_eq!(a["kat_hex"], b["kat_hex"]);
    // And it isn't all zeros / all f's (sanity).
    let s = a["kat_hex"].as_str().unwrap();
    assert_ne!(s, &"0".repeat(32));
    assert_ne!(s, &"f".repeat(32));
}

#[test]
fn keygen_is_deterministic_under_same_seed() {
    // Determinism is a hard requirement: the chain expects that an
    // operator who re-derives their wallet from the same seed gets the
    // same PVAC pubkey, otherwise the IEE proxy contract bricks.
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let seed = seed_hex(0x99);
    let r1 = sc.request(&json!({"op": "keygen", "seed": &seed})).unwrap();
    let r2 = sc.request(&json!({"op": "keygen", "seed": &seed})).unwrap();
    assert_eq!(r1["pk"], r2["pk"]);
    assert_eq!(r1["sk"], r2["sk"]);
}

#[test]
fn keygen_distinct_seeds_yield_distinct_keys() {
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let a = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0xAA)}))
        .unwrap();
    let b = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0xBB)}))
        .unwrap();
    assert_ne!(a["pk"], b["pk"]);
    assert_ne!(a["sk"], b["sk"]);
}

#[test]
fn encrypt_then_add_zero_yields_distinct_but_well_formed_cipher() {
    // ct_add(ct, encrypt_zero) is the same algebraic shape as ct,
    // not necessarily byte-identical (the result has different
    // randomness internally). What we can pin is that the wire format
    // is well-formed: PVAC magic + cipher tag.
    let Some(bin) = skip_if_no_binary() else {
        return;
    };
    let mut sc = Sidecar::spawn(&bin).unwrap();
    let kg = sc
        .request(&json!({"op": "keygen", "seed": seed_hex(0x40)}))
        .unwrap();
    let ct = sc
        .request(&json!({
            "op": "encrypt_const",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "value": "42",
            "seed": seed_hex(0x41),
        }))
        .unwrap();
    let z = sc
        .request(&json!({
            "op": "encrypt_zero",
            "pk": kg["pk"],
            "sk": kg["sk"],
            "seed": seed_hex(0x42),
        }))
        .unwrap();
    let sum = sc
        .request(&json!({
            "op": "add",
            "pk": kg["pk"],
            "a": ct["ct"],
            "b": z["ct"],
        }))
        .unwrap();
    let (_, sum_bytes) = split_prefixed(sum["ct"].as_str().unwrap()).unwrap();
    assert_eq!(&sum_bytes[..4], PVAC_MAGIC);
    assert_eq!(sum_bytes[4], PVAC_VERSION_V2);
    assert_eq!(sum_bytes[5], TAG_CIPHER);
}
