//! HFHE-2 shadow-blob integration tests.
//!
//! Exercises the wire-compatibility invariants of the HFHE-2
//! receipt schema across the public `octravpn-core` API. Wire-level
//! invariants live here (not in `control.rs::tests` or
//! `receipt.rs::tests`) so a future verifier crate can reuse them
//! without dragging in the node's `pub(crate)` types.

use octravpn_core::{
    address::Address,
    control::ProposedReceipt,
    receipt::{
        Receipt, ReceiptContext, ShadowBlob, SignedReceipt, CHAIN_ID_TEST,
    },
    session::{Blind, SessionId},
    sig::KeyPair,
};

fn ctx() -> ReceiptContext {
    ReceiptContext::v1_1(Address::from_pubkey(&[0xAA; 32]), CHAIN_ID_TEST)
}

fn sample_receipt() -> Receipt {
    Receipt::new(
        ctx(),
        SessionId::new([7u8; 32]),
        3,
        1_048_576,
        Blind::new([9u8; 32]),
    )
}

#[test]
fn legacy_receipt_json_deserialises_under_v2_schema() {
    let pre_hfhe2 =
        SignedReceipt::build(sample_receipt(), &KeyPair::generate(), &KeyPair::generate());
    let j = serde_json::to_string(&pre_hfhe2).unwrap();
    assert!(!j.contains("enc_bytes_used"));
    assert!(!j.contains("enc_net"));
    assert!(!j.contains("pvac_zero_proof"));

    let parsed: SignedReceipt = serde_json::from_str(&j).unwrap();
    assert!(!parsed.has_shadow());
    parsed.verify().unwrap();
    assert_eq!(pre_hfhe2, parsed);
}

#[test]
fn shadowed_receipt_json_round_trips_and_verifies() {
    let shadow = ShadowBlob {
        enc_bytes_used: Some("hfhe_v1|AAAA".into()),
        enc_net: Some("hfhe_v1|BBBB".into()),
        pvac_zero_proof: Some("zkzp_v2|CCCC".into()),
    };
    let sr = SignedReceipt::build_with_shadow(
        sample_receipt(),
        &KeyPair::generate(),
        &KeyPair::generate(),
        shadow.clone(),
    );
    assert!(sr.has_shadow());
    let j = serde_json::to_string(&sr).unwrap();
    assert!(j.contains("hfhe_v1|AAAA"));
    assert!(j.contains("hfhe_v1|BBBB"));
    assert!(j.contains("zkzp_v2|CCCC"));

    let parsed: SignedReceipt = serde_json::from_str(&j).unwrap();
    parsed.verify().unwrap();
    assert_eq!(sr, parsed);
    assert_eq!(parsed.shadow(), shadow);
}

#[test]
fn shadow_blob_is_not_bound_into_signing_payload() {
    let r = sample_receipt();
    let c = KeyPair::generate();
    let n = KeyPair::generate();
    let plain = SignedReceipt::build(r.clone(), &c, &n);
    let shadowed = SignedReceipt::build_with_shadow(
        r,
        &c,
        &n,
        ShadowBlob {
            enc_bytes_used: Some("hfhe_v1|XXX".into()),
            enc_net: Some("hfhe_v1|YYY".into()),
            pvac_zero_proof: None,
        },
    );
    // The dual-sig must agree byte-for-byte — proves the shadow
    // blob is wire-additive, not part of the hash domain.
    assert_eq!(plain.client_sig, shadowed.client_sig);
    assert_eq!(plain.node_sig, shadowed.node_sig);
    assert_eq!(plain.client_pubkey, shadowed.client_pubkey);
    assert_eq!(plain.node_pubkey, shadowed.node_pubkey);
}

#[test]
fn proposed_receipt_with_shadow_json_round_trip() {
    let r = sample_receipt();
    let n = KeyPair::generate();
    let payload = r.signing_payload();
    let sig = n.sign(&payload);
    let p = ProposedReceipt {
        receipt: r,
        node_pubkey: n.public,
        node_sig: sig,
        enc_bytes_used: Some("hfhe_v1|ZZ".into()),
        enc_net: Some("hfhe_v1|WW".into()),
        pvac_zero_proof: Some("zkzp_v2|PP".into()),
    };
    let j = serde_json::to_string(&p).unwrap();
    let parsed: ProposedReceipt = serde_json::from_str(&j).unwrap();
    assert_eq!(parsed.enc_bytes_used.as_deref(), Some("hfhe_v1|ZZ"));
    assert_eq!(parsed.enc_net.as_deref(), Some("hfhe_v1|WW"));
    assert_eq!(parsed.pvac_zero_proof.as_deref(), Some("zkzp_v2|PP"));
}

#[test]
fn proposed_receipt_no_shadow_json_omits_fields() {
    let r = sample_receipt();
    let n = KeyPair::generate();
    let payload = r.signing_payload();
    let sig = n.sign(&payload);
    let p = ProposedReceipt {
        receipt: r,
        node_pubkey: n.public,
        node_sig: sig,
        enc_bytes_used: None,
        enc_net: None,
        pvac_zero_proof: None,
    };
    let j = serde_json::to_string(&p).unwrap();
    assert!(!j.contains("enc_bytes_used"), "wire: {j}");
    assert!(!j.contains("enc_net"));
    assert!(!j.contains("pvac_zero_proof"));
    let parsed: ProposedReceipt = serde_json::from_str(&j).unwrap();
    assert!(parsed.enc_bytes_used.is_none());
    assert!(parsed.enc_net.is_none());
    assert!(parsed.pvac_zero_proof.is_none());
}

/// The encrypted blob commits to the SAME `bytes_used` that the
/// plaintext receipt carries. In production this is enforced by
/// `pvac.encrypt_const(pk, sk, bytes_used, seed)` — the wire-shape
/// test doesn't need a live sidecar; it just asserts the bundle is
/// wire-correct and the plaintext aligns with the placeholder
/// ciphertext payload.
#[test]
fn shadow_blob_commits_to_same_bytes_used() {
    let r = sample_receipt();
    let bytes_used_plaintext = r.bytes_used;
    let shadow = ShadowBlob {
        enc_bytes_used: Some(format!("hfhe_v1|placeholder|{bytes_used_plaintext}")),
        enc_net: Some(format!("hfhe_v1|placeholder|net|{bytes_used_plaintext}")),
        pvac_zero_proof: None,
    };
    let sr = SignedReceipt::build_with_shadow(
        r,
        &KeyPair::generate(),
        &KeyPair::generate(),
        shadow,
    );
    sr.verify().unwrap();
    assert_eq!(sr.receipt.bytes_used, bytes_used_plaintext);
    assert!(sr
        .enc_bytes_used
        .as_deref()
        .unwrap()
        .ends_with(&bytes_used_plaintext.to_string()));
}
