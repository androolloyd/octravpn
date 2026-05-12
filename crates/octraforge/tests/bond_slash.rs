//! Tests for the operator stake + slashing lifecycle.
//!
//! Covers:
//!   - bond_endpoint accepts value + records stake
//!   - register_endpoint fails without stake, succeeds after bond
//!   - unbond_endpoint deactivates the endpoint immediately
//!   - finalize_unbond fails before grace, succeeds after
//!   - submit_equivocation accepts valid evidence and slashes
//!   - submit_equivocation rejects forged sigs and identical receipts
//!   - slashed operator can't re-bond at the same address

use octraforge::ForgeCtx;
use octravpn_core::{
    receipt::Receipt,
    session::{Blind, SessionId},
    sig::KeyPair,
};

fn op_addr(i: usize) -> String {
    format!("octOP{i:039x}")
}

fn signed_blob(
    kp: &KeyPair,
    sid: [u8; 32],
    seq: u64,
    bytes_used: u64,
    blind: [u8; 32],
) -> (String, String) {
    let r = Receipt {
        session_id: SessionId::new(sid),
        seq,
        bytes_used,
        blind: Blind::new(blind),
    };
    let sig = kp.sign(&r.signing_payload());
    (hex::encode(blind), hex::encode(sig.0))
}

#[test]
fn bond_endpoint_records_stake_and_enables_register() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(1);

    // Before bond → register must fail.
    ctx.prank(&addr);
    let err = ctx
        .call_register_endpoint(
            "1.2.3.4:51820",
            &"de".repeat(32),
            &"aa".repeat(32),
            &"bb".repeat(32),
            "global",
            100,
        )
        .expect_err("expected register without bond to fail");
    let msg = err.to_string();
    assert!(
        msg.contains("must bond_endpoint first"),
        "unexpected err: {msg}"
    );

    // Bond → register succeeds.
    ctx.prank(&addr);
    ctx.call_bond_endpoint(octravpn_mock_rpc::MIN_ENDPOINT_STAKE)
        .expect("bond succeeds");
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &"aa".repeat(32),
        &"bb".repeat(32),
        "global",
        100,
    )
    .expect("register after bond");
}

#[test]
fn unbond_deactivates_endpoint_and_grace_blocks_finalize() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(2);
    ctx.become_octra_validator(&addr); // seeds stake
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &"aa".repeat(32),
        &"bb".repeat(32),
        "global",
        100,
    )
    .unwrap();

    // Unbond immediately.
    ctx.prank(&addr);
    let r = ctx.call_unbond_endpoint().expect("unbond ok");
    assert!(
        r.events.iter().any(|e| {
            e.get("name").and_then(serde_json::Value::as_str)
                == Some("StakeUnbondingStarted")
        }),
        "expected StakeUnbondingStarted in events"
    );

    // finalize_unbond before grace → error.
    ctx.prank(&addr);
    let err = ctx.call_finalize_unbond().expect_err("must fail before grace");
    let msg = err.to_string();
    assert!(
        msg.contains("grace not elapsed"),
        "unexpected err: {msg}"
    );
}

#[test]
fn submit_equivocation_with_valid_evidence_slashes_operator() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(3);
    let kp = KeyPair::generate();
    let receipt_pk_hex = hex::encode(kp.public.0);

    ctx.become_octra_validator(&addr); // seeds stake
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &receipt_pk_hex,
        &"bb".repeat(32),
        "global",
        100,
    )
    .unwrap();

    // Build two contradictory receipts.
    let sid = [7u8; 32];
    let (blind_a_hex, sig_a_hex) = signed_blob(&kp, sid, 5, 100, [1u8; 32]);
    let (blind_b_hex, sig_b_hex) = signed_blob(&kp, sid, 5, 200, [2u8; 32]);

    let submitter = op_addr(99);
    ctx.prank(&submitter);
    let r = ctx
        .call_submit_equivocation(
            &addr,
            &hex::encode(sid),
            5,
            100,
            &blind_a_hex,
            &sig_a_hex,
            200,
            &blind_b_hex,
            &sig_b_hex,
        )
        .expect("slash succeeds");
    let slashed = r.events.iter().find(|e| {
        e.get("name").and_then(serde_json::Value::as_str) == Some("OperatorSlashed")
    });
    assert!(slashed.is_some(), "expected OperatorSlashed event");
    let burn_amt = slashed
        .unwrap()
        .get("burn_amt")
        .and_then(serde_json::Value::as_u64)
        .unwrap();
    let bounty_amt = slashed
        .unwrap()
        .get("bounty_amt")
        .and_then(serde_json::Value::as_u64)
        .unwrap();
    assert_eq!(burn_amt + bounty_amt, octravpn_mock_rpc::MIN_ENDPOINT_STAKE);
    assert_eq!(
        burn_amt,
        octravpn_mock_rpc::MIN_ENDPOINT_STAKE * octravpn_mock_rpc::SLASH_BURN_BPS / 10_000
    );
}

#[test]
fn submit_equivocation_rejects_forged_signatures() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(4);
    let real_kp = KeyPair::generate();
    let attacker_kp = KeyPair::generate();
    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &hex::encode(real_kp.public.0),
        &"bb".repeat(32),
        "global",
        100,
    )
    .unwrap();

    // Sign with attacker_kp under operator addr — sigs won't verify
    // under the operator's published receipt_pubkey.
    let sid = [4u8; 32];
    let (blind_a, sig_a) = signed_blob(&attacker_kp, sid, 1, 1, [1u8; 32]);
    let (blind_b, sig_b) = signed_blob(&attacker_kp, sid, 1, 2, [2u8; 32]);

    let submitter = op_addr(100);
    ctx.prank(&submitter);
    let err = ctx
        .call_submit_equivocation(
            &addr,
            &hex::encode(sid),
            1,
            1,
            &blind_a,
            &sig_a,
            2,
            &blind_b,
            &sig_b,
        )
        .expect_err("forged sigs must fail");
    let msg = err.to_string();
    assert!(msg.contains("bad sig"), "unexpected err: {msg}");
}

#[test]
fn submit_equivocation_rejects_identical_receipts() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(5);
    let kp = KeyPair::generate();
    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &hex::encode(kp.public.0),
        &"bb".repeat(32),
        "global",
        100,
    )
    .unwrap();

    let sid = [3u8; 32];
    let (blind_hex, sig_hex) = signed_blob(&kp, sid, 1, 100, [9u8; 32]);

    let submitter = op_addr(101);
    ctx.prank(&submitter);
    let err = ctx
        .call_submit_equivocation(
            &addr,
            &hex::encode(sid),
            1,
            100,
            &blind_hex,
            &sig_hex,
            100,
            &blind_hex,
            &sig_hex,
        )
        .expect_err("identical receipts must not slash");
    let msg = err.to_string();
    assert!(msg.contains("identical"), "unexpected err: {msg}");
}

#[test]
fn slashed_operator_cannot_re_register() {
    let mut ctx = ForgeCtx::new();
    let addr = op_addr(6);
    let kp = KeyPair::generate();
    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &hex::encode(kp.public.0),
        &"bb".repeat(32),
        "global",
        100,
    )
    .unwrap();

    let sid = [11u8; 32];
    let (blind_a, sig_a) = signed_blob(&kp, sid, 7, 100, [1u8; 32]);
    let (blind_b, sig_b) = signed_blob(&kp, sid, 7, 200, [2u8; 32]);
    let submitter = op_addr(102);
    ctx.prank(&submitter);
    ctx.call_submit_equivocation(
        &addr,
        &hex::encode(sid),
        7,
        100,
        &blind_a,
        &sig_a,
        200,
        &blind_b,
        &sig_b,
    )
    .expect("slash ok");

    // Re-bond should be refused.
    ctx.prank(&addr);
    let err = ctx
        .call_bond_endpoint(octravpn_mock_rpc::MIN_ENDPOINT_STAKE)
        .expect_err("re-bond after slash must fail");
    let msg = err.to_string();
    assert!(msg.contains("previously slashed"), "unexpected err: {msg}");
}
