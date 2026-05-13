//! Tests for the operator stake + governance-slash lifecycle (v1).
//!
//! In-AML cryptographic equivocation slashing was deferred to v1.1
//! pending Octra's `verify_ed25519` host call. v1 uses governance
//! slashing: the program owner submits a slash backed by off-chain
//! evidence verification (`octravpn slash-evidence verify`).

use octraforge::ForgeCtx;

fn op_addr(i: usize) -> String {
    format!("octOP{i:039x}")
}

const OWNER: &str = "octGOVOWNER000000000000000000000000000001";

fn fresh_ctx_with_owner() -> ForgeCtx {
    let mut ctx = ForgeCtx::new();
    ctx.set_program_owner(OWNER);
    ctx
}

#[test]
fn bond_endpoint_records_stake_and_enables_register() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(1);

    // Before bond → register must fail.
    ctx.prank(&addr);
    let err = ctx
        .call_register_endpoint_simple(
            "1.2.3.4:51820",
            &"de".repeat(32),
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
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .expect("register after bond");
}

#[test]
fn unbond_deactivates_endpoint_and_grace_blocks_finalize() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(2);
    ctx.become_octra_validator(&addr); // seeds stake
    ctx.prank(&addr);
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .unwrap();

    ctx.prank(&addr);
    let r = ctx.call_unbond_endpoint().expect("unbond ok");
    assert!(
        r.events.iter().any(|e| {
            e.get("name").and_then(serde_json::Value::as_str)
                == Some("StakeUnbondingStarted")
        }),
        "expected StakeUnbondingStarted in events"
    );

    ctx.prank(&addr);
    let err = ctx.call_finalize_unbond().expect_err("must fail before grace");
    let msg = err.to_string();
    assert!(msg.contains("grace not elapsed"), "unexpected err: {msg}");
}

#[test]
fn gov_slash_burns_stake_and_pays_bounty() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(3);

    ctx.become_octra_validator(&addr); // seeds stake
    ctx.prank(&addr);
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .unwrap();

    ctx.prank(OWNER);
    let r = ctx
        .call_gov_slash_operator(&addr, "off-chain equivocation evidence #123")
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

    // Slashed operator's endpoint is now inactive.
    let slashed_view = ctx
        .view("is_endpoint_slashed", vec![serde_json::json!(addr)])
        .unwrap();
    assert_eq!(slashed_view, serde_json::Value::Bool(true));
}

#[test]
fn non_owner_cannot_gov_slash() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(4);
    let imposter = op_addr(5);

    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .unwrap();

    ctx.prank(&imposter);
    let err = ctx
        .call_gov_slash_operator(&addr, "trying to slash")
        .expect_err("non-owner slash must fail");
    let msg = err.to_string();
    assert!(msg.contains("not owner"), "unexpected err: {msg}");
}

#[test]
fn slashed_operator_cannot_re_register() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(6);

    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .unwrap();

    ctx.prank(OWNER);
    ctx.call_gov_slash_operator(&addr, "evidence-123")
        .expect("slash ok");

    // Re-bond must be refused.
    ctx.prank(&addr);
    let err = ctx
        .call_bond_endpoint(octravpn_mock_rpc::MIN_ENDPOINT_STAKE)
        .expect_err("re-bond after slash must fail");
    let msg = err.to_string();
    assert!(msg.contains("previously slashed"), "unexpected err: {msg}");
}

#[test]
fn cannot_slash_twice() {
    let mut ctx = fresh_ctx_with_owner();
    let addr = op_addr(7);

    ctx.become_octra_validator(&addr);
    ctx.prank(&addr);
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "global",
        100,
    )
    .unwrap();

    ctx.prank(OWNER);
    ctx.call_gov_slash_operator(&addr, "first").expect("first slash");
    ctx.prank(OWNER);
    let err = ctx
        .call_gov_slash_operator(&addr, "second")
        .expect_err("second slash must fail");
    let msg = err.to_string();
    assert!(msg.contains("already slashed"), "unexpected err: {msg}");
}
