//! Demo end-to-end test exercising `octraforge` against `OctraVPN` v1.
//!
//! Flow: bond + register an endpoint, create a tailnet with treasury,
//! configure the exit, open a session, settle (validator-only), claim
//! earnings.

use octraforge::{octra_test, ForgeCtx, SubmitError};
use octravpn_mock_rpc::PROTOCOL_FEE_BPS;
use serde_json::json;

const VALIDATOR: &str = "octV1Address0000000000000000000000000001";
const OWNER: &str = "octOWNER000000000000000000000000000000001";
const CLIENT: &str = "octCLIENT00000000000000000000000000000001";

fn register_one(forge: &mut ForgeCtx) {
    forge.become_octra_validator(VALIDATOR);
    forge.prank(VALIDATOR);
    forge.expect_emit("EndpointRegistered");
    forge
        .call_register_endpoint_simple(
            "1.2.3.4:51820",
            &"de".repeat(32),
            "eu-west",
            100,
        )
        .expect("register should succeed");
}

octra_test!(deploy_then_register, |forge| {
    let prog = forge.deploy_octravpn(100, 10);
    assert_eq!(prog, octraforge::DEFAULT_PROGRAM_ADDR);

    register_one(&mut forge);

    let active = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();
    let arr = active.as_array().unwrap();
    assert!(arr.iter().any(|v| v.as_str() == Some(VALIDATOR)));
});

octra_test!(warp_and_age_endpoint, |forge| {
    forge.deploy_octravpn(100, 10);
    register_one(&mut forge);

    let before = forge.current_epoch();
    forge.warp_epoch(before + 10);
    assert_eq!(forge.current_epoch(), before + 10);

    let active = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();
    assert!(active.as_array().unwrap().iter().any(|v| v.as_str() == Some(VALIDATOR)));
});

octra_test!(snapshot_and_revert, |forge| {
    forge.deploy_octravpn(100, 10);
    let snap = forge.snapshot();

    register_one(&mut forge);
    let active = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();
    assert_eq!(active.as_array().unwrap().len(), 1);

    assert!(forge.revert_to(snap));
    let active = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();
    assert!(active.as_array().unwrap().is_empty());
});

octra_test!(unbonded_address_cannot_register_endpoint, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(VALIDATOR);
    forge.expect_revert("must bond_endpoint first");
    let r = forge.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "eu-west",
        100,
    );
    assert!(r.is_ok(), "got: {r:?}");
});

octra_test!(full_lifecycle_endpoint_tailnet_session_claim, |forge| {
    forge.deploy_octravpn(100, 10);

    // 1. Bond + register the exit operator.
    register_one(&mut forge);

    // 2. Create a tailnet with 2000 OU treasury.
    forge.prank(OWNER);
    let created = forge
        .call_create_tailnet(&"ac".repeat(32), 2000)
        .expect("create tailnet");
    let tid = created
        .event_u64("TailnetCreated", "tailnet_id")
        .expect("tailnet id");

    // 3. Owner adds CLIENT as a member.
    forge.prank(OWNER);
    forge.call_add_member(tid, CLIENT).expect("add member");

    // 4. Owner configures the validator as a tailnet exit.
    forge.prank(OWNER);
    forge
        .call_configure_tailnet_exit(tid, VALIDATOR)
        .expect("configure exit");

    // 5. CLIENT opens a session against the configured exit, with
    //    max_pay = 1000 OU from the tailnet treasury.
    forge.prank(CLIENT);
    let opened = forge
        .call_open_session(tid, VALIDATOR, 1000)
        .expect("open session");
    let sid = opened
        .event_u64("SessionOpened", "session_id")
        .expect("session id");

    // 6. Validator-only settle: bytes_used=2 → gross=200, fee=1, net=199, refund=800.
    forge.prank(VALIDATOR);
    let settled = forge
        .call_settle_session(sid, 2)
        .expect("settle");
    assert_eq!(settled.event_u64("SessionSettled", "total_paid"), Some(200));
    assert_eq!(settled.event_u64("SessionSettled", "refund"), Some(800));

    // 7. Refund returned to tailnet treasury: 2000 - 1000 + 800 = 1800.
    let tnet = forge
        .view("get_tailnet", vec![json!(tid)])
        .unwrap();
    assert_eq!(tnet.get("treasury").and_then(serde_json::Value::as_u64), Some(1800));

    // 8. Program treasury collected the 0.5 % protocol fee = 1 OU.
    let pt = forge.view("get_program_treasury", vec![]).unwrap();
    assert_eq!(pt.as_u64(), Some(200 * PROTOCOL_FEE_BPS / 10_000));

    // 9. Validator claims the post-fee 199 OU. The mock simplifies the
    //    HFHE zero-proof to a direct equality check; the "proof" is
    //    any non-empty byte string.
    forge.prank(VALIDATOR);
    let claimed = forge
        .call_claim_earnings(199, &"00".repeat(32))
        .expect("claim earnings");
    assert!(claimed.find_event("EarningsClaimed").is_some());

    // 10. Earnings ledger reset to zero — exposed as the mock hex format.
    let earn = forge
        .view("get_encrypted_earnings", vec![json!(VALIDATOR)])
        .unwrap();
    assert_eq!(earn.as_str().unwrap(), "hfhe_v1|mock|0000000000000000");
});

octra_test!(expect_revert_on_bad_settle, |forge| {
    forge.deploy_octravpn(100, 10);
    register_one(&mut forge);

    forge.prank(OWNER);
    let tid = forge
        .call_create_tailnet(&"ac".repeat(32), 1000)
        .expect("create")
        .event_u64("TailnetCreated", "tailnet_id")
        .unwrap();
    forge.prank(OWNER);
    forge.call_add_member(tid, CLIENT).expect("add member");
    forge.prank(OWNER);
    forge
        .call_configure_tailnet_exit(tid, VALIDATOR)
        .expect("configure exit");

    forge.prank(CLIENT);
    let opened = forge
        .call_open_session(tid, VALIDATOR, 100)
        .expect("open session");
    let sid = opened.event_u64("SessionOpened", "session_id").unwrap();

    // Validator over-claims: bytes_used=2 → 200 OU > 100 OU deposit.
    forge.prank(VALIDATOR);
    forge.expect_revert("claim exceeds escrow");
    let res = forge.call_settle_session(sid, 2);
    assert!(res.is_ok(), "got: {res:?}");
});

octra_test!(wrong_revert_substring_surfaces_diff, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(CLIENT);
    forge.expect_revert("definitely not the actual reason");
    let res = forge.call_settle_session(999_999, 1);
    match res {
        Err(SubmitError::WrongRevert { actual, .. }) => {
            assert!(actual.contains("session not found"), "got: {actual}");
        }
        other => panic!("expected WrongRevert, got {other:?}"),
    }
});
