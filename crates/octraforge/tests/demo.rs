//! Demo end-to-end test exercising `octraforge` against `OctraVPN`.
//!
//! Flow: become an Octra validator, register an endpoint, create a
//! tailnet with treasury, open a session against an exit endpoint,
//! settle it, claim earnings.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use octraforge::{octra_test, ForgeCtx, SubmitError};
use octravpn_core::earnings::{self, h_generator};
use serde_json::json;

const VALIDATOR: &str = "octV1Address0000000000000000000000000001";
const OWNER: &str = "octOWNER000000000000000000000000000000001";
const CLIENT: &str = "octCLIENT00000000000000000000000000000001";

fn register_one(forge: &mut ForgeCtx) {
    forge.become_octra_validator(VALIDATOR);
    forge.prank(VALIDATOR);
    forge.expect_emit("EndpointRegistered");
    forge
        .call_register_endpoint(
            "1.2.3.4:51820",
            &"de".repeat(32),
            &"aa".repeat(32),
            "bb".repeat(32).as_str(),
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

    // After warping, the endpoint is still active because liveness is
    // delegated to the Octra protocol layer (mocked here as a static
    // membership in `octra_validators`).
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

octra_test!(non_octra_validator_cannot_register_endpoint, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(VALIDATOR);
    forge.expect_revert("not an Octra validator");
    let r = forge.call_register_endpoint(
        "1.2.3.4:51820",
        &"de".repeat(32),
        &"aa".repeat(32),
        &"bb".repeat(32),
        "eu-west",
        100,
    );
    assert!(r.is_ok(), "got: {r:?}");
});

octra_test!(full_lifecycle_endpoint_tailnet_session_claim, |forge| {
    forge.deploy_octravpn(100, 10);

    // 1. Register the exit endpoint (validator side).
    register_one(&mut forge);

    // 2. Create a tailnet with 2000 OU treasury (owner side).
    forge.prank(OWNER);
    let created = forge
        .call_create_tailnet(&"ac".repeat(32), 2000)
        .expect("create tailnet");
    let tid = created
        .event_str("TailnetCreated", "tailnet_id")
        .expect("tailnet id");

    // 3. Owner adds CLIENT as a member.
    forge.prank(OWNER);
    forge
        .call_add_member(&tid, CLIENT)
        .expect("add member");

    // 4. Owner configures the validator as a tailnet exit.
    forge.prank(OWNER);
    forge
        .call_configure_tailnet_exit(&tid, VALIDATOR)
        .expect("configure exit");

    // 5. CLIENT opens a session against the tailnet (1-hop, 1000 OU deposit).
    forge.prank(CLIENT);
    let opened = forge
        .call_open_session(&tid, &[&"aa".repeat(32)], &"bb".repeat(32), 1000)
        .expect("open session");
    let sid = opened
        .event_str("SessionOpened", "session_id")
        .expect("session id");

    // 6. Settle: bytes_used=2, single hop @ 100 price * 10000 split / 10000 = 200.
    let blind = earnings::fresh_blind();
    let blind_hex = hex::encode(earnings::scalar_to_bytes(&blind));
    forge.prank(CLIENT);
    let settled = forge
        .call_settle_session(
            &sid,
            7,
            2,
            &blind_hex,
            &[(VALIDATOR, &"11".repeat(32), 10_000)],
        )
        .expect("settle");
    assert_eq!(settled.event_u64("SessionSettled", "total_paid"), Some(200));
    assert_eq!(settled.event_u64("SessionSettled", "refund"), Some(800));

    // 7. Encrypted earnings on-chain == 200*G + blind*H.
    let earn = forge
        .view("get_encrypted_earnings", vec![json!(VALIDATOR)])
        .unwrap();
    let earn_hex = earn.as_str().unwrap();
    let scalar_200 = Scalar::from(200u64);
    let expected = &scalar_200 * RISTRETTO_BASEPOINT_TABLE + blind * h_generator();
    assert_eq!(earn_hex, hex::encode(expected.compress().to_bytes()));

    // 8. Refund returned to tailnet treasury: 2000 - 1000 + 800 = 1800.
    let tnet = forge
        .view("get_tailnet", vec![json!(tid)])
        .unwrap();
    assert_eq!(tnet.get("treasury").and_then(serde_json::Value::as_u64), Some(1800));

    // 9. Validator claims the 200 OU.
    forge.prank(VALIDATOR);
    let claimed = forge
        .call_claim_earnings(200, &blind_hex, &"ee".repeat(32))
        .expect("claim earnings");
    assert!(claimed.find_event("EarningsClaimed").is_some());

    // 10. Earnings reset to identity.
    let earn = forge
        .view("get_encrypted_earnings", vec![json!(VALIDATOR)])
        .unwrap();
    assert_eq!(
        earn.as_str().unwrap(),
        hex::encode(RistrettoPoint::identity().compress().to_bytes())
    );
});

octra_test!(expect_revert_on_bad_settle, |forge| {
    forge.deploy_octravpn(100, 10);
    register_one(&mut forge);

    // Tailnet + membership + exit configured.
    forge.prank(OWNER);
    let tid = forge
        .call_create_tailnet(&"ac".repeat(32), 1000)
        .expect("create")
        .event_str("TailnetCreated", "tailnet_id")
        .unwrap();
    forge.prank(OWNER);
    forge.call_add_member(&tid, CLIENT).expect("add member");
    forge.prank(OWNER);
    forge
        .call_configure_tailnet_exit(&tid, VALIDATOR)
        .expect("configure exit");

    forge.prank(CLIENT);
    let opened = forge
        .call_open_session(&tid, &[&"aa".repeat(32)], &"bb".repeat(32), 100)
        .expect("open session");
    let sid = opened.event_str("SessionOpened", "session_id").unwrap();

    // Settling for more than the deposit must revert with "claim exceeds escrow".
    let blind = earnings::fresh_blind();
    let blind_hex = hex::encode(earnings::scalar_to_bytes(&blind));
    forge.prank(CLIENT);
    forge.expect_revert("claim exceeds escrow");
    let res = forge.call_settle_session(
        &sid,
        1,
        100,
        &blind_hex,
        &[(VALIDATOR, &"11".repeat(32), 10_000)],
    );
    assert!(res.is_ok(), "got: {res:?}");
});

octra_test!(wrong_revert_substring_surfaces_diff, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(CLIENT);
    forge.expect_revert("definitely not the actual reason");
    let res = forge.call_settle_session(&"00".repeat(32), 1, 1, &"00".repeat(32), &[]);
    match res {
        Err(SubmitError::WrongRevert { actual, .. }) => {
            assert!(actual.contains("session not found"), "got: {actual}");
        }
        other => panic!("expected WrongRevert, got {other:?}"),
    }
});
