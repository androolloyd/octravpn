//! Pre-auth join tokens: a tailnet owner mints; a new device redeems
//! and self-joins without owner mediation.

use octraforge::{octra_test, ForgeCtx};
use serde_json::json;

const OWNER: &str = "octOWNER000000000000000000000000000000001";
const NEWBIE: &str = "octNEWBIE0000000000000000000000000000001";
const NEWBIE2: &str = "octNEWBIE0000000000000000000000000000002";

fn make_tailnet(forge: &mut ForgeCtx) -> String {
    forge.deploy_octravpn(100, 10);
    forge.prank(OWNER);
    forge
        .call_create_tailnet(&"ab".repeat(32), 2000)
        .expect("create")
        .event_str("TailnetCreated", "tailnet_id")
        .unwrap()
}

fn make_token(tid_hex: &str, hours_from_now: u64, nonce_byte: u8) -> Vec<serde_json::Value> {
    // Compute the future-epoch in mock terms: each accepted tx advances
    // epoch by 1 in the mock, so anything in the hundreds is "far future".
    let expiry_epoch = (hours_from_now + 1) * 1000;
    let nonce_hex = format!("{nonce_byte:02x}").repeat(32);
    // The mock doesn't verify the owner signature; pass a placeholder.
    let dummy_sig = "00".repeat(64);
    vec![
        json!(tid_hex),
        json!(expiry_epoch),
        json!(nonce_hex),
        json!(dummy_sig),
    ]
}

fn submit_redeem(
    forge: &mut ForgeCtx,
    caller: &str,
    params: &[serde_json::Value],
) -> Result<octraforge::SubmitResult, octraforge::SubmitError> {
    forge.prank(caller);
    let call = json!({
        "kind": "contract_call",
        "from": caller,
        "to": octraforge::DEFAULT_PROGRAM_ADDR,
        "method": "redeem_join_token",
        "params": params,
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    forge.submit(call)
}

octra_test!(redeem_token_adds_caller_as_member, |forge| {
    let tid = make_tailnet(&mut forge);
    let params = make_token(&tid, 24, 0xAA);
    let r = submit_redeem(&mut forge, NEWBIE, &params).expect("redeem");
    assert!(r.find_event("JoinTokenRedeemed").is_some());
    let is_member = forge
        .view("is_tailnet_member", vec![json!(tid), json!(NEWBIE)])
        .unwrap();
    assert_eq!(is_member, json!(true));
});

octra_test!(nonce_replay_is_rejected, |forge| {
    let tid = make_tailnet(&mut forge);
    let params = make_token(&tid, 24, 0xBB);
    submit_redeem(&mut forge, NEWBIE, &params).expect("first redeem");

    forge.expect_revert("nonce already redeemed");
    let r = submit_redeem(&mut forge, NEWBIE2, &params);
    assert!(r.is_ok(), "expected revert path, got {r:?}");
});

octra_test!(expired_token_is_rejected, |forge| {
    let tid = make_tailnet(&mut forge);
    // expiry = 0 — guaranteed in the past relative to current epoch.
    let nonce_hex = "cc".repeat(32);
    let params = vec![
        json!(tid),
        json!(0u64),
        json!(nonce_hex),
        json!("00".repeat(64)),
    ];
    forge.expect_revert("token expired");
    let r = submit_redeem(&mut forge, NEWBIE, &params);
    assert!(r.is_ok());
});

octra_test!(already_member_cannot_re_redeem, |forge| {
    let tid = make_tailnet(&mut forge);
    let params_a = make_token(&tid, 24, 0xDD);
    submit_redeem(&mut forge, NEWBIE, &params_a).expect("first redeem");
    // Different nonce — should still fail because NEWBIE is now a member.
    let params_b = make_token(&tid, 24, 0xEE);
    forge.expect_revert("already member");
    let r = submit_redeem(&mut forge, NEWBIE, &params_b);
    assert!(r.is_ok());
});
