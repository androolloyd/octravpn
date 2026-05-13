//! Multi-device per identity: a wallet can attach many devices; any of
//! them can open sessions on behalf of the wallet's tailnet membership.

use octraforge::{octra_test, ForgeCtx};
use serde_json::json;

const VALIDATOR: &str = "octV1Address0000000000000000000000000001";
const WALLET: &str = "octWALLET00000000000000000000000000000001";
const DEVICE_PHONE: &str = "octDEVPHONE000000000000000000000000000001";
const DEVICE_LAPTOP: &str = "octDEVLAPTOP00000000000000000000000000001";
const OTHER_WALLET: &str = "octOTHER00000000000000000000000000000001";

fn deploy_with_validator(forge: &mut ForgeCtx) {
    forge.deploy_octravpn(100, 10);
    forge.become_octra_validator(VALIDATOR);
    forge.prank(VALIDATOR);
    forge
        .call_register_endpoint_simple(
            "1.2.3.4:51820",
            &"de".repeat(32),
            "eu-west",
            100,
        )
        .expect("register endpoint");
}

octra_test!(wallet_can_register_two_devices, |forge| {
    deploy_with_validator(&mut forge);
    forge.prank(WALLET);
    forge
        .call_register_device(DEVICE_PHONE)
        .expect("register phone");
    forge.prank(WALLET);
    forge
        .call_register_device(DEVICE_LAPTOP)
        .expect("register laptop");

    // Sanity: view says both belong to WALLET.
    let owner_phone = forge
        .view("get_device_owner", vec![json!(DEVICE_PHONE)])
        .unwrap();
    let owner_laptop = forge
        .view("get_device_owner", vec![json!(DEVICE_LAPTOP)])
        .unwrap();
    assert_eq!(owner_phone.as_str(), Some(WALLET));
    assert_eq!(owner_laptop.as_str(), Some(WALLET));
});

octra_test!(device_cannot_be_attached_to_two_wallets, |forge| {
    deploy_with_validator(&mut forge);
    forge.prank(WALLET);
    forge.call_register_device(DEVICE_PHONE).expect("first attach");

    // Re-attach to a *different* wallet should revert.
    forge.prank(OTHER_WALLET);
    forge.expect_revert("already attached");
    let r = forge.call_register_device(DEVICE_PHONE);
    assert!(r.is_ok(), "expected the mock revert path; got {r:?}");
});

octra_test!(idempotent_self_register_is_noop, |forge| {
    deploy_with_validator(&mut forge);
    forge.prank(WALLET);
    forge.call_register_device(DEVICE_PHONE).expect("first attach");
    // Same wallet re-registering is a no-op (returns Ok with no events).
    forge.prank(WALLET);
    let r = forge.call_register_device(DEVICE_PHONE).expect("noop");
    assert!(r.find_event("DeviceRegistered").is_none());
});

octra_test!(revoke_only_by_owner, |forge| {
    deploy_with_validator(&mut forge);
    forge.prank(WALLET);
    forge.call_register_device(DEVICE_PHONE).expect("attach");

    // A different wallet trying to revoke must fail.
    forge.prank(OTHER_WALLET);
    forge.expect_revert("not device owner");
    let r = forge.call_revoke_device(DEVICE_PHONE);
    assert!(r.is_ok());

    // Owner revokes; succeeds.
    forge.prank(WALLET);
    forge.call_revoke_device(DEVICE_PHONE).expect("revoke");
    let owner = forge
        .view("get_device_owner", vec![json!(DEVICE_PHONE)])
        .unwrap();
    assert_eq!(owner.as_str().unwrap_or(""), "");
});

octra_test!(device_opens_session_on_behalf_of_owner, |forge| {
    deploy_with_validator(&mut forge);

    // WALLET creates a tailnet, attaches device, and configures exit.
    forge.prank(WALLET);
    let tid = forge
        .call_create_tailnet(&"ab".repeat(32), 2000)
        .expect("create")
        .event_u64("TailnetCreated", "tailnet_id")
        .unwrap();
    forge.prank(WALLET);
    forge.call_register_device(DEVICE_PHONE).expect("attach");
    forge.prank(WALLET);
    forge
        .call_configure_tailnet_exit(tid, VALIDATOR)
        .expect("exit");

    // The DEVICE opens the session — wallet itself isn't the caller.
    forge.prank(DEVICE_PHONE);
    let r = forge.call_open_session(tid, VALIDATOR, 500);
    assert!(
        r.is_ok(),
        "device should be allowed to open on behalf of owner; got {r:?}"
    );
});

octra_test!(unattached_addr_cannot_open_session, |forge| {
    deploy_with_validator(&mut forge);
    forge.prank(WALLET);
    let tid = forge
        .call_create_tailnet(&"ab".repeat(32), 2000)
        .expect("create")
        .event_u64("TailnetCreated", "tailnet_id")
        .unwrap();
    // Stranger neither a member nor an attached device.
    forge.prank(WALLET);
    forge
        .call_configure_tailnet_exit(tid, VALIDATOR)
        .expect("exit");
    forge.prank("octRANDOM000000000000000000000000000000001");
    forge.expect_revert("not a member");
    let r = forge.call_open_session(tid, VALIDATOR, 500);
    assert!(r.is_ok());
});
