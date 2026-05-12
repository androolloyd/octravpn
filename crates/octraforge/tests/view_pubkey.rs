//! Self-published view-pubkey registry on chain.
//!
//! The OctraVPN program lets every wallet publish its X25519 view
//! pubkey via `set_view_pubkey`. Senders read `get_view_pubkey` to
//! find a recipient's tag-derivation key. This removes the need for
//! Octra to expose an `octra_viewPubkey` RPC.

use octraforge::{octra_test, ForgeCtx};
use serde_json::json;

const ALICE: &str = "octALICE000000000000000000000000000000001";
const BOB: &str = "octBOB000000000000000000000000000000000001";

octra_test!(publish_then_read_view_pubkey, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(ALICE);
    let alice_vp = "de".repeat(32);
    let r = forge
        .call_set_view_pubkey(&alice_vp)
        .expect("set_view_pubkey");
    assert!(r.find_event("ViewPubkeyPublished").is_some());

    let stored = forge
        .view("get_view_pubkey", vec![json!(ALICE)])
        .unwrap();
    assert_eq!(stored.as_str(), Some(alice_vp.as_str()));

    // Unset for Bob.
    let bob_vp = forge.view("get_view_pubkey", vec![json!(BOB)]).unwrap();
    assert_eq!(bob_vp.as_str().unwrap_or(""), "");
});

octra_test!(republish_overwrites, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(ALICE);
    forge.call_set_view_pubkey(&"aa".repeat(32)).unwrap();
    forge.prank(ALICE);
    forge.call_set_view_pubkey(&"bb".repeat(32)).unwrap();
    let stored = forge.view("get_view_pubkey", vec![json!(ALICE)]).unwrap();
    assert_eq!(stored.as_str().unwrap(), "bb".repeat(32));
});

octra_test!(non_32B_pubkey_is_rejected, |forge| {
    forge.deploy_octravpn(100, 10);
    forge.prank(ALICE);
    forge.expect_revert("view pubkey 32B");
    let r = forge.call_set_view_pubkey(&"ab".repeat(15)); // 15B (too short)
    assert!(r.is_ok());
});
