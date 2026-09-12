//! v2 end-to-end: drives the full Circle lifecycle against the real
//! (mock) Octra RPC.
//!
//! Currently `#[ignore]`'d because v2 entrypoint dispatch lands in
//! `octra-foundry`'s `octra-mock-rpc` as a parallel deliverable. Drop
//! the `#[ignore]` once `cargo test --test v2_lifecycle` passes in
//! octra-foundry (the test there exercises the mock surface that this
//! test reuses).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use octra_circle_sim::{AclRule, CircleConfig, CircleSim, ExitClass, MemberTag, RpcChain};
use octravpn_core::{
    address::Address,
    rpc::{next_nonce, RpcClient},
    sig::KeyPair,
    tx::sign_call,
};
use serde_json::json;
use tokio::time::sleep;

const PROGRAM: &str = "octPROGmockaddress0000000000000000000000";

async fn spawn_mock(port: u16) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let prog = PROGRAM.to_string();
    tokio::spawn(async move {
        let _ = octra_mock_rpc::serve(addr, prog).await;
    });
    sleep(Duration::from_millis(150)).await;
}

fn mock_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/rpc")
}

async fn submit(
    rpc: &RpcClient,
    kp: &KeyPair,
    from: &Address,
    method: &str,
    params: Vec<serde_json::Value>,
    value: u64,
) -> serde_json::Value {
    let bal = rpc.balance(from).await.expect("balance");
    let fee = rpc
        .recommended_fee(Some("contract_call"))
        .await
        .expect("fee")
        .recommended;
    let call = json!({
        "kind": "contract_call",
        "from": from.display(),
        "to": PROGRAM,
        "method": method,
        "params": params,
        "value": value,
        "fee": fee,
        "nonce": next_nonce(&bal),
    });
    let signed = sign_call(kp, call).expect("sign");
    let r = rpc.submit(&signed).await.expect("submit");
    rpc.transaction(&r.hash).await.expect("tx")
}

#[tokio::test]
async fn v2_full_lifecycle_against_mock() {
    spawn_mock(18301).await;
    let rpc = Arc::new(RpcClient::new(mock_url(18301)));

    // Wallets.
    let owner_kp = KeyPair::generate();
    let owner_addr = Address::from_pubkey(&owner_kp.public.0);
    let client_kp = KeyPair::generate();
    let client_addr = Address::from_pubkey(&client_kp.public.0);
    let proxy_kp = Arc::new(KeyPair::generate());
    let proxy_addr = Address::from_pubkey(&proxy_kp.public.0);
    let program_addr = Address::from_display(PROGRAM);

    // 1. Owner creates a tailnet.
    let tnet_tx = submit(
        &rpc,
        &owner_kp,
        &owner_addr,
        "create_tailnet",
        vec![json!("ab".repeat(32))],
        2000,
    )
    .await;
    let tid = tnet_tx["events"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"] == "TailnetCreated"))
        .and_then(|e| e["tailnet_id"].as_u64())
        .expect("tailnet id");

    // 2. Owner adds the client as a member.
    submit(
        &rpc,
        &owner_kp,
        &owner_addr,
        "add_member",
        vec![json!(tid), json!(client_addr.display())],
        0,
    )
    .await;

    // 3. Owner authorizes the proxy.
    submit(
        &rpc,
        &owner_kp,
        &owner_addr,
        "authorize_proxy",
        vec![json!(tid), json!(proxy_addr.display())],
        0,
    )
    .await;

    // 4. Proxy registers HFHE keys.
    submit(
        &rpc,
        &proxy_kp,
        &proxy_addr,
        "proxy_register_keys",
        vec![
            json!("hfhe_v1|".to_string() + &"fe".repeat(32)),
            json!("hfhe_v1|".to_string() + &"00".repeat(32)),
        ],
        0,
    )
    .await;

    // 5. Client opens a session.
    let open_tx = submit(
        &rpc,
        &client_kp,
        &client_addr,
        "open_session_v2",
        vec![
            json!(tid),
            json!(proxy_addr.display()),
            json!(0u64), // shared
            json!(100u64),
            json!(1000u64),
        ],
        0,
    )
    .await;
    let sid = open_tx["events"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"] == "SessionOpened"))
        .and_then(|e| e["session_id"].as_u64())
        .expect("session id");

    // 6. CircleSim picks up the session.
    let chain = Arc::new(RpcChain::new(
        rpc.clone(),
        program_addr.clone(),
        proxy_addr.clone(),
        proxy_kp.clone(),
    ));
    let cfg = CircleConfig {
        proxy_addr: proxy_addr.display().to_string(),
        wg_pubkey_hex: "de".repeat(32),
        region: "eu-west".into(),
        tailnet_ids: vec![tid],
    };
    let circle = CircleSim::new(cfg, chain);
    circle.add_rule(
        tid,
        AclRule {
            require_tags: std::collections::BTreeSet::new(),
            class: ExitClass::Shared,
            price_per_mb: 100,
        },
    );
    circle.set_member_tags(
        tid,
        client_addr.display().as_ref(),
        std::iter::once(MemberTag::new("user")),
    );

    circle.accept_session(sid).await.expect("accept");

    // 7. Traffic flows.
    circle.record_bytes(sid, 5).expect("record bytes");
    assert_eq!(circle.active_sessions(), vec![sid]);

    // 8. Operator settles claim via the proxy.
    let bytes_claimed = circle.settle_claim(sid).await.expect("settle_claim");
    assert_eq!(bytes_claimed, 5);

    // 9. Client confirms matching bytes.
    let confirm_tx = submit(
        &rpc,
        &client_kp,
        &client_addr,
        "settle_confirm_v2",
        vec![json!(sid), json!(5u64)],
        0,
    )
    .await;
    let settled = confirm_tx["events"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"] == "SessionSettled"))
        .expect("session settled event");
    // total_paid = 1500 * 100 = 150_000; subject to fee.
    let total_paid = settled["total_paid"].as_u64().expect("total_paid");
    assert!(total_paid > 0);
}
