//! v2 model lifecycle with signed HTTP submissions and explicit inclusion.
//! Named events below come from the internal mock model; money/VM parity
//! is validated separately against the native node.

use std::sync::Arc;

use octra_circle_sim::{AclRule, CircleConfig, CircleSim, ExitClass, MemberTag, RpcChain};
use octravpn_core::{
    address::Address,
    rpc::{next_nonce, RpcClient},
    sig::KeyPair,
    tx_signer::sign_call_canonical,
};
use serde_json::json;

const PROGRAM: &str = "octPROGmockaddress0000000000000000000000";

async fn spawn_mock(port: u16, program: &str) -> octra_mock_rpc::AppState {
    let app = octra_mock_rpc::AppState {
        state: Arc::new(parking_lot::RwLock::new(octra_mock_rpc::ChainState {
            epoch: 1,
            ..Default::default()
        })),
        program_addr: program.to_string(),
        expected_chain_id: None,
    };
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let router = octra_mock_rpc::build_router(app.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    app
}
async fn model_events(
    app: &octra_mock_rpc::AppState,
    rpc: &RpcClient,
    hash: &str,
) -> serde_json::Value {
    octra_mock_rpc::advance_epoch(app);
    let tx = rpc.transaction(hash).await.expect("confirmed transaction");
    assert_eq!(tx["status"], "confirmed", "{tx}");
    assert!(
        tx.get("events").is_none(),
        "transaction view must not fabricate events"
    );
    let receipt = rpc
        .raw_call("contract_receipt", json!([hash]))
        .await
        .expect("execution receipt");
    assert_eq!(receipt["success"], true, "{receipt}");
    // Named records are the model's Rust test API, not the node wire payload.
    serde_json::Value::Array(app.state.read().txs[hash].events.clone())
}

fn mock_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/rpc")
}

async fn submit(
    app: &octra_mock_rpc::AppState,
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
            "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock before Unix epoch").as_secs_f64(),
        "from": from.display(),
        "to": PROGRAM,
        "method": method,
        "params": params,
        "value": value,
        "fee": fee,
        "nonce": next_nonce(&bal),
    });
    let signed = sign_call_canonical(kp, &call).expect("sign");
    let r = rpc.submit(&signed).await.expect("submit");
    model_events(app, rpc, &r.hash).await
}

#[tokio::test]
async fn v2_full_lifecycle_against_mock() {
    let app = spawn_mock(18301, PROGRAM).await;
    let rpc = Arc::new(RpcClient::new(mock_url(18301)));

    // Wallets.
    let owner_kp = KeyPair::generate();
    let owner_addr = Address::from_pubkey(&owner_kp.public.0);
    let client_kp = KeyPair::generate();
    let client_addr = Address::from_pubkey(&client_kp.public.0);
    let proxy_kp = Arc::new(KeyPair::generate());
    let proxy_addr = Address::from_pubkey(&proxy_kp.public.0);
    let program_addr = Address::from_display(PROGRAM);

    for kp in [&owner_kp, &client_kp, proxy_kp.as_ref()] {
        app.fund(
            Address::from_pubkey(&kp.public.0).display(),
            1_000_000_000,
            Some(octravpn_core::b64::encode(kp.public.0)),
        );
    }

    // 1. Owner creates a tailnet.
    let tnet_tx = submit(
        &app,
        &rpc,
        &owner_kp,
        &owner_addr,
        "create_tailnet",
        vec![json!("ab".repeat(32))],
        2000,
    )
    .await;
    let tid = tnet_tx
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"] == "TailnetCreated"))
        .and_then(|e| e["tailnet_id"].as_u64())
        .expect("tailnet id");

    // 2. Owner adds the client as a member.
    submit(
        &app,
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
        &app,
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
        &app,
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
        &app,
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
    let sid = open_tx
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
        &app,
        &rpc,
        &client_kp,
        &client_addr,
        "settle_confirm_v2",
        vec![json!(sid), json!(5u64)],
        0,
    )
    .await;
    let settled = confirm_tx
        .as_array()
        .and_then(|a| a.iter().find(|e| e["name"] == "SessionSettled"))
        .expect("session settled event");
    // total_paid = 5 * 100 = 500; paid in full to the operator.
    let total_paid = settled["total_paid"].as_u64().expect("total_paid");
    assert!(total_paid > 0);
}
