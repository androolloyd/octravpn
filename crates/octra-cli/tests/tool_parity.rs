//! anvil ↔ cast ↔ forge cross-tool parity.
//!
//! These tests verify that all four entry points into the mock chain
//! produce identical results when given the same input:
//!
//!   - `octraforge::ForgeCtx` (in-process, no IO)
//!   - `octra_cli::rpc_client` against `inprocess://` (in-process via
//!      the CLI's rpc shim)
//!   - HTTP `octra_mock_rpc::serve` (the same code anvil runs)
//!
//! Drift between any of these is a behavioral bug — `cast call` users
//! should see the same answer as `forge` test runners.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use octraforge::ForgeCtx;
use serde_json::json;
use tokio::time::sleep;

async fn spawn_anvil(port: u16, prog: &str) -> Arc<()> {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let p = prog.to_string();
    tokio::spawn(async move {
        let _ = octra_mock_rpc::serve(addr, p).await;
    });
    sleep(Duration::from_millis(150)).await;
    Arc::new(())
}

fn http_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/rpc")
}

/// `forge` (in-process) and `cast` against `inprocess://` must return
/// the same result for a fresh-chain view call.
#[test]
fn forge_view_matches_cast_inprocess_view() {
    let forge = ForgeCtx::with_program("octPROG");
    let forge_view = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();

    let ep = octra_cli::rpc_client::endpoint_from_url("inprocess://octPROG");
    let cast_view = octra_cli::rpc_client::call(
        &ep,
        "contract_call",
        json!(["octPROG", "list_active_endpoints", [0u64, 50u64]]),
    )
    .unwrap();

    assert_eq!(forge_view, cast_view, "forge view vs cast view drift");
}

/// `forge submit` and `cast send` against inprocess must produce the
/// same hash+events for the same tx.
#[test]
fn forge_submit_matches_cast_inprocess_submit() {
    // Pre-seed an Octra validator so register_endpoint will succeed
    // identically on both paths.
    let mut forge = ForgeCtx::with_program("octPROG");
    forge.become_octra_validator("octV");

    let tx = json!({
        "kind": "contract_call",
        "from": "octV",
        "to": "octPROG",
        "method": "register_endpoint",
        "params": [
            "1.2.3.4:51820",
            "de".repeat(32),
            "aa".repeat(32),
            "bb".repeat(32),
            "eu-west",
            100u64,
        ],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });

    let forge_result = forge.submit(tx.clone()).unwrap();
    let forge_event_names: Vec<String> = forge_result
        .events
        .iter()
        .filter_map(|e| e.get("name").and_then(|x| x.as_str()).map(String::from))
        .collect();

    // Fresh in-process backend for the cast path so state doesn't carry over.
    let mut forge2 = ForgeCtx::with_program("octPROG");
    forge2.become_octra_validator("octV");
    let ep = octra_cli::rpc_client::endpoint_from_url("inprocess://octPROG");
    let _ = octra_cli::rpc_client::call(
        &ep,
        "octra_test_grantValidator",
        json!(["octV"]),
    );
    // Seed operator stake on this fresh AppState so register_endpoint
    // passes the bond check on the cast path too.
    let _ = octra_cli::rpc_client::call(
        &ep,
        "octra_test_bondEndpoint",
        json!(["octV"]),
    );
    let cast_submit = octra_cli::rpc_client::call(&ep, "octra_submit", json!([tx])).unwrap();
    let cast_hash = cast_submit["hash"].as_str().unwrap().to_string();
    let cast_tx = octra_cli::rpc_client::call(&ep, "octra_transaction", json!([cast_hash]))
        .unwrap();
    let cast_event_names: Vec<String> = cast_tx["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| e.get("name").and_then(|x| x.as_str()).map(String::from))
        .collect();

    assert_eq!(
        forge_event_names, cast_event_names,
        "forge vs cast event-name drift"
    );
}

/// HTTP anvil mode and in-process mode must agree on the same view call.
#[tokio::test]
async fn http_anvil_matches_inprocess_view() {
    let _g = spawn_anvil(18301, "octPROG").await;

    // In-process forge.
    let forge = ForgeCtx::with_program("octPROG");
    let forge_view = forge
        .view("get_params", vec![])
        .unwrap();

    // HTTP via the core RPC client.
    let rpc = octravpn_core::rpc::RpcClient::new(http_url(18301));
    let http_view = rpc
        .contract_call(
            &octravpn_core::address::Address::from_display("octPROG"),
            "get_params",
            &[],
            None,
        )
        .await
        .unwrap();

    assert_eq!(forge_view, http_view, "forge vs http view drift on get_params");
}

/// HTTP anvil mode, when seeded with a validator and an endpoint, returns
/// the endpoint via `list_active_endpoints` — same shape as the in-process
/// forge view.
#[tokio::test]
async fn http_anvil_register_then_list_matches_forge() {
    let _g = spawn_anvil(18302, "octPROG").await;
    let rpc = octravpn_core::rpc::RpcClient::new(http_url(18302));

    let val = "octHTTPV0000000000000000000000000000VALI";

    // Seed validator status + operator stake via the test helpers.
    rpc.raw_call("octra_test_grantValidator", json!([val]))
        .await
        .unwrap();
    rpc.raw_call("octra_test_bondEndpoint", json!([val]))
        .await
        .unwrap();

    let tx = json!({
        "kind": "contract_call",
        "from": val,
        "to": "octPROG",
        "method": "register_endpoint",
        "params": [
            "1.2.3.4:51820",
            "de".repeat(32),
            "aa".repeat(32),
            "bb".repeat(32),
            "eu-west",
            100u64,
        ],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    rpc.submit(&tx).await.unwrap();

    let http_active = rpc
        .contract_call(
            &octravpn_core::address::Address::from_display("octPROG"),
            "list_active_endpoints",
            &[json!(0u64), json!(50u64)],
            None,
        )
        .await
        .unwrap();

    // Reproduce the same flow in-process.
    let mut forge = ForgeCtx::with_program("octPROG");
    forge.become_octra_validator(val);
    forge.prank(val);
    forge
        .call_register_endpoint(
            "1.2.3.4:51820",
            &"de".repeat(32),
            &"aa".repeat(32),
            &"bb".repeat(32),
            "eu-west",
            100,
        )
        .unwrap();
    let forge_active = forge
        .view("list_active_endpoints", vec![json!(0u64), json!(50u64)])
        .unwrap();

    assert_eq!(http_active, forge_active, "HTTP vs forge list drift");
}
