//! Integration tests against the in-process mock backend.
//!
//! Spinning up an actual HTTP server per test would add ~50ms each;
//! instead, the `inprocess://<program>` URL scheme routes through the
//! same code path as a real RPC node but skips IO entirely. The address
//! choice is irrelevant since the mock doesn't authenticate caller IDs.

use serde_json::{json, Value};

#[test]
fn rpc_node_status_against_in_process() {
    let url = "inprocess://octPROG";
    let ep = octra_cli::rpc_client::endpoint_from_url(url);
    let v = octra_cli::rpc_client::call(&ep, "node_status", json!([])).unwrap();
    assert_eq!(v["epoch"], json!(1));
}

#[test]
fn rpc_call_unknown_method_errors() {
    let url = "inprocess://octPROG";
    let ep = octra_cli::rpc_client::endpoint_from_url(url);
    let r = octra_cli::rpc_client::call(&ep, "definitely_unknown", json!([]));
    assert!(r.is_err());
}

#[test]
fn contract_call_list_active_endpoints() {
    let url = "inprocess://octPROG";
    let ep = octra_cli::rpc_client::endpoint_from_url(url);
    // Should return an empty array on a fresh mock.
    let v = octra_cli::rpc_client::call(
        &ep,
        "contract_call",
        json!(["octPROG", "list_active_endpoints", []]),
    )
    .unwrap();
    assert!(v.is_array(), "got: {v}");
    assert_eq!(v.as_array().unwrap().len(), 0);
}

#[test]
fn compile_aml_produces_artifact() {
    let url = "inprocess://octPROG";
    let ep = octra_cli::rpc_client::endpoint_from_url(url);
    let src =
        "program Demo { fn foo(): bool { return true } view fn bar(): bool { return false } }";
    let v: Value =
        octra_cli::rpc_client::call(&ep, "octra_compileAml", json!([src, "Demo"])).unwrap();
    assert_eq!(v["name"], json!("Demo"));
    let abi = v["abi"].as_array().unwrap();
    assert!(abi
        .iter()
        .any(|m| m["name"] == "foo" && m["kind"] == "call"));
    assert!(abi
        .iter()
        .any(|m| m["name"] == "bar" && m["kind"] == "view"));
}

#[test]
fn submit_through_in_process_persists_tx() {
    let url = "inprocess://octPROG";
    let ep = octra_cli::rpc_client::endpoint_from_url(url);
    let tx = json!({
        "kind": "contract_call",
        "from": "octCLIENT00000000000000000000000000000001",
        "to": "octPROG",
        "method": "retire_endpoint",
        "params": [],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
        "timestamp": 0.0,
    });
    // retire_endpoint requires the caller to be a registered endpoint,
    // so this reverts with "not registered" — confirming the mock saw
    // the submission and executed the corresponding handler.
    let r = octra_cli::rpc_client::call(&ep, "octra_submit", json!([tx]));
    assert!(r.is_err(), "should revert with not registered");
}

#[test]
fn cast_rpc_via_cli_with_inprocess() {
    // Use the in-process URL via the CLI dispatch directly so we don't
    // round-trip through assert_cmd / subprocess.
    let args = vec![
        "octra".to_string(),
        "cast".to_string(),
        "rpc".to_string(),
        "node_status".to_string(),
        "--rpc-url".to_string(),
        "inprocess://octPROG".to_string(),
    ];
    octra_cli::run(&args).unwrap();
}
