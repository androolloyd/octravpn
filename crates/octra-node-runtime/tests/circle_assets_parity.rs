//! Native lookup and policy parity; the browser applies additional local limits.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::circles::{self, AssetMeta, AssetPolicy};
use octra_node_runtime::{circle_assets::public_asset, state_batch::StateBatch};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(v))
}
fn result(v: Result<Value, circles::Error>) -> Value {
    v.unwrap_or_else(|e| json!({"error":b64(e.0)}))
}
fn execute(input: &Value) -> Value {
    let meta = || AssetMeta::parse(&bytes(&input["meta"]));
    match input["op"].as_str().unwrap() {
        "path"=>result(circles::normalize_path(&bytes(&input["path"])).map(|path|json!({"path":b64(&path),"key":circles::path_key(path.as_bytes()),"resource":circles::resource_key(&bytes(&input["circle"]),path.as_bytes()),"stable":circles::stable_key(path.as_bytes())}))),
        "meta"=>result(meta().map(|m|json!({"meta":b64(m.to_json_bytes())}))),
        "policy"=>{
            let value=|name|input[name].as_str().map(|_|bytes(&input[name]));
            let p=AssetPolicy {activate_after_epoch:value("activate").as_deref().and_then(circles::policy_integer),expire_after_epoch:value("expire").as_deref().and_then(circles::policy_integer),tombstone:value("tombstone").as_deref().is_some_and(circles::policy_bool),revoked:value("revoked").as_deref().is_some_and(circles::policy_bool)};
            result(meta().map(|m|json!(p.visible_at(input["epoch"].as_str().unwrap().parse().unwrap(),&m))))
        },
        "asset"=>{
            let mut state=StateBatch::default();state.begin().unwrap();
            for entry in input["entries"].as_array().unwrap() {
                let path=entry["path"].as_array().unwrap().iter().map(bytes).collect::<Vec<_>>();
                state.set(&path.iter().map(Vec::as_slice).collect::<Vec<_>>(),bytes(&entry["value"])).unwrap();
            }
            let snapshot=state.snapshot();
            let found=public_asset(&snapshot,&bytes(&input["circle"]),&bytes(&input["path"]),input["max_bytes"].as_i64().unwrap()).map(|a|json!({"path":b64(a.canonical_path),"key":a.path_key,"browser":b64(a.browser_mode),"resource":b64(a.resource_mode),"meta":b64(a.meta.to_json_bytes()),"body":b64(a.body_b64)}));
            json!({"root":hex::encode(state.root().unwrap()),"found":result(found)})
        },
        op=>panic!("unknown operation {op}"),
    }
}
#[test]
fn native_circle_paths_metadata_policy_and_snapshot_reads_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-assets.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], map["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], map["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-assets-oracle.ml"
        )))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            execute(&case["input"]),
            case["expected"],
            "case {index}: {}",
            case["input"]["op"]
        );
    }
}
