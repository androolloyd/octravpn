use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{circle_wasm::public_read, circles::Error};
use octra_node_runtime::{circle_reads, circle_store, state_batch::StateBatch};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn error(e: Error) -> Value {
    json!({"error":STANDARD.encode(e.0)})
}
fn declarations(input: &Value) -> Result<Vec<public_read::Declaration>, Error> {
    public_read::declarations(&bytes(&input["descriptor"])).map_err(|e| match e {
        octra_node_protocol::circle_wasm::Error::Rejected(e)
        | octra_node_protocol::circle_wasm::Error::Unavailable(e) => Error(e),
    })
}
fn actual(input: &Value) -> Value {
    if input["op"] == "declarations" {
        return match declarations(input) { Err(e)=>error(e), Ok(ds)=>json!(ds.iter().map(|d|json!({
            "method":STANDARD.encode(&d.method),"circle":STANDARD.encode(&d.circle),"path":STANDARD.encode(&d.path),
            "key":d.path_key,"offset":d.offset.to_string(),"max_bytes":d.max_bytes.to_string(),
        })).collect::<Vec<_>>()) };
    }
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for entry in input["entries"].as_array().unwrap() {
        let path = entry["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                bytes(&entry["value"]),
            )
            .unwrap();
    }
    let snapshot = state.snapshot();
    let circle = bytes(&input["circle"]);
    let mut spent = 0;
    let found = match input["op"].as_str().unwrap() {
        "info" => match circle_store::info(&snapshot, &circle) {
            Err(e) => error(e),
            Ok(None) => Value::Null,
            Ok(Some(i)) => json!({
                "circle":STANDARD.encode(&i.circle_id),"runtime":STANDARD.encode(&i.runtime),"version":i.version.to_string(),
                "owner":STANDARD.encode(&i.owner),"code_hash":STANDARD.encode(&i.code_hash),"stable_root":STANDARD.encode(&i.stable_root),
                "assets_root":STANDARD.encode(&i.assets_root),"privacy":STANDARD.encode(&i.privacy),"browser":STANDARD.encode(&i.browser),
                "resource":STANDARD.encode(&i.resource),"policy_hash":i.policy_hash.map(|v|STANDARD.encode(v)),
                "members_root":i.members_root.map(|v|STANDARD.encode(v)),"export_policy":i.export_policy.map(|v|STANDARD.encode(v)),
                "limits":i.limits.map(|n|n.to_string()),
            }),
        },
        "storage" => match circle_store::storage(&snapshot, &circle) {
            Err(e) => error(e),
            Ok(s) => json!(s
                .iter()
                .map(|(k, v)| [STANDARD.encode(k), STANDARD.encode(v)])
                .collect::<Vec<_>>()),
        },
        "inline" => match circle_store::inline(&snapshot, &circle, &bytes(&input["key"])) {
            Err(e) => error(e),
            Ok(v) => json!(v.map(|v| STANDARD.encode(v))),
        },
        "reads" => match declarations(input) {
            Err(e) => error(e),
            Ok(ds) => {
                let method = bytes(&input["method"]);
                let ds = ds
                    .into_iter()
                    .filter(|d| d.method == method)
                    .collect::<Vec<_>>();
                match circle_reads::load(
                    &snapshot,
                    input["epoch"].as_str().unwrap().parse().unwrap(),
                    &ds,
                    input["budget"].as_i64(),
                    &mut spent,
                ) {
                    Err(e) => error(e),
                    Ok(b) => {
                        json!({"effort":b.effort,"reads":b.reads.iter().map(|r|STANDARD.encode(r.native_json())).collect::<Vec<_>>()})
                    }
                }
            }
        },
        op => panic!("unexpected operation {op}"),
    };
    json!({"root":hex::encode(snapshot.root().unwrap()),"found":found,"spent":spent})
}
#[test]
fn native_circle_records_storage_and_public_reads_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-state.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(
            std::fs::read(root.join("scripts/node-port/circle-state-oracle.ml")).unwrap()
        ))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            actual(&case["input"]),
            case["expected"],
            "case {index}: {}",
            case["input"]
        );
    }
}
