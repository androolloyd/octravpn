use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{circle_storage::StorageTable, circles::Error};
use octra_node_runtime::{circle_store, state_batch::StateBatch};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn table(v: &Value) -> StorageTable {
    let mut out = StorageTable::new(v["capacity"].as_u64().unwrap() as usize);
    for pair in v["pairs"].as_array().unwrap() {
        out.replace(bytes(&pair[0]), bytes(&pair[1]));
    }
    out
}
fn describe(t: &StorageTable) -> Value {
    json!({"keys":t.keys().map(b64).collect::<Vec<_>>(),"values":t.values().iter().map(|(k,v)|json!([b64(k),b64(v)])).collect::<Vec<_>>(),"storage_effort":circle_store::storage_effort(t).to_string(),"write_effort":circle_store::write_effort(t).to_string()})
}
fn run(v: &Value) -> Value {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for entry in v["entries"].as_array().unwrap() {
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
    let original = state.root().unwrap();
    let circle = bytes(&v["circle"]);
    let mut spent = 0i64;
    let found: Result<Value, Error> = match v["op"].as_str().unwrap() {
        "load" => {
            let budget = v["budget"].as_str().map(|s| s.parse::<i64>().unwrap());
            let mut charge = |cost: usize| {
                let cost = i64::try_from(cost).unwrap();
                if cost > budget.unwrap() - spent {
                    false
                } else {
                    spent += cost;
                    true
                }
            };
            let snapshot = state.snapshot();
            let charge: &mut dyn FnMut(usize) -> bool = &mut charge;
            circle_store::load_storage(&snapshot, &circle, budget.map(|_| charge))
                .map(|t| describe(&t))
        }
        "save" => {
            let t = table(&v["table"]);
            circle_store::save_storage(
                &mut state,
                &circle,
                &t,
                v["max_stable"].as_str().unwrap().parse().unwrap(),
                v["max_inline"].as_str().unwrap().parse().unwrap(),
            )
            .map(|r| json!({"stable_root":String::from_utf8(r).unwrap(),"table":describe(&t)}))
        }
        op => panic!("unknown op {op}"),
    };
    if found.is_err() || v["op"] == "load" {
        assert_eq!(
            state.root().unwrap(),
            original,
            "failure/read changed speculative state"
        );
    }
    let found = found.unwrap_or_else(|e| json!({"error":b64(&e.0)}));
    json!({"found":found,"root":hex::encode(state.root().unwrap()),"stable":state.get(&[b"circles",&circle,b"stable_root"]).map(b64),"spent":spent})
}
#[test]
fn native_circle_load_costs_limits_and_stable_commits_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-stable.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-stable-oracle.ml"
        )))
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let mut input = case["input"].clone();
        input["entries"] = fixture["states"][input["state"].as_u64().unwrap() as usize].clone();
        assert_eq!(
            run(&input),
            case["expected"],
            "stable case {i}: {}",
            case["input"]["op"]
        );
    }
}
