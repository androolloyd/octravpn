use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::circle_storage::{self as storage, StorageTable};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn result(value: Result<(), storage::Error>) -> Value {
    match value {
        Ok(()) => Value::Null,
        Err(e) => json!([e.code, b64(&e.key), b64(&e.detail)]),
    }
}
fn table(v: &Value) -> StorageTable {
    let mut out = StorageTable::new(v["capacity"].as_u64().unwrap() as usize);
    for pair in v["pairs"].as_array().unwrap() {
        out.replace(bytes(&pair[0]), bytes(&pair[1]));
    }
    for key in v["remove"].as_array().unwrap() {
        out.remove(&bytes(key));
    }
    out
}
fn keys(t: &StorageTable) -> Vec<Value> {
    t.keys().map(b64).collect()
}
fn run(v: &Value) -> Value {
    match v["op"].as_str().unwrap() {
        "write" => result(storage::validate_write(
            &bytes(&v["key"]),
            &bytes(&v["value"]),
        )),
        "delete" => result(storage::validate_delete(&bytes(&v["key"]))),
        "hash" => json!(storage::string_hash(&bytes(&v["key"]))),
        "table" => {
            let t = table(&v["table"]);
            json!({"keys":keys(&t),"result":result(t.validate())})
        }
        "delta" => {
            let before = table(&v["before"]);
            let after = table(&v["after"]);
            json!({"before":keys(&before),"after":keys(&after),"result":result(storage::validate_delta(&before,&after,v["active"].as_bool().unwrap()))})
        }
        op => panic!("unknown operation {op}"),
    }
}
#[test]
fn native_circle_storage_guards_and_legacy_traversal_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-storage.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-storage-oracle.ml"
        )))
    );
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "storage case {i}: {}",
            case["input"]
        );
    }
}
