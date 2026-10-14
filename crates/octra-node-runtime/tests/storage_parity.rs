use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::irmin::{self, Entry, Kind};
use octra_node_runtime::state_batch::StateBatch;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn bytes(value: &Value, name: &str) -> Vec<u8> {
    decode(&value[name])
}
fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn checked(preimage: Vec<u8>, hash: irmin::Hash) -> Value {
    json!({"preimage":STANDARD.encode(preimage),"hash":hex::encode(hash)})
}

#[test]
fn native_irmin_preimages_and_tree_roots_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/irmin-storage.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/storage-oracle.ml"
        )))
    );
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["source_sha256"], map["files"]);
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&fixture["dependencies"]).unwrap()
        )),
        "5ef46d181c747af6aae227d4720eaf5f05c611058c619d6c7023fc0d97294ea4"
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let actual = match input["op"].as_str().unwrap() {
            "contents" => checked(
                irmin::contents_preimage(&bytes(input, "value")),
                irmin::contents_hash(&bytes(input, "value")),
            ),
            "step" => checked(
                bytes(input, "value"),
                irmin::step_hash(&bytes(input, "value")),
            ),
            "node" => {
                let entries = input["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| Entry {
                        name: bytes(e, "name"),
                        hash: bytes(e, "hash").try_into().unwrap(),
                        kind: if e["kind"] == "node" {
                            Kind::Node
                        } else {
                            Kind::Contents
                        },
                    })
                    .collect::<Vec<_>>();
                let preimage = irmin::flat_node_preimage(&entries);
                // Flat schema preimages are separately qualified from pack roots.
                checked(preimage.clone(), irmin::step_hash(&preimage))
            }
            "commit" => {
                let node = bytes(input, "node").try_into().unwrap();
                let parents = input["parents"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| decode(p).try_into().unwrap())
                    .collect::<Vec<_>>();
                let date = input["date"].as_str().unwrap().parse().unwrap();
                checked(
                    irmin::commit_preimage(
                        &node,
                        &parents,
                        date,
                        &bytes(input, "author"),
                        &bytes(input, "message"),
                    ),
                    irmin::commit_hash(
                        &node,
                        &parents,
                        date,
                        &bytes(input, "author"),
                        &bytes(input, "message"),
                    ),
                )
            }
            "tree" => {
                let mut store = StateBatch::default();
                store.begin().unwrap();
                let mut roots = vec![hex::encode(store.root().unwrap())];
                for op in input["operations"].as_array().unwrap() {
                    let path = op["path"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(decode)
                        .collect::<Vec<_>>();
                    let refs = path.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    if op["op"] == "set" {
                        store.set(&refs, bytes(op, "value")).unwrap();
                    } else {
                        store.remove(&refs).unwrap();
                    }
                    roots.push(hex::encode(store.root().unwrap()));
                    assert_eq!(
                        json!(roots.last().unwrap()),
                        case["expected"][roots.len() - 1],
                        "tree case {index}, operation {}: {op}",
                        roots.len() - 2
                    );
                }
                json!(roots)
            }
            other => panic!("unknown operation {other}"),
        };
        assert_eq!(actual, case["expected"], "case {index}: {}", input["op"]);
    }
}
