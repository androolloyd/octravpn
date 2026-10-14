use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_runtime::{
    private_outputs::{self, Output},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
#[test]
fn native_private_records_claim_replay_and_storage_roots() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-outputs.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sources: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], sources["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, path) in [
        ("oracle_sha256", "private-output-oracle.ml"),
        ("generator_sha256", "private-output-fixtures.py"),
        ("runner_sha256", "native-oracle.py"),
    ] {
        assert_eq!(
            fixture[key],
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(path)).unwrap()
            ))
        );
    }
    for case in fixture["cases"].as_array().unwrap() {
        let input = &case["input"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for row in input["state"].as_array().unwrap() {
            let key = row["key"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().as_bytes())
                .collect::<Vec<_>>();
            state.set(&key, bytes(&row["value"])).unwrap();
        }
        let before = state.root().unwrap();
        let counter = state.stealth_counter();
        let save = state.save().unwrap();
        let mut results = Vec::new();
        for op in input["operations"].as_array().unwrap() {
            let result = match op["operation"].as_str().unwrap() {
                "insert" => match private_outputs::insert(
                    &mut state,
                    Output {
                        id: 99,
                        claimed: 99,
                        stealth_tag: bytes(&op["tag"]),
                        eph_pub: bytes(&op["ephemeral"]),
                        enc_amount: bytes(&op["encrypted"]),
                        amount: bytes(&op["amount"]),
                        epoch_id: op["epoch"].as_i64().unwrap(),
                        tx_hash: bytes(&op["hash"]),
                        sender_addr: bytes(&op["sender"]),
                        claim_pub: bytes(&op["claim"]),
                        delta_cipher_stored: bytes(&op["delta"]),
                        amount_hash: bytes(&op["amount_hash"]),
                        amount_commitment: bytes(&op["commitment"]),
                    },
                ) {
                    Ok(id) => json!({"id":id.to_string()}),
                    Err(e) => json!({"exception":STANDARD.encode(e.0)}),
                },
                "claim" => match private_outputs::mark_claimed(
                    &mut state,
                    op["id"].as_i64().unwrap(),
                    &bytes(&op["hash"]),
                )
                .unwrap()
                {
                    Ok(()) => json!(true),
                    Err(e) => json!({"error":STANDARD.encode(e)}),
                },
                _ => panic!("unknown oracle operation"),
            };
            results.push(result);
        }
        let rows=input["ids"].as_array().unwrap().iter().map(|id|{
   let id=id.as_i64().unwrap();json!({"id":id,"raw":state.get(&[b"stealth",id.to_string().as_bytes()]).map(|v|STANDARD.encode(v)),"output":private_outputs::get(&state,id).unwrap().map(|v|STANDARD.encode(v.to_bytes()))})
  }).collect::<Vec<_>>();
        let actual = json!({"results":results,"root":hex::encode(state.root().unwrap()),"rows":rows,
         "counter":state.get(&[b"index",b"stealth_counter"]).map(|v|STANDARD.encode(v)),
         "sum":private_outputs::unclaimed_amount(&state).unwrap().to_string(),
         "claims":private_outputs::claimed_hashes(&state).unwrap().iter().map(|v|STANDARD.encode(v)).collect::<Vec<_>>(),
         "since":STANDARD.encode(private_outputs::since(&state,input["since"].as_i64().unwrap()).unwrap()),
        });
        assert_eq!(actual, case["expected"], "{}", input["name"]);
        state.restore(save).unwrap();
        assert_eq!(state.root().unwrap(), before);
        assert_eq!(state.stealth_counter(), counter);
    }
}
