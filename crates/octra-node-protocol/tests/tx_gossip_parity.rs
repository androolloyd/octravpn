use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::network::{
    transaction_gossip::{self, Message, Plan},
    Error,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b(v: impl AsRef<[u8]>) -> Value {
    json!(STANDARD.encode(v))
}
fn blob(v: &[u8]) -> Value {
    json!({"size":v.len(),"sha256":hex::encode(Sha256::digest(v))})
}
fn run(v: &Value) -> Result<Value, Error> {
    let message = match v["kind"].as_str().unwrap() {
        "inv" => Message::Inventory(v["hashes"].as_array().unwrap().iter().map(bytes).collect()),
        "get" => Message::Get(v["hashes"].as_array().unwrap().iter().map(bytes).collect()),
        _ => Message::Transaction {
            hash: bytes(&v["hash"]),
            json: vec![v["byte"].as_u64().unwrap() as u8; v["length"].as_u64().unwrap() as usize],
        },
    };
    let mut wire = message.encode()?;
    if v["op"] == "encode" {
        return Ok(blob(&wire));
    }
    if let Some(cut) = v["cut"].as_u64() {
        wire.truncate(cut as usize);
    }
    if let Some(offset) = v["offset"].as_u64() {
        wire[offset as usize] = v["replacement"].as_u64().unwrap() as u8;
    }
    wire.extend(bytes(&v["append"]));
    if v["op"] == "decode" {
        return Ok(blob(&Message::decode(&wire)?.encode()?));
    }
    let known = v["known"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect::<Vec<_>>();
    Ok(
        match transaction_gossip::plan(
            &wire,
            |h| known.iter().any(|k| k == h),
            v["requests"].as_u64().unwrap() as usize,
            v["replies"].as_u64().unwrap() as usize,
        ) {
            Plan::Request(h) => json!({"request":h.iter().map(b).collect::<Vec<_>>()}),
            Plan::Serve(h) => json!({"serve":h.iter().map(b).collect::<Vec<_>>()}),
            Plan::Receive { hash, json } => json!({"hash":b(hash),"json":blob(&json)}),
            Plan::Legacy => json!("legacy"),
        },
    )
}
#[test]
fn native_gossip_codecs_inventory_planning_and_legacy_fallback() {
    let f: Value = serde_json::from_str(include_str!("fixtures/tx-gossip.json")).unwrap();
    let s: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], s["upstream_commit"]);
    assert_eq!(f["source_sha256"], s["files"]);
    assert_eq!(
        f["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/tx-gossip-oracle.ml"
        )))
    );
    for (i, c) in f["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&c["input"]).unwrap_or_else(|e| json!({"error":b(e.as_bytes())})),
            c["expected"],
            "native case {i}: {}",
            c["input"]
        );
    }
}
