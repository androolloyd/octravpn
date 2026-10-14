use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::network::gossip_guard::{Config, Guard, Seen};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn f(v: &Value, k: &str) -> f64 {
    v[k].as_str().unwrap().parse().unwrap()
}
fn run(v: &Value) -> Value {
    if v["op"] == "seen" {
        let mut seen = Seen::default();
        return json!(v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let key = bytes(&s["key"]);
                let result = if s["remember"].as_bool().unwrap() {
                    seen.remember(f(s, "now"), &key)
                } else {
                    seen.recent(f(s, "now"), &key)
                };
                json!({"result":result,"size":seen.len()})
            })
            .collect::<Vec<_>>());
    }
    let c = &v["config"];
    let config = Config {
        window: f(c, "window"),
        max_messages: c["messages"].as_i64().unwrap(),
        max_bytes: c["bytes"].as_i64().unwrap(),
        max_payload: c["payload"].as_i64().unwrap(),
    };
    let mut g = Guard::default();
    let results = v["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let result = if s["prune"] == true {
                g.prune(
                    f(s, "now"),
                    f(s, "ttl"),
                    s["maximum"].as_u64().unwrap() as usize,
                );
                None
            } else {
                g.admit(
                    config,
                    f(s, "now"),
                    &bytes(&s["key"]),
                    s["bytes"].as_i64().unwrap(),
                )
                .err()
            };
            json!({"result":result,"size":g.len()})
        })
        .collect::<Vec<_>>();
    json!({"results":results,"peers":g.snapshot().map(|(k,b)|json!({"key":STANDARD.encode(k),"start_bits":format!("{:016x}",b.start.to_bits()),"messages":b.messages,"bytes":b.bytes,"last_bits":format!("{:016x}",b.last_seen.to_bits())})).collect::<Vec<_>>()})
}
#[test]
fn native_gossip_quotas_seen_cache_clock_recovery_and_eviction() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/gossip-guard.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/gossip-guard-oracle.ml"
        )))
    );
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = run(&c["input"]);
        if actual != c["expected"] {
            for (n, (left, right)) in actual["results"]
                .as_array()
                .unwrap()
                .iter()
                .zip(c["expected"]["results"].as_array().unwrap())
                .enumerate()
            {
                assert_eq!(
                    left, right,
                    "native case {i}, step {n}: {}",
                    c["input"]["steps"][n]
                );
            }
            assert_eq!(
                actual["peers"], c["expected"]["peers"],
                "native case {i} peer snapshot"
            );
            panic!("native case {i}");
        }
    }
}
