use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::network::{
    endpoint::{self, Endpoint},
    guard::{self, Bad, Config, Guard},
    handshake::node_id,
    peer_record::{self, Added, Record, Registry},
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
fn record(v: &Value) -> Result<Record, Error> {
    let key = SigningKey::from_bytes(&bytes(&v["seed"]).try_into().unwrap());
    let public = v
        .get("public_key")
        .map_or_else(|| key.verifying_key().to_bytes().to_vec(), bytes);
    let mut r = Record {
        chain_id: bytes(&v["chain_id"]),
        node_id: v.get("node_id").map_or_else(|| node_id(&public), bytes),
        public_key: public,
        node_address: bytes(&v["address"]),
        binary_hash: bytes(&v["binary"]),
        config_hash: bytes(&v["config"]),
        host: bytes(&v["host"]),
        port: v["port"].as_i64().unwrap(),
        features: v["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect(),
        timestamp: v["timestamp"].as_str().unwrap().parse().unwrap(),
        signature: vec![],
    };
    r.signature = if let Some(value) = v.get("signature") {
        bytes(value)
    } else {
        key.sign(&r.sign_bytes()?).to_bytes().to_vec()
    };
    Ok(r)
}
fn f(v: &Value, k: &str) -> f64 {
    v[k].as_f64().unwrap()
}
fn run(v: &Value) -> Result<Value, Error> {
    Ok(match v["op"].as_str().unwrap() {
        "record" => {
            let r = record(&v["record"])?;
            let binary = v["binary"].as_str().map(|_| bytes(&v["binary"]));
            let allowed = v["allowed"]
                .as_array()
                .unwrap()
                .iter()
                .map(bytes)
                .collect::<Vec<_>>();
            json!({"wire":b(r.encode()?),"sign_bytes":b(r.sign_bytes()?),"validation":r.validate(&bytes(&v["chain"]),&bytes(&v["config"]),binary.as_deref(),&allowed).err().map(|e|b(e.as_bytes()))})
        }
        "decode" => {
            let r = record(&v["record"])?;
            let list = v["list"].as_bool().unwrap();
            let mut wire = if list {
                peer_record::encode_list(&vec![r; v["count"].as_u64().unwrap() as usize])?
            } else {
                r.encode()?
            };
            if let Some(cut) = v["cut"].as_u64() {
                wire.truncate(cut as usize);
            }
            if let Some(offset) = v["offset"].as_u64() {
                wire[offset as usize] = v["byte"].as_u64().unwrap() as u8;
            }
            wire.extend(bytes(&v["append"]));
            b(if list {
                peer_record::encode_list(&peer_record::decode_list(&wire)?)?
            } else {
                Record::decode(&wire)?.encode()?
            })
        }
        "bucket" => b(peer_record::bucket(&bytes(&v["host"]))),
        "registry" => {
            let mut registry = Registry::new(f(v, "ttl"), v["maximum"].as_i64().unwrap());
            let mut out = vec![];
            for s in v["steps"].as_array().unwrap() {
                let now = f(s, "now");
                let result = match s["kind"].as_str().unwrap() {
                    "add" => match registry.add(now, record(&s["record"])?) {
                        Ok(Added::New) => json!("new"),
                        Ok(Added::Refreshed) => json!("refreshed"),
                        Err(e) => json!(String::from_utf8(e.into_bytes()).unwrap()),
                    },
                    "clear" => {
                        registry.clear();
                        Value::Null
                    }
                    _ => Value::Null,
                };
                out.push(json!({"result":result,"values":registry.values(now).map(|r|b(r.encode().unwrap())).collect::<Vec<_>>()}));
            }
            json!(out)
        }
        "guard" => {
            let c = &v["config"];
            let config = Config {
                bad_window: f(c, "bad_window"),
                max_bad: c["max_bad"].as_i64().unwrap(),
                ban: f(c, "ban"),
                connection_window: f(c, "connection_window"),
                max_connections: c["max_connections"].as_i64().unwrap(),
            };
            let mut g = Guard::default();
            let results = v["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    let key = bytes(&s["key"]);
                    let now = f(s, "now");
                    match s["kind"].as_str().unwrap() {
                        "admit" => json!(g.admit(config, now, &key).err()),
                        "report" => match g.report(config, now, &key, &bytes(&s["reason"])) {
                            Bad::Noted(n) => json!({"noted":n}),
                            Bad::Banned(t) => json!({"banned":t}),
                        },
                        "prune" => {
                            g.prune(now, f(s, "ttl"), s["maximum"].as_u64().unwrap() as usize);
                            Value::Null
                        }
                        _ => json!(g.is_banned(now, &key)),
                    }
                })
                .collect::<Vec<_>>();
            json!({"results":results,"scores":g.snapshot().map(|(k,s)|json!({"key":b(k),"bad":s.bad_count,"connections":s.connection_count,"until":s.ban_until,"reason":b(&s.last_reason),"frames":s.invalid_frames,"signatures":s.bad_signatures,"stale":s.stale_roots})).collect::<Vec<_>>()})
        }
        "guard_key" => {
            let raw = bytes(&v["value"]);
            json!({"host":b(guard::host_key(&raw)),"identity":b(guard::identity_key(&raw)),"penalty":guard::handshake_penalty(&raw)})
        }
        "endpoint" => {
            let raw = bytes(&v["value"]);
            json!({"parsed":Endpoint::parse(&raw).map(|e|b(e.encode())),"csv":endpoint::csv(&raw).iter().map(|e|b(e.encode())).collect::<Vec<_>>()})
        }
        "bootstrap" => json!(endpoint::bootstrap(
            &v["configured"]
                .as_array()
                .unwrap()
                .iter()
                .map(bytes)
                .collect::<Vec<_>>(),
            &bytes(&v["base"]),
            &bytes(&v["extra"])
        )
        .iter()
        .map(|e| b(e.encode()))
        .collect::<Vec<_>>()),
        _ => panic!("unknown operation"),
    })
}
#[test]
fn native_signed_discovery_registry_abuse_guard_and_endpoints() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/peer-policy.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/peer-oracle.ml"
        )))
    );
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = run(&c["input"]).unwrap_or_else(|e| json!({"error":b(e.as_bytes())}));
        assert_eq!(actual, c["expected"], "native case {i}: {}", c["input"]);
    }
}
