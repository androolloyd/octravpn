use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::network::{
    budget::PeerClass,
    swarm_policy::{self as s, Direction},
    upgrade::{self as u, Plan, Target},
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
fn target(v: &Value) -> Target {
    Target {
        epoch: v["epoch"].as_str().unwrap().parse().unwrap(),
        binary_hash: bytes(&v["binary"]),
        config_hash: bytes(&v["config"]),
    }
}
fn run(v: &Value) -> Result<Value, Error> {
    Ok(match v["op"].as_str().unwrap() {
        "upgrade" => {
            let plan = (!v["plan"].is_null()).then(|| Plan {
                target: target(&v["plan"]),
                rollback: (!v["plan"]["rollback"].is_null())
                    .then(|| target(&v["plan"]["rollback"])),
            });
            let epoch = v["epoch"].as_str().unwrap().parse().unwrap();
            let config = bytes(&v["config"]);
            let binary = bytes(&v["binary"]);
            let required = v["required"].as_bool().unwrap();
            json!({"handshake":b(u::handshake_hash(epoch,&config,&binary,required,plan.as_ref())?),"active":plan.as_ref().is_some_and(|p|p.active(epoch)),"rollback":plan.as_ref().is_some_and(|p|p.rollback_active(epoch)),"required":u::binary_required(epoch,required,plan.as_ref()),"expected":b(u::expected_binary(epoch,&binary,plan.as_ref())),"ready":plan.as_ref().and_then(|p|p.ready(epoch,&config,&binary,required).err()).map(|e|String::from_utf8(e.into_bytes()).unwrap()),"schedule":plan.as_ref().map(|p|p.schedule_hash(&config).map(b)).transpose()?})
        }
        "normalize" => b(u::normalize_hash("test", &bytes(&v["value"]))?),
        "retry" => json!(s::record_dial_due(
            v["now"].as_f64().unwrap(),
            v["due"].as_f64(),
            v["active"].as_u64().unwrap() as usize
        )),
        "capacity" => json!(s::capacity(
            v["maximum"].as_i64().unwrap(),
            v["validators"].as_i64().unwrap(),
            v["observers"].as_i64().unwrap(),
            if v["validator"].as_bool().unwrap() {
                PeerClass::Validator
            } else {
                PeerClass::Observer
            }
        )),
        "keep" => {
            let offered = (!v["offered"].is_null()).then(|| bytes(&v["offered"]));
            json!(s::keep_profile(
                &bytes(&v["target"]),
                &bytes(&v["current"]),
                offered.as_deref()
            ))
        }
        "roles" => {
            let mut keys = v["keys"]
                .as_array()
                .filter(|a| !a.is_empty())
                .map(|a| a.iter().map(bytes).collect::<Vec<_>>());
            let updated = if let Some(update) = v["update"].as_array() {
                let update = update.iter().map(bytes).collect::<Vec<_>>();
                match s::validate_validators(&update) {
                    Ok(()) => {
                        keys = Some(update);
                        Value::Null
                    }
                    Err(e) => b(e.as_bytes()),
                }
            } else {
                Value::Null
            };
            json!({"validator":s::role(keys.as_deref(),&bytes(&v["peer_id"]))==PeerClass::Validator,"local":s::local_is_validator(keys.as_deref(),&bytes(&v["public"])),"observers":s::accepts_observers(keys.as_deref(),&bytes(&v["public"])),"direction":match s::preferred_direction(&bytes(&v["local_id"]),&bytes(&v["peer_id"])){Direction::Inbound=>"inbound",Direction::Outbound=>"outbound"},"updated":updated})
        }
        _ => panic!("unknown operation"),
    })
}
#[test]
fn native_upgrade_rollback_and_swarm_policy() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/swarm-policy.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/swarm-policy-oracle.ml"
        )))
    );
    for (i, c) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            run(&c["input"]).unwrap_or_else(|e| json!({"error":b(e.as_bytes())})),
            c["expected"],
            "native case {i}: {}",
            c["input"]
        );
    }
}
