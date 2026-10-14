use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::consensus::{
    codec::Wire, finality_query as f, hash, policy::Protocol, relief as r, root_query::RootQueries,
    Error, RoundStep, RoundSync, Validator, ValidatorSet,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn number(j: &Value, k: &str) -> i64 {
    j[k].as_str().unwrap().parse().unwrap()
}
fn integer(j: &Value, k: &str) -> i64 {
    j[k].as_i64().unwrap()
}
fn flag(j: &Value, k: &str) -> bool {
    j[k].as_bool().unwrap()
}
fn raw(j: &Value, k: &str) -> Vec<u8> {
    hex::decode(j[k].as_str().unwrap()).unwrap()
}
fn address(id: i64) -> Vec<u8> {
    format!("validator-{id}").into_bytes()
}
fn key(id: i64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}
fn validators(j: &Value, name: &str, weighted: bool) -> Result<ValidatorSet, Error> {
    let entries = j[name]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                Validator {
                    address: address(integer(m, "id")),
                    pubkey: key(integer(m, "key")).verifying_key().to_bytes().to_vec(),
                },
                m["weight"].as_str().unwrap().parse().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    if weighted {
        ValidatorSet::weighted(entries)
    } else {
        Ok(ValidatorSet::unweighted(
            entries.into_iter().map(|(v, _)| v).collect(),
        ))
    }
}
fn sync(j: &Value) -> Result<RoundSync, Error> {
    let id = integer(j, "id");
    let mut sync = RoundSync {
        chain_id: raw(j, "chain"),
        epoch_id: number(j, "height"),
        round: integer(j, "round"),
        step: RoundStep::from_byte(integer(j, "step") as u8)?,
        request: flag(j, "request"),
        validator: address(id),
        signature: vec![0; 64],
    };
    if !flag(j, "corrupt") {
        sync.signature = key(id)
            .sign(&hash::round_sync_sign_bytes(&sync)?)
            .to_bytes()
            .to_vec();
    }
    Ok(sync)
}
fn wires(proof: &[RoundSync]) -> Result<Value, Error> {
    Ok(json!(proof
        .iter()
        .map(|s| s.encode().map(hex::encode))
        .collect::<Result<Vec<_>, _>>()?))
}
fn mark(m: &r::Mark) -> Result<Value, Error> {
    Ok(
        json!({"height":m.height.to_string(),"round":m.round,"activate":m.activate_epoch.to_string(),"source":hex::encode(&m.source_hash),"target":hex::encode(&m.target_hash),"fingerprint":hex::encode(&m.fingerprint),"proof":wires(&m.proof)?}),
    )
}
fn caught(r: Result<Value, Error>) -> Value {
    r.unwrap_or_else(|e| json!({"error":e.to_string()}))
}
fn verdict<T>(r: Result<T, Error>) -> Value {
    caught(r.map(|_| Value::Null))
}
fn execute(j: &Value) -> Result<Value, Error> {
    Ok(match j["op"].as_str().unwrap() {
        "protocol" => {
            let value = if j["value"].is_null() {
                None
            } else {
                Some(raw(j, "value"))
            };
            let protocol = Protocol::from_activation_value(value.as_deref())?;
            json!({"activation":protocol.activation_epoch().to_string(),"id":protocol.consensus_id(),"version":protocol.version_at(number(j,"epoch"))})
        }
        "route" => json!(match f::route(
            f::scope(flag(j, "complete_request"), flag(j, "finality_request")),
            f::proof(
                flag(j, "complete"),
                flag(j, "legacy"),
                flag(j, "legacy_complete")
            )
        ) {
            f::Route::Complete => "complete",
            f::Route::LegacyRange => "legacy",
            f::Route::Finality => "finality",
            f::Route::IgnoreLegacy => "ignore",
            f::Route::Reject => "reject",
        }),
        "query" => {
            let state = if flag(j, "idle") {
                f::Query::Idle
            } else {
                f::Query::Sent {
                    epoch: number(j, "prior_epoch"),
                    attempts: integer(j, "attempts"),
                    sent_at: number(j, "sent_at"),
                }
            };
            match state.plan(number(j, "now"), number(j, "epoch")) {
                f::Plan::Wait => json!("wait"),
                f::Plan::Rest => json!("rest"),
                f::Plan::Send(f::Query::Idle) => panic!("idle send"),
                f::Plan::Send(f::Query::Sent {
                    epoch,
                    attempts,
                    sent_at,
                }) => {
                    json!({"epoch":epoch.to_string(),"attempts":attempts,"sent_at":sent_at.to_string()})
                }
            }
        }
        "roots" => {
            let mut queries = RootQueries::default();
            let mut leases = BTreeMap::new();
            let mut answers = Vec::new();
            for step in j["steps"].as_array().unwrap() {
                let epoch = number(step, "epoch");
                let name = integer(step, "lease");
                let answer = match step["op"].as_str().unwrap() {
                    "join" => match queries.join(epoch) {
                        Ok(lease) => {
                            leases.insert(name, lease);
                            Value::Null
                        }
                        Err(e) => json!(e.to_string()),
                    },
                    "add" => {
                        queries.add(epoch, raw(step, "value"), PartialEq::eq);
                        Value::Null
                    }
                    "leave" => {
                        queries.leave(leases[&name]);
                        Value::Null
                    }
                    "read" => json!(queries
                        .read(leases[&name])
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>()),
                    _ => panic!("root operation"),
                };
                answers.push(json!({"answer":answer,"listening":queries.listening(epoch)}));
            }
            json!(answers)
        }
        "relief" => {
            let current = validators(j, "current", flag(j, "weighted"))?;
            let target = validators(j, "target", flag(j, "target_weighted"))?;
            let chain = raw(j, "chain");
            let fingerprint = raw(j, "fingerprint");
            let proof = j["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(sync)
                .collect::<Result<Vec<_>, _>>()?;
            let plan = r::Plan {
                chain_id: &chain,
                height: number(j, "height"),
                current: &current,
                activate_epoch: number(j, "activate"),
                target: &target,
                fingerprint: &fingerprint,
            };
            let decision = plan.decide(&proof)?;
            let restore = if let r::Decision::Apply(mark) = &decision {
                let mut m = mark.clone();
                match j["mutation"].as_str().unwrap() {
                    "height" => m.height = m.height.wrapping_add(1),
                    "activation" => m.activate_epoch = m.activate_epoch.wrapping_add(1),
                    "fingerprint" => m.fingerprint = b"bad".to_vec(),
                    "source" => m.source_hash = vec![0; 32],
                    "target" => m.target_hash = vec![0; 32],
                    "round" => m.round += 1,
                    "proof" => m.proof.clear(),
                    "inactive" => m.height = 1,
                    _ => (),
                }
                caught(
                    r::Plan {
                        height: number(j, "restore_height"),
                        ..plan
                    }
                    .restore(&m)
                    .map(|v| json!(v.is_some())),
                )
            } else {
                Value::Null
            };
            let proof = caught(
                r::check_proof(&chain, plan.height, &current, &proof)
                    .and_then(|(round, proof)| Ok(json!({"round":round,"proof":wires(&proof)?}))),
            );
            json!({"set":verdict(r::check_set(&current,&target)),"plan":verdict(plan.check()),"proof":proof,"decision":match decision {r::Decision::Wait=>json!("wait"),r::Decision::Refuse(e)=>json!({"refuse":e.to_string()}),r::Decision::Apply(m)=>mark(&m)?},"restore":restore})
        }
        op => panic!("unexpected recovery operation {op}"),
    })
}
#[test]
fn native_relief_marker_recovery_finality_retries_and_query_leases_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/consensus-recovery.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/consensus-recovery-oracle.ml"
        )))
    );
    let mut applied = 0;
    let mut restored = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = caught(execute(&case["input"]));
        assert_eq!(
            actual, case["expected"],
            "native recovery case {index}: {}",
            case["input"]
        );
        if actual["decision"]["proof"].is_array() {
            applied += 1;
        }
        if actual["restore"] == true {
            restored += 1;
        }
    }
    assert!(
        applied > 0 && restored > 0,
        "oracle must exercise successful authenticated recovery"
    );
}
