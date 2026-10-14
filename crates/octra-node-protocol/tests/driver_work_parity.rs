use octra_node_protocol::consensus::{
    driver_work::{
        OutputActor, Relay, RelayEffect, RelayItem, RelayMessage, RelayOutcome, WorkEffect,
        WorkMessage, WorkSlot,
    },
    round_pool::RoundPool,
    RoundStep, RoundSync, Validator, ValidatorSet,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn n(j: &Value, k: &str) -> i64 {
    j[k].as_i64().unwrap()
}
fn s<'a>(j: &'a Value, k: &str) -> &'a str {
    j[k].as_str().unwrap()
}
fn b(j: &Value, k: &str) -> bool {
    j[k].as_bool().unwrap()
}
fn f(j: &Value, k: &str) -> f64 {
    s(j, k).parse().unwrap()
}
fn i(j: &Value, k: &str) -> i64 {
    s(j, k).parse().unwrap()
}
fn raw(j: &Value, k: &str) -> Vec<u8> {
    hex::decode(s(j, k)).unwrap()
}
fn time(f: f64) -> Value {
    json!(format!("{:016x}", f.to_bits()))
}
fn item(j: &Value) -> RelayItem<i64> {
    RelayItem {
        key: raw(j, "key"),
        value: n(j, "value"),
        expires: f(j, "expires"),
    }
}
fn ji(v: &RelayItem<i64>) -> Value {
    json!({"key":hex::encode(&v.key),"value":v.value,"expires":time(v.expires)})
}
fn effect(e: RelayEffect<i64>) -> Value {
    match e {
        RelayEffect::Cancel => json!("cancel"),
        RelayEffect::Dropped(reason) => json!(["dropped", hex::encode(reason)]),
        RelayEffect::Send(id, v) => json!(["send", id, ji(&v)]),
    }
}
fn sync(j: &Value) -> RoundSync {
    RoundSync {
        chain_id: raw(j, "chain"),
        epoch_id: i(j, "epoch"),
        round: n(j, "round"),
        step: RoundStep::from_byte(n(j, "step") as u8).unwrap(),
        request: b(j, "request"),
        validator: raw(j, "validator"),
        signature: raw(j, "signature"),
    }
}
fn js(v: &RoundSync) -> Value {
    json!({"chain":hex::encode(&v.chain_id),"epoch":v.epoch_id.to_string(),"round":v.round,"step":v.step as u8,"request":v.request,"validator":hex::encode(&v.validator),"signature":hex::encode(&v.signature)})
}
fn run(j: &Value) -> Value {
    let steps = j["steps"].as_array().unwrap();
    match s(j, "kind") {
        "actor" => {
            let mut actor = OutputActor::default();
            json!(steps
                .iter()
                .map(|step| {
                    let result = match step.as_str().unwrap() {
                        "request" => json!(if actor.request() { "start" } else { "join" }),
                        "complete" => json!(if actor.complete() { "continue" } else { "stop" }),
                        _ => {
                            actor.fail();
                            Value::Null
                        }
                    };
                    json!({"result":result,"idle":actor.idle()})
                })
                .collect::<Vec<_>>())
        }
        "work" => {
            let mut slot = WorkSlot::default();
            let mut last = -1;
            json!(steps
                .iter()
                .map(|j| {
                    let message = match s(j, "op") {
                        "submit" => WorkMessage::Submit(n(j, "job")),
                        "take" => WorkMessage::Take,
                        "open" => WorkMessage::Open,
                        "close" => WorkMessage::Close,
                        _ => WorkMessage::Finish(
                            if b(j, "active") { last } else { n(j, "id") },
                            n(j, "reply"),
                        ),
                    };
                    let effects = slot
                        .step(message)
                        .map(|e| match e {
                            WorkEffect::Run(id, job) => {
                                last = id;
                                json!(["run", id, job])
                            }
                            WorkEffect::Complete(job) => json!(["complete", job]),
                            WorkEffect::Deliver(job, reply) => json!(["deliver", job, reply]),
                        })
                        .into_iter()
                        .collect::<Vec<_>>();
                    json!({"idle":slot.idle(),"ready":slot.ready(),"effects":effects})
                })
                .collect::<Vec<_>>())
        }
        "relay" => {
            let mut relay = Relay {
                serial: n(j, "serial"),
                ..Relay::default()
            };
            json!(steps.iter().map(|j| {
                let message=match s(j,"op") {
                    "offer"=>RelayMessage::Offer { generation:n(j,"generation"),now:f(j,"now"),item:item(j) },
                    "advance"=>RelayMessage::Advance { generation:n(j,"generation"),now:f(j,"now") },
                    "open"=>RelayMessage::Open(n(j,"generation")),"close"=>RelayMessage::Close,
                    _=>RelayMessage::Finished { serial:if b(j,"active"){relay.active.as_ref().map_or(-1,|(id,_)|*id)}else{n(j,"id")},now:f(j,"now"),outcome:match s(j,"outcome") {
                        "sent"=>RelayOutcome::Sent,"expired"=>RelayOutcome::Expired,"cancelled"=>RelayOutcome::Cancelled,_=>RelayOutcome::Failed(raw(j,"reason")),
                    } },
                };
                let effects=relay.step(message).into_iter().map(effect).collect::<Vec<_>>();
                json!({"generation":relay.generation,"serial":relay.serial,"active":relay.active.as_ref().map(|(id,v)|json!([id,ji(v)])),
                    "queue":relay.queue.iter().map(ji).collect::<Vec<_>>(),"seen":relay.seen.iter().map(hex::encode).collect::<Vec<_>>(),"closed":relay.closed,"effects":effects})
            }).collect::<Vec<_>>())
        }
        "pool" => {
            let entries = j["validators"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(idx, v)| {
                    (
                        Validator {
                            address: raw(v, "address"),
                            pubkey: vec![(idx + 1) as u8; 32],
                        },
                        s(v, "weight").parse().unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let validators = if b(j, "weighted") {
                ValidatorSet::weighted(entries).unwrap()
            } else {
                ValidatorSet::unweighted(entries.into_iter().map(|(v, _)| v).collect())
            };
            let mut pool = RoundPool::default();
            json!(steps.iter().map(|action| {
                match s(action,"op") {
                    "clear"=>pool.clear(),"add"=>pool.add(sync(&action["sync"]),f(action,"now")),
                    "local"=>pool.add_local(sync(&action["sync"]),f(action,"now")),
                    "add_at"=>pool.add_at(n(action,"current"),sync(&action["sync"]),f(action,"now")),_=>(),
                }
                action["queries"].as_array().unwrap().iter().map(|q| {
                    let epoch=i(q,"epoch");let after=n(q,"after");let through=n(q,"through");
                    json!({"reply":pool.reply(epoch,&raw(q,"validator")).map(|(s,t)|json!([js(s),time(*t)])),
                        "sent":pool.sent_reply(epoch,after,through).map(js),
                        "range":pool.sent_range(epoch,after,through).iter().map(js).collect::<Vec<_>>(),
                        "witness":pool.witness(&raw(q,"chain"),epoch,after,through,&validators).iter().map(js).collect::<Vec<_>>()})
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>())
        }
        kind => panic!("unknown trace {kind}"),
    }
}
#[test]
fn native_proposal_work_relay_and_round_history_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/driver-work.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    for (field, path) in [
        ("oracle_sha256", "scripts/node-port/driver-work-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            fixture[field],
            hex::encode(Sha256::digest(std::fs::read(root.join(path)).unwrap()))
        );
    }
    let instrumentation = fixture["instrumentation"].as_object().unwrap();
    assert_eq!(instrumentation.len(), 1);
    let clock = &instrumentation["lib/consensus/c_round_pool.ml"];
    assert_eq!(
        clock["original_sha256"],
        inventory["files"]["lib/consensus/c_round_pool.ml"]
    );
    assert_eq!(clock["prefix"],"module Unix = struct include Unix let gettimeofday () = float_of_string (Sys.getenv \"OCTRA_ROUND_POOL_ORACLE_TIME\") end\n");
    assert_eq!(clock["replacements"], json!([]));
    let cases = fixture["cases"].as_array().unwrap();
    for (index, case) in cases.iter().enumerate() {
        if matches!(case["input"]["kind"].as_str(), Some("gate" | "async_relay")) {
            continue;
        }
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "native trace {index}: {}",
            case["input"]
        );
    }
}
