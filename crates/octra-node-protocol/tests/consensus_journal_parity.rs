use ed25519_dalek::{Signer as _, SigningKey};
use octra_node_protocol::consensus::{
    codec::Wire,
    vote_log::{self, VoteLog},
    Error, Vote,
};
use octra_node_protocol::consensus::{
    hash,
    sync_log::{self, SyncLog},
    RoundStep, RoundSync,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "octra-vote-journal-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn i64_(v: &Value, k: &str) -> i64 {
    v[k].as_str().unwrap().parse().unwrap()
}
fn catch(result: Result<Value, Error>) -> Value {
    result.unwrap_or_else(|e| json!({"error":e.to_string()}))
}
#[allow(clippy::needless_pass_by_value)] // Result::map adapter.
fn vote(v: Vote) -> Value {
    json!(hex::encode(v.encode().unwrap()))
}
fn mark(position: vote_log::Position) -> Value {
    json!({"epoch":position.epoch_id.to_string(),"round":position.round})
}
fn sync(j: &Value) -> RoundSync {
    let mut s = RoundSync {
        chain_id: raw(&j["chain"]),
        validator: raw(&j["validator"]),
        epoch_id: i64_(j, "epoch"),
        round: j["round"].as_i64().unwrap(),
        step: RoundStep::from_byte(j["step"].as_u64().unwrap() as u8).unwrap(),
        request: j["request"].as_bool().unwrap(),
        signature: vec![0; 64],
    };
    if !j["corrupt"].as_bool().unwrap() {
        s.signature = SigningKey::from_bytes(&[1; 32])
            .sign(&hash::round_sync_sign_bytes(&s).unwrap())
            .to_bytes()
            .to_vec();
    }
    s
}
fn execute(j: &Value) -> Result<Value, Error> {
    Ok(match j["op"].as_str().unwrap() {
        "sync_meta" => {
            let s = sync(j);
            json!({"key":hex::encode(sync_log::key(&s)),"name":sync_log::name(&s),"valid":sync_log::valid(&s),"wire":hex::encode(s.encode()?)})
        }
        "sync_epoch" => json!(sync_log::epoch_of_name(&raw(&j["value"])).map(|e| e.to_string())),
        "sync_trace" => {
            let dir = Temp::new();
            let disk = j["mode"] == "disk";
            let mut log = if disk {
                SyncLog::disk(&dir.0)
            } else {
                SyncLog::memory()
            };
            let public = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
            let mut results = Vec::new();
            for step in j["steps"].as_array().unwrap() {
                let result = match step["op"].as_str().unwrap() {
                    "keep" => log
                        .keep(sync(step), &public)
                        .and_then(|s| s.encode())
                        .map(|wire| json!(hex::encode(wire))),
                    "load" => log
                        .load(
                            &raw(&step["chain"]),
                            &raw(&step["validator"]),
                            i64_(step, "epoch"),
                            &public,
                        )
                        .map(|rows| {
                            json!(rows
                                .iter()
                                .map(|s| hex::encode(s.encode().unwrap()))
                                .collect::<Vec<_>>())
                        }),
                    "prune" => log.prune(i64_(step, "epoch")).map(|()| Value::Null),
                    _ => panic!("unknown sync trace"),
                };
                results.push(catch(result));
                if disk {
                    log = SyncLog::disk(&dir.0);
                }
            }
            json!(results)
        }
        "meta" => {
            let v = Vote::decode(&raw(&j["wire"]))?;
            json!({"key":hex::encode(vote_log::key(&v)),"name":vote_log::name(&v),"position":vote_log::record_position(vote_log::name(&v).as_bytes()).map(mark),"wire":catch(vote_log::vote_of_wire(&raw(&j["wire"])).map(vote))})
        }
        "decode" => catch(vote_log::vote_of_wire(&raw(&j["wire"])).map(vote)),
        "position" => vote_log::record_position(&raw(&j["value"])).map_or(Value::Null, mark),
        kind @ ("floor" | "mark") => {
            let dir = Temp::new();
            let p = dir.0.join("vote_log");
            fs::create_dir(&p).unwrap();
            fs::write(
                p.join(if kind == "floor" {
                    "floor"
                } else {
                    "round_mark"
                }),
                raw(&j["wire"]),
            )
            .unwrap();
            let store = VoteLog::disk(&dir.0);
            if kind == "floor" {
                catch(store.floor().map(|v| json!(v.map(|n| n.to_string()))))
            } else {
                catch(store.round_mark().map(|v| v.map_or(Value::Null, mark)))
            }
        }
        "trace" => {
            let dir = Temp::new();
            let disk = j["mode"] == "disk";
            let mut store = if disk {
                VoteLog::disk(&dir.0)
            } else {
                VoteLog::memory()
            };
            let mut results = Vec::new();
            for step in j["steps"].as_array().unwrap() {
                let epoch = i64_(step, "epoch");
                let round = step["round"].as_i64().unwrap();
                let result = catch((|| -> Result<Value, Error> {
                    Ok(match step["op"].as_str().unwrap() {
                        "floor" => {
                            store.set_floor(epoch)?;
                            Value::Null
                        }
                        "mark" => {
                            store.set_round_mark(epoch, round)?;
                            Value::Null
                        }
                        "keep" => vote(store.keep(Vote::decode(&raw(&step["wire"]))?)?),
                        "check" => {
                            store.check(&Vote::decode(&raw(&step["wire"]))?)?;
                            Value::Null
                        }
                        "find" => store
                            .find_statement(&Vote::decode(&raw(&step["wire"]))?)?
                            .map_or(Value::Null, vote),
                        "prune" => {
                            store.prune(epoch)?;
                            Value::Null
                        }
                        "corrupt" => {
                            let v = Vote::decode(&raw(&step["wire"]))?;
                            let path = dir.0.join("vote_log");
                            fs::create_dir_all(&path).unwrap();
                            fs::write(path.join(vote_log::name(&v)), raw(&step["data"])).unwrap();
                            Value::Null
                        }
                        _ => Value::Null,
                    })
                })());
                if disk {
                    store = VoteLog::disk(&dir.0);
                }
                results.push(json!({"result":result,"floor":catch(store.floor().map(|v|json!(v.map(|n|n.to_string())))),"mark":catch(store.round_mark().map(|v|v.map_or(Value::Null,mark))),"max":catch(store.max_round(&raw(&j["chain"]),&raw(&j["validator"]),epoch).map(|v|json!(v)))}));
            }
            json!(results)
        }
        _ => panic!("unknown journal case"),
    })
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/consensus-journal.json")).unwrap()
}
#[test]
fn native_vote_journal_bytes_conflicts_corruption_and_restart() {
    let f = fixture();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], manifest["upstream_commit"]);
    for (p, h) in f["source_sha256"].as_object().unwrap() {
        assert_eq!(*h, manifest["files"][p]);
    }
    for (index, c) in f["cases"].as_array().unwrap().iter().enumerate() {
        assert_eq!(
            catch(execute(&c["input"])),
            c["expected"],
            "journal case {index} {}",
            c["input"]["op"]
        );
    }
}
#[test]
fn concurrent_conflicting_publication_never_replaces_existing_statement() {
    let f = fixture();
    let vote = Vote::decode(&raw(&f["cases"][0]["input"]["wire"])).unwrap();
    let mut conflicting = vote.clone();
    conflicting.proposal_id[0] ^= 1;
    let dir = Temp::new();
    let path = dir.0.clone();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let worker = std::thread::spawn(move || {
        let mut log = VoteLog::disk(path);
        other.wait();
        log.keep(conflicting)
    });
    let mut log = VoteLog::disk(&dir.0);
    barrier.wait();
    let first = log.keep(vote);
    let second = worker.join().unwrap();
    assert_ne!(first.is_ok(), second.is_ok());
    let accepted = first.as_ref().ok().or(second.as_ref().ok()).unwrap();
    let rejected = first.as_ref().err().or(second.as_ref().err()).unwrap();
    assert_eq!(
        rejected.to_string(),
        "local vote conflicts with stored vote"
    );
    assert_eq!(
        log.find_statement(accepted).unwrap(),
        Some(accepted.clone())
    );
    assert_eq!(fs::read_dir(dir.0.join("vote_log")).unwrap().count(), 1);
}
