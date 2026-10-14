#![cfg(unix)]
use octra_node_protocol::consensus::{
    codec::Wire,
    journal::JournalOwner,
    relief::Mark,
    relief_log::{self, ReliefLog},
    Error, RoundSync,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "octra-relief-{}-{}",
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
fn mark(v: &Value) -> Mark {
    Mark {
        height: v["height"].as_str().unwrap().parse().unwrap(),
        round: v["round"].as_i64().unwrap(),
        activate_epoch: v["activate_epoch"].as_str().unwrap().parse().unwrap(),
        source_hash: raw(&v["source_hash"]),
        target_hash: raw(&v["target_hash"]),
        fingerprint: raw(&v["fingerprint"]),
        proof: v["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| RoundSync::decode(&raw(v)).unwrap())
            .collect(),
    }
}
fn jm(m: &Mark) -> Value {
    json!({"height":m.height.to_string(),"round":m.round,"activate_epoch":m.activate_epoch.to_string(),"source_hash":hex::encode(&m.source_hash),"target_hash":hex::encode(&m.target_hash),"fingerprint":hex::encode(&m.fingerprint),"proof":m.proof.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>()})
}
fn result<T>(value: Result<T, Error>, encode: impl FnOnce(T) -> Value) -> Value {
    match value {
        Ok(v) => encode(v),
        Err(error) => {
            let error = error.to_string();
            let error = if error.starts_with("journal I/O:") {
                "os"
            } else if error.starts_with("invalid native JSON") {
                "json"
            } else {
                &error
            };
            json!({"error":error})
        }
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/relief-log.json")).unwrap()
}
fn trace(j: &Value) -> Vec<Value> {
    let dir = Temp::new();
    let disk = j["mode"] == "disk";
    let root = dir.0.join("relief_log");
    let mut log = if disk {
        ReliefLog::disk(&dir.0)
    } else {
        ReliefLog::memory()
    };
    j["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            let height = step["height"].as_str().unwrap().parse().unwrap();
            let record = root.join(relief_log::name(height));
            match step["op"].as_str().unwrap() {
                "keep" => result(log.keep(mark(&step["mark"])), |m| jm(&m)),
                "latest" => result(log.latest(height), |m| m.map_or(Value::Null, |m| jm(&m))),
                "prune" => result(log.prune(height), |()| Value::Null),
                "restart" => {
                    if disk {
                        log = ReliefLog::disk(&dir.0);
                    }
                    Value::Null
                }
                "read" => json!(hex::encode(fs::read(record).unwrap())),
                "corrupt" | "file" => {
                    fs::create_dir_all(&root).unwrap();
                    let path = if step["op"] == "file" {
                        use std::os::unix::ffi::OsStringExt;
                        root.join(std::ffi::OsString::from_vec(raw(&step["name"])))
                    } else {
                        record
                    };
                    fs::write(path, raw(&step["data"])).unwrap();
                    Value::Null
                }
                "symlink" => {
                    fs::create_dir_all(&root).unwrap();
                    let backing = dir.0.join("backing");
                    fs::write(&backing, raw(&step["data"])).unwrap();
                    std::os::unix::fs::symlink(backing, record).unwrap();
                    Value::Null
                }
                "stage" => {
                    fs::create_dir_all(&root).unwrap();
                    for attempt in 0..step["count"].as_u64().unwrap() {
                        let mut name = record.as_os_str().to_owned();
                        name.push(format!(".staged.{}.{attempt}", std::process::id()));
                        fs::write(PathBuf::from(name), b"stale").unwrap();
                    }
                    Value::Null
                }
                _ => panic!("unknown fixture operation"),
            }
        })
        .collect()
}
#[test]
fn native_relief_journal_bytes_recovery_conflicts_and_pruning() {
    let fixture = fixture();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        ("oracle_sha256", "scripts/node-port/relief-log-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            fixture[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let actual = trace(&case["input"]);
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(actual.len(), expected.len());
        for (step, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                actual, expected,
                "native relief journal trace {index} step {step}: {}",
                case["input"]["steps"][step]
            );
        }
    }
}
#[test]
fn conflicting_relief_writers_publish_exactly_one_durable_plan() {
    let f = fixture();
    let original = mark(&f["cases"][0]["input"]["steps"][1]["mark"]);
    let mut changed = original.clone();
    changed.fingerprint = vec![b'e'; 64];
    let dir = Temp::new();
    let gate = Arc::new(Barrier::new(2));
    let tasks = [original, changed].map(|m| {
        let path = dir.0.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            gate.wait();
            ReliefLog::disk(path).keep(m)
        })
    });
    let results = tasks.map(|t| t.join().unwrap());
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .find_map(|r| r.as_ref().err())
            .unwrap()
            .to_string(),
        "relief log plan conflicts"
    );
    let stored = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(
        ReliefLog::disk(&dir.0).latest(stored.height).unwrap(),
        Some(stored)
    );
    assert_eq!(fs::read_dir(dir.0.join("relief_log")).unwrap().count(), 1);
}
#[test]
fn relief_uses_exclusive_journal_owner_and_survives_reopen() {
    let f = fixture();
    let m = mark(&f["cases"][0]["input"]["steps"][1]["mark"]);
    let dir = Temp::new();
    let owner = JournalOwner::open(&dir.0).unwrap();
    owner.keep_relief(m.clone()).unwrap();
    assert!(JournalOwner::open(&dir.0).is_err());
    let worker = owner.clone();
    drop(owner);
    assert!(JournalOwner::open(&dir.0).is_err());
    assert_eq!(worker.latest_relief(m.height).unwrap(), Some(m.clone()));
    drop(worker);
    let owner = JournalOwner::open(&dir.0).unwrap();
    assert_eq!(owner.latest_relief(m.height).unwrap(), Some(m.clone()));
    let prune = owner.prune_finalized(m.activate_epoch - 1).unwrap();
    prune.votes.unwrap();
    prune.syncs.unwrap();
    prune.relief.unwrap();
    assert_eq!(owner.latest_relief(m.height).unwrap(), None);
}

#[test]
fn restored_relief_reauthenticates_the_plan_and_every_witness() {
    use ed25519_dalek::{Signer, SigningKey};
    use octra_node_protocol::consensus::{
        hash,
        policy::DEVNET,
        relief::{Decision, Plan},
        RoundStep, Validator, ValidatorSet,
    };
    let keys = (1..=7)
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .collect::<Vec<_>>();
    let entries = keys
        .iter()
        .enumerate()
        .map(|(n, key)| {
            (
                Validator {
                    address: format!("validator-{n}").into_bytes(),
                    pubkey: key.verifying_key().to_bytes().to_vec(),
                },
                1.into(),
            )
        })
        .collect::<Vec<_>>();
    let current = ValidatorSet::weighted(entries.clone()).unwrap();
    let target = ValidatorSet::weighted(entries[..6].to_vec()).unwrap();
    let proof = keys
        .iter()
        .enumerate()
        .map(|(n, key)| {
            let mut s = RoundSync {
                chain_id: DEVNET.to_vec(),
                epoch_id: 1_380_000,
                round: 64,
                step: RoundStep::Precommit,
                request: false,
                validator: entries[n].0.address.clone(),
                signature: vec![],
            };
            s.signature = key
                .sign(&hash::round_sync_sign_bytes(&s).unwrap())
                .to_bytes()
                .to_vec();
            s
        })
        .collect::<Vec<_>>();
    let plan = Plan {
        chain_id: DEVNET,
        height: 1_380_000,
        current: &current,
        activate_epoch: 1_380_020,
        target: &target,
        fingerprint: b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    let Decision::Apply(mark) = plan.decide(&proof).unwrap() else {
        panic!("fixture relief must be authenticated");
    };
    let dir = Temp::new();
    let owner = JournalOwner::open(&dir.0).unwrap();
    owner.keep_relief(mark.clone()).unwrap();
    drop(owner);
    let owner = JournalOwner::open(&dir.0).unwrap();
    let saved = owner.latest_relief(plan.height).unwrap().unwrap();
    assert_eq!(plan.restore(&saved).unwrap(), Some(&target));
    let record = dir.0.join("relief_log").join(relief_log::name(mark.height));
    let mut altered = mark;
    altered.proof[0].signature[0] ^= 1;
    fs::write(record, relief_log::encode(&altered).unwrap()).unwrap();
    let saved = owner.latest_relief(plan.height).unwrap().unwrap();
    assert_eq!(
        plan.restore(&saved).unwrap_err().to_string(),
        "validator relief proof signature is invalid"
    );
}
