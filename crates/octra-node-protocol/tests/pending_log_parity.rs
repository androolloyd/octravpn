#![cfg(unix)]
use octra_node_protocol::consensus::{
    journal::JournalOwner,
    pending_log::{self, PendingCommit},
    Error,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "octra-pending-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn raw(j: &Value) -> Vec<u8> {
    hex::decode(j.as_str().unwrap()).unwrap()
}
fn record(j: &Value) -> PendingCommit {
    PendingCommit {
        epoch_id: j["epoch"].as_i64().unwrap(),
        round: j["round"].as_i64().unwrap(),
        proposal_id: raw(&j["pid"]),
        proposed_state_root: raw(&j["root"]),
        txid_hi: j["txid"].as_str().unwrap().parse().unwrap(),
        ts: f64::from_bits(u64::from_str_radix(j["time"].as_str().unwrap(), 16).unwrap()),
        validator_addr: raw(&j["validator"]),
        proposal_b64: j["proposal"].as_str().map(|_| raw(&j["proposal"])),
        vote_b64: j["vote"].as_str().map(|_| raw(&j["vote"])),
        tx_hashes: j["hashes"].as_array().unwrap().iter().map(raw).collect(),
        txs_json: j["txs"].as_array().unwrap().iter().map(raw).collect(),
        receipts_json: j["receipts"].as_array().unwrap().iter().map(raw).collect(),
    }
}
fn jr(p: &PendingCommit) -> Value {
    json!({"epoch":p.epoch_id,"round":p.round,"pid":hex::encode(&p.proposal_id),"root":hex::encode(&p.proposed_state_root),"txid":p.txid_hi.to_string(),"time":format!("{:016x}",p.ts.to_bits()),"validator":hex::encode(&p.validator_addr),"proposal":p.proposal_b64.as_ref().map(hex::encode),"vote":p.vote_b64.as_ref().map(hex::encode),"hashes":p.tx_hashes.iter().map(hex::encode).collect::<Vec<_>>(),"txs":p.txs_json.iter().map(hex::encode).collect::<Vec<_>>(),"receipts":p.receipts_json.iter().map(hex::encode).collect::<Vec<_>>()})
}
fn result<T>(r: Result<T, Error>, encode: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => encode(v),
        Err(e) => {
            let s = e.to_string();
            let e = if s.starts_with("journal I/O:") {
                "os"
            } else if s.starts_with("invalid native JSON") {
                "json"
            } else if s == "pending commit position differs from filename" {
                "position"
            } else if s == "WAL directory is not a directory" {
                "directory"
            } else if s == "pending commit is not regular" {
                "pending commit is not a regular file"
            } else if s == "pending commit txid is invalid" {
                "Int64.of_string"
            } else if s.contains("required") {
                "type"
            } else {
                &s
            };
            json!({"error":e})
        }
    }
}
fn run(j: &Value) -> Value {
    match j["kind"].as_str().unwrap() {
        "encode" => result(
            record(&j["record"])
                .encode()
                .and_then(|wire| PendingCommit::decode(&wire).map(|p| (wire, p))),
            |(wire, p)| json!({"wire":hex::encode(wire),"parsed":jr(&p)}),
        ),
        "parse" => result(PendingCommit::decode(&raw(&j["wire"])), |p| jr(&p)),
        _ => {
            let dir = Temp::new();
            let owner = JournalOwner::open(&dir.0).unwrap();
            let answers = j["steps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|step| {
                    let epoch = step["epoch"].as_i64().unwrap();
                    let round = step["round"].as_i64().unwrap();
                    let path = dir.0.join("wal").join(pending_log::name(epoch, round));
                    match step["op"].as_str().unwrap() {
                        "keep" => result(owner.keep_pending(&record(&step["record"])), |()| {
                            Value::Null
                        }),
                        "read" => result(owner.pending(), |v| {
                            json!(v.iter().map(jr).collect::<Vec<_>>())
                        }),
                        "wire" => json!(hex::encode(fs::read(path).unwrap())),
                        "delete" => result(owner.delete_pending(epoch, round), |()| Value::Null),
                        "delete_epoch" => {
                            result(owner.delete_pending_epoch(epoch), |()| Value::Null)
                        }
                        "corrupt" => {
                            fs::create_dir_all(path.parent().unwrap()).unwrap();
                            fs::write(path, raw(&step["data"])).unwrap();
                            Value::Null
                        }
                        "oversize" => {
                            fs::create_dir_all(path.parent().unwrap()).unwrap();
                            fs::File::create(path)
                                .unwrap()
                                .set_len(pending_log::MAX_BYTES + 1)
                                .unwrap();
                            Value::Null
                        }
                        _ => Value::Null,
                    }
                })
                .collect::<Vec<_>>();
            json!(answers)
        }
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/pending-log.json")).unwrap()
}
#[test]
fn native_pending_commit_bytes_legacy_input_conflicts_and_restart_reads() {
    let f = fixture();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(f["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        ("oracle_sha256", "scripts/node-port/pending-log-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            f[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    for (index, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let actual = run(&case["input"]);
        if let Some(steps) = actual.as_array() {
            let expected = case["expected"].as_array().unwrap();
            assert_eq!(steps.len(), expected.len());
            for (step, (a, e)) in steps.iter().zip(expected).enumerate() {
                assert_eq!(
                    a, e,
                    "native pending trace {index} step {step}: {}",
                    case["input"]["steps"][step]
                );
            }
        } else {
            assert_eq!(
                actual, case["expected"],
                "native pending case {index}: {}",
                case["input"]
            );
        }
    }
}
#[test]
fn pending_owner_reopens_and_refuses_staging_symlinks() {
    let f = fixture();
    let record = record(&f["cases"][0]["input"]["record"]);
    let dir = Temp::new();
    let owner = JournalOwner::open(&dir.0).unwrap();
    owner.keep_pending(&record).unwrap();
    drop(owner);
    let owner = JournalOwner::open(&dir.0).unwrap();
    assert_eq!(owner.pending().unwrap(), vec![record.clone()]);
    owner.delete_pending(record.epoch_id, record.round).unwrap();
    let victim = dir.0.join("unrelated");
    fs::write(&victim, b"must remain unchanged").unwrap();
    let path = dir.0.join("wal").join(format!(
        "{}.staged",
        pending_log::name(record.epoch_id, record.round)
    ));
    std::os::unix::fs::symlink(&victim, &path).unwrap();
    assert!(owner.keep_pending(&record).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"must remain unchanged");
    assert!(owner.pending().unwrap().is_empty());
    fs::remove_file(path).unwrap();
    owner.keep_pending(&record).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(
        dir.0
            .join("wal")
            .join(pending_log::name(record.epoch_id, record.round)),
    )
    .unwrap()
    .permissions()
    .mode();
    assert_eq!(mode & 0o077, 0);
}
