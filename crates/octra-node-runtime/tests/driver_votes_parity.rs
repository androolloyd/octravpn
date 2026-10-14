use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::consensus::{
    codec::Wire,
    engine::{self, Engine, TimeoutConfig},
    hash,
    journal::JournalOwner,
    policy::Protocol,
    EpochHeader, Error, Proposal, Validator, ValidatorSet, Vote, VoteType,
};
use octra_node_runtime::consensus_votes::{Precommit, Readiness, VoteGuard};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
const CHAIN: &[u8] = b"vote-guard-fixture";
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn address(n: u8) -> Vec<u8> {
    format!("v{n}").into_bytes()
}
fn raw(j: &Value, k: &str) -> Vec<u8> {
    hex::decode(j[k].as_str().unwrap()).unwrap()
}
fn integer(j: &Value, k: &str) -> i64 {
    j[k].as_str().unwrap().parse().unwrap()
}
fn validators() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|n| Validator {
                address: address(n),
                pubkey: key(n).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    )
}
fn engine(local: u8, height: i64) -> Engine {
    Engine::new(
        CHAIN.to_vec(),
        address(local),
        validators(),
        height,
        Protocol::default(),
        TimeoutConfig::default(),
    )
}
fn proposal(j: &Value) -> Proposal {
    let chain_id = raw(j, "chain");
    let epoch_id = integer(j, "epoch");
    let header = EpochHeader {
        proto_version: Protocol::default().version_at(epoch_id),
        chain_id: chain_id.clone(),
        epoch_id,
        prev_state_root: vec![0; 32],
        tx_list_hash: engine::tx_list_hash_for_header(&[]).to_vec(),
        receipt_root: hash::receipt_root(&[]).unwrap().to_vec(),
        proposed_state_root: vec![3; 32],
        parent_commit_hash: vec![0; 32],
        creator_addr: b"v1".to_vec(),
        txid_hi: 7,
        ts: 1.,
    };
    let mut p = Proposal {
        chain_id,
        epoch_id,
        round: j["round"].as_i64().unwrap(),
        valid_round: None,
        header,
        tx_hashes: vec![],
        parent_commit: None,
        proposer: b"v1".to_vec(),
        signature: vec![],
    };
    p.signature = key(1)
        .sign(&hash::propose_sign_bytes(&p).unwrap())
        .to_bytes()
        .to_vec();
    p
}
fn vote(j: &Value) -> Vote {
    let p = proposal(j);
    let proposal_id = match j["pid"].as_str().unwrap() {
        "nil" => vec![0; 32],
        "other" => vec![4; 32],
        _ => hash::proposal_id(&p.header).unwrap().to_vec(),
    };
    let signer = j["signer"].as_u64().unwrap() as u8;
    let mut v = Vote {
        chain_id: p.chain_id,
        epoch_id: p.epoch_id,
        round: p.round,
        vote_type: if j["type"] == 1 {
            VoteType::Prevote
        } else {
            VoteType::Precommit
        },
        proposal_id,
        validator: address(signer),
        signature: vec![0; 64],
    };
    if !j["corrupt"].as_bool().unwrap() {
        v.signature = key(signer)
            .sign(&hash::vote_sign_bytes(&v).unwrap())
            .to_bytes()
            .to_vec();
    }
    v
}
fn proposed(j: &Value) -> Option<Proposal> {
    let mut p = proposal(j);
    match j["proposal"].as_str().unwrap() {
        "missing" => return None,
        "round" => p.round += 1,
        "chain" => p.chain_id = b"other".to_vec(),
        "header" => p.header.chain_id = b"other".to_vec(),
        _ => (),
    }
    Some(p)
}
fn saved(value: Precommit) -> Value {
    json!({"epoch":value.epoch_id.to_string(),"round":value.round,"pid":hex::encode(value.proposal_id),"root":hex::encode(value.proposed_state_root),"txid":value.txid_hi.to_string(),"proposal":hex::encode(value.proposal_wire),"vote":hex::encode(value.vote_wire)})
}
fn result<T>(r: Result<T, Error>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => f(v),
        Err(e) => json!({"error":e.to_string()}),
    }
}
async fn trace(j: &Value) -> Vec<Value> {
    let dir = tempfile::tempdir().unwrap();
    let owner = JournalOwner::open(dir.path()).unwrap();
    let local = j["local"].as_u64().unwrap() as u8;
    let mut engine = engine(local, integer(j, "height"));
    let mut guard = VoteGuard::new(CHAIN.to_vec(), address(local), owner.clone());
    let mut ready = Readiness {
        role_can_vote: true,
        can_vote: true,
        finality_proof_needed: false,
    };
    let mut running = false;
    let mut calls = vec![];
    let mut results = vec![];
    for step in j["steps"].as_array().unwrap() {
        let answer = match step["op"].as_str().unwrap() {
            "prepare" => {
                let wires = if let Some(error) = step["restore_error"].as_str() {
                    Err(Error::from(error))
                } else {
                    Ok(step["wires"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|j| {
                            if j["raw"].is_null() {
                                vote(j).encode().unwrap()
                            } else {
                                raw(j, "raw")
                            }
                        })
                        .collect())
                };
                result(guard.prepare(running, &mut engine, wires), |()| Value::Null)
            }
            "save" => {
                let v = vote(&step["vote"]);
                let p = proposed(&step["vote"]);
                result(
                    guard
                        .save(
                            &engine,
                            &v,
                            p.as_ref(),
                            ready.finality_proof_needed,
                            |data| {
                                calls.push(saved(data));
                                std::future::ready(step["persist"].as_bool().unwrap())
                            },
                        )
                        .await,
                    |v| v.map_or(Value::Null, |v| json!(hex::encode(v.encode().unwrap()))),
                )
            }
            "floor" => result(owner.set_floor(integer(step, "epoch")), |()| Value::Null),
            "flags" => {
                running = step["running"].as_bool().unwrap();
                ready = Readiness {
                    role_can_vote: step["role"].as_bool().unwrap(),
                    can_vote: step["ready"].as_bool().unwrap(),
                    finality_proof_needed: step["finality"].as_bool().unwrap(),
                };
                Value::Null
            }
            _ => Value::Null,
        };
        results.push(json!({"result":answer,"issue":guard.issue().map(ToString::to_string),"fault":guard.fault().map(|f|json!({"epoch":f.epoch_id.to_string(),"round":f.round,"reason":f.reason})),
            "state":guard.state(&engine,ready),"allowed":guard.allowed(ready),"bootstrap":guard.bootstrap_pending(),"round":engine.state().round,
            "floor":result(owner.floor(),|v|json!(v.map(|v|v.to_string()))),"calls":calls}));
    }
    results
}
#[tokio::test]
async fn native_local_vote_bootstrap_recovery_and_durability_match() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/driver-votes.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        ("oracle_sha256", "scripts/node-port/driver-votes-oracle.ml"),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            fixture[field],
            hex::encode(Sha256::digest(std::fs::read(root.join(path)).unwrap()))
        );
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 164);
    for (case_index, case) in cases.iter().enumerate() {
        let actual = trace(&case["input"]).await;
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(actual.len(), expected.len());
        for (index, (a, e)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                a, e,
                "native vote guard trace {case_index}, step {index}: {}",
                case["input"]["steps"][index]
            );
        }
    }
}

#[tokio::test]
async fn cancelled_precommit_cannot_become_a_durable_vote_and_retry_rechecks_host() {
    let dir = tempfile::tempdir().unwrap();
    let owner = JournalOwner::open(dir.path()).unwrap();
    let mut engine = engine(1, 1);
    let mut guard = VoteGuard::new(CHAIN.to_vec(), address(1), owner.clone());
    guard.prepare(false, &mut engine, Ok(vec![])).unwrap();
    let j = json!({"chain":hex::encode(CHAIN),"epoch":"1","round":0,"type":2,"pid":"bound","signer":1,"corrupt":false,"proposal":"present"});
    let v = vote(&j);
    let p = proposal(&j);
    let mut called = false;
    let mut save = Box::pin(guard.save(&engine, &v, Some(&p), false, |_| {
        called = true;
        std::future::pending::<bool>()
    }));
    assert!(futures::poll!(&mut save).is_pending());
    drop(save);
    assert!(called);
    assert!(owner.find_vote(&v).unwrap().is_none());
    let mut retries = 0;
    assert!(guard
        .save(&engine, &v, Some(&p), false, |_| {
            retries += 1;
            std::future::ready(false)
        })
        .await
        .unwrap()
        .is_none());
    assert!(owner.find_vote(&v).unwrap().is_none());
    assert!(guard
        .save(&engine, &v, Some(&p), false, |_| {
            retries += 1;
            std::future::ready(true)
        })
        .await
        .unwrap()
        .is_some());
    assert_eq!(retries, 2);
    assert_eq!(owner.find_vote(&v).unwrap(), Some(v.clone()));
    drop(guard);
    drop(owner);
    let owner = JournalOwner::open(dir.path()).unwrap();
    let mut guard = VoteGuard::new(CHAIN.to_vec(), address(1), owner);
    guard.prepare(false, &mut engine, Ok(vec![])).unwrap();
    assert_eq!(engine.state().round, 1);
}
