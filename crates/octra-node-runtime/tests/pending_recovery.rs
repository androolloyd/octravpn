use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{
        codec::Wire, journal::JournalOwner, pending_log::PendingCommit, policy::Protocol,
        Validator, ValidatorSet,
    },
    transaction::RuleMode,
    transaction_outcome,
};
use octra_node_runtime::{
    consensus_bundle::{self as bundle, RawBundle, Rules},
    consensus_recovery::{self as recovery, Context},
    consensus_votes::Precommit,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
fn raw(j: &Value) -> Vec<u8> {
    hex::decode(j.as_str().unwrap()).unwrap()
}
fn validators() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|n| Validator {
                address: format!("v{n}").into_bytes(),
                pubkey: SigningKey::from_bytes(&[n; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            })
            .collect(),
    )
}
fn rules(j: &Value) -> Rules {
    let mode = |name: &str| {
        if j[name] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: transaction_outcome::Rules {
            envelope: mode("envelope"),
            compute: mode("compute"),
            settle: mode("settle"),
        },
    }
}
fn encoded(v: &[Vec<u8>]) -> Value {
    json!(v.iter().map(hex::encode).collect::<Vec<_>>())
}
fn output(b: &bundle::Accepted) -> Value {
    json!({"hashes":encoded(&b.tx_hashes),"txs":encoded(&b.txs.iter().map(|t|t.to_json_bytes().unwrap()).collect::<Vec<_>>()),"receipts":encoded(&b.receipts_json),"rejections":b.rejections.len()})
}
fn result<T>(r: Result<T, impl std::fmt::Display>, f: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => f(v),
        Err(e) => json!({"error":e.to_string()}),
    }
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/pending-recovery.json")).unwrap()
}
fn raw_bundle(p: &PendingCommit) -> RawBundle {
    RawBundle {
        tx_hashes: p.tx_hashes.clone(),
        txs_json: p.txs_json.clone(),
        receipts_json: p.receipts_json.clone(),
    }
}
fn request(expected: &Value, p: &PendingCommit) -> Precommit {
    Precommit {
        epoch_id: p.epoch_id,
        round: p.round,
        proposal_id: hex::decode(&p.proposal_id).unwrap(),
        proposed_state_root: hex::decode(&p.proposed_state_root).unwrap(),
        txid_hi: p.txid_hi,
        proposal_wire: raw(&expected["proposal"]),
        vote_wire: raw(&expected["vote"]),
    }
}
fn normalize(value: &mut Value) {
    if let Some(s) = value.get("error").and_then(Value::as_str) {
        if s.contains("Yojson") || s.contains("invalid native JSON") {
            *value = json!({"error":"JSON parser diagnostic"});
        }
    }
}
#[test]
fn native_proposal_bundle_admission_order_and_cache_representation() {
    let f: Value = serde_json::from_str(include_str!("fixtures/proposal-bundles.json")).unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(f["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        (
            "oracle_sha256",
            "scripts/node-port/proposal-bundles-oracle.ml",
        ),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            f[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    for (index, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let bytes = |name: &str| {
            input[name]
                .as_array()
                .unwrap()
                .iter()
                .map(raw)
                .collect::<Vec<_>>()
        };
        let proposal =
            octra_node_protocol::consensus::Proposal::decode(&raw(&input["proposal"])).unwrap();
        let response = RawBundle {
            tx_hashes: bytes("hashes"),
            txs_json: bytes("txs"),
            receipts_json: bytes("receipts"),
        };
        let mut actual = result(
            bundle::proposal(
                &proposal.header,
                &bytes("expected_hashes"),
                &response,
                &rules(&input["rules"]),
            ),
            |accepted| {
                let cached = accepted.to_raw().unwrap();
                assert_eq!(encoded(&cached.tx_hashes), case["expected"]["hashes"]);
                assert_eq!(encoded(&cached.txs_json), case["expected"]["txs"]);
                assert_eq!(encoded(&cached.receipts_json), case["expected"]["receipts"]);
                output(&accepted)
            },
        );
        let mut expected = case["expected"].clone();
        normalize(&mut actual);
        normalize(&mut expected);
        assert_eq!(actual, expected, "native proposal bundle {index}");
    }
}
#[test]
fn native_signed_pending_recovery_and_bundle_admission() {
    let f = fixture();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(f["upstream_commit"], source["upstream_commit"]);
    assert_eq!(f["source_sha256"], source["files"]);
    assert_eq!(f["instrumentation"], json!({}));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (field, path) in [
        (
            "oracle_sha256",
            "scripts/node-port/pending-recovery-oracle.ml",
        ),
        ("runner_sha256", "scripts/node-port/native-oracle.py"),
    ] {
        assert_eq!(
            f[field],
            hex::encode(Sha256::digest(fs::read(root.join(path)).unwrap()))
        );
    }
    let set = validators();
    for (index, case) in f["cases"].as_array().unwrap().iter().enumerate() {
        let expected = &case["expected"];
        let p = PendingCommit::decode(&raw(&expected["record"])).unwrap();
        let rules = rules(&expected["rules"]);
        let context = Context {
            chain_id: case["input"]["chain"].as_str().unwrap().as_bytes(),
            validator_set: &set,
            protocol: Protocol::default(),
            rules: &rules,
        };
        let raw = raw_bundle(&p);
        let req = request(expected, &p);
        let proposal =
            octra_node_protocol::consensus::Proposal::decode(&req.proposal_wire).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let journal = JournalOwner::open(dir.path()).unwrap();
        let mut calls = vec![];
        let ok = recovery::before_precommit(
            &context,
            &journal,
            &p.validator_addr,
            &req,
            &raw,
            &[],
            3.,
            |_| {
                calls.push("sync");
                Ok(())
            },
        )
        .is_ok();
        let saved = journal.pending().unwrap();
        if ok {
            calls.push("write");
        }
        let host = json!({"ok":ok,"unsynced":!ok,"calls":calls,
            "saved":saved.first().map(|p|hex::encode(p.encode().unwrap()))});
        let answers = [
            (
                "recover",
                result(
                    recovery::recover(&context, &p),
                    |r| json!({"proposal":hex::encode(r.proposal.encode().unwrap()),"vote":hex::encode(r.vote.encode().unwrap()),"hashes":encoded(&r.bundle.tx_hashes),"txs":output(&r.bundle)["txs"],"receipts":encoded(&r.bundle.receipts_json)}),
                ),
            ),
            ("host", host),
            (
                "bundle",
                result(bundle::finalized(&proposal.header, &raw, &rules), |b| {
                    output(&b)
                }),
            ),
        ];
        for (name, mut actual) in answers {
            let mut want = expected[name].clone();
            normalize(&mut actual);
            normalize(&mut want);
            assert_eq!(
                actual, want,
                "native recovery case {index} {name}: {}",
                case["input"]
            );
        }
    }
}
#[test]
fn host_syncs_before_persisting_and_restores_authenticated_bundle() {
    let f = fixture();
    let set = validators();
    let case = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["mutate"] == "none" && c["input"]["ops"].as_array().unwrap().len() == 1
        })
        .unwrap();
    let expected = &case["expected"];
    let pending = PendingCommit::decode(&raw(&expected["record"])).unwrap();
    let rules = rules(&expected["rules"]);
    let context = Context {
        chain_id: case["input"]["chain"].as_str().unwrap().as_bytes(),
        validator_set: &set,
        protocol: Protocol::default(),
        rules: &rules,
    };
    let req = request(expected, &pending);
    let raw = raw_bundle(&pending);
    let dir = tempfile::tempdir().unwrap();
    let owner = JournalOwner::open(dir.path()).unwrap();
    assert!(
        recovery::before_precommit(&context, &owner, b"v1", &req, &raw, &[], 3., |_| Err(
            "execution unavailable".into()
        ))
        .is_err()
    );
    assert!(owner.pending().unwrap().is_empty());
    let mut synced = false;
    recovery::before_precommit(&context, &owner, b"v1", &req, &raw, &[], 3., |bundle| {
        assert!(owner.pending().unwrap().is_empty());
        assert_eq!(bundle.tx_hashes, raw.tx_hashes);
        synced = true;
        Ok(())
    })
    .unwrap();
    assert!(synced);
    drop(owner);
    let owner = JournalOwner::open(dir.path()).unwrap();
    let stored = owner.pending().unwrap();
    assert_eq!(stored.len(), 1);
    let recovered = recovery::recover(&context, &stored[0]).unwrap();
    assert_eq!(recovered.bundle.tx_hashes, raw.tx_hashes);
    // Crash after pending fsync, before the vote journal write: authenticated
    // recovery restores the signed vote and advances beyond its round.
    use octra_node_protocol::consensus::engine::{Engine, TimeoutConfig};
    use octra_node_runtime::consensus_votes::VoteGuard;
    assert!(owner.find_vote(&recovered.vote).unwrap().is_none());
    let mut engine = Engine::new(
        context.chain_id.to_vec(),
        b"v1".to_vec(),
        set.clone(),
        pending.epoch_id,
        Protocol::default(),
        TimeoutConfig::default(),
    );
    let mut cached = false;
    assert_eq!(
        recovery::restore(&context, &stored[0], false, &mut engine, |r| {
            assert_eq!(r.bundle.tx_hashes, raw.tx_hashes);
            cached = true;
            Ok(())
        }),
        recovery::Restored::Lock
    );
    assert!(cached);
    assert!(engine.restored_precommit_lock(&recovered.proposal).unwrap());
    let mut guard = VoteGuard::new(context.chain_id.to_vec(), b"v1".to_vec(), owner.clone());
    guard
        .prepare(
            false,
            &mut engine,
            Ok(vec![recovered.vote.encode().unwrap()]),
        )
        .unwrap();
    assert_eq!(engine.state().round, pending.round + 1);
    assert_eq!(
        owner.find_vote(&recovered.vote).unwrap(),
        Some(recovered.vote.clone())
    );
    // Idempotent retry cannot overwrite the original write timestamp.
    recovery::before_precommit(
        &context,
        &owner,
        b"v1",
        &req,
        &raw,
        &raw.tx_hashes,
        4.,
        |_| panic!("current bundle was resynced"),
    )
    .unwrap();
    assert_eq!(owner.pending().unwrap()[0].ts.to_bits(), 3_f64.to_bits());
    // Well-formed WAL encoding does not grant authenticity.
    let mut corrupt = stored[0].clone();
    let mut vote = recovered.vote;
    vote.signature[0] ^= 1;
    use base64::Engine as _;
    corrupt.vote_b64 = Some(
        base64::engine::general_purpose::STANDARD
            .encode(vote.encode().unwrap())
            .into_bytes(),
    );
    assert_eq!(
        recovery::recover(&context, &corrupt)
            .err()
            .unwrap()
            .to_string(),
        "pending vote signature invalid"
    );
}
