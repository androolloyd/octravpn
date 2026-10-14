//! Real signed TCP bundle transfer and durable recovery. Execution and
//! historical validator selection remain explicit host inputs in this test.
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        engine::{Engine, TimeoutConfig},
        hash,
        journal::JournalOwner,
        pending_log::PendingCommit,
        policy::Protocol,
        Proposal, Validator, ValidatorSet,
    },
    network::endpoint::Endpoint,
    transaction::RuleMode,
    transaction_outcome,
};
use octra_node_runtime::{
    consensus_bundle::{self as bundle, RawBundle, Rules},
    consensus_recovery::{self as recovery, Context, Restored},
    consensus_votes::Precommit,
    query_peers,
};
use serde_json::Value;
use std::{sync::atomic::Ordering, time::Duration};
const WAIT: Duration = Duration::from_secs(10);
const CHAIN: &[u8] = b"recovery-fixture";
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn validators() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|n| Validator {
                address: format!("v{n}").into_bytes(),
                pubkey: key(n).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    )
}
fn fixture() -> (PendingCommit, Precommit, Proposal, Rules) {
    let f: Value = serde_json::from_str(include_str!("fixtures/pending-recovery.json")).unwrap();
    let c = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["chain"] == "recovery-fixture"
                && c["input"]["mutate"] == "none"
                && c["input"]["ops"].as_array().unwrap().len() == 1
        })
        .unwrap();
    let e = &c["expected"];
    let decode = |name: &str| hex::decode(e[name].as_str().unwrap()).unwrap();
    let pending = PendingCommit::decode(&decode("record")).unwrap();
    let proposal = Proposal::decode(&decode("proposal")).unwrap();
    let request = Precommit {
        epoch_id: pending.epoch_id,
        round: pending.round,
        proposal_id: hex::decode(&pending.proposal_id).unwrap(),
        proposed_state_root: hex::decode(&pending.proposed_state_root).unwrap(),
        txid_hi: pending.txid_hi,
        proposal_wire: decode("proposal"),
        vote_wire: decode("vote"),
    };
    let mode = |name: &str| {
        if e["rules"][name] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    let rules = Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: transaction_outcome::Rules {
            envelope: mode("envelope"),
            compute: mode("compute"),
            settle: mode("settle"),
        },
    };
    (pending, request, proposal, rules)
}
fn raw(p: &PendingCommit) -> RawBundle {
    RawBundle {
        tx_hashes: p.tx_hashes.clone(),
        txs_json: p.txs_json.clone(),
        receipts_json: p.receipts_json.clone(),
    }
}
#[path = "common/bundle_peer.rs"]
mod bundle_peer;
use bundle_peer::{wait_for, Node};
async fn node(seed: u8, bootstrap: Vec<Endpoint>) -> Node {
    bundle_peer::node(
        CHAIN,
        format!("v{seed}").into_bytes(),
        key(seed),
        validators(),
        bootstrap,
    )
    .await
}
async fn cluster(id: [u8; 32], raw: &RawBundle) -> Vec<Node> {
    let mut nodes = vec![node(1, vec![]).await];
    for seed in 2..=4 {
        let n = node(seed, vec![nodes[0].endpoint.clone()]).await;
        n.authority.cached.lock().unwrap().insert(id, raw.clone());
        nodes.push(n);
    }
    wait_for(|| nodes[0].swarm.peers().len() == 3).await;
    nodes
}
fn requests(nodes: &[Node]) -> usize {
    nodes[1..]
        .iter()
        .map(|n| n.authority.requests.lock().unwrap().len())
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_forgery_falls_back_and_recovers_the_fetched_bundle() {
    let (pending, request, proposal, rules) = fixture();
    let id = hash::proposal_id(&proposal.header).unwrap();
    let expected = raw(&pending);
    let nodes = cluster(id, &expected).await;
    let ordered = query_peers::ordered(
        &validators(),
        &id,
        &nodes[0]
            .swarm
            .peers()
            .iter()
            .map(|p| p.hello().node_id.clone())
            .collect::<Vec<_>>(),
    );
    let peer = |index: usize| {
        nodes
            .iter()
            .find(|n| n.swarm.node_id() == ordered[index])
            .unwrap()
    };
    peer(0).authority.corrupt.store(true, Ordering::SeqCst);
    let mut bad = expected.clone();
    bad.txs_json[0] = b"{}".to_vec();
    peer(1).authority.cached.lock().unwrap().insert(id, bad);
    peer(1).authority.duplicate.store(true, Ordering::SeqCst);
    let mut checked = vec![];
    let (response, accepted) = nodes[0]
        .bundles
        .query(pending.epoch_id, id, 3., |r| {
            checked.push(r.responder.clone());
            Ok(bundle::finalized(&proposal.header, &r.bundle, &rules).ok())
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        checked
            .iter()
            .filter(|a| **a == peer(1).authority.address.as_slice())
            .count(),
        1
    );
    assert!(!checked.contains(&peer(0).authority.address.clone()));
    assert_eq!(response.responder, peer(2).authority.address.as_slice());
    assert_eq!(
        response.bundle.tx_hashes,
        expected
            .tx_hashes
            .iter()
            .map(|h| hex::decode(h).unwrap())
            .collect::<Vec<_>>()
    );
    let cached = accepted.to_raw().unwrap();
    assert_eq!(cached, expected);
    assert_eq!(accepted.tx_hashes, expected.tx_hashes);
    assert_eq!(checked.len(), 2);

    let set = validators();
    let context = Context {
        chain_id: CHAIN,
        validator_set: &set,
        protocol: Protocol::default(),
        rules: &rules,
    };
    let directory = tempfile::tempdir().unwrap();
    let journal = JournalOwner::open(directory.path()).unwrap();
    recovery::before_precommit(
        &context,
        &journal,
        b"v1",
        &request,
        &cached,
        &[],
        3.,
        |decoded| {
            assert_eq!(decoded.tx_hashes, accepted.tx_hashes);
            Ok(())
        },
    )
    .unwrap();
    drop(journal);
    let reopened = JournalOwner::open(directory.path()).unwrap();
    let saved = reopened.pending().unwrap();
    assert_eq!(saved.len(), 1);
    let mut engine = Engine::new(
        CHAIN.to_vec(),
        b"v1".to_vec(),
        set.clone(),
        pending.epoch_id,
        Protocol::default(),
        TimeoutConfig::default(),
    );
    assert_eq!(
        recovery::restore(&context, &saved[0], false, &mut engine, |recovered| {
            assert_eq!(recovered.bundle.tx_hashes, accepted.tx_hashes);
            assert_eq!(
                recovered.bundle.txs[0].to_json_bytes().unwrap(),
                accepted.txs[0].to_json_bytes().unwrap()
            );
            Ok(())
        }),
        Restored::Lock
    );
    assert!(engine.restored_precommit_lock(&proposal).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_one_reader_keeps_the_next_reader_and_other_proposals_usable() {
    let (pending, _, proposal, _) = fixture();
    let id = hash::proposal_id(&proposal.header).unwrap();
    let nodes = cluster(id, &raw(&pending)).await;
    nodes[0].gate.send_replace(false);
    let service = nodes[0].bundles.clone();
    let first = tokio::spawn(async move { service.query(1, id, 10., |_| Ok(Some(()))).await });
    wait_for(|| requests(&nodes) >= 2).await;
    let service = nodes[0].bundles.clone();
    let second = tokio::spawn(async move { service.query(1, id, 10., |_| Ok(Some(()))).await });
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    wait_for(|| requests(&nodes) >= 4).await;
    assert!(!second.is_finished());
    nodes[0].gate.send_replace(true);
    assert!(tokio::time::timeout(WAIT, second)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .is_some());

    // Distinct proposal slots run concurrently; a missing one does not hold up
    // an available one. Validation errors also release their same-ID gate.
    let service = nodes[0].bundles.clone();
    let missing =
        tokio::spawn(async move { service.query(1, [9; 32], 10., |_| Ok(Some(()))).await });
    let mut called = false;
    let result = nodes[0]
        .bundles
        .query::<()>(1, id, 3., |_| {
            called = true;
            Err("execution unavailable".into())
        })
        .await;
    assert!(called);
    assert_eq!(result.unwrap_err().to_string(), "execution unavailable");
    assert!(!missing.is_finished());
    missing.abort();
    assert!(missing.await.unwrap_err().is_cancelled());
    assert!(nodes[0]
        .bundles
        .query(1, id, 3., |_| Ok(Some(())))
        .await
        .unwrap()
        .is_some());
    assert!(nodes[0]
        .bundles
        .query::<()>(1, [9; 32], 0.15, |_| panic!("missing bundle admitted"))
        .await
        .unwrap()
        .is_none());
}
