//! c49de45 staged quorum, recovery and bounded query regression controls.
use ed25519_dalek::{Signer as _, SigningKey};
use octra_node_protocol::consensus::{
    codec::Wire,
    engine::{self, Engine, Output, TimeoutConfig},
    hash,
    policy::{self, Protocol, QuorumPolicy, Rule},
    proof_search::Search,
    query_work::{self, QueryWork},
    relief::{Decision, Plan},
    reply_window::{Decision as Reply, ReplyWindow},
    value_log::{self, Record},
    vote_log::{self, VoteLog},
    EpochHeader, Proposal, RoundStep, RoundSync, Validator, ValidatorSet, Vote, VoteType, NIL,
};
const HEIGHT: i64 = policy::ROUND_ACTIVATION;
fn member(id: u8) -> Validator {
    Validator {
        address: vec![id],
        pubkey: SigningKey::from_bytes(&[id; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    }
}
fn set(n: u8) -> ValidatorSet {
    ValidatorSet::weighted((1..=n).map(|id| (member(id), 1.into())).collect()).unwrap()
}
fn policy() -> QuorumPolicy {
    QuorumPolicy::for_chain(policy::DEVNET)
}
fn vote(id: u8, round: i64, pid: &[u8], kind: VoteType) -> Vote {
    let mut v = Vote {
        chain_id: policy::DEVNET.to_vec(),
        epoch_id: HEIGHT,
        round,
        vote_type: kind,
        proposal_id: pid.to_vec(),
        validator: vec![id],
        signature: Vec::new(),
    };
    v.signature = SigningKey::from_bytes(&[id; 32])
        .sign(&hash::vote_sign_bytes(&v).unwrap())
        .to_bytes()
        .to_vec();
    v
}
fn proof(round: i64, pid: &[u8]) -> Vec<Vote> {
    (1..=3)
        .map(|id| vote(id, round, pid, VoteType::Prevote))
        .collect()
}
fn proposal(set: &ValidatorSet, round: i64) -> Proposal {
    let proposer = set.leader(HEIGHT, round).unwrap().address.clone();
    let mut p = Proposal {
        chain_id: policy::DEVNET.to_vec(),
        epoch_id: HEIGHT,
        round,
        valid_round: None,
        header: EpochHeader {
            proto_version: Protocol::default().version_at(HEIGHT),
            chain_id: policy::DEVNET.to_vec(),
            epoch_id: HEIGHT,
            prev_state_root: vec![1; 32],
            tx_list_hash: engine::tx_list_hash_for_header(&[]).to_vec(),
            receipt_root: vec![2; 32],
            proposed_state_root: vec![3; 32],
            parent_commit_hash: NIL.to_vec(),
            creator_addr: proposer.clone(),
            txid_hi: 0,
            ts: 1.0,
        },
        tx_hashes: Vec::new(),
        parent_commit: None,
        proposer: proposer.clone(),
        signature: Vec::new(),
    };
    p.signature = SigningKey::from_bytes(&[proposer[0]; 32])
        .sign(&hash::propose_sign_bytes(&p).unwrap())
        .to_bytes()
        .to_vec();
    p
}
fn engine() -> Engine {
    Engine::new(
        policy::DEVNET.to_vec(),
        vec![1],
        set(4),
        HEIGHT,
        Protocol::default(),
        TimeoutConfig::default(),
    )
    .unwrap()
}
#[allow(clippy::unnecessary_wraps)] // Engine signer callback signature.
fn sign(bytes: &[u8]) -> Result<Vec<u8>, octra_node_protocol::consensus::Error> {
    Ok(SigningKey::from_bytes(&[1; 32])
        .sign(bytes)
        .to_bytes()
        .to_vec())
}
#[test]
fn activation_boundaries_and_stake_count_floor() {
    let p = policy();
    assert_eq!(p.select(policy::QUORUM_ACTIVATION - 1), Rule::Prior);
    assert_eq!(p.select(policy::QUORUM_ACTIVATION), Rule::Capped);
    assert_eq!(p.select(policy::STAKE_ACTIVATION), Rule::Stake);
    assert!(!p.round_wait(HEIGHT - 1));
    assert!(p.round_wait(HEIGHT));
    for boundary in p.epochs() {
        assert!(!p.rewind_allowed(boundary, boundary - 1));
    }
    let weighted = ValidatorSet::weighted(
        (1..=4)
            .map(|id| (member(id), if id == 1 { 1000.into() } else { 1.into() }))
            .collect(),
    )
    .unwrap();
    assert_eq!(
        weighted
            .for_epoch(policy::DEVNET, HEIGHT)
            .unwrap()
            .weight(&[1]),
        Some(&1000.into())
    );
    assert!(!weighted
        .has_quorum_for_policy(p, HEIGHT, &[vec![1]])
        .unwrap());
    assert!(weighted
        .has_quorum_for_policy(p, HEIGHT, &[vec![1], vec![2], vec![3]])
        .unwrap());
    assert!(!weighted
        .has_quorum_for_policy(p, HEIGHT, &[vec![2], vec![3], vec![4]])
        .unwrap());
}
#[test]
fn relief_authors_are_context_bound_and_cannot_vote() {
    let current = set(6);
    let target = set(5);
    let fingerprint = vec![b'a'; 64];
    let plan = Plan {
        chain_id: policy::DEVNET,
        height: HEIGHT,
        current: &current,
        activate_epoch: HEIGHT + 2,
        target: &target,
        fingerprint: &fingerprint,
    };
    assert_eq!(plan.clock_limit(), Some(64));
    let witnesses = (1..=3)
        .map(|id| {
            let mut s = RoundSync {
                chain_id: policy::DEVNET.to_vec(),
                epoch_id: HEIGHT,
                round: 64,
                step: RoundStep::Prevote,
                request: false,
                validator: vec![id],
                signature: Vec::new(),
            };
            s.signature = SigningKey::from_bytes(&[id; 32])
                .sign(&hash::round_sync_sign_bytes(&s).unwrap())
                .to_bytes()
                .to_vec();
            s
        })
        .collect::<Vec<_>>();
    let Decision::Apply(mark) = plan.decide(&witnesses).unwrap() else {
        panic!("authenticated relief refused")
    };
    let relieved = plan.restore_with_authors(&mark).unwrap().unwrap();
    assert!(relieved.is_author(policy::DEVNET, HEIGHT, &[6]));
    assert!(!relieved.is_validator(&[6]));
    assert_eq!(
        ValidatorSet::decode(&relieved.encode().unwrap()).unwrap(),
        relieved
    );
    assert_ne!(
        hash::validator_set_hash(&target).unwrap(),
        hash::validator_set_hash(&relieved).unwrap()
    );
    assert!(relieved
        .for_epoch(policy::DEVNET, HEIGHT + 1)
        .unwrap()
        .authors
        .is_none());
    assert!(relieved
        .source_set(policy::DEVNET, HEIGHT)
        .unwrap()
        .is_validator(&[6]));
    let mut invalid = relieved;
    invalid.authors.as_mut().unwrap().1[0].0.pubkey = member(1).pubkey;
    assert!(ValidatorSet::decode(&invalid.encode().unwrap()).is_err());
}
#[test]
fn proof_cache_rejects_forgery_equivocation_and_restores_source_quorums() {
    let mut log = VoteLog::memory();
    let vs = set(4);
    let p = policy();
    let first = proof(3, &[3; 32]);
    log.save_proof(p, policy::DEVNET, HEIGHT, &vs, 3, &[], &first)
        .unwrap();
    assert_eq!(
        log.load_proofs(p, policy::DEVNET, HEIGHT, &vs).unwrap(),
        first
    );
    assert!(log
        .save_proof(p, policy::DEVNET, HEIGHT, &vs, 3, &[], &proof(3, &[4; 32]))
        .is_err());
    let mut forged = first.clone();
    forged[0].signature[0] ^= 1;
    assert!(vote_log::check_proof(p, policy::DEVNET, HEIGHT, &vs, &forged).is_err());
    let mut repeated = first.clone();
    repeated[2] = repeated[0].clone();
    assert!(vote_log::check_proof(p, policy::DEVNET, HEIGHT, &vs, &repeated).is_err());
    for round in 4..20 {
        log.save_proof(
            p,
            policy::DEVNET,
            HEIGHT,
            &vs,
            3,
            &[],
            &proof(round, &[round as u8; 32]),
        )
        .unwrap();
    }
    let kept = log.load_proofs(p, policy::DEVNET, HEIGHT, &vs).unwrap();
    assert_eq!(kept.len(), 6);
    assert!(kept.iter().all(|v| [3, 19].contains(&v.round)));
    let mut reduced =
        ValidatorSet::weighted((2..=4).map(|id| (member(id), 1.into())).collect()).unwrap();
    reduced.authors = Some((HEIGHT, vec![(member(1), 1.into())]));
    assert!(vote_log::check_proof(p, policy::DEVNET, HEIGHT, &reduced, &first).is_ok());
    assert!(vote_log::check_proof(p, policy::DEVNET, HEIGHT + 1, &reduced, &first).is_err());
}
#[test]
fn persisted_value_is_authenticated_and_replayed_before_becoming_valid() {
    let vs = set(4);
    let proposal = proposal(&vs, 2);
    let pid = hash::proposal_id(&proposal.header).unwrap();
    let record = Record {
        proposal: proposal.clone(),
        votes: proof(2, &pid),
    };
    let mut log = VoteLog::memory();
    record
        .save(
            &mut log,
            policy(),
            Protocol::default(),
            policy::DEVNET,
            HEIGHT,
            &vs,
        )
        .unwrap();
    assert_eq!(
        value_log::load(
            &log,
            policy(),
            Protocol::default(),
            policy::DEVNET,
            HEIGHT,
            &vs
        )
        .unwrap(),
        Some(record.clone())
    );
    let mut engine = engine();
    engine.restore_proofs(&record.votes).unwrap();
    assert_eq!(engine.state().round, 2);
    assert!(engine.state().valid_value.is_none());
    assert!(engine.learn_recovered_proposal(proposal).unwrap());
    assert_eq!(engine.state().valid_round, 2);
    let mut bad = record;
    bad.proposal.tx_hashes.push(vec![7; 32]);
    assert!(bad
        .save(
            &mut log,
            policy(),
            Protocol::default(),
            policy::DEVNET,
            HEIGHT,
            &vs
        )
        .is_err());
}
#[test]
fn round_wait_needs_votes_or_checked_relief_clock() {
    let mut engine = engine();
    engine.set_voting_ready(true);
    engine.start_round(0);
    engine.drain_outputs();
    engine
        .on_timeout(RoundStep::Propose, 0, engine.generation(), &mut sign)
        .unwrap();
    assert_eq!(engine.state().step, RoundStep::Prevote);
    assert!(!engine.drain_outputs().iter().any(|o| matches!(
        o,
        Output::ScheduleTimeout {
            step: RoundStep::Prevote,
            ..
        }
    )));
    engine
        .on_timeout(RoundStep::Prevote, 0, engine.generation(), &mut sign)
        .unwrap();
    assert_eq!(engine.state().step, RoundStep::Prevote);
    for id in [2, 3] {
        engine
            .on_vote(vote(id, 0, &NIL, VoteType::Prevote), &mut sign)
            .unwrap();
    }
    assert_eq!(engine.state().step, RoundStep::Precommit);
    assert!(!engine.drain_outputs().iter().any(|o| matches!(
        o,
        Output::ScheduleTimeout {
            step: RoundStep::Precommit,
            ..
        }
    )));
    for id in [2, 3] {
        engine
            .on_vote(vote(id, 0, &NIL, VoteType::Precommit), &mut sign)
            .unwrap();
    }
    assert!(engine.drain_outputs().iter().any(|o| matches!(
        o,
        Output::ScheduleTimeout {
            step: RoundStep::Precommit,
            ..
        }
    )));
    let mut relief = crate::engine();
    relief.set_relief_limit(Some(64));
    relief.set_voting_ready(true);
    relief.start_round(0);
    relief.drain_outputs();
    relief
        .on_timeout(RoundStep::Propose, 0, relief.generation(), &mut sign)
        .unwrap();
    assert!(relief.drain_outputs().iter().any(|o| matches!(
        o,
        Output::ScheduleTimeout {
            step: RoundStep::Prevote,
            ..
        }
    )));
}
#[test]
fn stored_local_vote_resumes_same_round_and_cannot_change_statement() {
    let mut engine = engine();
    engine.start_round(2);
    let saved = vote(1, 2, &NIL, VoteType::Prevote);
    engine
        .restore_local_votes(std::slice::from_ref(&saved))
        .unwrap();
    assert_eq!(engine.state().round, 2);
    assert_eq!(engine.state().step, RoundStep::Prevote);
    assert!(engine
        .restore_local_votes(&[vote(1, 2, &[9; 32], VoteType::Prevote)])
        .is_err());
    engine.start_height(HEIGHT).unwrap();
    assert_eq!(engine.state().round, 3);
}
#[test]
fn stalled_step_requires_authenticated_higher_round_witness() {
    let mut engine = engine();
    engine.set_round_skip_ready(true);
    assert!(!engine.try_round_step().unwrap());
    let mut bad = vote(2, 4, &NIL, VoteType::Prevote);
    bad.signature[0] ^= 1;
    engine.on_vote(bad, &mut sign).unwrap();
    assert!(!engine.try_round_step().unwrap());
    engine
        .on_vote(vote(2, 4, &NIL, VoteType::Prevote), &mut sign)
        .unwrap();
    assert_eq!(engine.state().round, 0);
    assert!(engine.try_round_step().unwrap());
    assert_eq!(engine.state().round, 1);
}
#[test]
fn proof_search_is_bounded_per_round_and_rolling_window() {
    let (mut state, request) = Search::step(None, 4, HEIGHT, 4, Some(2), true, 0);
    assert_eq!(request, Some(2));
    let (same, request) = Search::step(state.clone(), 4, HEIGHT, 4, Some(2), true, 1);
    assert_eq!(request, None);
    assert_eq!(same, state);
    for now in [2_100_000_000, 6_300_000_000, 14_700_000_000] {
        (state, _) = Search::step(state, 4, HEIGHT, 4, Some(2), true, now);
    }
    assert_eq!(state.as_ref().unwrap().attempts, 4);
    assert!(
        Search::step(state, 4, HEIGHT, 4, Some(2), true, 60_000_000_000)
            .1
            .is_none()
    );
    let (large, _) = Search::step(None, 255, HEIGHT, 2, None, true, 0);
    assert!(
        Search::step(large, 255, HEIGHT, 3, None, true, 3_000_000_000)
            .1
            .is_none()
    );
}
#[test]
fn query_lanes_account_for_reserved_bytes_and_one_reply_per_request() {
    let mut work = QueryWork::new(0);
    let first = work.start(0, b"a", b"net", false, 16).unwrap();
    assert!(work.start(0, b"b", b"net", false, 1).is_none());
    assert!(work.start(0, b"a", b"other", true, 1).is_none());
    let validator = work.start(0, b"v", b"net", true, 16).unwrap();
    assert!(!work.prepared(first, query_work::REPLY_LIMIT + 1, 1));
    assert!(work.prepared(first, 100, 1));
    assert!(!work.prepared(first, 100, 1));
    work.finish(first);
    assert!(work.start(0, b"b", b"net", false, 1).is_some());
    work.finish(validator);
    let peers = vec![b"a".to_vec()];
    let mut window = ReplyWindow::new(10, peers);
    assert_eq!(window.take(0, b"b"), Reply::UnexpectedPeer);
    assert_eq!(window.take(0, b"a"), Reply::Read);
    assert_eq!(window.take(1, b"a"), Reply::Repeated);
    window.extend([b"b".to_vec()]);
    assert_eq!(window.take(10, b"b"), Reply::Expired);
    assert_eq!(
        query_work::network("192.0.2.42:80".parse().unwrap()),
        b"192.0.2.0"
    );
    assert_eq!(
        query_work::network("[::ffff:192.0.2.42]:80".parse().unwrap()),
        b"192.0.2.0"
    );
}

#[test]
fn injected_policy_controls_local_engine_without_rewriting_network_epochs() {
    let policy = QuorumPolicy::new(0, Some(1), Some(2)).unwrap();
    let mut engine = Engine::new_for_policy(
        policy,
        b"local-network".to_vec(),
        vec![1],
        set(4),
        2,
        Protocol::default(),
        TimeoutConfig::default(),
    )
    .unwrap();
    assert!(engine.round_wait());
    engine.set_voting_ready(true);
    engine.start_round(0);
    engine.drain_outputs();
    engine
        .on_timeout(RoundStep::Propose, 0, engine.generation(), &mut sign)
        .unwrap();
    assert!(!engine.drain_outputs().iter().any(|o| matches!(
        o,
        Output::ScheduleTimeout {
            step: RoundStep::Prevote,
            ..
        }
    )));
    assert_eq!(
        engine.quorum_policy().id_at(b"local-network", 2),
        "resilient:genesis:stake:1"
    );
}
