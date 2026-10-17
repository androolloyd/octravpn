use super::*;
use octra_node_protocol::consensus::{RoundStep, NIL};
use std::collections::BTreeMap;

fn context(now: f64) -> LivenessContext {
    LivenessContext {
        expected: 1,
        now,
        stall_sec: 150.,
        observer: false,
        voting: true,
        catchup_active: false,
        quarantine_active: false,
        state_attested: true,
        pending_finalized: false,
    }
}

fn set_clock(node: &Node, now: f64) {
    *node.authority.liveness.lock().unwrap() = Some(context(now));
}

fn resets(node: &Node) -> usize {
    node.authority
        .warnings
        .lock()
        .unwrap()
        .iter()
        .filter(|warning| warning.starts_with("liveness realign "))
        .count()
}

async fn poll(node: &Node) {
    let before = node.authority.health_polls.load(Ordering::SeqCst);
    node.handle.poll_health().unwrap();
    wait(|| node.authority.health_polls.load(Ordering::SeqCst) > before).await;
    // Only the actor calls readiness. A subsequent refresh follows the poll's
    // synchronous native policy decision, including any reset warning.
    let before = node.authority.readiness_checks.load(Ordering::SeqCst);
    node.handle.wake().unwrap();
    wait(|| node.authority.readiness_checks.load(Ordering::SeqCst) > before).await;
}

fn proposal(round: i64, count: u8) -> Proposal {
    let creator = validators(count).leader(1, round).unwrap().address.clone();
    let signer = (1..=count).find(|id| address(*id) == creator).unwrap();
    let mut proposal = Proposal {
        chain_id: CHAIN.to_vec(),
        epoch_id: 1,
        round,
        valid_round: None,
        header: header(1, creator.clone()),
        tx_hashes: vec![],
        parent_commit: None,
        proposer: creator,
        signature: vec![],
    };
    proposal.signature = key(signer)
        .sign(&hash::propose_sign_bytes(&proposal).unwrap())
        .to_bytes()
        .to_vec();
    proposal
}

async fn send_proposal(sender: &Node, receiver: &Node, proposal: &Proposal) {
    assert!(
        sender
            .swarm
            .send_to(
                receiver.swarm.node_id(),
                Frame {
                    message: 0x30,
                    payload: proposal.encode().unwrap(),
                }
            )
            .await
    );
}

fn durable_votes(sender: &Node, receiver: &Node) -> Vec<Vote> {
    let mut positions = BTreeMap::new();
    let votes = receiver
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|frame| frame.message == 0x31)
        .map(|frame| Vote::decode(&frame.payload).unwrap())
        .filter(|vote| vote.validator == address(sender.authority.id))
        .collect::<Vec<_>>();
    for vote in &votes {
        assert!(
            hash::verify_vote(key(sender.authority.id).verifying_key().as_bytes(), vote).unwrap()
        );
        assert_eq!(
            sender.authority.journal.find_vote(vote).unwrap().as_ref(),
            Some(vote)
        );
        if let Some(old) = positions.insert(
            (vote.epoch_id, vote.round, vote.vote_type as u8),
            vote.proposal_id.clone(),
        ) {
            assert_eq!(
                old, vote.proposal_id,
                "one signing position emitted conflicting statements"
            );
        }
    }
    votes
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn liveness_round_realign_preserves_restored_lock_durable_vote_and_replay() {
    let restored = proposal(4, 4);
    let leader5 = validators(4).leader(1, 5).unwrap().address.clone();
    let leader6 = validators(4).leader(1, 6).unwrap().address.clone();
    let id = (1..=4)
        .find(|id| address(*id) != leader5 && address(*id) != leader6)
        .unwrap();
    let mut receiver = node(id, 4, vec![], Some(restored.clone())).await;
    let other = if id == 1 { 2 } else { 1 };
    let sender = node(other, 4, vec![receiver.endpoint.clone()], None).await;
    let third_id = (1..=4)
        .find(|member| *member != id && *member != other)
        .unwrap();
    let _third = node(
        third_id,
        4,
        vec![receiver.endpoint.clone(), sender.endpoint.clone()],
        None,
    )
    .await;
    wait(|| receiver.handle.status().borrow().started && receiver.swarm.peers().len() == 2).await;
    let pid = hash::proposal_id(&restored.header).unwrap().to_vec();
    let mut vote = Vote {
        chain_id: CHAIN.to_vec(),
        epoch_id: 1,
        round: 4,
        vote_type: VoteType::Precommit,
        proposal_id: pid.clone(),
        validator: address(id),
        signature: vec![],
    };
    vote.signature = key(id)
        .sign(&hash::vote_sign_bytes(&vote).unwrap())
        .to_bytes()
        .to_vec();
    assert!(
        receiver
            .authority
            .before_precommit(Precommit {
                epoch_id: 1,
                round: 4,
                proposal_id: pid.clone(),
                proposed_state_root: restored.header.proposed_state_root.clone(),
                txid_hi: restored.header.txid_hi,
                proposal_wire: restored.encode().unwrap(),
                vote_wire: vote.encode().unwrap(),
            })
            .await
    );
    receiver.authority.journal.keep_vote(vote.clone()).unwrap();
    receiver.authority.ready.store(true, Ordering::SeqCst);
    set_clock(&receiver, 0.);
    poll(&receiver).await;
    let before = receiver.handle.status().borrow().round;
    assert_eq!(before, 5);
    let mut held = context(1000.);
    held.quarantine_active = true;
    *receiver.authority.liveness.lock().unwrap() = Some(held);
    poll(&receiver).await;
    assert_eq!(resets(&receiver), 0);
    assert_eq!(receiver.handle.status().borrow().round, before);
    set_clock(&receiver, 1000.);
    poll(&receiver).await;
    wait(|| resets(&receiver) == 1 && receiver.handle.status().borrow().round == before + 1).await;
    assert_eq!(receiver.handle.status().borrow().height, 1);
    assert_eq!(receiver.handle.status().borrow().locked_round, 4);
    assert_eq!(receiver.authority.journal.floor().unwrap(), Some(0));
    assert_eq!(
        receiver.authority.journal.find_vote(&vote).unwrap(),
        Some(vote.clone())
    );
    let pending = receiver.authority.journal.pending().unwrap();
    assert_eq!(pending.len(), 1);
    let recovered = consensus_recovery::recover(
        &consensus_recovery::Context {
            chain_id: CHAIN,
            validator_set: &validators(4),
            protocol: Protocol::default(),
            rules: &rules(),
        },
        &pending[0],
    )
    .unwrap();
    assert_eq!(recovered.vote, vote);
    assert_eq!(recovered.proposal, restored);

    let candidate = proposal(before + 1, 4);
    assert_ne!(
        hash::proposal_id(&candidate.header).unwrap().as_slice(),
        pid
    );
    send_proposal(&sender, &receiver, &candidate).await;
    wait(|| {
        receiver
            .authority
            .journal
            .max_round(CHAIN, &address(id), 1)
            .unwrap()
            .is_some_and(|round| round > before)
    })
    .await;
    wait(|| !durable_votes(&receiver, &sender).is_empty()).await;
    let emitted = durable_votes(&receiver, &sender);
    assert!(emitted.iter().any(|vote| vote.round == before + 1
        && vote.vote_type == VoteType::Prevote
        && vote.proposal_id == NIL));
    assert!(emitted
        .iter()
        .filter(|vote| vote.vote_type == VoteType::Precommit && vote.proposal_id != NIL)
        .all(|vote| vote.proposal_id == pid));
    assert_eq!(receiver.handle.status().borrow().locked_round, 4);
    receiver.stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(12), &mut receiver.driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut replay = Engine::new(
        CHAIN.to_vec(),
        address(id),
        validators(4),
        1,
        Protocol::default(),
        TimeoutConfig::default(),
    );
    replay.restore_precommit_lock(recovered.proposal).unwrap();
    let mut guard = octra_node_runtime::consensus_votes::VoteGuard::new(
        CHAIN.to_vec(),
        address(id),
        receiver.authority.journal.clone(),
    );
    guard
        .prepare(
            false,
            &mut replay,
            Ok(vec![recovered.vote.encode().unwrap()]),
        )
        .unwrap();
    assert_eq!(replay.state().locked_round, 4);
    assert!(replay.state().round > before);
    assert_eq!(receiver.authority.journal.floor().unwrap(), Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finalized_publication_blocks_resets_and_queued_polls_cannot_jump_committed_height() {
    let first = node(1, 2, vec![], None).await;
    let second = node(2, 2, vec![first.endpoint.clone()], None).await;
    let nodes = [first, second];
    wait(|| {
        nodes
            .iter()
            .all(|node| node.handle.status().borrow().started && node.swarm.peers().len() == 1)
    })
    .await;
    nodes[0]
        .authority
        .reject_publish
        .store(true, Ordering::SeqCst);
    set_clock(&nodes[0], 0.);
    poll(&nodes[0]).await;
    enable(&nodes);
    wait(|| {
        nodes[0].authority.attempts.load(Ordering::SeqCst) > 0
            && nodes[0].handle.status().borrow().finalized
    })
    .await;
    let round = nodes[0].handle.status().borrow().round;
    set_clock(&nodes[0], 1000.);
    poll(&nodes[0]).await;
    assert_eq!(resets(&nodes[0]), 0);
    assert_eq!(nodes[0].handle.status().borrow().round, round);
    assert_eq!(nodes[0].authority.journal.floor().unwrap(), Some(0));

    nodes[0].publish_gate.send_replace(false);
    let attempts = nodes[0].authority.attempts.load(Ordering::SeqCst);
    nodes[0]
        .authority
        .reject_publish
        .store(false, Ordering::SeqCst);
    wait(|| nodes[0].authority.attempts.load(Ordering::SeqCst) > attempts).await;
    let polls = nodes[0].authority.health_polls.load(Ordering::SeqCst);
    set_clock(&nodes[0], 2000.); // Context.expected intentionally remains old height1.
    for _ in 0..8 {
        nodes[0].handle.poll_health().unwrap();
    }
    assert_eq!(
        nodes[0].authority.health_polls.load(Ordering::SeqCst),
        polls,
        "publication gate did not hold the owning actor"
    );
    nodes[0].publish_gate.send_replace(true);
    wait(|| {
        nodes[0].handle.status().borrow().height == 2
            && nodes[0].authority.health_polls.load(Ordering::SeqCst) >= polls + 8
    })
    .await;
    assert_eq!(resets(&nodes[0]), 0);
    assert_eq!(nodes[0].handle.status().borrow().round, 0);
    assert_eq!(nodes[0].handle.status().borrow().step, RoundStep::Propose);
    assert_eq!(nodes[0].authority.journal.floor().unwrap(), Some(1));
    assert!(nodes[0]
        .authority
        .journal
        .max_round(CHAIN, &address(1), 2)
        .unwrap()
        .is_none());
    assert_eq!(nodes[0].authority.commits.lock().unwrap().len(), 1);
    assert!(!durable_votes(&nodes[0], &nodes[1]).is_empty());
}

#[tokio::test]
async fn wall_clock_cannot_skip_current_proposal_grace_and_expired_work_cannot_reenter() {
    let current_leader = validators(4).leader(1, 0).unwrap().address.clone();
    let next_leader = validators(4).leader(1, 1).unwrap().address.clone();
    let id = (1..=4)
        .find(|id| address(*id) != current_leader && address(*id) != next_leader)
        .unwrap();
    let other = if id == 1 { 2 } else { 1 };
    let timeouts = TimeoutConfig {
        propose: 300_000,
        ..TimeoutConfig::default()
    };
    let receiver =
        node_with_timeouts(id, 4, vec![], None, timeouts, Duration::from_secs(2000)).await;
    let sender = node_with_timeouts(
        other,
        4,
        vec![receiver.endpoint.clone()],
        None,
        timeouts,
        Duration::from_secs(2000),
    )
    .await;
    let third_id = (1..=4)
        .find(|member| *member != id && *member != other)
        .unwrap();
    let third = node_with_timeouts(
        third_id,
        4,
        vec![receiver.endpoint.clone(), sender.endpoint.clone()],
        None,
        timeouts,
        Duration::from_secs(2000),
    )
    .await;
    wait(|| {
        receiver.handle.status().borrow().started
            && sender.handle.status().borrow().started
            && third.handle.status().borrow().started
            && receiver.swarm.peers().len() == 2
    })
    .await;
    receiver.gate.send_replace(false);
    receiver.authority.ready.store(true, Ordering::SeqCst);
    set_clock(&receiver, 0.);
    poll(&receiver).await;
    send_proposal(&sender, &receiver, &proposal(0, 4)).await;
    wait(|| receiver.authority.checks.load(Ordering::SeqCst) == 1).await;
    set_clock(&receiver, 1000.);
    poll(&receiver).await;
    assert_eq!(resets(&receiver), 0);
    assert_eq!(receiver.handle.status().borrow().round, 0);
    assert_eq!(receiver.authority.journal.floor().unwrap(), Some(0));

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(181)).await;
    tokio::time::resume();
    set_clock(&receiver, 2000.);
    poll(&receiver).await;
    wait(|| resets(&receiver) == 1 && receiver.handle.status().borrow().round == 1).await;
    send_proposal(&sender, &receiver, &proposal(1, 4)).await;
    wait(|| receiver.authority.checks.load(Ordering::SeqCst) == 2).await;
    // Advance past the old300s propose timer while the replacement round1
    // timer is only120s old. Real socket I/O runs with time resumed.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::time::resume();
    poll(&receiver).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(resets(&receiver), 1);
    assert_eq!(receiver.handle.status().borrow().round, 1);
    assert_eq!(receiver.handle.status().borrow().step, RoundStep::Propose);
    receiver.gate.send_replace(true);
    wait(|| {
        receiver
            .authority
            .journal
            .max_round(CHAIN, &address(id), 1)
            .unwrap()
            .is_some_and(|round| round == 1)
    })
    .await;
    assert_eq!(
        receiver.authority.checks.load(Ordering::SeqCst),
        2,
        "cancelled verifier reentered the actor"
    );
    assert_eq!(receiver.authority.journal.floor().unwrap(), Some(0));
    assert!(receiver.authority.commits.lock().unwrap().is_empty());
    wait(|| !durable_votes(&receiver, &sender).is_empty()).await;
    assert!(durable_votes(&receiver, &sender)
        .iter()
        .all(|vote| vote.round == 1));
}
