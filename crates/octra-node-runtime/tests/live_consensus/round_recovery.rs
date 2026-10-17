//! Signed round announcements over the actual actor's authenticated TCP peers.
use super::*;
use octra_node_protocol::consensus::{RoundFetch, RoundStep, RoundSync};

async fn send_sync(sender: &Node, receiver: &Node, round: i64, corrupt: bool) {
    let mut sync = RoundSync {
        chain_id: CHAIN.to_vec(),
        epoch_id: 1,
        round,
        step: RoundStep::Propose,
        request: false,
        validator: address(sender.authority.id),
        signature: vec![],
    };
    sync.signature = key(sender.authority.id)
        .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
        .to_bytes()
        .to_vec();
    if corrupt {
        sync.signature[0] ^= 1;
    }
    assert!(
        sender
            .swarm
            .send_to(
                receiver.swarm.node_id(),
                Frame {
                    message: 0x3e,
                    payload: sync.encode().unwrap()
                }
            )
            .await
    );
}

fn replay_requests(node: &Node, signer: u8, round: i64) -> usize {
    node.seen
        .lock()
        .unwrap()
        .iter()
        .filter(|frame| {
            if frame.message != 0x3e {
                return false;
            }
            let sync = RoundSync::decode(&frame.payload).unwrap();
            sync.validator == address(signer)
                && sync.epoch_id == 1
                && sync.round == round
                && sync.request
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_round_jump_requests_replay_again_after_native_delay() {
    let receiver = node(1, 4, vec![], None).await;
    let sender = node(2, 4, vec![receiver.endpoint.clone()], None).await;
    let third = node(
        3,
        4,
        vec![receiver.endpoint.clone(), sender.endpoint.clone()],
        None,
    )
    .await;
    wait(|| {
        receiver.handle.status().borrow().started
            && sender.handle.status().borrow().started
            && third.handle.status().borrow().started
    })
    .await;
    send_sync(&sender, &receiver, 64, false).await;
    send_sync(&third, &receiver, 64, false).await;
    wait(|| receiver.handle.status().borrow().round == 64).await;
    wait(|| replay_requests(&sender, 1, 64) >= 2).await;
    assert!(!receiver.driver.is_finished());
    assert!(receiver.authority.commits.lock().unwrap().is_empty());
    assert_eq!(receiver.authority.journal.floor().unwrap(), Some(0));
    for frame in sender
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|frame| frame.message == 0x3e)
    {
        let sync = RoundSync::decode(&frame.payload).unwrap();
        if sync.validator == address(1) && sync.round == 64 && sync.request {
            assert!(hash::verify_round_sync(key(1).verifying_key().as_bytes(), &sync).unwrap());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fresh_ahead_peer_requests_bounded_history_but_forged_sync_does_not() {
    let receiver = node(1, 4, vec![], None).await;
    let sender = node(2, 4, vec![receiver.endpoint.clone()], None).await;
    let third = node(
        3,
        4,
        vec![receiver.endpoint.clone(), sender.endpoint.clone()],
        None,
    )
    .await;
    wait(|| {
        receiver.handle.status().borrow().started
            && sender.handle.status().borrow().started
            && third.handle.status().borrow().started
    })
    .await;
    send_sync(&sender, &receiver, 96, true).await;
    wait(|| {
        receiver
            .authority
            .warnings
            .lock()
            .unwrap()
            .iter()
            .any(|warning| warning.contains("invalid round sync signature"))
    })
    .await;
    assert!(!sender
        .seen
        .lock()
        .unwrap()
        .iter()
        .any(|frame| frame.message == 0x3f));
    send_sync(&sender, &receiver, 96, false).await;
    wait(|| {
        receiver
            .handle
            .diagnostics()
            .unwrap()
            .is_some_and(|diagnostics| {
                diagnostics
                    .round_peers
                    .iter()
                    .any(|peer| peer.validator_addr == address(2) && peer.state.round == 96)
            })
    })
    .await;
    // Two authenticated higher-round signers permit round1. Only the first
    // reports round96, so the native proposer hook fetches its historical
    // window rather than treating that one announcement as a round96 quorum.
    send_sync(&third, &receiver, 1, false).await;
    wait(|| {
        sender
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|frame| frame.message == 0x3f)
    })
    .await;
    let requests = sender
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|frame| frame.message == 0x3f)
        .map(|frame| RoundFetch::decode(&frame.payload).unwrap())
        .collect::<Vec<_>>();
    assert!(!requests.is_empty());
    for request in requests {
        assert_eq!(request.chain_id, CHAIN);
        assert_eq!(request.epoch_id, 1);
        assert!(request.after_round < request.through_round);
        assert!(request.through_round - request.after_round <= engine::ROUND_HISTORY_LIMIT);
        assert!(request.through_round <= 96);
    }
    assert!(
        receiver.handle.status().borrow().round < 96,
        "one ahead signer cannot authorize a quorum round jump"
    );
    assert!(receiver.authority.commits.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_envelope_fault_belongs_to_signer_and_unresolved_membership_does_not_ban_relay() {
    use octra_node_protocol::network::{guard, handshake};
    let receiver = node(1, 4, vec![], None).await;
    let relay = node(2, 4, vec![receiver.endpoint.clone()], None).await;
    let third = node(
        3,
        4,
        vec![receiver.endpoint.clone(), relay.endpoint.clone()],
        None,
    )
    .await;
    wait(|| {
        receiver.handle.status().borrow().started
            && relay.handle.status().borrow().started
            && third.handle.status().borrow().started
    })
    .await;
    let score = |signer: u8| {
        receiver.swarm.scores().into_iter().find_map(|(id, score)| {
            (id == guard::identity_key(&handshake::node_id(key(signer).verifying_key().as_bytes())))
                .then_some(score)
        })
    };
    for timestamp in [10., 11., 12.] {
        let mut header = header(1, address(4));
        header.proto_version = 3; // Validly signed, wrong active envelope.
        header.ts = timestamp;
        let mut proposal = Proposal {
            chain_id: CHAIN.to_vec(),
            epoch_id: 1,
            round: 0,
            valid_round: None,
            header,
            tx_hashes: vec![],
            parent_commit: None,
            proposer: address(4),
            signature: vec![],
        };
        proposal.signature = key(4)
            .sign(&hash::propose_sign_bytes(&proposal).unwrap())
            .to_bytes()
            .to_vec();
        assert!(
            relay
                .swarm
                .send_to(
                    receiver.swarm.node_id(),
                    Frame {
                        message: 0x30,
                        payload: proposal.encode().unwrap()
                    }
                )
                .await
        );
    }
    wait(|| score(4).is_some_and(|score| score.bad_count == 3)).await;
    assert!(score(2).is_none_or(|score| score.bad_count == 0));
    assert_eq!(
        score(4).unwrap().last_reason,
        b"invalid_frame_propose_envelope"
    );

    // Forged known-signer bytes are instead charged to their transport sender.
    send_sync(&relay, &receiver, 96, true).await;
    wait(|| score(2).is_some_and(|score| score.bad_signatures == 1)).await;
    for round in 0..3 {
        let unknown = b"not-in-resolved-validator-set".to_vec();
        let vote = Vote {
            chain_id: CHAIN.to_vec(),
            epoch_id: 1,
            round,
            vote_type: VoteType::Prevote,
            proposal_id: vec![0; 32],
            validator: unknown.clone(),
            signature: vec![0; 64],
        };
        assert!(
            relay
                .swarm
                .send_to(
                    receiver.swarm.node_id(),
                    Frame {
                        message: 0x31,
                        payload: vote.encode().unwrap()
                    }
                )
                .await
        );
        let sync = RoundSync {
            chain_id: CHAIN.to_vec(),
            epoch_id: 1,
            round,
            step: RoundStep::Propose,
            request: false,
            validator: unknown,
            signature: vec![0; 64],
        };
        assert!(
            relay
                .swarm
                .send_to(
                    receiver.swarm.node_id(),
                    Frame {
                        message: 0x3e,
                        payload: sync.encode().unwrap()
                    }
                )
                .await
        );
    }
    wait(|| {
        receiver
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| match frame.message {
                0x31 => {
                    Vote::decode(&frame.payload).unwrap().validator
                        == b"not-in-resolved-validator-set"
                }
                0x3e => {
                    RoundSync::decode(&frame.payload).unwrap().validator
                        == b"not-in-resolved-validator-set"
                }
                _ => false,
            })
            .count()
            == 6
    })
    .await;
    let before = receiver.authority.readiness_checks.load(Ordering::SeqCst);
    receiver.handle.wake().unwrap();
    wait(|| receiver.authority.readiness_checks.load(Ordering::SeqCst) > before).await;
    assert_eq!(score(2).unwrap().bad_count, 1);
    assert_eq!(score(2).unwrap().last_reason, b"bad_signature_round_sync");
    assert!(receiver
        .swarm
        .peers()
        .iter()
        .any(|peer| peer.hello().node_id.as_slice() == relay.swarm.node_id()));
    assert!(receiver.authority.commits.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_vote_evidence_keeps_native_window_and_signing_slot_bound() {
    use octra_node_protocol::{
        consensus::evidence,
        network::{guard, handshake},
    };
    let receiver = node(1, 4, vec![], None).await;
    let relay = node(2, 4, vec![receiver.endpoint.clone()], None).await;
    let third = node(
        3,
        4,
        vec![receiver.endpoint.clone(), relay.endpoint.clone()],
        None,
    )
    .await;
    wait(|| {
        receiver.handle.status().borrow().started
            && relay.handle.status().borrow().started
            && third.handle.status().borrow().started
    })
    .await;
    let score = |signer: u8| {
        receiver.swarm.scores().into_iter().find_map(|(id, score)| {
            (id == guard::identity_key(&handshake::node_id(key(signer).verifying_key().as_bytes())))
                .then_some(score)
        })
    };
    let conflict = |epoch, value: u8| {
        let mut vote = Vote {
            chain_id: CHAIN.to_vec(),
            epoch_id: epoch,
            round: 0,
            vote_type: VoteType::Precommit,
            proposal_id: vec![0; 32],
            validator: address(4),
            signature: vec![],
        };
        vote.signature = key(4)
            .sign(&hash::vote_sign_bytes(&vote).unwrap())
            .to_bytes()
            .to_vec();
        let mut second = vote.clone();
        second.proposal_id = vec![value; 32];
        second.signature = key(4)
            .sign(&hash::vote_sign_bytes(&second).unwrap())
            .to_bytes()
            .to_vec();
        evidence::vote_conflict(&vote, &second).unwrap()
    };
    for epoch in [-128, 3] {
        // Current1 minus129 and plus2 are both outside.
        assert!(
            relay
                .swarm
                .send_to(
                    receiver.swarm.node_id(),
                    Frame {
                        message: 0x3d,
                        payload: conflict(epoch, 1).encode().unwrap()
                    }
                )
                .await
        );
    }
    wait(|| score(2).is_some_and(|score| score.bad_count == 2)).await;
    assert!(receiver.authority.evidence.lock().unwrap().is_empty());
    assert!(score(4).is_none_or(|score| score.bad_count == 0));
    assert!(
        relay
            .swarm
            .send_to(
                receiver.swarm.node_id(),
                Frame {
                    message: 0x3d,
                    payload: conflict(-127, 1).encode().unwrap()
                }
            )
            .await
    );
    wait(|| receiver.authority.evidence.lock().unwrap().len() == 1).await;
    assert_eq!(score(4).unwrap().last_reason, b"vote_equivocation");
    // A different pair for the same signing position proves the same slot.
    assert!(
        relay
            .swarm
            .send_to(
                receiver.swarm.node_id(),
                Frame {
                    message: 0x3d,
                    payload: conflict(-127, 2).encode().unwrap()
                }
            )
            .await
    );
    wait(|| score(4).is_some_and(|score| score.bad_count == 2)).await;
    assert_eq!(receiver.authority.evidence.lock().unwrap().len(), 1);
    assert!(
        relay
            .swarm
            .send_to(
                receiver.swarm.node_id(),
                Frame {
                    message: 0x3d,
                    payload: conflict(2, 1).encode().unwrap()
                }
            )
            .await
    );
    wait(|| receiver.authority.evidence.lock().unwrap().len() == 2).await;
    assert_eq!(score(2).unwrap().bad_count, 2);
    assert!(receiver.authority.commits.lock().unwrap().is_empty());
}
