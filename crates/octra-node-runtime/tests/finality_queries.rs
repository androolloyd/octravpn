#[path = "common/bundle_peer.rs"]
mod peer;
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{
        codec::Wire, engine, hash, qc, CatchupEpochRecord, CatchupFinality, CatchupQuery,
        CatchupResponse, EpochHeader, Finalize, RewardMember, RewardSource, Validator,
        ValidatorSet, Vote, VoteType,
    },
    network::frame::Frame,
};
use octra_node_runtime::epoch_roots::Response;
use std::sync::atomic::Ordering;
const CHAIN: &[u8] = b"finality-fixture";
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn sign_range(mut response: CatchupResponse, signer: u8, complete: bool) -> CatchupResponse {
    response.responder_addr = format!("validator-{signer}").into_bytes();
    let bytes = if complete {
        hash::catchup_complete_sign_bytes(7, &response).unwrap()
    } else {
        hash::catchup_response_sign_bytes(
            CHAIN,
            &response.request_id,
            &response.responder_addr,
            7,
            &hash::catchup_records_root(&response.records).unwrap(),
        )
        .unwrap()
    };
    response.signature = key(signer).sign(&bytes).to_bytes().to_vec();
    response
}
fn last_query(server: &peer::Node) -> CatchupQuery {
    let seen = server.seen.lock().unwrap();
    let frame = seen.iter().rev().find(|f| f.message == 0x3a).unwrap();
    CatchupQuery::decode(&frame.payload).unwrap()
}
fn without(signer: u8) -> ValidatorSet {
    ValidatorSet::unweighted(
        set()
            .validators
            .into_iter()
            .filter(|v| v.address != format!("validator-{signer}").as_bytes())
            .collect(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn range_agreement_deduplicates_and_authenticates_legacy_sources() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    *reader.authority.activation.lock().unwrap() = Some(8);
    // These test peers receive queries without automatically serving them;
    // the reader still authenticates their real validator signing keys.
    let first = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        without(2),
        vec![reader.endpoint.clone()],
    )
    .await;
    let second = peer::node(
        CHAIN,
        b"validator-3".to_vec(),
        key(3),
        without(3),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 2).await;
    let service = reader.finality.clone();
    let validations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let checked = validations.clone();
    let pending = tokio::spawn(async move {
        service
            .query_range(7, 16, 5., |r| {
                checked.fetch_add(1, Ordering::SeqCst);
                Ok(r.records.iter().all(|r| {
                    r.finality.as_ref().is_some_and(|proof| {
                        qc::validate_finalize(
                            CHAIN,
                            &set(),
                            &proof.finalize,
                            qc::FinalityMode::Persisted,
                        )
                        .is_ok()
                    })
                }))
            })
            .await
    });
    peer::wait_for(|| {
        first.seen.lock().unwrap().iter().any(|f| f.message == 0x3a)
            && second
                .seen
                .lock()
                .unwrap()
                .iter()
                .any(|f| f.message == 0x3a)
    })
    .await;
    let query = last_query(&first);
    assert_eq!(
        query.max_epochs, 1,
        "request crossed the scheduled activation"
    );
    let answer = signed(query.request_id.clone(), record(), true, true);
    inject(&first, &reader, &answer, true).await;
    inject(&first, &reader, &answer, true).await;
    peer::wait_for(|| validations.load(Ordering::SeqCst) >= 2).await;
    assert!(!pending.is_finished(), "one source counted more than once");
    let mut legacy = sign_range(answer.clone(), 3, false);
    // Unsigned legacy metadata is normalized before it can influence grouping
    // or peer head observations. A relay cannot impersonate its source.
    legacy.status = b"unsigned".to_vec();
    legacy.next_epoch = Some(900);
    let observations = reader.authority.observations.lock().unwrap().len();
    inject(&first, &reader, &legacy, true).await;
    assert_eq!(
        reader.authority.observations.lock().unwrap().len(),
        observations
    );
    assert!(!pending.is_finished());
    inject(&second, &reader, &legacy, true).await;
    let chosen = pending.await.unwrap().unwrap().unwrap();
    assert_eq!(chosen.status, b"ok");
    assert_eq!(chosen.next_epoch, Some(8));
    assert_eq!(chosen.records, vec![record()]);
    assert!(
        reader.authority.finalities.lock().unwrap().is_empty(),
        "range frames leaked into individual finality delivery"
    );
    assert!(reader
        .authority
        .observations
        .lock()
        .unwrap()
        .iter()
        .all(|(_, r)| r.responder_head_epoch == 7));
    let observations = reader.authority.observations.lock().unwrap().len();
    inject(&second, &reader, &legacy, true).await;
    assert_eq!(
        reader.authority.observations.lock().unwrap().len(),
        observations,
        "completed window accepted a late reply"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn range_cancellation_timeout_and_validation_failure_release_only_their_window() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let first = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    let second = peer::node(
        CHAIN,
        b"validator-3".to_vec(),
        key(3),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 2).await;
    for server in [&first, &second] {
        server.authority.ranges.lock().unwrap().insert(7, record());
    }
    reader.gate.send(false).unwrap();
    let service = reader.finality.clone();
    let pending = tokio::spawn(async move { service.query_range(7, 16, 5., |_| Ok(true)).await });
    peer::wait_for(|| {
        first.authority.range_requests.lock().unwrap().len() == 1
            && second.authority.range_requests.lock().unwrap().len() == 1
    })
    .await;
    assert!(
        reader
            .finality
            .query_range(7, 16, 0.02, |_| Ok(true))
            .await
            .unwrap()
            .is_none(),
        "queued reader exceeded its timeout"
    );
    let roots = [Response {
        responder_addr: b"validator-2".to_vec(),
        responder_head_epoch: 7,
        state_root: None,
    }];
    reader.finality.request(7, &roots).await.unwrap().unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    reader.gate.send(true).unwrap();
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 1).await;
    peer::wait_for(|| {
        reader
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x3b)
            .count()
            == 3
    })
    .await;
    assert_eq!(
        reader.authority.observations.lock().unwrap().len(),
        1,
        "cancelled range reported peer state"
    );
    let result = reader
        .finality
        .query_range(7, 16, 2., |_| Err("fixture validation failure".into()))
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("fixture validation failure"));
    assert!(reader
        .finality
        .query_range(7, 16, 2., |_| Ok(true))
        .await
        .unwrap()
        .is_some());
    reader.gate.send(false).unwrap();
    let requests = first.authority.range_requests.lock().unwrap().len();
    let service = reader.finality.clone();
    let timed = tokio::spawn(async move { service.query_range(7, 16, 0.15, |_| Ok(true)).await });
    peer::wait_for(|| first.authority.range_requests.lock().unwrap().len() > requests).await;
    assert!(timed.await.unwrap().unwrap().is_none());
    let observations = reader.authority.observations.lock().unwrap().len();
    reader.gate.send(true).unwrap();
    assert!(reader
        .finality
        .query_range(7, 16, 2., |_| Ok(true))
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        reader.authority.observations.lock().unwrap().len(),
        observations + 2,
        "expired query accepted delayed replies"
    );
}
fn set() -> ValidatorSet {
    ValidatorSet::unweighted(
        (1..=4)
            .map(|n| Validator {
                address: format!("validator-{n}").into_bytes(),
                pubkey: key(n).verifying_key().to_bytes().to_vec(),
            })
            .collect(),
    )
}
fn record() -> CatchupEpochRecord {
    let header = EpochHeader {
        proto_version: 4,
        chain_id: CHAIN.to_vec(),
        epoch_id: 7,
        prev_state_root: vec![1; 32],
        proposed_state_root: vec![2; 32],
        tx_list_hash: engine::tx_list_hash_for_header(&[]).to_vec(),
        receipt_root: hash::receipt_root(&[]).unwrap().to_vec(),
        parent_commit_hash: vec![0; 32],
        creator_addr: b"validator-1".to_vec(),
        txid_hi: 0,
        ts: 7.,
    };
    let id = hash::proposal_id(&header).unwrap().to_vec();
    let votes = (1..=3)
        .map(|n| {
            let mut vote = Vote {
                chain_id: CHAIN.to_vec(),
                epoch_id: 7,
                round: 0,
                vote_type: VoteType::Precommit,
                proposal_id: id.clone(),
                validator: format!("validator-{n}").into_bytes(),
                signature: vec![],
            };
            vote.signature = key(n)
                .sign(&hash::vote_sign_bytes(&vote).unwrap())
                .to_bytes()
                .to_vec();
            vote
        })
        .collect();
    let finalized = Finalize {
        chain_id: CHAIN.to_vec(),
        epoch_id: 7,
        commit_round: 0,
        header: header.clone(),
        proposal_id: id,
        precommits: votes,
        parent_commit: None,
    };
    qc::validate_finalize(CHAIN, &set(), &finalized, qc::FinalityMode::Persisted).unwrap();
    CatchupEpochRecord {
        epoch_id: 7,
        prev_state_root: header.prev_state_root,
        state_root: header.proposed_state_root,
        tx_list_hash: header.tx_list_hash,
        tx_hashes: vec![],
        txs_json: vec![],
        receipt_root: header.receipt_root,
        receipts_json: vec![],
        epoch_ts: header.ts,
        creator_addr: header.creator_addr,
        commit_round: 0,
        reward_source: Some(RewardSource {
            reward_proposer_addr: b"validator-1".to_vec(),
            reward_proposer_public_key: Some(key(1).verifying_key().to_bytes().to_vec()),
            reward_members: set()
                .validators
                .into_iter()
                .map(|v| RewardMember {
                    reward_address: v.address,
                    reward_public_key: Some(v.pubkey),
                    reward_weight: 1.into(),
                })
                .collect(),
        }),
        finality: Some(CatchupFinality {
            finalize: finalized,
            validator_set: set(),
        }),
    }
}
async fn inject(sender: &peer::Node, receiver: &peer::Node, response: &CatchupResponse, v2: bool) {
    let frame = Frame {
        message: if v2 { 0x3b } else { 0x39 },
        payload: response.encode(v2).unwrap(),
    };
    let matches = || {
        receiver
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.message == frame.message && seen.payload == frame.payload)
            .count()
    };
    let count = matches();
    sender
        .swarm
        .send_to(receiver.swarm.node_id(), frame.clone())
        .await;
    peer::wait_for(|| matches() > count).await;
}
fn signed(id: Vec<u8>, record: CatchupEpochRecord, complete: bool, v2: bool) -> CatchupResponse {
    let mut response = CatchupResponse {
        chain_id: CHAIN.to_vec(),
        request_id: id,
        status: b"ok".to_vec(),
        error_code: None,
        records: vec![record],
        next_epoch: Some(8),
        responder_addr: b"validator-2".to_vec(),
        signature: vec![],
    };
    let bytes = if complete {
        hash::catchup_complete_sign_bytes(7, &response).unwrap()
    } else {
        let root = if v2 {
            hash::catchup_records_root(&response.records).unwrap()
        } else {
            hash::catchup_records_root_v1(&response.records).unwrap()
        };
        hash::catchup_response_sign_bytes(
            CHAIN,
            &response.request_id,
            &response.responder_addr,
            7,
            &root,
        )
        .unwrap()
    };
    response.signature = key(2).sign(&bytes).to_bytes().to_vec();
    response
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_finality_windows_retry_legacy_proofs_and_stale_responses() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let server = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    let record = record();
    let roots = [Response {
        responder_addr: b"validator-2".to_vec(),
        responder_head_epoch: 7,
        state_root: Some(vec![2; 32]),
    }];
    server
        .authority
        .ranges
        .lock()
        .unwrap()
        .insert(7, record.clone());
    let id = reader.finality.request(7, &roots).await.unwrap().unwrap();
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 1).await;
    assert_eq!(
        reader.authority.finalities.lock().unwrap()[0],
        record.finality.as_ref().unwrap().finalize
    );
    assert_eq!(reader.authority.observations.lock().unwrap().len(), 1);
    assert!(reader.finality.request(7, &roots).await.unwrap().is_none());

    // A malformed signature never reaches finality admission; the observed
    // handler completion makes the negative assertion independent of sleeps.
    let mut forged = signed(id.clone(), record.clone(), true, true);
    forged.signature[0] ^= 1;
    inject(&server, &reader, &forged, true).await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 1);
    let mut wrong_epoch = signed(id.clone(), record.clone(), true, true);
    wrong_epoch.records[0].epoch_id = 8;
    inject(&server, &reader, &wrong_epoch, true).await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 1);

    // The native legacy-complete proof can carry a certificate but must not
    // authenticate unsigned status/continuation metadata as peer state.
    let mut legacy = signed(id.clone(), record.clone(), false, true);
    legacy.status = b"unsigned metadata".to_vec();
    legacy.next_epoch = Some(900);
    inject(&server, &reader, &legacy, true).await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 2);
    assert_eq!(reader.authority.observations.lock().unwrap().len(), 1);
    inject(
        &server,
        &reader,
        &signed(id.clone(), record.clone(), false, false),
        false,
    )
    .await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 2);

    reader.clock.store(5_000_000_000, Ordering::SeqCst);
    let next = reader.finality.request(7, &roots).await.unwrap().unwrap();
    assert_ne!(next, id);
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 3).await;
    inject(
        &server,
        &reader,
        &signed(id.clone(), record.clone(), true, true),
        true,
    )
    .await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 3);
    let proof = reader
        .finality
        .request_proof(7, &roots)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(proof, next);
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 4).await;
    // Proof and retry windows coexist. A proof request does not erase the
    // current retry window, and closing both prevents late deliveries.
    reader.finality.clear_proofs();
    inject(
        &server,
        &reader,
        &signed(proof.clone(), record.clone(), true, true),
        true,
    )
    .await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 4);
    inject(
        &server,
        &reader,
        &signed(next.clone(), record.clone(), true, true),
        true,
    )
    .await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 5);
    reader.finality.close();
    inject(
        &server,
        &reader,
        &signed(proof, record.clone(), true, true),
        true,
    )
    .await;
    inject(&server, &reader, &signed(next, record, true, true), true).await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 5);
    reader.clock.store(10_000_000_000, Ordering::SeqCst);
    assert!(reader.finality.request(7, &roots).await.unwrap().is_some());
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 6).await;
    reader.clock.store(69_999_999_999, Ordering::SeqCst);
    assert!(reader.finality.request(7, &roots).await.unwrap().is_none());
    reader.clock.store(70_000_000_000, Ordering::SeqCst);
    assert!(reader.finality.request(7, &roots).await.unwrap().is_some());
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 7).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn awaited_proof_cancellation_preserves_driver_requests_and_drops_late_replies() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let server = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    let record = record();
    let expected = record.finality.as_ref().unwrap().finalize.clone();
    server
        .authority
        .ranges
        .lock()
        .unwrap()
        .insert(7, record.clone());
    let roots = vec![Response {
        responder_addr: b"validator-2".to_vec(),
        responder_head_epoch: 7,
        state_root: Some(vec![2; 32]),
    }];
    let answer = reader
        .finality
        .query_proof(7, &roots, 1., |_| async { Ok(true) })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, expected);
    let response = reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|f| f.message == 0x3b)
        .cloned()
        .unwrap();
    let response = CatchupResponse::decode(&response.payload, true).unwrap();
    inject(&server, &reader, &response, true).await;
    assert_eq!(
        reader.authority.finalities.lock().unwrap().len(),
        1,
        "completed proof window was closed"
    );

    reader.gate.send(false).unwrap();
    reader.clock.store(1, Ordering::SeqCst);
    let before = server.authority.range_requests.lock().unwrap().len();
    let service = reader.finality.clone();
    let hints = roots.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(7, &hints, 10., |_| async { Ok(true) })
            .await
    });
    peer::wait_for(|| server.authority.range_requests.lock().unwrap().len() > before).await;
    // Cancellation of a queued second reader must not close the first window.
    let service = reader.finality.clone();
    let hints = roots.clone();
    let queued = tokio::spawn(async move {
        service
            .query_proof(7, &hints, 10., |_| async { Ok(true) })
            .await
    });
    queued.abort();
    assert!(queued.await.unwrap_err().is_cancelled());
    // The ordinary driver's missing-finality window remains independently live.
    let missing = reader.finality.request(7, &roots).await.unwrap().unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    reader.gate.send(true).unwrap();
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 2).await;
    // The only delivered completion was the independent driver request.
    let received = reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.message == 0x3b)
        .map(|f| CatchupResponse::decode(&f.payload, true).unwrap())
        .collect::<Vec<_>>();
    let cancelled = received
        .iter()
        .find(|r| r.request_id != response.request_id && r.request_id != missing)
        .unwrap();
    inject(&server, &reader, cancelled, true).await;
    assert_eq!(reader.authority.finalities.lock().unwrap().len(), 2);

    // Replacing an awaited proof with an explicit driver proof also survives
    // cancellation of the old reader, even when the native request IDs collide.
    reader.gate.send(false).unwrap();
    reader.clock.store(2, Ordering::SeqCst);
    let before = server.authority.range_requests.lock().unwrap().len();
    let service = reader.finality.clone();
    let hints = roots.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(7, &hints, 10., |_| async { Ok(true) })
            .await
    });
    peer::wait_for(|| server.authority.range_requests.lock().unwrap().len() > before).await;
    reader
        .finality
        .request_proof(7, &roots)
        .await
        .unwrap()
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    reader.gate.send(true).unwrap();
    peer::wait_for(|| reader.authority.finalities.lock().unwrap().len() == 4).await;
    reader.finality.close();
    assert!(reader
        .finality
        .query_proof(7, &[], 1., |_| async { Ok(true) })
        .await
        .unwrap()
        .is_none());
    assert!(reader
        .finality
        .query_proof(7, &roots, 0., |_| async { Ok(true) })
        .await
        .unwrap()
        .is_none());
    assert!(reader
        .finality
        .query_proof(8, &roots, 0.1, |_| async { Ok(true) })
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn awaited_proof_timeout_and_queued_reader_cancellation() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let server = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    server.authority.ranges.lock().unwrap().insert(7, record());
    let roots = vec![Response {
        responder_addr: b"validator-2".to_vec(),
        responder_head_epoch: 7,
        state_root: None,
    }];
    reader.gate.send(false).unwrap();
    let service = reader.finality.clone();
    let hints = roots.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(7, &hints, 2., |_| async { Ok(true) })
            .await
    });
    peer::wait_for(|| server.authority.range_requests.lock().unwrap().len() == 1).await;
    assert!(reader
        .finality
        .query_proof(7, &roots, 0.02, |_| async { Ok(true) })
        .await
        .unwrap()
        .is_none());
    reader.gate.send(true).unwrap();
    assert_eq!(
        pending.await.unwrap().unwrap().unwrap(),
        record().finality.unwrap().finalize
    );
    reader.gate.send(false).unwrap();
    reader.clock.store(1, Ordering::SeqCst);
    let service = reader.finality.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(7, &roots, 0.1, |_| async { Ok(true) })
            .await
    });
    peer::wait_for(|| server.authority.range_requests.lock().unwrap().len() == 2).await;
    assert!(pending.await.unwrap().unwrap().is_none());
    reader.gate.send(true).unwrap();
    peer::wait_for(|| {
        reader
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.message == 0x3b)
            .count()
            == 2
    })
    .await;
    assert_eq!(
        reader.authority.finalities.lock().unwrap().len(),
        1,
        "timed-out proof delivered late"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_certificate_does_not_mask_a_later_valid_proof() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let server = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    let mut bad = record();
    bad.finality.as_mut().unwrap().finalize.precommits[0].signature[0] ^= 1;
    server.authority.ranges.lock().unwrap().insert(7, bad);
    let rejected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let checked = rejected.clone();
    let service = reader.finality.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(
                7,
                &[Response {
                    responder_addr: b"validator-2".to_vec(),
                    responder_head_epoch: 7,
                    state_root: None,
                }],
                2.,
                |finalized| {
                    let valid = qc::validate_finalize(
                        CHAIN,
                        &set(),
                        &finalized,
                        qc::FinalityMode::Persisted,
                    )
                    .is_ok();
                    if !valid {
                        checked.store(true, Ordering::SeqCst);
                    }
                    std::future::ready(Ok(valid))
                },
            )
            .await
    });
    peer::wait_for(|| rejected.load(Ordering::SeqCst)).await;
    let frame = reader
        .seen
        .lock()
        .unwrap()
        .iter()
        .find(|f| f.message == 0x3b)
        .cloned()
        .unwrap();
    let response = CatchupResponse::decode(&frame.payload, true).unwrap();
    inject(
        &server,
        &reader,
        &signed(response.request_id, record(), true, true),
        true,
    )
    .await;
    assert_eq!(
        pending.await.unwrap().unwrap().unwrap(),
        record().finality.unwrap().finalize
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_during_async_authority_lookup_cannot_return_a_certificate() {
    let reader = peer::node(CHAIN, b"validator-1".to_vec(), key(1), set(), vec![]).await;
    let server = peer::node(
        CHAIN,
        b"validator-2".to_vec(),
        key(2),
        set(),
        vec![reader.endpoint.clone()],
    )
    .await;
    peer::wait_for(|| reader.swarm.peers().len() == 1).await;
    server.authority.ranges.lock().unwrap().insert(7, record());
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let service = reader.finality.clone();
    let waiting = entered.clone();
    let resume = release.clone();
    let pending = tokio::spawn(async move {
        service
            .query_proof(
                7,
                &[Response {
                    responder_addr: b"validator-2".to_vec(),
                    responder_head_epoch: 7,
                    state_root: None,
                }],
                2.,
                move |_| {
                    let waiting = waiting.clone();
                    let resume = resume.clone();
                    async move {
                        waiting.notify_one();
                        resume.notified().await;
                        Ok(true)
                    }
                },
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    reader.finality.clear_proofs();
    release.notify_one();
    assert!(pending.await.unwrap().unwrap().is_none());
    // The revoked reader releases its serialized window and cannot erase this one.
    assert!(reader
        .finality
        .query_proof(
            7,
            &[Response {
                responder_addr: b"validator-2".to_vec(),
                responder_head_epoch: 7,
                state_root: None
            }],
            1.,
            |_| async { Ok(true) }
        )
        .await
        .unwrap()
        .is_some());
}
