use super::*;
use octra_exex::{CommittedEpochSource, Sequence};
use octra_node::{
    executor::{Native, ProposalError},
    proposal::Candidate,
};
use octra_node_protocol::{
    consensus::{hash, policy::Protocol, Proposal},
    preverify_receipt::{Binding, Receipt},
    rules::Graph,
    transaction_outcome,
};

fn sign(proposal: &mut Proposal) {
    proposal.signature = SigningKey::from_bytes(&[1; 32])
        .sign(&hash::propose_sign_bytes(proposal).unwrap())
        .to_bytes()
        .to_vec();
}
async fn candidate(node: &Node<Authority>, proposal: &Proposal) -> Arc<Candidate> {
    Arc::new(
        node.proposal_candidate(
            proposal,
            &Graph::new(proposal.chain_id.clone(), None),
            octra_node_runtime::finality::proposal::Policy {
                protocol: Protocol::new(2).unwrap(),
                genesis_time: Some(0.),
            },
            10.,
        )
        .await
        .unwrap(),
    )
}
async fn invalid(
    node: &Node<Authority>,
    executor: &Native,
    proposal: &Proposal,
    raw: &RawBundle,
    expected: &str,
) {
    let error = executor
        .verify_proposal(candidate(node, proposal).await, raw)
        .await
        .err()
        .expect("forged proposal accepted");
    assert!(
        matches!(error, ProposalError::Invalid(_)) && error.to_string().contains(expected),
        "{error}"
    );
}

#[tokio::test]
async fn local_proposal_capture_checks_receipts_outcomes_and_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let circle = format!("oct{}", "1".repeat(44));
    let state = genesis(circle.as_bytes());
    let chain = ChainIdentity {
        chain_id: "proposal-capture-fixture".into(),
        genesis_root: StateRoot(finality_host::root(None, &state, &[])),
    };
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let db = dir.path().join("node.db");
    let store = CanonicalStore::create(&db, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap();
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("exex.db"))
            .await
            .unwrap(),
    );
    let node = open(&db, checkpoints, chain, Arc::default()).await;
    node.resume().await.unwrap();
    let view = node.snapshot().unwrap();
    let (_, expected) = execute(&view, circle.as_bytes(), &authority);
    let raw = network_bundle(&expected);
    let mut header = finality_host::certificate(view.head(), &expected, &authority).header;
    header.proto_version = Protocol::new(2).unwrap().version_at(1);
    let set = authority.validators(view.head(), 1).unwrap();
    let mut proposal = Proposal {
        chain_id: header.chain_id.clone(),
        epoch_id: 1,
        round: (0..32)
            .find(|&r| set.leader(1, r).unwrap().address == b"validator-0")
            .unwrap(),
        valid_round: None,
        header,
        tx_hashes: raw.tx_hashes.clone(),
        parent_commit: None,
        proposer: b"validator-0".to_vec(),
        signature: vec![],
    };
    sign(&mut proposal);
    let executor =
        ImportExecutor::with_protocol(&authority, &node, Protocol::new(2).unwrap()).native;
    let draft = Arc::new(
        node.proposal_draft(
            &Graph::new(proposal.chain_id.clone(), None),
            octra_node_runtime::finality::proposal::Policy {
                protocol: Protocol::new(2).unwrap(),
                genesis_time: Some(0.),
            },
            b"validator-0",
            10.,
        )
        .await
        .unwrap(),
    );
    let built = executor
        .build_proposal(draft.clone(), vec![circle_call(1, circle.as_bytes())])
        .await
        .unwrap();
    assert_eq!(built.plan().header, proposal.header);
    assert_eq!(built.bundle(), &raw);
    assert_eq!(
        built.execution().state.root().unwrap(),
        expected.state.root().unwrap()
    );
    assert!(node.draft_current(built.draft()));
    assert!(built.draft().context().rules().authority().is_err());
    let prepared = executor
        .verify_proposal(candidate(&node, &proposal).await, &raw)
        .await
        .unwrap();
    assert_eq!(
        prepared.execution().state.root().unwrap(),
        expected.state.root().unwrap()
    );
    assert_eq!(prepared.bundle(), &raw);
    assert!(node.proposal_current(prepared.candidate()));

    // Structurally valid and self-consistent commitments are not local proof.
    let tx = Transaction::from_document(
        &octra_node_protocol::native_json::Document::parse(&raw.txs_json[0]).unwrap(),
    )
    .unwrap();
    let mut forged = raw.clone();
    let mut receipt = Receipt::parse(&forged.receipts_json[0]).unwrap();
    let Binding::Circle(binding) = &mut receipt.binding else {
        panic!("Circle receipt expected")
    };
    binding.context_hash = vec![b'0'; 64];
    receipt.input_hash = receipt.binding.input_hash(&tx).unwrap();
    receipt.output_hash = receipt.binding.output_hash(&tx, b"ok").unwrap();
    forged.receipts_json[0] = receipt.canonical();
    let mut malicious = proposal.clone();
    malicious.header.receipt_root = hash::receipt_root(&forged.receipts_json).unwrap().to_vec();
    sign(&mut malicious);
    invalid(
        &node,
        &executor,
        &malicious,
        &forged,
        "local_preverify_receipt_mismatch",
    )
    .await;
    malicious = proposal.clone();
    malicious.header.proposed_state_root[0] ^= 1;
    sign(&mut malicious);
    invalid(&node, &executor, &malicious, &raw, "state root mismatch").await;
    malicious = proposal.clone();
    malicious.header.txid_hi += 1;
    sign(&mut malicious);
    invalid(
        &node,
        &executor,
        &malicious,
        &raw,
        "transaction index mismatch",
    )
    .await;

    // A rejected public successor belongs in the all-candidate replay but must
    // leave neither its nonce nor its fee in the final partition.
    let mut rejected = tx.clone();
    rejected.op_type = OpType::Standard;
    rejected.nonce = Nonce::new(2).unwrap();
    rejected.amount = 1_000_000.into();
    rejected.encrypted_data = None;
    rejected.message = None;
    rejected.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[42; 32])
                .sign(&rejected.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let mut scratch = StateBatch::from_snapshot(expected.state.clone());
    scratch.begin().unwrap();
    let mut ledger = account_store::ledger(&scratch).unwrap();
    let octra_node_runtime::epoch_execution::Effect::Rejected(reason) =
        octra_node_runtime::epoch_execution::public(&rejected, &mut ledger, &mut scratch).unwrap()
    else {
        panic!("expected insufficient balance")
    };
    let rejections = transaction_outcome::build(
        &[tx.clone(), rejected.clone()],
        &[(rejected, reason.error_type, reason.reason)],
        &[],
    )
    .unwrap();
    let mut outcomes = raw.clone();
    outcomes.receipts_json = transaction_outcome::encode(&raw.receipts_json, &rejections).unwrap();
    let mut proposal_outcomes = proposal.clone();
    proposal_outcomes.header.receipt_root = hash::receipt_root(&outcomes.receipts_json)
        .unwrap()
        .to_vec();
    sign(&mut proposal_outcomes);
    let replayed = executor
        .verify_proposal(candidate(&node, &proposal_outcomes).await, &outcomes)
        .await
        .unwrap();
    assert_eq!(
        replayed.execution().state.root().unwrap(),
        expected.state.root().unwrap()
    );
    let inputs = transaction_outcome::merge(std::slice::from_ref(&tx), &rejections).unwrap();
    let built_rejections = executor
        .build_proposal(draft.clone(), inputs)
        .await
        .unwrap();
    assert_eq!(built_rejections.plan().header, proposal_outcomes.header);
    assert_eq!(built_rejections.bundle(), &outcomes);
    assert_eq!(
        built_rejections.execution().state.root().unwrap(),
        expected.state.root().unwrap()
    );
    let empty = executor
        .build_proposal(draft.clone(), vec![])
        .await
        .unwrap();
    assert_eq!(empty.plan().header.txid_hi, view.head().txid_hi);
    assert!(empty.bundle().txs_json.is_empty());
    let mut empty_proposal = proposal.clone();
    empty_proposal.header = empty.plan().header.clone();
    empty_proposal.tx_hashes.clear();
    sign(&mut empty_proposal);
    executor
        .verify_proposal(candidate(&node, &empty_proposal).await, empty.bundle())
        .await
        .unwrap();
    let mut forged = tx.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(
        executor.build_proposal(draft.clone(), vec![forged]).await,
        Err(ProposalError::Invalid(_))
    ));
    // A failed VM call advances the nonce in candidate preview. Its public
    // successor cannot survive finalized replay after that ordinary rejection
    // is removed. Native recovery cuts off the successor and replays the failure
    // alone before building the empty final state with its refusal record.
    let mut failed_call = tx.clone();
    failed_call.encrypted_data = Some(b"missing_method".to_vec());
    let mut successor = tx.clone();
    successor.op_type = OpType::Standard;
    successor.nonce = Nonce::new(2).unwrap();
    successor.encrypted_data = None;
    successor.message = None;
    for tx in [&mut failed_call, &mut successor] {
        tx.signature = STANDARD
            .encode(
                SigningKey::from_bytes(&[42; 32])
                    .sign(&tx.signing_bytes().unwrap())
                    .to_bytes(),
            )
            .into_bytes();
    }
    let recovered = executor
        .build_proposal(draft.clone(), vec![failed_call.clone(), successor])
        .await
        .unwrap();
    assert!(recovered.bundle().txs_json.is_empty());
    assert_eq!(recovered.refused(), &[failed_call]);
    assert!(recovered.held().is_empty());
    assert_eq!(
        recovered.execution().state.root().unwrap(),
        empty.execution().state.root().unwrap()
    );
    let mut recovered_proposal = proposal.clone();
    recovered_proposal.header = recovered.plan().header.clone();
    recovered_proposal.tx_hashes.clear();
    sign(&mut recovered_proposal);
    let verified = executor
        .verify_proposal(
            candidate(&node, &recovered_proposal).await,
            recovered.bundle(),
        )
        .await
        .unwrap();
    assert_eq!(
        verified.execution().state.root().unwrap(),
        recovered.execution().state.root().unwrap()
    );
    let mut wrong = rejections;
    wrong[0].reason = b"invented rejection".to_vec();
    outcomes.receipts_json = transaction_outcome::encode(&raw.receipts_json, &wrong).unwrap();
    proposal_outcomes.header.receipt_root = hash::receipt_root(&outcomes.receipts_json)
        .unwrap()
        .to_vec();
    sign(&mut proposal_outcomes);
    invalid(
        &node,
        &executor,
        &proposal_outcomes,
        &outcomes,
        "preview_rejection_mismatch",
    )
    .await;
    assert_eq!(store.head().await.unwrap(), *view.head());
    assert_eq!(store.source().head().await.unwrap().sequence, Sequence(0));
    node.suspend("prepared proposal revocation");
    assert!(!node.proposal_current(prepared.candidate()));
    node.resume().await.unwrap();
    assert!(!node.draft_current(&draft));
    assert!(matches!(
        executor.build_proposal(draft, vec![tx]).await,
        Err(ProposalError::Unavailable(_))
    ));
    assert!(!node.proposal_current(prepared.candidate()));
    node.shutdown().await.unwrap();
}
