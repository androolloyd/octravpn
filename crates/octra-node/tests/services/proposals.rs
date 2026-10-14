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
    assert!(!node.proposal_current(prepared.candidate()));
    node.shutdown().await.unwrap();
}
