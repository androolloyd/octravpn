//! Stateful local acquisition through real proposal execution and publication.
//! Fixed development authorities authenticate these fixtures; no public network
//! or native compiler/VM equivalence is inferred from the tests.
use super::*;
use octra_node::{
    driver,
    executor::{Native, Pending, ProposalError},
    peers::Network,
};
use octra_node_protocol::{
    consensus::{journal::JournalOwner, policy::Protocol, Proposal},
    network::{endpoint::Endpoint, session::Timeouts, swarm},
    preverify_receipt::{Binding, Receipt},
    rules::Graph,
};
use octra_node_runtime::{
    consensus_driver::{Host as DriverHost, Verdict},
    finality::proposal::Policy,
    staging::{Limits, Pool},
    validator_history::{CanonicalValidators, Environment},
};

fn policy() -> Policy {
    Policy {
        protocol: Protocol::new(2).unwrap(),
        genesis_time: Some(0.),
    }
}
fn sign(proposal: &mut Proposal) {
    proposal.signature = SigningKey::from_bytes(&[1; 32])
        .sign(&hash::propose_sign_bytes(proposal).unwrap())
        .to_bytes()
        .to_vec();
}
struct Fixture {
    directory: tempfile::TempDir,
    node: Arc<Node<Authority>>,
    reader: octra_node_runtime::canonical::Reader,
    authority: finality_host::Authority,
    native: Native,
    proposal: Proposal,
    raw: RawBundle,
    transactions: Vec<Transaction>,
    certificate: Finalize,
}
impl Fixture {
    async fn new(count: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let circle = format!("oct{}", "1".repeat(44));
        let state = genesis(circle.as_bytes());
        let chain = ChainIdentity::genesis(
            "local-bundle-fixture",
            StateRoot(finality_host::root(None, &state, &[])),
        );
        let authority = finality_host::Authority {
            seed: 1,
            chain: chain.clone(),
        };
        let db = directory.path().join("node.db");
        let store = CanonicalStore::create(&db, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap();
        let reader = store.reader();
        drop(store);
        let checkpoints = Arc::new(
            SqliteCheckpoints::open(&directory.path().join("exex.db"))
                .await
                .unwrap(),
        );
        let node = Arc::new(open(&db, checkpoints, chain, Arc::default()).await);
        assert!(node.resume().await.unwrap());
        let native = ImportExecutor::with_protocol(&authority, &node, policy().protocol).native;
        let draft = Arc::new(
            node.proposal_draft(
                &Graph::new(authority.chain.chain_id.as_bytes().to_vec(), None),
                policy(),
                b"validator-0",
                10.,
            )
            .await
            .unwrap(),
        );
        let transactions = (1..=count)
            .map(|nonce| {
                let mut tx = circle_call(nonce, circle.as_bytes());
                if nonce > 1 {
                    // The adopted CircleCompute lane permits one call per
                    // proposal. Use a real signed self-transfer for the second
                    // item so order/missing-body tests retain two valid inputs.
                    tx.op_type = OpType::Standard;
                    tx.to = tx.from.clone();
                    tx.amount = 0.into();
                    tx.message = None;
                    tx.encrypted_data = None;
                    tx.signature = STANDARD
                        .encode(
                            SigningKey::from_bytes(&[42; 32])
                                .sign(&tx.signing_bytes().unwrap())
                                .to_bytes(),
                        )
                        .into_bytes();
                }
                tx
            })
            .collect::<Vec<_>>();
        let built = native
            .build_proposal(draft, transactions.clone())
            .await
            .unwrap();
        assert_eq!(
            built.bundle().txs_json.len(),
            usize::try_from(count).unwrap()
        );
        let set = authority
            .validators(node.snapshot().unwrap().head(), 1)
            .unwrap();
        let mut proposal = Proposal {
            chain_id: built.plan().header.chain_id.clone(),
            epoch_id: 1,
            round: (0..32)
                .find(|&round| set.leader(1, round).unwrap().address == b"validator-0")
                .unwrap(),
            valid_round: None,
            header: built.plan().header.clone(),
            tx_hashes: built.plan().tx_hashes.clone(),
            parent_commit: None,
            proposer: b"validator-0".to_vec(),
            signature: vec![],
        };
        sign(&mut proposal);
        let mut certificate = finality_host::certificate(
            node.snapshot().unwrap().head(),
            built.execution(),
            &authority,
        );
        certificate.header = proposal.header.clone();
        finality_host::sign(&mut certificate, 1);
        Self {
            directory,
            node,
            reader,
            authority,
            native,
            proposal,
            raw: built.bundle().clone(),
            transactions,
            certificate,
        }
    }
    async fn candidate(&self, proposal: &Proposal) -> Arc<octra_node::proposal::Candidate> {
        Arc::new(
            self.node
                .proposal_candidate(proposal, &self.native.graph(), policy(), 10.)
                .await
                .unwrap(),
        )
    }
    async fn validator(
        &self,
        transactions: &[Transaction],
    ) -> (Network, driver::Validator<Authority>, Endpoint) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Endpoint {
            host: b"127.0.0.1".to_vec(),
            port: listener.local_addr().unwrap().port(),
        };
        let reader = self.reader.clone();
        let set = self
            .authority
            .validators(self.node.snapshot().unwrap().head(), 1)
            .unwrap();
        let journal = JournalOwner::open(
            self.directory
                .path()
                .join(format!("journal-{}", endpoint.port)),
        )
        .unwrap();
        journal.set_floor(0).unwrap();
        let network = Network::new(
            listener,
            swarm::Config {
                chain_id: self.proposal.chain_id.clone(),
                node_address: b"validator-0".to_vec(),
                config_hash: vec![1; 32],
                binary_hash: vec![2; 32],
                require_binary_hash: false,
                upgrade: None,
                profiles: vec![],
                allowed_public_keys: set.validators.iter().map(|v| v.pubkey.clone()).collect(),
                bootstrap: vec![],
                maximum_validators: 16,
                advertised: endpoint.clone(),
                timeouts: Timeouts::default(),
                head: Arc::new(|| (0, [0; 32])),
            },
            SigningKey::from_bytes(&[1; 32]),
            self.node.history(),
            reader.clone(),
            CanonicalValidators::new(reader, Environment::default()),
            set,
            journal.clone(),
        )
        .unwrap();
        let state = StateBatch::from_snapshot(self.node.snapshot().unwrap().state().clone());
        let ledger = account_store::ledger(&state).unwrap();
        let mut pool = Pool::default();
        for tx in transactions {
            pool.add(
                tx.clone(),
                &Limits::default(),
                Some(0),
                &|sender| ledger.account(sender).map(|a| (a.balance.clone(), a.nonce)),
                &|| 10.,
            )
            .unwrap();
        }
        let validator = driver::Validator::new(
            self.node.clone(),
            self.native.clone(),
            Arc::new(Pending::new(pool)),
            &network,
            driver::Config {
                key: SigningKey::from_bytes(&[1; 32]),
                address: b"validator-0".to_vec(),
                policy: policy(),
                journal,
                epoch_capacity: 10_000_000_000_u64.into(),
                stealth_slots: 4,
                evidence_dir: self.directory.path().join("evidence"),
                release: None,
                liveness_clock: None,
            },
        )
        .unwrap();
        (network, validator, endpoint)
    }
}

#[test]
fn local_acquisition_branches_are_bound_to_the_adopted_native_source() {
    let source: Value =
        serde_json::from_str(include_str!("../../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(
        source["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    for (path, hash) in [
        (
            "node_runtime/consensus_bundle_fetch.ml",
            "c0b93606f3346019472c0f6eff46e7993bcdaa6d863902c3d52ff40ee0ae57c2",
        ),
        (
            "node_runtime/consensus_proposal.ml",
            "ac587584360918761eee859662772993a1d99b83d93b3f1a8d22ae6040a491fe",
        ),
        (
            "node_runtime/consensus_finalized_apply.ml",
            "4c367740d3d134a519265a3c0d6f5829a2bc10246a515afed9ff58bf0437fe07",
        ),
    ] {
        assert_eq!(source["files"][path], hash);
    }
}

#[tokio::test]
async fn actual_validator_accepts_cached_and_complete_staging_without_any_peer() {
    let fixture = Fixture::new(2).await;
    let base = fixture.node.head().await.unwrap();
    for cached in [false, true] {
        let staged = if cached {
            &[][..]
        } else {
            &fixture.transactions
        };
        let (network, validator, _) = fixture.validator(staged).await;
        assert!(network.swarm.peers().is_empty());
        if cached {
            network
                .authority
                .cache(
                    1,
                    hash::proposal_id(&fixture.proposal.header).unwrap(),
                    fixture.raw.clone(),
                )
                .unwrap();
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), validator.verify(&fixture.proposal))
                .await
                .expect("local acquisition queried absent peers")
                .unwrap(),
            Verdict::Accept
        );
        assert_eq!(
            network
                .bundles
                .local(&hash::proposal_id(&fixture.proposal.header).unwrap())
                .await
                .unwrap(),
            Some(fixture.raw.clone())
        );
        for tx in &fixture.transactions {
            let hash = hex::encode(tx.hash().unwrap()).into_bytes();
            assert_eq!(
                fixture.native.shared_transaction(&hash).unwrap(),
                Some(tx.clone()),
                "only completely verified proposal transactions enter shared gossip"
            );
        }
        assert_eq!(
            fixture.node.head().await.unwrap(),
            base,
            "speculative replay must not publish"
        );
    }
    let prepared = fixture
        .native
        .verify_local_proposal(
            fixture.candidate(&fixture.proposal).await,
            fixture.transactions.clone(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.bundle(), &fixture.raw);
    let mut reversed = fixture.transactions.clone();
    reversed.reverse();
    for incomplete in [vec![], reversed, fixture.transactions[..1].to_vec()] {
        let error = fixture
            .native
            .verify_local_proposal(fixture.candidate(&fixture.proposal).await, incomplete)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, ProposalError::Invalid(_))
                && error.to_string().contains("local_preverify_tx_mismatch"),
            "{error}"
        );
    }
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn empty_proposal_and_finalized_bundle_need_no_serving_peer() {
    let fixture = Fixture::new(0).await;
    let candidate = fixture.candidate(&fixture.proposal).await;
    assert!(candidate.context().rules().authority().is_err());
    assert!(candidate.context().authority().validators.n > 0);
    // Proposal authentication supplies membership and policy, but must never
    // grant the Bound finalized-certificate replay authority, even on retries.
    for _ in 0..2 {
        fixture
            .native
            .verify_local_proposal(candidate.clone(), vec![])
            .await
            .unwrap();
        assert!(candidate.context().rules().authority().is_err());
    }
    let (network, validator, _) = fixture.validator(&[]).await;
    assert!(network.swarm.peers().is_empty());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), validator.verify(&fixture.proposal))
            .await
            .expect("empty bundle queried absent peers")
            .unwrap(),
        Verdict::Accept
    );
    // Use a fresh local reader so finality must take the native empty-bundle
    // branch rather than consume the proposal cache populated by verification.
    let reader = bundle_peer::node(
        &fixture.proposal.chain_id,
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        fixture
            .authority
            .validators(fixture.node.snapshot().unwrap().head(), 1)
            .unwrap(),
        vec![],
    )
    .await;
    assert!(reader.swarm.peers().is_empty());
    let publication = fixture
        .node
        .import_finalized(
            &fixture.certificate.encode().unwrap(),
            &reader.bundles,
            &fixture.native,
            0.,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publication.head.cursor.epoch.0, 1);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn cached_bytes_cannot_bypass_order_receipt_epoch_or_local_proof_checks() {
    let fixture = Fixture::new(2).await;
    let base = fixture.node.head().await.unwrap();
    let mut reordered = fixture.raw.clone();
    reordered.txs_json.reverse();
    let mut missing = fixture.raw.clone();
    missing.txs_json.pop();
    let mut corrupt = fixture.raw.clone();
    corrupt.txs_json[0] = b"{bad JSON".to_vec();
    let mut receipts = fixture.raw.clone();
    receipts.receipts_json.clear();
    for raw in [reordered, missing, corrupt, receipts] {
        let (network, validator, _) = fixture.validator(&[]).await;
        network
            .authority
            .cache(1, hash::proposal_id(&fixture.proposal.header).unwrap(), raw)
            .unwrap();
        assert_eq!(
            validator.verify(&fixture.proposal).await.unwrap(),
            Verdict::Reject
        );
        assert_eq!(fixture.node.head().await.unwrap(), base);
    }
    for corrupt_root in [false, true] {
        let mut forged = fixture.proposal.clone();
        if corrupt_root {
            forged.header.proposed_state_root[0] ^= 1;
        } else {
            forged.header.txid_hi += 1;
        }
        sign(&mut forged);
        let (network, validator, _) = fixture.validator(&[]).await;
        network
            .authority
            .cache(
                1,
                hash::proposal_id(&forged.header).unwrap(),
                fixture.raw.clone(),
            )
            .unwrap();
        assert_eq!(validator.verify(&forged).await.unwrap(), Verdict::Reject);
        assert_eq!(fixture.node.head().await.unwrap(), base);
    }
    // A receipt may pass structural checks and match a freshly signed header,
    // yet disagree with the binding produced by actual local Circle execution.
    let mut raw = fixture.raw.clone();
    let mut receipt = Receipt::parse(&raw.receipts_json[0]).unwrap();
    let Binding::Circle(binding) = &mut receipt.binding else {
        panic!("Circle binding expected")
    };
    binding.context_hash = vec![b'0'; 64];
    receipt.input_hash = receipt
        .binding
        .input_hash(&fixture.transactions[0])
        .unwrap();
    receipt.output_hash = receipt
        .binding
        .output_hash(&fixture.transactions[0], b"ok")
        .unwrap();
    raw.receipts_json[0] = receipt.canonical();
    let mut forged = fixture.proposal.clone();
    forged.header.receipt_root = hash::receipt_root(&raw.receipts_json).unwrap().to_vec();
    sign(&mut forged);
    let (network, validator, _) = fixture.validator(&[]).await;
    network
        .authority
        .cache(1, hash::proposal_id(&forged.header).unwrap(), raw)
        .unwrap();
    assert_eq!(validator.verify(&forged).await.unwrap(), Verdict::Reject);
    let mut wrong_epoch = fixture.proposal.clone();
    wrong_epoch.epoch_id = 2;
    wrong_epoch.header.epoch_id = 2;
    sign(&mut wrong_epoch);
    assert_eq!(
        validator.verify(&wrong_epoch).await.unwrap(),
        Verdict::Reject
    );
    assert_eq!(fixture.node.head().await.unwrap(), base);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn local_capture_refusal_cannot_turn_an_unexecuted_transaction_into_a_bundle() {
    let fixture = Fixture::new(1).await;
    let mut refused = fixture.transactions[0].clone();
    refused.nonce = Nonce::new(2).unwrap();
    refused.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[42; 32])
                .sign(&refused.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let mut proposal = fixture.proposal.clone();
    proposal.tx_hashes = vec![hex::encode(refused.hash().unwrap()).into_bytes()];
    proposal.header.tx_list_hash =
        octra_node_protocol::consensus::engine::tx_list_hash_for_header(&proposal.tx_hashes)
            .to_vec();
    sign(&mut proposal);
    let base = fixture.node.head().await.unwrap();
    let error = fixture
        .native
        .verify_local_proposal(fixture.candidate(&proposal).await, vec![refused])
        .await
        .err()
        .expect("nonce-gap local execution was accepted");
    assert!(
        matches!(error, ProposalError::Invalid(_))
            && error.to_string().contains("bundle receipt_root mismatch"),
        "{error}"
    );
    assert_eq!(fixture.node.head().await.unwrap(), base);
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn local_receipt_mismatch_fetches_signed_outcomes_and_rechecks_local_execution() {
    let fixture = Fixture::new(1).await;
    let prepared = fixture
        .native
        .verify_local_proposal(
            fixture.candidate(&fixture.proposal).await,
            fixture.transactions.clone(),
        )
        .await
        .unwrap();
    let confirmed = fixture.transactions[0].clone();
    let mut rejected = confirmed.clone();
    rejected.op_type = OpType::Standard;
    rejected.nonce = Nonce::new(2).unwrap();
    rejected.amount = 1_000_000.into();
    rejected.message = None;
    rejected.encrypted_data = None;
    rejected.signature = STANDARD
        .encode(
            SigningKey::from_bytes(&[42; 32])
                .sign(&rejected.signing_bytes().unwrap())
                .to_bytes(),
        )
        .into_bytes();
    let mut scratch = StateBatch::from_snapshot(prepared.execution().state.clone());
    scratch.begin().unwrap();
    let mut ledger = account_store::ledger(&scratch).unwrap();
    let octra_node_runtime::epoch_execution::Effect::Rejected(reason) =
        octra_node_runtime::epoch_execution::public(&rejected, &mut ledger, &mut scratch).unwrap()
    else {
        panic!("expected actual insufficient-balance refusal")
    };
    let rejections = octra_node_protocol::transaction_outcome::build(
        &[confirmed.clone(), rejected.clone()],
        &[(rejected, reason.error_type, reason.reason)],
        &[],
    )
    .unwrap();
    let mut outcomes = fixture.raw.clone();
    outcomes.receipts_json =
        octra_node_protocol::transaction_outcome::encode(&outcomes.receipts_json, &rejections)
            .unwrap();
    let mut proposal = fixture.proposal.clone();
    proposal.header.receipt_root = hash::receipt_root(&outcomes.receipts_json)
        .unwrap()
        .to_vec();
    sign(&mut proposal);
    for complete_staging in [false, true] {
        let staged = if complete_staging {
            std::slice::from_ref(&confirmed)
        } else {
            &[]
        };
        let (network, validator, endpoint) = fixture.validator(staged).await;
        let set = fixture
            .authority
            .validators(fixture.node.snapshot().unwrap().head(), 1)
            .unwrap();
        let server = bundle_peer::node(
            &proposal.chain_id,
            b"validator-1".to_vec(),
            SigningKey::from_bytes(&[2; 32]),
            set,
            vec![endpoint],
        )
        .await;
        let id = hash::proposal_id(&proposal.header).unwrap();
        server
            .authority
            .cached
            .lock()
            .unwrap()
            .insert(id, outcomes.clone());
        let authority = network.authority.clone();
        let swarm = network.swarm.clone();
        let (stop, signal) = watch::channel(false);
        let task = tokio::spawn(network.run(signal));
        bundle_peer::wait_for(|| swarm.peers().len() == 1).await;
        assert_eq!(validator.verify(&proposal).await.unwrap(), Verdict::Accept);
        assert!(
            !server.authority.requests.lock().unwrap().is_empty(),
            "local receipt-root mismatch must acquire the committed rejection artifacts"
        );
        assert_eq!(
            octra_node_runtime::bundle_queries::Host::lookup(&authority, &id)
                .await
                .unwrap(),
            Some(outcomes.clone())
        );
        assert_eq!(fixture.node.head().await.unwrap().cursor.epoch.0, 0);
        stop.send_replace(true);
        task.await.unwrap().unwrap();
    }
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn cached_nonempty_finality_uses_the_native_authority_without_a_remote_query() {
    let fixture = Fixture::new(1).await;
    let (network, _, _) = fixture.validator(&[]).await;
    assert!(network.swarm.peers().is_empty());
    let id = hash::proposal_id(&fixture.certificate.header).unwrap();
    network.authority.cache(1, id, fixture.raw.clone()).unwrap();
    let publication = fixture
        .node
        .import_finalized(
            &fixture.certificate.encode().unwrap(),
            &network.bundles,
            &fixture.native,
            0.,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(publication.head.cursor.epoch.0, 1);
    assert_eq!(
        fixture.node.history().bundle(&id).await.unwrap(),
        Some(fixture.raw.clone())
    );
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn finalized_local_bundle_publishes_without_remote_service_and_rejects_corruption() {
    let fixture = Fixture::new(1).await;
    let reader = bundle_peer::node(
        &fixture.proposal.chain_id,
        b"validator-0".to_vec(),
        SigningKey::from_bytes(&[1; 32]),
        fixture
            .authority
            .validators(fixture.node.snapshot().unwrap().head(), 1)
            .unwrap(),
        vec![],
    )
    .await;
    let id = hash::proposal_id(&fixture.certificate.header).unwrap();
    let certificate = fixture.certificate.encode().unwrap();
    let base = fixture.node.head().await.unwrap();
    // Absent local bytes and no peer are still a deferral, never fabricated
    // empty finality or a replay of a different proposal's bundle.
    assert!(fixture
        .node
        .import_finalized(&certificate, &reader.bundles, &fixture.native, 0.)
        .await
        .unwrap()
        .is_none());
    let mut bad = fixture.raw.clone();
    bad.receipts_json.clear();
    reader.authority.cached.lock().unwrap().insert(id, bad);
    assert!(fixture
        .node
        .import_finalized(&certificate, &reader.bundles, &fixture.native, 0.)
        .await
        .is_err());
    assert_eq!(fixture.node.head().await.unwrap(), base);
    reader.authority.cached.lock().unwrap().remove(&id);
    let prior = reader.authority.requests.lock().unwrap().len();
    let mut importing = Box::pin(fixture.node.import_finalized(
        &certificate,
        &reader.bundles,
        &fixture.native,
        2.,
    ));
    tokio::select! {
        result = &mut importing => panic!("import completed before the local bundle appeared: {}", result.is_ok()),
        () = bundle_peer::wait_for(|| reader.authority.requests.lock().unwrap().len() > prior) => (),
    }
    reader
        .authority
        .cached
        .lock()
        .unwrap()
        .insert(id, fixture.raw.clone());
    let published = importing.await.unwrap().unwrap();
    assert_eq!(published.head.cursor.epoch.0, 1);
    assert_eq!(
        fixture.node.history().bundle(&id).await.unwrap(),
        Some(fixture.raw.clone())
    );
    fixture.node.shutdown().await.unwrap();
}
