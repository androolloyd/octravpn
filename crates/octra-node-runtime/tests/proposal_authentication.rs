use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{ChainIdentity, CommittedEpochSource, Sequence, StateRoot};
use octra_node_protocol::{
    consensus::{codec::Wire, hash, policy::Protocol, ParentCommit, Proposal, ValidatorSet},
    rules::Graph,
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head, ReliefSource},
    finality::{
        proposal::{Authenticated, Policy},
        EpochRules, Error, ExecutedEpoch, Publisher, ValidatorHistory,
    },
    state_batch::StateBatch,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[path = "common/finality_host.rs"]
mod finality_host;

struct Authority {
    fixed: finality_host::Authority,
    reads: Arc<Mutex<BTreeMap<u64, usize>>>,
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        base: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        *self.reads.lock().unwrap().entry(epoch).or_default() += 1;
        self.fixed.resolve(base, epoch, relief).await
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<CanonicalStore>,
    publisher: Publisher<Authority>,
    fixed: finality_host::Authority,
    reads: Arc<Mutex<BTreeMap<u64, usize>>>,
    graph: Graph,
    policy: Policy,
}
impl Fixture {
    async fn new(chain: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = StateBatch::default();
        let chain =
            ChainIdentity::genesis(chain, StateRoot(finality_host::root(None, &state, &[])));
        let store = Arc::new(
            CanonicalStore::create(
                &dir.path().join("node.db"),
                chain.clone(),
                state.snapshot(),
                999_999,
            )
            .await
            .unwrap(),
        );
        let fixed = finality_host::Authority {
            seed: 1,
            chain: chain.clone(),
        };
        let reads = Arc::new(Mutex::new(BTreeMap::new()));
        let publisher = Publisher::open(
            store.clone(),
            Authority {
                fixed: fixed.clone(),
                reads: reads.clone(),
            },
        )
        .await
        .unwrap();
        Self {
            dir,
            store,
            publisher,
            fixed,
            reads,
            graph: Graph::new(chain.chain_id.into_bytes(), None),
            policy: Policy {
                protocol: Protocol::new(2).unwrap(),
                genesis_time: Some(0.),
            },
        }
    }
    fn executed() -> ExecutedEpoch {
        ExecutedEpoch {
            epoch_observation: None,
            metrics: octra_node_protocol::metrics::Epoch::default(),
            vm_receipts: std::collections::BTreeMap::default(),
            state: StateBatch::default().snapshot(),
            transactions: vec![],
            consensus_receipts: vec![],
            reward_source: finality_host::reward_source(1),
            date: 999_999,
            message: b"local metadata".to_vec(),
        }
    }
    async fn proposal(&self) -> (Head, Proposal) {
        let base = self.store.head().await.unwrap();
        let set = self
            .fixed
            .validators(&base, base.cursor.epoch.0 + 1)
            .unwrap();
        let finalized = finality_host::certificate(&base, &Self::executed(), &self.fixed);
        let parent_commit = if base.cursor.epoch.0 == 0 {
            None
        } else {
            let proof = self
                .publisher
                .record(base.cursor.sequence)
                .await
                .unwrap()
                .finality
                .unwrap();
            Some(ParentCommit {
                certificate: proof.finalize.certificate(),
                validator_set: proof.validator_set,
            })
        };
        let mut proposal = Proposal {
            chain_id: finalized.chain_id,
            epoch_id: finalized.epoch_id,
            round: 0,
            valid_round: None,
            header: finalized.header,
            tx_hashes: vec![],
            parent_commit,
            proposer: set.leader(finalized.epoch_id, 0).unwrap().address.clone(),
            signature: vec![],
        };
        proposal.header.creator_addr = proposal.proposer.clone();
        proposal.header.proto_version = self.policy.protocol.version_at(proposal.epoch_id);
        parent_hash(&mut proposal);
        sign(&mut proposal);
        self.reads.lock().unwrap().clear();
        (base, proposal)
    }
    async fn authenticate(&self, base: &Head, proposal: &Proposal) -> Result<Authenticated, Error> {
        self.publisher
            .authenticate_proposal(base, proposal, &self.graph, self.policy, 20.)
            .await
    }
    async fn publish_first(&self) {
        let base = self.store.head().await.unwrap();
        assert_eq!(base.cursor.epoch.0, 0);
        let executed = Self::executed();
        let mut finalized = finality_host::certificate(&base, &executed, &self.fixed);
        finalized.header.proto_version = 3;
        finality_host::sign(&mut finalized, 1);
        self.publisher
            .prepare(&base, &finalized.encode().unwrap(), executed)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
}

fn parent_hash(proposal: &mut Proposal) {
    proposal.header.parent_commit_hash =
        hash::parent_commit_hash_opt(proposal.parent_commit.as_ref())
            .unwrap()
            .to_vec();
}
fn sign(proposal: &mut Proposal) {
    let id: u8 = std::str::from_utf8(&proposal.proposer)
        .unwrap()
        .strip_prefix("validator-")
        .unwrap()
        .parse()
        .unwrap();
    proposal.signature = SigningKey::from_bytes(&[id + 1; 32])
        .sign(&hash::propose_sign_bytes(proposal).unwrap())
        .to_bytes()
        .to_vec();
}
fn rejected(result: Result<Authenticated, Error>, message: &str) {
    match result {
        Err(Error::Invalid(reason)) => {
            assert!(reason.contains(message), "{reason} lacks {message}");
        }
        Err(e) => panic!("expected invalid {message}, got {e}"),
        Ok(_) => panic!("accepted {message}"),
    }
}

#[tokio::test]
async fn canonical_proposal_captures_authority_without_finalized_privileges() {
    let fixture = Fixture::new("proposal-auth-fixture").await;
    for epoch in [1, 2] {
        if epoch == 2 {
            fixture.publish_first().await;
        }
        let (base, proposal) = fixture.proposal().await;
        let context = fixture.authenticate(&base, &proposal).await.unwrap();
        assert_eq!(context.parent(), &base);
        assert_eq!(context.proposal(), &proposal);
        assert_eq!(
            context.authority().validators,
            fixture.fixed.validators(&base, epoch).unwrap()
        );
        assert_eq!(fixture.reads.lock().unwrap()[&epoch], 1);
        assert!(
            context.rules().authority().is_err(),
            "a proposal acquired finalized replay authority"
        );
        assert_eq!(fixture.store.head().await.unwrap(), base);
        assert!(fixture
            .store
            .source()
            .load(Sequence(epoch))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            base.date, 999_999,
            "signed time must be independent of local commit date"
        );
    }
}

#[tokio::test]
async fn local_build_context_uses_signed_history_and_never_grants_finality() {
    let fixture = Fixture::new("proposal-build-context").await;
    for epoch in [1, 2] {
        if epoch == 2 {
            fixture.publish_first().await;
        }
        let base = fixture.store.head().await.unwrap();
        let time = f64::from(u32::try_from(epoch).unwrap()) * 10.;
        let context = fixture
            .publisher
            .proposal_build_context(&base, &fixture.graph, fixture.policy, b"validator-0", time)
            .await
            .unwrap();
        assert_eq!(context.parent(), &base);
        assert_eq!(context.header().epoch_id, epoch as i64);
        assert_eq!(context.header().prev_state_root, base.cursor.state_root.0);
        assert_eq!(context.header().ts.to_bits(), time.to_bits());
        assert_eq!(
            context.authority().validators,
            fixture.fixed.validators(&base, epoch).unwrap()
        );
        assert_eq!(context.parent_commit().is_some(), epoch == 2);
        assert!(context.rules().authority().is_err());
        assert_eq!(fixture.store.head().await.unwrap(), base);
    }
}

#[tokio::test]
async fn local_build_refuses_missing_authority_time_and_stale_parent() {
    let fixture = Fixture::new("proposal-build-context").await;
    let base = fixture.store.head().await.unwrap();
    let attempt = |policy, creator: &'static [u8], now| {
        fixture
            .publisher
            .proposal_build_context(&base, &fixture.graph, policy, creator, now)
    };
    assert!(matches!(
        attempt(fixture.policy, b"unknown", 10.).await,
        Err(Error::Invalid(_))
    ));
    for now in [0., 9.999, f64::NAN, f64::INFINITY] {
        assert!(attempt(fixture.policy, b"validator-0", now).await.is_err());
    }
    assert!(matches!(
        attempt(
            Policy {
                genesis_time: None,
                ..fixture.policy
            },
            b"validator-0",
            10.
        )
        .await,
        Err(Error::Unavailable(_))
    ));
    assert!(matches!(
        attempt(
            Policy {
                protocol: Protocol::default(),
                ..fixture.policy
            },
            b"validator-0",
            10.
        )
        .await,
        Err(Error::Invalid(_))
    ));
    fixture.publish_first().await;
    assert!(matches!(
        attempt(fixture.policy, b"validator-0", 20.).await,
        Err(Error::Unavailable(_))
    ));
    assert_eq!(
        fixture.store.source().head().await.unwrap().sequence,
        Sequence(1)
    );
}

#[tokio::test]
async fn startup_requires_explicit_time_and_parent_activation_evidence() {
    let mut fixture = Fixture::new("proposal-auth-fixture").await;
    let (base, mut proposal) = fixture.proposal().await;
    fixture.policy.genesis_time = None;
    assert!(matches!(fixture.authenticate(&base, &proposal).await,
        Err(Error::Unavailable(e)) if e == "previous_epoch_time_unavailable"));
    fixture.policy.genesis_time = Some(f64::NAN);
    rejected(fixture.authenticate(&base, &proposal).await, "not finite");
    fixture.policy.genesis_time = Some(0.);
    fixture.policy.protocol = Protocol::default();
    proposal.header.proto_version = 4;
    sign(&mut proposal);
    rejected(
        fixture.authenticate(&base, &proposal).await,
        "parent finality entry is missing",
    );
    fixture.policy.protocol = Protocol::new(2).unwrap();
    proposal.header.proto_version = 3;
    let finalized = finality_host::certificate(&base, &Fixture::executed(), &fixture.fixed);
    proposal.parent_commit = Some(ParentCommit {
        certificate: finalized.certificate(),
        validator_set: fixture.fixed.validators(&base, 1).unwrap(),
    });
    parent_hash(&mut proposal);
    sign(&mut proposal);
    rejected(
        fixture.authenticate(&base, &proposal).await,
        "unexpected parent commit",
    );
    assert_eq!(fixture.store.head().await.unwrap(), base);
}

#[tokio::test]
async fn proposal_frame_and_canonical_bindings_reject_forgery_without_publication() {
    let fixture = Fixture::new("proposal-auth-fixture").await;
    let (base, proposal) = fixture.proposal().await;
    for (field, reason) in [
        ("signature", "bad_signature"),
        ("member", "unknown_validator"),
        ("round", "envelope"),
        ("epoch", "not consecutive"),
        ("version", "envelope"),
        ("chain", "envelope"),
        ("transactions", "tx_list_hash"),
        ("parent_hash", "parent_commit_hash"),
        ("root", "previous root mismatch"),
        ("time", "interval is below"),
        ("future", "too far in the future"),
    ] {
        let mut bad = proposal.clone();
        match field {
            "member" => bad.proposer = b"unknown".to_vec(),
            "round" => bad.valid_round = Some(bad.round),
            "epoch" => bad.epoch_id += 1,
            "version" => bad.header.proto_version = 4,
            "chain" => bad.header.chain_id = b"different-chain".to_vec(),
            "transactions" => bad.tx_hashes.push(b"uncommitted transaction".to_vec()),
            "parent_hash" => bad.header.parent_commit_hash[0] ^= 1,
            "root" => bad.header.prev_state_root[0] ^= 1,
            "time" => bad.header.ts = 9.999,
            "future" => bad.header.ts = 25.001,
            _ => (),
        }
        if field != "member" {
            sign(&mut bad);
        }
        if field == "signature" {
            bad.signature[0] ^= 1;
        }
        rejected(fixture.authenticate(&base, &bad).await, reason);
    }
    let wrong = Graph::new(b"other-chain".to_vec(), None);
    rejected(
        fixture
            .publisher
            .authenticate_proposal(&base, &proposal, &wrong, fixture.policy, 20.)
            .await,
        "graph differs",
    );
    let mut altered = base.clone();
    altered.ledger_root = "fabricated".into();
    assert!(matches!(
        fixture.authenticate(&altered, &proposal).await,
        Err(Error::Unavailable(_))
    ));
    assert_eq!(fixture.store.head().await.unwrap(), base);
    assert!(fixture
        .store
        .source()
        .load(Sequence(1))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn parent_qc_must_match_local_finality_but_may_have_different_quorum_signers() {
    let fixture = Fixture::new("proposal-auth-fixture").await;
    let (old_base, old_proposal) = fixture.proposal().await;
    fixture.publish_first().await;
    assert!(matches!(
        fixture.authenticate(&old_base, &old_proposal).await,
        Err(Error::Unavailable(_))
    ));
    let (base, proposal) = fixture.proposal().await;
    for (field, reason) in [
        ("missing", "parent commit is missing"),
        ("signer", "qc_signature"),
        ("quorum", "qc_quorum"),
        ("set", "validator_set"),
        ("fork", "proposal_id"),
    ] {
        let mut bad = proposal.clone();
        let parent = bad.parent_commit.as_mut().unwrap();
        match field {
            "signer" => parent.certificate.precommits[0].signature[0] ^= 1,
            "quorum" => parent.certificate.precommits.pop().map(|_| ()).unwrap(),
            "set" => {
                let mut members = parent.validator_set.validators.clone();
                members[0].pubkey[0] ^= 1;
                parent.validator_set = ValidatorSet::unweighted(members);
            }
            "fork" => {
                let mut fork =
                    finality_host::certificate(&old_base, &Fixture::executed(), &fixture.fixed);
                fork.header.proto_version = 3;
                fork.header.proposed_state_root[0] ^= 1;
                finality_host::sign(&mut fork, 1);
                parent.certificate = fork.certificate();
            }
            _ => bad.parent_commit = None,
        }
        parent_hash(&mut bad);
        sign(&mut bad);
        rejected(fixture.authenticate(&base, &bad).await, reason);
    }
    let mut alternative = proposal.clone();
    let votes = &mut alternative
        .parent_commit
        .as_mut()
        .unwrap()
        .certificate
        .precommits;
    let mut fourth = votes[0].clone();
    fourth.validator = b"validator-3".to_vec();
    fourth.signature = SigningKey::from_bytes(&[4; 32])
        .sign(&hash::vote_sign_bytes(&fourth).unwrap())
        .to_bytes()
        .to_vec();
    votes.remove(0);
    votes.push(fourth);
    parent_hash(&mut alternative);
    sign(&mut alternative);
    fixture.authenticate(&base, &alternative).await.unwrap();
    assert_eq!(fixture.store.head().await.unwrap(), base);
    assert!(fixture
        .store
        .source()
        .load(Sequence(2))
        .await
        .unwrap()
        .is_none());

    // Reopen and audit retained certificates; authentication must still bind
    // to the signed parent time, rather than the store's date or startup time.
    let store = Arc::new(
        CanonicalStore::open(&fixture.dir.path().join("node.db"), &fixture.fixed.chain)
            .await
            .unwrap(),
    );
    let reopened = Publisher::open(store, fixture.fixed.clone()).await.unwrap();
    reopened
        .authenticate_proposal(
            &base,
            &proposal,
            &fixture.graph,
            Policy {
                genesis_time: Some(1_000_000.),
                ..fixture.policy
            },
            20.,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn historical_reproposal_retains_native_time_policy() {
    for chain in ["octra-mainnet", "proposal-auth-fixture"] {
        let fixture = Fixture::new(chain).await;
        let (base, mut proposal) = fixture.proposal().await;
        proposal.round = 1;
        proposal.valid_round = Some(0);
        proposal.proposer = fixture
            .fixed
            .validators(&base, 1)
            .unwrap()
            .leader(1, 1)
            .unwrap()
            .address
            .clone();
        proposal.header.ts = 100.;
        sign(&mut proposal);
        let result = fixture.authenticate(&base, &proposal).await;
        if chain == "octra-mainnet" {
            result.unwrap();
        } else {
            rejected(result, "too far in the future");
        }
        proposal.header.ts = 9.;
        sign(&mut proposal);
        rejected(
            fixture.authenticate(&base, &proposal).await,
            "interval is below",
        );
    }
}

#[tokio::test]
async fn concurrent_canonical_commit_invalidates_in_flight_authentication() {
    use tokio::sync::oneshot;
    struct Paused {
        fixed: finality_host::Authority,
        entered: Mutex<Option<oneshot::Sender<()>>>,
        resume: Mutex<Option<oneshot::Receiver<()>>>,
    }
    #[async_trait::async_trait]
    impl ValidatorHistory for Paused {
        async fn resolve(
            &self,
            base: &Head,
            epoch: u64,
            relief: ReliefSource,
        ) -> Result<EpochRules, String> {
            let authority = self.fixed.resolve(base, epoch, relief).await?;
            let entered = self.entered.lock().unwrap().take();
            let resume = self.resume.lock().unwrap().take();
            if let (Some(entered), Some(resume)) = (entered, resume) {
                entered.send(()).unwrap();
                resume.await.unwrap();
            }
            Ok(authority)
        }
    }
    for local_build in [false, true] {
        let fixture = Fixture::new("proposal-auth-race").await;
        let (base, proposal) = fixture.proposal().await;
        let executed = Fixture::executed();
        let mut finalized = finality_host::certificate(&base, &executed, &fixture.fixed);
        finalized.header.proto_version = 3;
        finality_host::sign(&mut finalized, 1);
        let commit = fixture
            .publisher
            .prepare(&base, &finalized.encode().unwrap(), executed)
            .await
            .unwrap();
        let (entered, waiting) = oneshot::channel();
        let (resume, paused) = oneshot::channel();
        let publisher = Publisher::open(
            fixture.store.clone(),
            Paused {
                fixed: fixture.fixed.clone(),
                entered: Mutex::new(Some(entered)),
                resume: Mutex::new(Some(paused)),
            },
        )
        .await
        .unwrap();
        let (result, ()) = tokio::join!(
            async {
                if local_build {
                    publisher
                        .proposal_build_context(
                            &base,
                            &fixture.graph,
                            fixture.policy,
                            b"validator-0",
                            20.,
                        )
                        .await
                        .map(|_| ())
                } else {
                    publisher
                        .authenticate_proposal(
                            &base,
                            &proposal,
                            &fixture.graph,
                            fixture.policy,
                            20.,
                        )
                        .await
                        .map(|_| ())
                }
            },
            async {
                waiting.await.unwrap();
                commit.commit().await.unwrap();
                resume.send(()).unwrap();
            }
        );
        assert!(
            matches!(result, Err(Error::Unavailable(e)) if e == "proposal parent is no longer current")
        );
        assert_eq!(fixture.store.head().await.unwrap().cursor.epoch.0, 1);
    }
}
