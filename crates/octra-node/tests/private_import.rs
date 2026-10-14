//! Production finalized executor with native private ciphertext/proof material.
//! Local proposal checks verify real proofs before independently certified
//! historical import. Both routes use content-addressed public key files.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
};
use octra_node::{
    executor::{Config, Limits, Native, ProposalError},
    import::{Execution, Executor},
    Node,
};
use octra_node_protocol::{
    consensus::{codec::Wire, hash, policy::Protocol, Proposal},
    emission::Schedule,
    preverify_receipt::{self, Binding, Receipt, State},
    rules::Graph,
    state::Account,
    transaction::{address_from_public_key, Nonce, OpType, RuleMode, Transaction},
    transaction_policy::Profile,
    validator::policy::Policy,
};
use octra_node_runtime::{
    account_store,
    canonical::{CanonicalStore, Head, ReliefSource},
    consensus_bundle::{self, RawBundle},
    epoch_footer,
    finality::{EpochRules, ExecutedEpoch, Publisher, ReceiptRules, ValidatorHistory},
    state_batch::StateBatch,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[path = "../../octra-node-runtime/tests/common/circle_host.rs"]
#[allow(dead_code)] // This private-only path uses the runtime, not Circle fixtures.
mod circle_host;
#[path = "../../octra-node-runtime/tests/common/finality_host.rs"]
mod common;

#[derive(Clone)]
struct Authority(common::Authority);
impl octra_node::Host for Authority {
    fn check_views(&self, _: &Head) -> Result<(), String> {
        Ok(())
    }
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        let mut rules = self.0.resolve(parent, epoch, relief).await?;
        rules.receipts = ReceiptRules {
            required: true,
            crypto_active: true,
            stealth_minimum: 5000.into(),
        };
        Ok(rules)
    }
}
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn digest(value: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(value)).into_bytes()
}
fn emission() -> epoch_footer::Policy {
    epoch_footer::Policy {
        emission_guard: true,
        schedule: Schedule::Inactive,
        legacy_total: None,
    }
}

#[tokio::test]
async fn finalized_mixed_import_uses_bound_key_files_and_survives_restart() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../octra-node-runtime/tests/fixtures/private-balance.json"
    ))
    .unwrap();
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["input"]["withdraw"] == true && c["expected"]["outcome"]["applied"] == true)
        .unwrap();
    let current = bytes(&case["input"]["current"]);
    let public = bytes(&case["input"]["public"]);
    let next = bytes(&case["expected"]["outcome"]["plan"]["next"]);
    let signer = SigningKey::from_bytes(&[42; 32]);
    let public_signing = STANDARD
        .encode(signer.verifying_key().to_bytes())
        .into_bytes();
    let sender = address_from_public_key(&public_signing);
    let mut initial = StateBatch::default();
    initial.begin().unwrap();
    initial
        .set(&[b"meta", b"last_epoch"], b"0".to_vec())
        .unwrap();
    account_store::set(
        &mut initial,
        &sender,
        &Account {
            balance: 30000.into(),
            encrypted_balance: Some(current.clone()),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    initial
        .set(&[b"pvac_hashes", &sender], digest(&public))
        .unwrap();
    initial
        .set(&[b"meta", b"total_supply"], b"30000".to_vec())
        .unwrap();
    initial
        .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
        .unwrap();
    initial.acknowledge_commit().unwrap();
    let chain = ChainIdentity {
        chain_id: "private-import".into(),
        genesis_root: StateRoot(common::root(None, &initial, &[])),
    };
    let authority = Authority(common::Authority {
        seed: 1,
        chain: chain.clone(),
    });
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("node.db");
    let pvac = dir.path().join("pvac");
    let blob = pvac
        .join("blobs")
        .join(format!("{}.pk", hex::encode(Sha256::digest(&public))));
    let store = Arc::new(
        CanonicalStore::create(&database, chain.clone(), initial.snapshot(), 0)
            .await
            .unwrap(),
    );
    let publisher = Arc::new(
        Publisher::open(store.clone(), authority.clone())
            .await
            .unwrap(),
    );
    let config = Config {
        graph: Graph::new(chain.chain_id.as_bytes().to_vec(), None),
        protocol: Protocol::new(2).unwrap(),
        profile: Profile {
            private_v1: true,
            ..Profile::default()
        },
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        bundle: Limits::new(100, 50_000_000, 100_000.into()),
        validators: Policy::Inactive,
        emission: emission(),
        sender_key_activation: Some(0),
        private_result_activation: 0,
        max_fhe: 4,
        ready_max_lag: 10,
        pvac_dir: pvac,
    };
    let executor = Native::new(config, circle_host::runtime(), publisher.clone()).unwrap();
    let (parent, state) = store.snapshot().await.unwrap();
    let mut tx = Transaction {
        from: sender.clone(),
        to: sender.clone(),
        amount: 7.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 5000.into(),
        timestamp: 10.,
        signature: vec![],
        public_key: Some(public_signing),
        message: None,
        encrypted_data: Some(bytes(&case["input"]["payload"])),
        op_type: OpType::Decrypt,
    };
    tx.signature = STANDARD
        .encode(signer.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    let mut transfer = tx.clone();
    transfer.op_type = OpType::Standard;
    transfer.to = address_from_public_key(&STANDARD.encode([73_u8; 32]).into_bytes());
    transfer.amount = 42.into();
    transfer.nonce = Nonce::new(2).unwrap();
    transfer.ou = 1000.into();
    transfer.encrypted_data = None;
    transfer.signature = STANDARD
        .encode(signer.sign(&transfer.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    let binding = Binding::Private(State {
        pre_state_hash: preverify_receipt::state_hash(parent.ledger_root.as_bytes()),
        source_cipher_hash: digest(&current),
        pvac_key_hash: digest(&public),
        transition_hash: Some(
            case["expected"]["outcome"]["plan"]["hash"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
    });
    let receipt = Receipt::for_tx(
        &tx,
        binding.clone(),
        binding.input_hash(&tx).unwrap(),
        binding.output_hash(&tx, b"ok").unwrap(),
        true,
        vec![],
        &5000.into(),
    )
    .unwrap()
    .canonical();

    // Construct the expected committed tree from the native golden ciphertext
    // and withdrawal/transfer accounting, independently of the import executor.
    let mut expected = state.clone();
    expected.begin().unwrap();
    account_store::set(
        &mut expected,
        &sender,
        &Account {
            balance: 23965.into(),
            nonce: transfer.nonce,
            public_key: tx.public_key.clone(),
            encrypted_balance: Some(next.clone()),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    account_store::set(
        &mut expected,
        &transfer.to,
        &Account {
            balance: 42.into(),
            ..Account::default()
        },
        RuleMode::Prior,
    )
    .unwrap();
    let mut ledger = account_store::ledger(&expected).unwrap();
    epoch_footer::apply(
        &emission(),
        &epoch_footer::Request {
            epoch: 1,
            reward: &common::reward(1),
            validator_keys: &[],
            confirmed_fees: 6000.into(),
        },
        &mut ledger,
        &mut expected,
    )
    .unwrap();
    account_store::flush_dirty(&mut ledger, &mut expected, RuleMode::Prior).unwrap();
    let planned = ExecutedEpoch {
        state: expected.snapshot(),
        transactions: [&tx, &transfer]
            .into_iter()
            .enumerate()
            .map(|(offset, tx)| {
                let identity = tx.identity_bytes().unwrap();
                NativeTransaction {
                    txid: parent.txid_hi + 1 + i64::try_from(offset).unwrap(),
                    hash: hex::encode(tx.hash().unwrap()),
                    identity: identity.clone(),
                    transaction: identity,
                    proof: ArchiveProof::Exact,
                    receipt: None,
                }
            })
            .collect(),
        consensus_receipts: vec![receipt.clone()],
        reward_source: common::reward_source(1),
        date: 1,
        message: b"private import expectation".to_vec(),
    };
    let mut finalized = common::certificate(&parent, &planned, &authority.0);
    finalized.header.proto_version = Protocol::new(2).unwrap().version_at(1);
    common::sign(&mut finalized, 1);
    let certificate = finalized.encode().unwrap();
    let raw = RawBundle {
        tx_hashes: planned
            .transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().to_vec())
            .collect(),
        txs_json: planned
            .transactions
            .iter()
            .map(|tx| tx.transaction.clone())
            .collect(),
        receipts_json: vec![receipt],
    };
    let node = Node::open(
        CanonicalStore::open(&database, &chain).await.unwrap(),
        authority.clone(),
        circle_host::runtime(),
        Arc::new(octra_browser::application::UnavailableHost),
        Arc::new(
            octra_exex::sqlite::SqliteCheckpoints::open(&dir.path().join("exex.db"))
                .await
                .unwrap(),
        ),
    )
    .await
    .unwrap();
    node.resume().await.unwrap();
    let set = authority.0.validators(&parent, 1).unwrap();
    let mut proposal = Proposal {
        chain_id: finalized.chain_id.clone(),
        epoch_id: 1,
        round: (0..32)
            .find(|&r| set.leader(1, r).unwrap().address == b"validator-0")
            .unwrap(),
        valid_round: None,
        header: finalized.header.clone(),
        tx_hashes: raw.tx_hashes.clone(),
        parent_commit: None,
        proposer: b"validator-0".to_vec(),
        signature: vec![],
    };
    let sign = |p: &mut Proposal| {
        p.signature = SigningKey::from_bytes(&[1; 32])
            .sign(&hash::propose_sign_bytes(p).unwrap())
            .to_bytes()
            .to_vec();
    };
    sign(&mut proposal);
    let candidate = |p: Proposal| {
        let node = &node;
        let graph = executor.graph();
        async move {
            Arc::new(
                node.proposal_candidate(
                    &p,
                    &graph,
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
    };
    let mut result = None;
    for scenario in ["missing", "corrupt", "valid"] {
        if scenario != "missing" {
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(
                &blob,
                if scenario == "valid" {
                    public.as_slice()
                } else {
                    b"wrong public key"
                },
            )
            .unwrap();
        }
        let draft = Arc::new(
            node.proposal_draft(
                &executor.graph(),
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
        let inputs: Vec<Transaction> = raw
            .txs_json
            .iter()
            .map(|raw| {
                Transaction::from_document(
                    &octra_node_protocol::native_json::Document::parse(raw).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let normalized = RawBundle {
            // Incoming archive documents include explicit null fields; native
            // bundle serialization omits absent fields after decoding.
            txs_json: inputs
                .iter()
                .map(|tx| tx.to_json_bytes().unwrap())
                .collect(),
            ..raw.clone()
        };
        let built = executor.build_proposal(draft, inputs).await;
        if scenario == "valid" {
            let built = built.unwrap();
            assert_eq!(built.plan().header, proposal.header);
            assert_eq!(built.bundle(), &normalized);
            assert_eq!(
                built.execution().state.root().unwrap(),
                expected.root().unwrap()
            );
        } else {
            assert!(
                matches!(built, Err(ProposalError::Unavailable(_))),
                "{scenario}"
            );
        }
        let verified = executor
            .verify_proposal(candidate(proposal.clone()).await, &raw)
            .await;
        if scenario == "valid" {
            let verified = verified.unwrap();
            assert_eq!(
                verified.execution().state.root().unwrap(),
                expected.root().unwrap()
            );
            assert!(node.proposal_current(verified.candidate()));
            let mut forged = raw.clone();
            let mut receipt = Receipt::parse(&forged.receipts_json[0]).unwrap();
            let Binding::Private(binding) = &mut receipt.binding else {
                panic!("private receipt")
            };
            binding.transition_hash = Some(vec![b'0'; 64]);
            receipt.input_hash = receipt.binding.input_hash(&tx).unwrap();
            receipt.output_hash = receipt.binding.output_hash(&tx, b"ok").unwrap();
            forged.receipts_json[0] = receipt.canonical();
            let mut malicious = proposal.clone();
            malicious.header.receipt_root =
                hash::receipt_root(&forged.receipts_json).unwrap().to_vec();
            sign(&mut malicious);
            let error = executor
                .verify_proposal(candidate(malicious).await, &forged)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(error, ProposalError::Invalid(_))
                    && error
                        .to_string()
                        .contains("local_preverify_receipt_mismatch"),
                "{error}"
            );
        } else {
            let error = verified.err().unwrap();
            assert!(
                matches!(error, ProposalError::Unavailable(_)),
                "{scenario}: {error}"
            );
        }
        if scenario == "valid" {
            // A self-consistent transition receipt cannot excuse an invalid
            // proof, even under the historical non-strict execution profile.
            let mut bad_tx = tx.clone();
            let mut payload: Value =
                serde_json::from_slice(bad_tx.encrypted_data.as_ref().unwrap()).unwrap();
            payload["zero_proof"] = Value::String("invalid".into());
            bad_tx.encrypted_data = Some(serde_json::to_vec(&payload).unwrap());
            bad_tx.signature = STANDARD
                .encode(signer.sign(&bad_tx.signing_bytes().unwrap()).to_bytes())
                .into_bytes();
            let mut forged = raw.clone();
            forged.tx_hashes[0] = hex::encode(bad_tx.hash().unwrap()).into_bytes();
            forged.txs_json[0] = bad_tx.to_json_bytes().unwrap();
            let mut receipt = Receipt::parse(&forged.receipts_json[0]).unwrap();
            receipt.tx_hash = forged.tx_hashes[0].clone();
            receipt.input_hash = receipt.binding.input_hash(&bad_tx).unwrap();
            receipt.output_hash = receipt.binding.output_hash(&bad_tx, b"ok").unwrap();
            receipt.cost =
                octra_node_protocol::resource_lanes::cost(&bad_tx, &5000.into()).unwrap();
            forged.receipts_json[0] = receipt.canonical();
            let mut malicious = proposal.clone();
            malicious.tx_hashes = forged.tx_hashes.clone();
            malicious.header.tx_list_hash =
                octra_node_protocol::consensus::engine::tx_list_hash_for_header(&forged.tx_hashes)
                    .to_vec();
            malicious.header.receipt_root =
                hash::receipt_root(&forged.receipts_json).unwrap().to_vec();
            sign(&mut malicious);
            let error = executor
                .verify_proposal(candidate(malicious).await, &forged)
                .await
                .err()
                .unwrap();
            assert!(
                matches!(error, ProposalError::Invalid(_))
                    && error.to_string().contains("local_preverify_mismatch"),
                "{error}"
            );
        }
        let (finalized, context) = publisher
            .verify_execution(&parent, &certificate, &executor.graph())
            .await
            .unwrap();
        let rules = executor
            .rules(&parent, &finalized.header, &context)
            .unwrap();
        let bundle = consensus_bundle::finalized(&finalized.header, &raw, &rules)
            .unwrap()
            .replay(rules.envelope)
            .unwrap();
        let executed = executor
            .execute(Execution {
                parent: &parent,
                state: state.clone(),
                finalized: &finalized,
                reward_source: None,
                bundle,
                rules: context,
            })
            .await;
        match scenario {
            "missing" => assert!(executed
                .err()
                .unwrap()
                .to_string()
                .contains("pvac blob unavailable")),
            "corrupt" => assert!(executed
                .err()
                .unwrap()
                .to_string()
                .contains("pvac blob hash mismatch")),
            _ => result = Some(executed.unwrap()),
        }
        assert_eq!(store.head().await.unwrap(), parent);
        assert!(store.source().load(Sequence(1)).await.unwrap().is_none());
    }
    node.shutdown().await.unwrap();
    drop(node);
    let executed = result.unwrap();
    assert_eq!(
        StateBatch::from_snapshot(executed.state.clone())
            .root()
            .unwrap(),
        expected.root().unwrap()
    );
    let committed = publisher
        .prepare(&parent, &certificate, executed)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(publisher
        .verify_execution(&committed, &certificate, &executor.graph())
        .await
        .is_err());
    let event = store.source().load(Sequence(1)).await.unwrap().unwrap();
    assert_eq!(event.events.len(), 2);
    assert_eq!(event.events[0].hash, hex::encode(tx.hash().unwrap()));
    assert_eq!(event.events[1].hash, hex::encode(transfer.hash().unwrap()));
    drop(executor);
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
    let store = Arc::new(CanonicalStore::open(&database, &chain).await.unwrap());
    let publisher = Publisher::open(store.clone(), authority).await.unwrap();
    assert_eq!(store.head().await.unwrap(), committed);
    assert_eq!(
        publisher.record(Sequence(1)).await.unwrap().txs_json.len(),
        2
    );
    let (_, state) = store.snapshot().await.unwrap();
    let account = account_store::load(&state, &sender).unwrap().unwrap();
    assert_eq!(account.balance, 23965.into());
    assert_eq!(account.encrypted_balance, Some(next));
    assert_eq!(account.nonce, transfer.nonce);
    assert_eq!(
        account_store::load(&state, &transfer.to)
            .unwrap()
            .unwrap()
            .balance,
        42.into()
    );
}
