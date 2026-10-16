//! Real native proof material through signed transactions, epoch savepoints,
//! quorum publication, the durable ExEx outbox and restart. Local development
//! authority and test keys; this does not qualify production proposal assembly.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    consensus::codec::Wire,
    emission::Schedule,
    preverify_commit::Gate,
    preverify_receipt::{self, Binding, Receipt, State},
    state::Account,
    transaction::{address_from_public_key, Nonce, OpType, RuleMode, Transaction},
    transaction_outcome,
    validator::policy::Policy,
};
use octra_node_runtime::{
    account_store, admission,
    canonical::{CanonicalStore, Head, ReliefSource},
    epoch_execution::{self, Preverification, Request},
    epoch_footer,
    execution::Error,
    finality::{EpochRules, ExecutedEpoch, Publisher, ReceiptRules, ValidatorHistory},
    private_balance::Profile,
    private_crypto::{self, ResultPolicy},
    private_epoch::Epoch,
    state_batch::StateBatch,
    validator_epoch,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[path = "common/finality_host.rs"]
mod common;
#[derive(Clone)]
struct Authority(common::Authority);
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
fn digest(bytes: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(bytes)).into_bytes()
}
fn execute(
    parent: &Head,
    state: &mut StateBatch,
    tx: &Transaction,
    gate: &Gate,
    public: Option<&[u8]>,
    seed: u8,
) -> Result<(), Error> {
    let mut ledger = account_store::ledger(state).unwrap();
    admission::signature(
        tx,
        ledger
            .account(&tx.from)
            .and_then(|a| a.public_key.as_deref()),
    )
    .unwrap();
    let before = state.snapshot();
    let accounts = ledger.accounts().clone();
    state.begin().unwrap();
    let previous = hex::encode(parent.cursor.state_root.0);
    let emission = epoch_footer::Policy {
        emission_guard: true,
        schedule: Schedule::Inactive,
        legacy_total: None,
    };
    let reward = common::reward(seed);
    let minimum = 5000.into();
    let request = Request {
        validators: validator_epoch::Request {
            chain: b"private-application",
            epoch: parent.cursor.epoch.0 as i64 + 1,
            policy: &Policy::Inactive,
            legacy_members: &[],
            previous_root: previous.as_bytes(),
            committed_head: Some(&before),
        },
        envelope: transaction_outcome::Rules {
            envelope: RuleMode::Active,
            compute: RuleMode::Prior,
            settle: RuleMode::Prior,
        },
        sender_key_activation: Some(0),
        preverification: Some(Preverification {
            gate,
            crypto_active: true,
            minimum: &minimum,
        }),
        emission: &emission,
        reward: &reward,
        validator_keys: &[],
    };
    let fold = |_: i64, _: &StateBatch| {
        Ok(validator_epoch::Fold {
            account_mode: RuleMode::Active,
            ..validator_epoch::Fold::prior()
        })
    };
    let mut host = Epoch::new(
        octra_node_runtime::private_key::Policy {
            balance: Profile {
                fields: RuleMode::Active,
                strict: true,
                math: ScalarRule::Wide,
                result: ResultPolicy::Recoverable,
            },
            owner: RuleMode::Prior,
            cipher: RuleMode::Prior,
        },
        octra_node_runtime::private_epoch::Limits {
            max_fhe: 1,
            max_stealth: 1,
        },
        request.validators.epoch,
        Some(gate),
        None,
    );
    let executed = epoch_execution::execute(
        &request,
        &fold,
        std::slice::from_ref(tx),
        &mut ledger,
        state,
        |tx, ledger, state| {
            host.process(
                tx,
                ledger,
                state,
                |_| Ok(public.map(<[u8]>::to_vec)),
                |_| {
                    Err(octra_node_runtime::execution::Error(
                        "unexpected key persistence".into(),
                    ))
                },
            )
        },
    );
    match executed {
        Ok(executed) => {
            assert!(executed.artifacts.rejected.is_empty());
            assert_eq!(executed.artifacts.confirmed, [(0, 0)]);
            assert_eq!(executed.artifacts.confirmed_fees, tx.ou);
            assert_eq!(ledger.account(&tx.from).unwrap().public_key, tx.public_key);
            Ok(())
        }
        Err(error) => {
            assert_eq!(*ledger.accounts(), accounts);
            assert_eq!(state.root().unwrap(), before.root().unwrap());
            assert!(!ledger.is_dirty());
            assert!(!ledger.journal_active());
            Err(error)
        }
    }
}
#[tokio::test]
async fn signed_private_epochs_publish_exex_and_recover_with_bound_receipts() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-balance.json")).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["withdraw"] == true
                && c["input"]["strict"] == true
                && c["expected"]["outcome"]["applied"] == true
        })
        .unwrap();
    let input = &case["input"];
    let current = bytes(&input["current"]);
    let public = bytes(&input["public"]);
    let signer = SigningKey::from_bytes(&[42; 32]);
    let signing_public = STANDARD
        .encode(signer.verifying_key().to_bytes())
        .into_bytes();
    let sender = address_from_public_key(&signing_public);
    let mut initial = StateBatch::default();
    initial.begin().unwrap();
    account_store::set(
        &mut initial,
        &sender,
        &Account {
            balance: 30000.into(),
            encrypted_balance: Some(current),
            ..Account::default()
        },
        RuleMode::Active,
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
    let chain = ChainIdentity::genesis(
        "private-application",
        StateRoot(common::root(None, &initial, &[])),
    );
    let authority = Authority(common::Authority {
        seed: 1,
        chain: chain.clone(),
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let store = Arc::new(
        CanonicalStore::create(&path, chain.clone(), initial.snapshot(), 0)
            .await
            .unwrap(),
    );
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let mut previous_receipt: Option<Receipt> = None;
    let mut saved_heads = Vec::new();
    for epoch in 1..=2 {
        let (parent, state) = store.snapshot().await.unwrap();
        let mut tx = Transaction {
            from: sender.clone(),
            to: sender.clone(),
            amount: 7.into(),
            nonce: Nonce::new(epoch).unwrap(),
            ou: 5000.into(),
            timestamp: f64::from(u32::try_from(epoch).unwrap()),
            signature: vec![],
            public_key: Some(signing_public.clone()),
            message: None,
            encrypted_data: Some(bytes(&input["payload"])),
            op_type: if epoch == 1 {
                OpType::Decrypt
            } else {
                OpType::Encrypt
            },
        };
        tx.signature = STANDARD
            .encode(signer.sign(&tx.signing_bytes().unwrap()).to_bytes())
            .into_bytes();
        let current = account_store::load(&state, &sender)
            .unwrap()
            .unwrap()
            .encrypted_balance
            .unwrap();
        let payload: Value = serde_json::from_slice(tx.encrypted_data.as_ref().unwrap()).unwrap();
        let delta = private_crypto::decode_cipher(
            payload["cipher"].as_str().unwrap().as_bytes(),
            true,
            true,
        )
        .unwrap();
        let next = private_crypto::balance(
            &private_crypto::load_pubkey(&public).unwrap(),
            &current,
            &delta,
            epoch == 1,
            true,
            ResultPolicy::Recoverable,
        )
        .unwrap();
        let transcript = format!(
            "octra:private_transition:{}\0{}\0{}",
            if epoch == 1 { "decrypt" } else { "encrypt" },
            hex::encode(Sha256::digest(&current)),
            hex::encode(Sha256::digest(&next))
        );
        let transition = digest(transcript.as_bytes());
        if epoch == 1 {
            assert_eq!(next, bytes(&case["expected"]["outcome"]["plan"]["next"]));
            assert_eq!(
                transition,
                case["expected"]["outcome"]["plan"]["hash"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            );
        }
        let binding = Binding::Private(State {
            pre_state_hash: preverify_receipt::state_hash(parent.ledger_root.as_bytes()),
            source_cipher_hash: digest(&current),
            pvac_key_hash: digest(&public),
            transition_hash: Some(transition),
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
        .unwrap();
        let gate = Gate {
            receipts: vec![receipt.clone()],
        };
        let mut bad = receipt.clone();
        if let Binding::Private(binding) = &mut bad.binding {
            binding.source_cipher_hash = vec![b'a'; 64];
        }
        bad.input_hash = bad.binding.input_hash(&tx).unwrap();
        bad.output_hash = bad.binding.output_hash(&tx, b"ok").unwrap();
        let error = execute(
            &parent,
            &mut state.clone(),
            &tx,
            &Gate {
                receipts: vec![bad],
            },
            Some(&public),
            authority.0.seed,
        )
        .unwrap_err();
        assert!(error.0.contains("receipt_source_mismatch"), "{error}");
        let error = execute(
            &parent,
            &mut state.clone(),
            &tx,
            &gate,
            None,
            authority.0.seed,
        )
        .unwrap_err();
        assert!(error.0.contains("pvac blob unavailable"), "{error}");
        if let Some(mut stale) = previous_receipt.take() {
            // Same new transaction, authenticated receipt framing, stale source/head.
            stale.tx_hash = receipt.tx_hash.clone();
            stale.input_hash = stale.binding.input_hash(&tx).unwrap();
            stale.output_hash = stale.binding.output_hash(&tx, b"ok").unwrap();
            let error = execute(
                &parent,
                &mut state.clone(),
                &tx,
                &Gate {
                    receipts: vec![stale],
                },
                Some(&public),
                authority.0.seed,
            )
            .unwrap_err();
            assert!(error.0.contains("receipt_state_mismatch"), "{error}");
        }
        let mut candidate = state.clone();
        execute(
            &parent,
            &mut candidate,
            &tx,
            &gate,
            Some(&public),
            authority.0.seed,
        )
        .unwrap();
        assert_eq!(store.head().await.unwrap(), parent);
        assert!(store
            .source()
            .load(Sequence(parent.cursor.sequence.0 + 1))
            .await
            .unwrap()
            .is_none());
        let identity = tx.identity_bytes().unwrap();
        let executed = ExecutedEpoch {
            epoch_observation: None,
            metrics: octra_node_protocol::metrics::Epoch::default(),
            vm_receipts: std::collections::BTreeMap::default(),
            state: candidate.snapshot(),
            transactions: vec![NativeTransaction {
                txid: parent.txid_hi + 1,
                hash: hex::encode(tx.hash().unwrap()),
                identity: identity.clone(),
                transaction: identity,
                proof: ArchiveProof::Exact,
                receipt: None,
            }],
            consensus_receipts: vec![receipt.canonical()],
            reward_source: common::reward_source(authority.0.seed),
            date: epoch,
            message: b"signed private epoch".to_vec(),
        };
        let certificate = common::certificate(&parent, &executed, &authority.0);
        let mut invalid = certificate.clone();
        invalid.precommits[0].signature[0] ^= 1;
        assert!(publisher
            .prepare(&parent, &invalid.encode().unwrap(), executed.clone())
            .await
            .is_err());
        assert_eq!(store.head().await.unwrap(), parent);
        let committed = publisher
            .prepare(&parent, &certificate.encode().unwrap(), executed)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        let event = store
            .source()
            .load(committed.cursor.sequence)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.events.len(), 1);
        assert_eq!(event.events[0].hash, hex::encode(tx.hash().unwrap()));
        assert_eq!(event.cursor, committed.cursor);
        assert_eq!(event.parent_root, parent.cursor.state_root);
        let (_, persisted) = store.snapshot().await.unwrap();
        let account = account_store::load(&persisted, &sender).unwrap().unwrap();
        assert_eq!(account.encrypted_balance, Some(next));
        assert_eq!(account.nonce, tx.nonce);
        assert_eq!(
            account.balance,
            if epoch == 1 {
                25007.into()
            } else {
                20000.into()
            }
        );
        previous_receipt = Some(receipt);
        saved_heads.push(committed);
    }
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
    let reopened = Arc::new(CanonicalStore::open(&path, &chain).await.unwrap());
    let audited = Publisher::open(reopened.clone(), authority).await.unwrap();
    assert_eq!(reopened.head().await.unwrap(), *saved_heads.last().unwrap());
    for head in saved_heads {
        let record = audited.record(head.cursor.sequence).await.unwrap();
        assert_eq!(record.receipts_json.len(), 1);
        assert_eq!(
            reopened
                .source()
                .load(head.cursor.sequence)
                .await
                .unwrap()
                .unwrap()
                .events
                .len(),
            1
        );
    }
    let (_, state) = reopened.snapshot().await.unwrap();
    let account = account_store::load(&state, &sender).unwrap().unwrap();
    assert_eq!(account.balance, 20000.into());
    assert_eq!(account.nonce, Nonce::new(2).unwrap());
}
