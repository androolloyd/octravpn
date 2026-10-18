use super::*;
use crate::{
    account_store,
    crypto_worker::{Limits as WorkerLimits, Pool},
    epoch_execution::Effect,
    private_crypto::ResultPolicy,
    private_epoch::{Epoch, Limits},
    private_key::Policy,
    private_outputs::Output,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::scalar::ScalarRule;
use octra_node_protocol::{
    preverify_commit::Gate,
    preverify_receipt::{self, Binding as ReceiptBinding, Receipt, State},
    state::{Account as LedgerAccount, Ledger},
    transaction::{Nonce, RuleMode},
};
use serde_json::{json, Value};
use std::sync::{atomic::AtomicBool, OnceLock};

struct Fixture {
    account: LedgerAccount,
    public: Vec<u8>,
    tx: Transaction,
    profile: Profile,
    artifact: Artifact,
}
impl Fixture {
    fn ledger(&self) -> Ledger {
        Ledger::from_accounts([(b"alice".to_vec(), self.account.clone())].into()).unwrap()
    }
    fn state(&self) -> StateBatch {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        account_store::set(&mut state, b"alice", &self.account, RuleMode::Prior).unwrap();
        state
            .set(
                &[b"pvac_hashes", b"alice"],
                hex::encode(hash(&self.public)).into_bytes(),
            )
            .unwrap();
        state
    }
    fn bound(&self, ledger: &Ledger, state: &StateBatch) -> Bound {
        let Binding::Ready(bound) = self
            .artifact
            .bind(ledger, state, &self.tx, self.profile, || {
                Ok(Some(self.public.clone()))
            })
            .unwrap()
        else {
            panic!("real native fixture must bind Ready")
        };
        bound
    }
    fn gate(&self, state: &StateBatch) -> Gate {
        let bound = self.bound(&self.ledger(), state);
        let binding = ReceiptBinding::Private(State {
            pre_state_hash: preverify_receipt::state_hash(&state.root().unwrap()),
            source_cipher_hash: hex::encode(hash(bound.current_cipher())).into_bytes(),
            pvac_key_hash: hex::encode(hash(&self.public)).into_bytes(),
            transition_hash: Some(bound.transition_hash().into_bytes()),
        });
        let receipt = Receipt::for_tx(
            &self.tx,
            binding.clone(),
            binding.input_hash(&self.tx).unwrap(),
            binding.output_hash(&self.tx, b"ok").unwrap(),
            true,
            vec![],
            &1.into(),
        )
        .unwrap();
        Gate::check_receipt(&self.tx, &receipt, true, &1.into()).unwrap();
        Gate {
            receipts: vec![receipt],
        }
    }
    fn policy(&self) -> Policy {
        Policy {
            balance: self.profile,
            owner: RuleMode::Prior,
            cipher: RuleMode::Prior,
        }
    }
}
fn fixture(withdraw: bool) -> &'static Fixture {
    static ENCRYPT: OnceLock<Fixture> = OnceLock::new();
    static DECRYPT: OnceLock<Fixture> = OnceLock::new();
    let slot = if withdraw { &DECRYPT } else { &ENCRYPT };
    slot.get_or_init(|| {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../../tests/fixtures/private-balance.json"))
                .unwrap();
        let case = &fixture["cases"][if withdraw { 30 } else { 1 }];
        assert_eq!(case["expected"]["outcome"]["applied"], true);
        let input = &case["input"];
        let bytes = |name: &str| STANDARD.decode(input[name].as_str().unwrap()).unwrap();
        let account = LedgerAccount {
            balance: input["balance"].as_str().unwrap().parse().unwrap(),
            encrypted_balance: Some(bytes("current")),
            ..LedgerAccount::default()
        };
        let public = bytes("public");
        let tx = Transaction {
            from: b"alice".to_vec(),
            to: b"alice".to_vec(),
            amount: input["amount"].as_str().unwrap().parse().unwrap(),
            nonce: Nonce::new(input["nonce"].as_i64().unwrap()).unwrap(),
            ou: input["fee"].as_str().unwrap().parse().unwrap(),
            timestamp: 1.,
            signature: b"fixture".to_vec(),
            public_key: None,
            message: None,
            op_type: if withdraw {
                OpType::Decrypt
            } else {
                OpType::Encrypt
            },
            encrypted_data: Some(bytes("payload")),
        };
        let profile = Profile {
            fields: RuleMode::Active,
            strict: true,
            math: ScalarRule::Wide,
            result: ResultPolicy::Recoverable,
        };
        let ledger = Ledger::from_accounts([(b"alice".to_vec(), account.clone())].into()).unwrap();
        // This is a genuine cryptographic verification, not a receipt-derived plan.
        let artifact = Artifact::preverify(&ledger, &StateBatch::default(), &tx, profile, || {
            Ok(Some(public.clone()))
        })
        .unwrap();
        assert!(matches!(
            artifact
                .bind(&ledger, &StateBatch::default(), &tx, profile, || Ok(Some(
                    public.clone()
                )))
                .unwrap(),
            Binding::Ready(_)
        ));
        Fixture {
            account,
            public,
            tx,
            profile,
            artifact,
        }
    })
}
fn limits() -> Limits {
    Limits {
        max_fhe: 4,
        max_stealth: 4,
    }
}
fn cancelled_pool() -> Arc<Pool> {
    // Explicit trusted test image, never started: the cancelled scope makes
    // every actual proof request fail before process launch.
    Pool::open(
        &std::env::current_exe().unwrap(),
        WorkerLimits {
            capacity: 1,
            timeout_seconds: 600.,
            rss_mb: 9216,
        },
    )
    .unwrap()
}

#[test]
fn genuine_encrypt_and_decrypt_artifacts_rebind_across_unrelated_heads() {
    for withdraw in [false, true] {
        let f = fixture(withdraw);
        let ledger = f.ledger();
        let mut state = f.state();
        let before = state.root().unwrap();
        state.set(&[b"meta", b"epoch"], b"800".to_vec()).unwrap();
        state
            .set(&[b"unrelated", b"value"], b"changed".to_vec())
            .unwrap();
        assert_ne!(state.root().unwrap(), before);
        let bound = f.bound(&ledger, &state);
        assert_eq!(
            bound.current_cipher(),
            f.account.encrypted_balance.as_deref().unwrap()
        );
        assert!(f.artifact.estimated_bytes() >= f.public.len());
    }
}

#[test]
fn artifact_rechecks_transaction_cipher_account_key_and_every_policy() {
    let f = fixture(false);
    let ledger = f.ledger();
    let state = f.state();
    for public in [None, Some(b"different public bytes".to_vec())] {
        assert!(matches!(
            f.artifact
                .bind(&ledger, &state, &f.tx, f.profile, || Ok(public))
                .unwrap(),
            Binding::SourceChanged
        ));
    }
    let empty = Ledger::from_accounts(std::collections::BTreeMap::new()).unwrap();
    assert!(matches!(
        f.artifact
            .bind(&empty, &state, &f.tx, f.profile, || Ok(Some(
                f.public.clone()
            )))
            .unwrap(),
        Binding::SourceChanged
    ));
    let mut changed = f.ledger();
    changed.update_encrypted_balance(b"alice", b"0".to_vec());
    assert!(matches!(
        f.artifact
            .bind(&changed, &state, &f.tx, f.profile, || Ok(Some(
                f.public.clone()
            )))
            .unwrap(),
        Binding::SourceChanged
    ));
    let mut changed_transactions = vec![f.tx.clone(); 4];
    changed_transactions[0].amount += 1;
    changed_transactions[1].nonce = Nonce::new(2).unwrap();
    changed_transactions[2].signature.push(1);
    changed_transactions[3].op_type = OpType::Decrypt;
    for tx in changed_transactions {
        assert!(matches!(
            f.artifact
                .bind(&ledger, &state, &tx, f.profile, || Ok(Some(
                    f.public.clone()
                )))
                .unwrap(),
            Binding::SourceChanged
        ));
    }
    let mut profiles = [f.profile; 4];
    profiles[0].fields = RuleMode::Prior;
    profiles[1].strict = false;
    profiles[2].math = ScalarRule::Prior;
    profiles[3].result = ResultPolicy::Legacy;
    for profile in profiles {
        assert!(matches!(
            f.artifact
                .bind(&ledger, &state, &f.tx, profile, || Ok(Some(
                    f.public.clone()
                )))
                .unwrap(),
            Binding::SourceChanged
        ));
    }
    assert!(
        matches!(f.artifact.bind(&ledger, &state, &f.tx, f.profile, || Err(Error::Unavailable("public blob I/O".into()))), Err(Error::Unavailable(reason)) if reason == "public blob I/O")
    );
}

#[test]
fn deterministic_rejections_are_bound_but_operational_failures_are_not_artifacts() {
    let f = fixture(false);
    let ledger = f.ledger();
    let state = f.state();
    for operation in [
        OpType::Encrypt,
        OpType::Decrypt,
        OpType::Stealth,
        OpType::Claim,
    ] {
        let mut tx = f.tx.clone();
        tx.op_type = operation;
        tx.encrypted_data = Some(b"{}".to_vec());
        let artifact = Artifact::preverify(&ledger, &state, &tx, f.profile, || {
            Ok(Some(f.public.clone()))
        })
        .unwrap();
        let Binding::Invalid(first) = artifact
            .bind(&ledger, &state, &tx, f.profile, || {
                Ok(Some(f.public.clone()))
            })
            .unwrap()
        else {
            panic!("malformed operation must stay rejected")
        };
        let Binding::Invalid(second) = artifact
            .bind(&ledger, &state, &tx, f.profile, || {
                Ok(Some(f.public.clone()))
            })
            .unwrap()
        else {
            panic!("rejection must be retained")
        };
        assert_eq!(first, second);
        assert!(matches!(
            artifact
                .bind(&ledger, &state, &tx, f.profile, || Ok(None))
                .unwrap(),
            Binding::SourceChanged
        ));
    }
    assert!(
        matches!(Artifact::preverify(&ledger, &state, &f.tx, f.profile, || Err(Error::Unavailable("key unavailable".into()))), Err(Error::Unavailable(reason)) if reason == "key unavailable")
    );
    let mut unsupported = f.tx.clone();
    unsupported.op_type = OpType::Private;
    assert!(matches!(
        Artifact::preverify(&ledger, &state, &unsupported, f.profile, || panic!(
            "ineligible operation must not read key"
        )),
        Err(Error::Rejected(_))
    ));
}

#[test]
fn rejected_local_artifact_keeps_original_payload_before_missing_key_refusal() {
    let f = fixture(false);
    let mut tx = f.tx.clone();
    tx.encrypted_data = Some(b"{}".to_vec());
    let mut ledger = f.ledger();
    let mut state = f.state();
    let artifact = Artifact::preverify(&ledger, &state, &tx, f.profile, || {
        Ok(Some(f.public.clone()))
    })
    .unwrap();
    let Binding::Invalid(expected) = artifact
        .bind(&ledger, &state, &tx, f.profile, || {
            Ok(Some(f.public.clone()))
        })
        .unwrap()
    else {
        panic!("malformed payload rejection")
    };
    // A remote receipt cannot authorize this malformed transaction. The test
    // checks refusal priority, with no successful state transition expected.
    let mut binding = f.gate(&state).receipts.remove(0).binding;
    if let ReceiptBinding::Private(ref mut private) = binding {
        private.transition_hash = Some(vec![b'0'; 64]);
    }
    let receipt = Receipt::for_tx(
        &tx,
        binding.clone(),
        binding.input_hash(&tx).unwrap(),
        binding.output_hash(&tx, b"ok").unwrap(),
        true,
        vec![],
        &1.into(),
    )
    .unwrap();
    let gate = Gate {
        receipts: vec![receipt],
    };
    let before = ledger.freeze().unwrap();
    let root = state.root().unwrap();
    let mut epoch =
        Epoch::new(f.policy(), limits(), 1, Some(&gate), None).with_artifacts([artifact]);
    let Effect::Rejected(refusal) = epoch
        .process(
            &tx,
            &mut ledger,
            &mut state,
            |_| Err(crate::execution::Error("missing public blob".into())),
            |_| panic!("not a key update"),
        )
        .unwrap()
    else {
        panic!("payload must still reject before missing blob")
    };
    assert_eq!(refusal.error_type, expected.tag.as_bytes());
    assert_eq!(refusal.reason, expected.reason);
    assert_eq!(ledger.freeze().unwrap(), before);
    assert_eq!(state.root().unwrap(), root);
}

fn claim_transaction() -> Transaction {
    let mut tx = fixture(false).tx.clone();
    tx.op_type = OpType::Claim;
    tx.encrypted_data = Some(serde_json::to_vec(&json!({"version":5,"output_id":7,"claim_cipher":"c","commitment":"p","claim_secret":"s","zero_proof":"z"})).unwrap());
    tx
}
fn output() -> Output {
    Output {
        id: 7,
        stealth_tag: b"tag".to_vec(),
        eph_pub: b"eph".to_vec(),
        enc_amount: b"enc".to_vec(),
        amount: b"7".to_vec(),
        epoch_id: 2,
        tx_hash: b"hash".to_vec(),
        sender_addr: b"sender".to_vec(),
        claimed: 0,
        claim_pub: b"claim".to_vec(),
        delta_cipher_stored: b"cipher".to_vec(),
        amount_hash: b"amount hash".to_vec(),
        amount_commitment: b"commitment".to_vec(),
    }
}
#[test]
fn claim_source_binds_all_thirteen_parsed_output_fields_and_missing_states() {
    let f = fixture(false);
    let ledger = f.ledger();
    let tx = claim_transaction();
    let mut state = f.state();
    let source = |state: &StateBatch, tx: &Transaction| {
        Source::capture(&ledger, state, tx, f.profile, Some(f.public.clone())).unwrap()
    };
    let missing = source(&state, &tx);
    let original = output();
    state.set(&[b"stealth", b"7"], original.to_bytes()).unwrap();
    let present = source(&state, &tx);
    assert!(missing != present);
    // These are source-comparison records, never successful proof artifacts.
    let mut variations = vec![original; 13];
    variations[0].id += 1;
    variations[1].stealth_tag.push(1);
    variations[2].eph_pub.push(1);
    variations[3].enc_amount.push(1);
    variations[4].amount.push(1);
    variations[5].epoch_id += 1;
    variations[6].tx_hash.push(1);
    variations[7].sender_addr.push(1);
    variations[8].claimed = 1;
    variations[9].claim_pub.push(1);
    variations[10].delta_cipher_stored.push(1);
    variations[11].amount_hash.push(1);
    variations[12].amount_commitment.push(1);
    for changed in variations {
        state.set(&[b"stealth", b"7"], changed.to_bytes()).unwrap();
        assert!(source(&state, &tx) != present);
    }
    let mut invalid = tx;
    invalid.encrypted_data = Some(b"{}".to_vec());
    assert!(source(&state, &invalid) != missing);
}

#[test]
fn strict_epoch_uses_only_genuine_fresh_local_artifacts_not_receipts_alone() {
    for withdraw in [false, true] {
        let f = fixture(withdraw);
        let mut state = f.state();
        let gate = f.gate(&state);
        let mut ledger = f.ledger();
        let pool = cancelled_pool();
        let _scope = pool.scope(false, Arc::new(AtomicBool::new(true)));
        let mut epoch = Epoch::new(f.policy(), limits(), 800, Some(&gate), None)
            .with_artifacts([f.artifact.clone()]);
        assert_eq!(
            epoch
                .process(
                    &f.tx,
                    &mut ledger,
                    &mut state,
                    |_| Ok(Some(f.public.clone())),
                    |_| panic!("not a key update")
                )
                .unwrap(),
            Effect::Confirmed(f.tx.ou.clone())
        );
        assert_eq!(ledger.account(b"alice").unwrap().nonce, f.tx.nonce);
        assert_eq!(
            ledger.account(b"alice").unwrap().balance,
            &f.account.balance - &f.tx.ou
                + if withdraw {
                    f.tx.amount.clone()
                } else {
                    -&f.tx.amount
                }
        );
        let mut ledger = f.ledger();
        let mut state = f.state();
        let mut epoch = Epoch::new(f.policy(), limits(), 800, Some(&gate), None);
        assert!(
            epoch
                .process(
                    &f.tx,
                    &mut ledger,
                    &mut state,
                    |_| Ok(Some(f.public.clone())),
                    |_| panic!("not a key update")
                )
                .is_err(),
            "a peer receipt cannot manufacture the local proof capability"
        );
        assert_eq!(ledger.freeze().unwrap(), f.ledger().freeze().unwrap());
        let mut epoch =
            Epoch::new(f.policy(), limits(), 800, None, None).with_artifacts([f.artifact.clone()]);
        assert!(
            epoch
                .process(
                    &f.tx,
                    &mut ledger,
                    &mut state,
                    |_| Ok(Some(f.public.clone())),
                    |_| panic!("not a key update")
                )
                .is_err(),
            "local artifact reuse still requires the strict receipt gate"
        );
    }
}

#[test]
fn strict_artifact_reuse_still_rolls_back_current_nonce_and_public_debit_failures() {
    let f = fixture(false);
    for nonce_failure in [false, true] {
        let mut account = f.account.clone();
        if nonce_failure {
            account.nonce = f.tx.nonce;
        } else {
            account.balance = 0.into();
        }
        let mut ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
        let mut state = f.state();
        f.bound(&ledger, &state); // Source deliberately excludes current nonce/public balance.
        let gate = f.gate(&state);
        let before = ledger.freeze().unwrap();
        let spent = ledger.spent_nonces().clone();
        let dirty = ledger.dirty_addresses().clone();
        let root = state.root().unwrap();
        let pool = cancelled_pool();
        let _scope = pool.scope(false, Arc::new(AtomicBool::new(true)));
        let mut epoch = Epoch::new(f.policy(), limits(), 800, Some(&gate), None)
            .with_artifacts([f.artifact.clone()]);
        let Effect::Rejected(refusal) = epoch
            .process(
                &f.tx,
                &mut ledger,
                &mut state,
                |_| Ok(Some(f.public.clone())),
                |_| panic!("not a key update"),
            )
            .unwrap()
        else {
            panic!("current debit/nonce must still reject")
        };
        assert_eq!(refusal.error_type, b"insufficient_balance");
        assert_eq!(
            refusal.reason,
            if nonce_failure {
                b"Invalid nonce".as_slice()
            } else {
                b"Insufficient balance".as_slice()
            }
        );
        assert_eq!(ledger.freeze().unwrap(), before);
        assert_eq!(ledger.spent_nonces(), &spent);
        assert_eq!(ledger.dirty_addresses(), &dirty);
        assert_eq!(ledger.journal_depth(), 0);
        assert_eq!(state.root().unwrap(), root);
    }
}

#[test]
fn strict_artifact_cannot_bypass_stale_cipher_corrupt_blob_or_receipt_transition() {
    let f = fixture(false);
    let pool = cancelled_pool();
    let _scope = pool.scope(false, Arc::new(AtomicBool::new(true)));
    for stale_cipher in [false, true] {
        let mut ledger = f.ledger();
        let mut state = f.state();
        let gate = f.gate(&state);
        if stale_cipher {
            ledger.update_encrypted_balance(b"alice", b"0".to_vec());
            // Persist the deliberate fixture mutation before taking a clean
            // ledger baseline; proof refusal must leave this state unchanged.
            account_store::flush_dirty(&mut ledger, &mut state, RuleMode::Prior).unwrap();
        }
        let before = ledger.freeze().unwrap();
        let root = state.root().unwrap();
        let mut epoch = Epoch::new(f.policy(), limits(), 1, Some(&gate), None)
            .with_artifacts([f.artifact.clone()]);
        assert!(epoch
            .process(
                &f.tx,
                &mut ledger,
                &mut state,
                |_| Ok(Some(if stale_cipher {
                    f.public.clone()
                } else {
                    b"corrupt blob".to_vec()
                })),
                |_| panic!("not a key update")
            )
            .is_err());
        assert_eq!(ledger.freeze().unwrap(), before);
        assert_eq!(state.root().unwrap(), root);
    }
    let mut ledger = f.ledger();
    let mut state = f.state();
    let mut binding = f.gate(&state).receipts.remove(0).binding;
    let ReceiptBinding::Private(ref mut private) = binding else {
        panic!("private receipt")
    };
    private.transition_hash = Some(vec![b'0'; 64]);
    let receipt = Receipt::for_tx(
        &f.tx,
        binding.clone(),
        binding.input_hash(&f.tx).unwrap(),
        binding.output_hash(&f.tx, b"ok").unwrap(),
        true,
        vec![],
        &1.into(),
    )
    .unwrap();
    Gate::check_receipt(&f.tx, &receipt, true, &1.into()).unwrap();
    let gate = Gate {
        receipts: vec![receipt],
    };
    let before = ledger.freeze().unwrap();
    let root = state.root().unwrap();
    let mut epoch =
        Epoch::new(f.policy(), limits(), 1, Some(&gate), None).with_artifacts([f.artifact.clone()]);
    let Effect::Rejected(refusal) = epoch
        .process(
            &f.tx,
            &mut ledger,
            &mut state,
            |_| Ok(Some(f.public.clone())),
            |_| panic!("not a key update"),
        )
        .unwrap()
    else {
        panic!("transition mismatch must refuse")
    };
    assert_eq!(refusal.error_type, b"preverify_transition_mismatch");
    assert_eq!(ledger.freeze().unwrap(), before);
    assert_eq!(state.root().unwrap(), root);
}

fn key_transaction() -> Transaction {
    let f = fixture(false);
    let mut tx = f.tx.clone();
    tx.op_type = OpType::KeySwitch;
    tx.amount = 0.into();
    tx.encrypted_data = Some(serde_json::to_vec(&json!({"new_pubkey":STANDARD.encode(&f.public),"aes_kat":hex::encode(octra_hfhe::seeded_rng::aes_kat())})).unwrap());
    tx
}
#[test]
fn key_artifact_has_its_own_exact_source_and_excludes_history_forms() {
    let f = fixture(false);
    let tx = key_transaction();
    let account = LedgerAccount {
        balance: 100.into(),
        ..LedgerAccount::default()
    };
    let ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
    let policy = f.policy();
    let artifact = KeyArtifact::preverify(&ledger, &tx, policy, 1, || Ok(None)).unwrap();
    assert!(matches!(
        artifact.bind(&ledger, &tx, policy, || Ok(None)).unwrap(),
        KeyBinding::Ready(_)
    ));
    assert!(artifact.estimated_bytes() >= f.public.len());
    let mut policies = [policy; 4];
    policies[0].balance.fields = RuleMode::Prior;
    policies[1].balance.strict = false;
    policies[2].balance.math = ScalarRule::Prior;
    policies[3].cipher = RuleMode::Active;
    for changed in policies {
        assert!(matches!(
            artifact.bind(&ledger, &tx, changed, || Ok(None)).unwrap(),
            KeyBinding::SourceChanged
        ));
    }
    let mut unused_policies = policy;
    unused_policies.balance.result = ResultPolicy::Legacy;
    unused_policies.owner = RuleMode::Active;
    assert!(
        matches!(
            artifact
                .bind(&ledger, &tx, unused_policies, || Ok(None))
                .unwrap(),
            KeyBinding::Ready(_)
        ),
        "eligible key artifacts do not consume result policy or owner-history activation"
    );
    let mut changed_ledger = Ledger::from_accounts(
        [(
            b"alice".to_vec(),
            LedgerAccount {
                balance: 100.into(),
                ..LedgerAccount::default()
            },
        )]
        .into(),
    )
    .unwrap();
    changed_ledger.update_encrypted_balance(b"alice", b"changed".to_vec());
    assert!(matches!(
        artifact
            .bind(&changed_ledger, &tx, policy, || Ok(None))
            .unwrap(),
        KeyBinding::SourceChanged
    ));
    assert!(matches!(
        artifact
            .bind(&ledger, &tx, policy, || Ok(Some(f.public.clone())))
            .unwrap(),
        KeyBinding::SourceChanged
    ));
    let mut changed = tx.clone();
    changed.nonce = Nonce::new(2).unwrap();
    assert!(
        matches!(artifact.bind(&ledger, &changed, policy, || panic!("tx mismatch before key read")).unwrap(), KeyBinding::Invalid(f) if f.reason == b"key switch artifact transaction mismatch")
    );
    for (mode, active) in [
        ("public_history", false),
        ("commitment_history", false),
        ("historical_owner_proof", false),
        ("rejected_rebinding", false),
        ("verified_zero_reset", true),
    ] {
        let mut body: Value = serde_json::from_slice(tx.encrypted_data.as_ref().unwrap()).unwrap();
        body["migration_mode"] = mode.into();
        let mut changed = tx.clone();
        changed.encrypted_data = Some(serde_json::to_vec(&body).unwrap());
        let mut policy = policy;
        if active {
            policy.cipher = RuleMode::Active;
        }
        assert!(!KeyArtifact::eligible(&changed, &policy), "{mode}");
        assert!(
            matches!(KeyArtifact::preverify(&ledger, &changed, policy, 1, || panic!("history eligibility before key read")), Err(Error::Rejected(f)) if f.reason == b"legacy key switch requires history-bound verification")
        );
    }
    let mut body: Value = serde_json::from_slice(tx.encrypted_data.as_ref().unwrap()).unwrap();
    body["migration_mode"] = "cipher_proof".into();
    let mut cipher = tx.clone();
    cipher.encrypted_data = Some(serde_json::to_vec(&body).unwrap());
    assert!(!KeyArtifact::eligible(&cipher, &policy));
    let mut active = policy;
    active.cipher = RuleMode::Active;
    assert!(KeyArtifact::eligible(&cipher, &active));
    active.balance.strict = false;
    assert!(!KeyArtifact::eligible(&cipher, &active));

    let KeyBinding::Ready(bound) = artifact.bind(&ledger, &tx, policy, || Ok(None)).unwrap() else {
        panic!("genuine initial key plan")
    };
    let mut state = StateBatch::default();
    state.begin().unwrap();
    let binding = ReceiptBinding::Private(State {
        pre_state_hash: preverify_receipt::state_hash(&state.root().unwrap()),
        source_cipher_hash: hex::encode(hash(b"0")).into_bytes(),
        pvac_key_hash: vec![b'0'; 64],
        transition_hash: Some(bound.transition_hash().into_bytes()),
    });
    let receipt = Receipt::for_tx(
        &tx,
        binding.clone(),
        binding.input_hash(&tx).unwrap(),
        binding.output_hash(&tx, b"ok").unwrap(),
        true,
        vec![],
        &1.into(),
    )
    .unwrap();
    Gate::check_receipt(&tx, &receipt, true, &1.into()).unwrap();
    let gate = Gate {
        receipts: vec![receipt],
    };
    let mut ledger = ledger;
    let pool = cancelled_pool();
    let _scope = pool.scope(false, Arc::new(AtomicBool::new(true)));
    let mut persisted = None;
    let mut epoch = Epoch::new(policy, limits(), 10, Some(&gate), None).with_keys([artifact]);
    assert_eq!(
        epoch
            .process(
                &tx,
                &mut ledger,
                &mut state,
                |_| panic!("initial key has no old bound blob"),
                |public| {
                    persisted = Some(public.to_vec());
                    Ok(())
                }
            )
            .unwrap(),
        Effect::Confirmed(tx.ou.clone())
    );
    assert_eq!(ledger.account(b"alice").unwrap().nonce, tx.nonce);
    assert_eq!(
        state.get(&[b"pvac_hashes", b"alice"]),
        Some(hex::encode(hash(&persisted.unwrap())).as_bytes())
    );
}
