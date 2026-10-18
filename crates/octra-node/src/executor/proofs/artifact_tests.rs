//! Genuine native fixture proofs through the Node artifact/receipt boundary.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{consensus::policy::Protocol, state::Account, transaction::Nonce};
use octra_node_runtime::{
    account_store, circle_hfhe, finality, finality::history::History, state_batch::StateBatch,
};
use serde_json::Value;
use std::sync::Arc;

struct NoHistory;
#[async_trait::async_trait]
impl History for NoHistory {
    async fn head(&self) -> Result<octra_node_runtime::canonical::Head, finality::Error> {
        Err(finality::Error::Unavailable(
            "no history in proof test".into(),
        ))
    }
    async fn root(&self, _: i64) -> Result<Option<Vec<u8>>, finality::Error> {
        Err(finality::Error::Unavailable(
            "no history in proof test".into(),
        ))
    }
    async fn range(
        &self,
        _: i64,
        _: i64,
    ) -> Result<octra_node_runtime::finality_queries::Range, finality::Error> {
        Err(finality::Error::Unavailable(
            "no history in proof test".into(),
        ))
    }
    async fn bundle(
        &self,
        _: &[u8; 32],
    ) -> Result<Option<octra_node_runtime::consensus_bundle::RawBundle>, finality::Error> {
        Err(finality::Error::Unavailable(
            "no history in proof test".into(),
        ))
    }
}
fn host(directory: &std::path::Path) -> Native {
    Native::new_with_cache_inputs(
        super::super::Config {
            graph: octra_node_protocol::rules::Graph::new(b"artifact-test".to_vec(), None),
            protocol: Protocol::default(),
            profile: octra_node_protocol::transaction_policy::Profile::default(),
            payload: octra_node_protocol::transaction_payload::Limits::default(),
            bundle: super::super::Limits::new(128, 50_000_000, 10_000_000_000_u64.into()),
            validators: octra_node_protocol::validator::policy::Policy::Inactive,
            emission: octra_node_runtime::epoch_footer::Policy {
                emission_guard: true,
                schedule: octra_node_protocol::emission::Schedule::Inactive,
                legacy_total: None,
            },
            sender_key_activation: None,
            private_result_activation: 0,
            max_fhe: 32,
            max_stealth: 32,
            max_multi_exec_calls: 8,
            ready_max_lag: 10,
            pvac_dir: directory.join("pvac"),
            migration: None,
        },
        octra_node_runtime::circle::CircleRuntime::new(Arc::new(circle_hfhe::Backend)),
        Arc::new(NoHistory),
        None,
    )
    .unwrap()
}
fn fixture() -> (
    StateBatch,
    Ledger,
    Transaction,
    Vec<u8>,
    octra_node_runtime::private_key::Policy,
) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../octra-node-runtime/tests/fixtures/private-balance.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    assert_eq!(fixture["instrumentation"], serde_json::json!({}));
    let input = &fixture["cases"][0]["input"];
    let bytes = |name: &str| STANDARD.decode(input[name].as_str().unwrap()).unwrap();
    let current = bytes("current");
    let account = Account {
        balance: input["balance"].as_str().unwrap().parse().unwrap(),
        encrypted_balance: (current != b"0").then_some(current),
        ..Account::default()
    };
    let tx = Transaction {
        from: b"alice".to_vec(),
        to: b"alice".to_vec(),
        amount: input["amount"].as_str().unwrap().parse().unwrap(),
        nonce: Nonce::new(input["nonce"].as_i64().unwrap()).unwrap(),
        ou: input["fee"].as_str().unwrap().parse().unwrap(),
        timestamp: 1.,
        signature: b"native fixture".to_vec(),
        public_key: None,
        message: None,
        op_type: OpType::Encrypt,
        encrypted_data: Some(bytes("payload")),
    };
    let public = bytes("public");
    let mut state = StateBatch::default();
    state.begin().unwrap();
    account_store::set(
        &mut state,
        b"alice",
        &account,
        octra_node_protocol::transaction::RuleMode::Prior,
    )
    .unwrap();
    state
        .set(
            &[b"pvac_hashes", b"alice"],
            hex::encode(Sha256::digest(&public)).into_bytes(),
        )
        .unwrap();
    let ledger = Ledger::from_accounts([(b"alice".to_vec(), account)].into()).unwrap();
    let policy = octra_node_runtime::private_key::Policy {
        balance: private_balance::Profile {
            fields: octra_node_protocol::transaction::RuleMode::Prior,
            strict: true,
            math: octra_hfhe::scalar::ScalarRule::Wide,
            result: octra_node_runtime::private_crypto::ResultPolicy::Recoverable,
        },
        owner: octra_node_protocol::transaction::RuleMode::Prior,
        cipher: octra_node_protocol::transaction::RuleMode::Prior,
    };
    (state, ledger, tx, public, policy)
}
fn ready(value: Checked) -> Receipt {
    match value {
        Checked::Ready(Some(receipt)) => *receipt,
        _ => panic!("genuine native artifact did not produce a bound receipt"),
    }
}

#[test]
fn genuine_completed_proof_survives_unrelated_head_but_receipt_is_newly_bound() {
    let directory = tempfile::tempdir().unwrap();
    let native = host(directory.path());
    let (mut state, ledger, tx, public, policy) = fixture();
    native.persist_key(&public).unwrap();
    let hash = hex::encode(tx.hash().unwrap()).into_bytes();
    let minimum = 5000.into();
    let first = ready(native.prove_private(
        &tx,
        &ledger,
        &state.snapshot(),
        b"first root",
        7,
        policy,
        &minimum,
    ));
    let artifact = native.warmups.as_ref().unwrap().completed(&hash).unwrap();
    // Changing unrelated state changes HEAD, but no source used by this proof.
    state.set(&[b"unrelated", b"epoch"], b"8".to_vec()).unwrap();
    let second = ready(native.prove_private(
        &tx,
        &ledger,
        &state.snapshot(),
        b"second root",
        8,
        policy,
        &minimum,
    ));
    assert!(Arc::ptr_eq(
        &artifact,
        &native.warmups.as_ref().unwrap().completed(&hash).unwrap()
    ));
    assert_ne!(first.canonical(), second.canonical());
    let Binding::Private(first) = first.binding else {
        panic!("private binding absent")
    };
    let Binding::Private(second) = second.binding else {
        panic!("private binding absent")
    };
    assert_eq!(
        first.pre_state_hash,
        preverify_receipt::state_hash(b"first root")
    );
    assert_eq!(
        second.pre_state_hash,
        preverify_receipt::state_hash(b"second root")
    );
    assert_eq!(first.transition_hash, second.transition_hash);
    assert_eq!(first.source_cipher_hash, second.source_cipher_hash);
    assert_eq!(first.pvac_key_hash, second.pvac_key_hash);
    native.warmups.as_ref().unwrap().shutdown();
}

#[test]
fn changed_registered_key_cannot_reuse_old_ready_artifact_or_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let native = host(directory.path());
    let (mut state, ledger, tx, public, policy) = fixture();
    native.persist_key(&public).unwrap();
    let minimum = 5000.into();
    ready(native.prove_private(
        &tx,
        &ledger,
        &state.snapshot(),
        b"old root",
        7,
        policy,
        &minimum,
    ));
    let hash = hex::encode(tx.hash().unwrap()).into_bytes();
    let old = native.warmups.as_ref().unwrap().completed(&hash).unwrap();
    // This is a genuinely missing current binding, not a replacement proof.
    state.remove(&[b"pvac_hashes", b"alice"]).unwrap();
    let checked = native.prove_private(
        &tx,
        &ledger,
        &state.snapshot(),
        b"new root",
        8,
        policy,
        &minimum,
    );
    assert!(matches!(
        checked,
        Checked::Skip {
            kind: Kind::Invalid,
            ..
        }
    ));
    if let Some(new) = native.warmups.as_ref().unwrap().completed(&hash) {
        assert!(!Arc::ptr_eq(&old, &new));
    }
    native.warmups.as_ref().unwrap().shutdown();
}

#[test]
fn artifact_key_io_cannot_mask_original_malformed_payload_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let native = host(directory.path());
    let (state, ledger, mut tx, _public, policy) = fixture();
    // The canonical key hash exists, but its external file is unavailable.
    // Eager artifact capture fails before parsing; the original lazy verifier
    // must still decide the malformed payload, rather than report unavailable.
    tx.encrypted_data = Some(b"{".to_vec());
    let snapshot = state.snapshot();
    let direct = Native {
        warmups: None,
        ..native.clone()
    };
    let minimum = 5000.into();
    let expected = direct.prove_private(&tx, &ledger, &snapshot, b"root", 7, policy, &minimum);
    let actual = native.prove_private(&tx, &ledger, &snapshot, b"root", 7, policy, &minimum);
    match (expected, actual) {
        (
            Checked::Skip {
                kind: Kind::Invalid,
                reason: expected,
            },
            Checked::Skip {
                kind: Kind::Invalid,
                reason: actual,
            },
        ) => assert_eq!(actual, expected),
        _ => panic!("artifact key IO changed malformed-payload refusal precedence"),
    }
    assert!(native
        .warmups
        .as_ref()
        .unwrap()
        .completed(hex::encode(tx.hash().unwrap()).as_bytes())
        .is_none());
    native.warmups.as_ref().unwrap().shutdown();
}
