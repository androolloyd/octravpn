use super::*;
use octra_node_protocol::{
    consensus::{Validator, ValidatorSet},
    transaction::{Nonce, RuleMode},
};
use octra_node_runtime::{
    consensus_preverify_cache::Cache,
    finality::{EpochRules, ReceiptRules},
};

fn authority() -> EpochRules {
    EpochRules {
        validators: ValidatorSet::unweighted(
            (1..=4)
                .map(|id| Validator {
                    address: vec![id],
                    pubkey: ed25519_dalek::SigningKey::from_bytes(&[id; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                })
                .collect(),
        ),
        receipts: ReceiptRules {
            required: false,
            crypto_active: false,
            stealth_minimum: 5000.into(),
        },
        relief: None,
    }
}
fn policy() -> octra_node_runtime::private_key::Policy {
    octra_node_runtime::private_key::Policy {
        balance: private_balance::Profile {
            fields: RuleMode::Prior,
            strict: false,
            math: octra_hfhe::scalar::ScalarRule::Prior,
            result: octra_node_runtime::private_crypto::ResultPolicy::Legacy,
        },
        owner: RuleMode::Prior,
        cipher: RuleMode::Prior,
    }
}
fn rules() -> octra_node_runtime::consensus_bundle::Rules {
    octra_node_runtime::consensus_bundle::Rules {
        payload: octra_node_protocol::transaction_payload::Limits::default(),
        crypto_active: false,
        stealth_minimum: 5000.into(),
        envelope: octra_node_protocol::transaction_outcome::Rules {
            envelope: RuleMode::Prior,
            compute: RuleMode::Prior,
            settle: RuleMode::Prior,
        },
    }
}
fn transaction() -> Transaction {
    Transaction {
        from: b"sender".to_vec(),
        to: b"receiver".to_vec(),
        amount: 0.into(),
        nonce: Nonce::new(1).unwrap(),
        ou: 3000.into(),
        timestamp: 1.,
        signature: b"signature".to_vec(),
        public_key: None,
        message: None,
        op_type: OpType::KeySwitch,
        encrypted_data: None,
    }
}

#[test]
fn newly_authenticated_membership_or_receipt_policy_cannot_reuse_a_ready_proof() {
    let mutate: [fn(&mut EpochRules); 6] = [
        |rules| {
            rules.validators.validators[0].pubkey = ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes()
                .to_vec();
        },
        |rules| rules.validators.validators.reverse(),
        |rules| {
            rules.validators = ValidatorSet::weighted(
                rules
                    .validators
                    .validators
                    .iter()
                    .enumerate()
                    .map(|(index, validator)| (validator.clone(), (index + 1).into()))
                    .collect(),
            )
            .unwrap();
        },
        |rules| rules.receipts.required = true,
        |rules| rules.receipts.crypto_active = true,
        |rules| rules.receipts.stealth_minimum = 5001.into(),
    ];
    for change in mutate {
        let cache = Cache::new(8, usize::MAX);
        let baseline = cache
            .select(
                b"same authenticated root",
                ProofBinding::new(&authority(), policy(), &rules()),
            )
            .unwrap();
        let tx = transaction();
        let ready = cache
            .run(&baseline, 7, Purpose::Validate, &tx, || {
                Ok(Checked::Ready(None))
            })
            .unwrap();
        assert!(matches!(ready, Checked::Ready(None)));
        let identical = cache
            .select(
                b"same authenticated root",
                ProofBinding::new(&authority(), policy(), &rules()),
            )
            .unwrap();
        cache
            .run(&identical, 7, Purpose::Validate, &tx, || {
                panic!("identical policy lost its cache")
            })
            .unwrap();
        let mut selected = authority();
        change(&mut selected);
        let changed = cache
            .select(
                b"same authenticated root",
                ProofBinding::new(&selected, policy(), &rules()),
            )
            .unwrap();
        let refused = cache
            .run(&changed, 7, Purpose::Validate, &tx, || {
                Ok(Checked::Skip {
                    kind: Kind::Invalid,
                    reason: b"new selected authority".to_vec(),
                })
            })
            .unwrap();
        assert!(matches!(
            refused,
            Checked::Skip {
                kind: Kind::Invalid,
                ..
            }
        ));
    }
}
