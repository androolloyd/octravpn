//! KeySwitch uses a separate native artifact source/eligibility contract.
use super::{unavailable, AccountView, Error, Failure, Result};
use crate::private_key::{self, Policy};
use octra_node_protocol::transaction::{OpType, RuleMode, Transaction};
use std::sync::Arc;
#[derive(Clone)]
struct Source {
    transaction: [u8; 32],
    cipher: Vec<u8>,
    public: Option<Vec<u8>>,
    policy: Policy,
}
impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        self.transaction == other.transaction
            && self.cipher == other.cipher
            && self.public == other.public
            && self.policy.balance.fields == other.policy.balance.fields
            && self.policy.balance.strict == other.policy.balance.strict
            && self.policy.balance.math == other.policy.balance.math
            && self.policy.cipher == other.policy.cipher
    }
}
impl Source {
    fn capture(
        ledger: &impl AccountView,
        tx: &Transaction,
        policy: Policy,
        public: Option<Vec<u8>>,
    ) -> Result<Self> {
        let account = ledger.account(&tx.from).ok_or_else(|| {
            crate::private_error::failure("key_switch_rejected", "account not found", None)
        })?;
        Ok(Self {
            transaction: tx.hash().map_err(unavailable)?,
            cipher: account
                .encrypted_balance
                .as_deref()
                .unwrap_or(b"0")
                .to_vec(),
            public,
            policy,
        })
    }
}
enum Outcome {
    Verified(private_key::Verified),
    Rejected(Failure),
}
struct Inner {
    source: Source,
    outcome: Outcome,
}
#[derive(Clone)]
pub struct KeyArtifact(Arc<Inner>);
#[derive(Clone)]
pub struct KeyBound(KeyArtifact);
pub enum KeyBinding {
    Ready(KeyBound),
    SourceChanged,
    Invalid(Failure),
}
impl KeyArtifact {
    pub fn eligible(tx: &Transaction, policy: &Policy) -> bool {
        tx.op_type == OpType::KeySwitch
            && !private_key::requires_history(tx, *policy)
            && (!private_key::cipher_requested(tx, policy.balance.fields)
                || policy.cipher == RuleMode::Active && policy.balance.strict)
    }
    pub fn transaction_hash(&self) -> [u8; 32] {
        self.0.source.transaction
    }
    pub fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Inner>()
            .saturating_add(self.0.source.cipher.capacity())
            .saturating_add(self.0.source.public.as_ref().map_or(0, Vec::capacity))
            .saturating_add(match &self.0.outcome {
                Outcome::Verified(p) => p.retained_bytes(),
                Outcome::Rejected(f) => f
                    .reason
                    .capacity()
                    .saturating_add(f.user_reason.capacity())
                    .saturating_add(f.preverify_reason.as_ref().map_or(0, Vec::capacity)),
            })
    }
    pub fn preverify(
        ledger: &impl AccountView,
        tx: &Transaction,
        policy: Policy,
        epoch: i64,
        key: impl FnOnce() -> Result<Option<Vec<u8>>>,
    ) -> Result<Self> {
        if tx.op_type != OpType::KeySwitch {
            return Err(Error::Unavailable("key-switch route mismatch".into()));
        }
        if private_key::cipher_requested(tx, policy.balance.fields)
            && (policy.cipher != RuleMode::Active || !policy.balance.strict)
        {
            return Err(crate::private_error::failure(
                "key_switch_rejected",
                "unknown key_switch migration_mode = cipher_proof",
                None,
            ));
        }
        if private_key::requires_history(tx, policy) {
            return Err(crate::private_error::failure(
                "key_switch_artifact_rejected",
                "legacy key switch requires history-bound verification",
                None,
            ));
        }
        let source = Source::capture(ledger, tx, policy, key()?)?;
        let public = source.public.clone();
        let outcome = match private_key::verify(ledger, tx, policy, epoch, None, || Ok(public)) {
            Ok(plan) => Outcome::Verified(plan),
            Err(Error::Rejected(f)) => Outcome::Rejected(f),
            Err(error) => return Err(error),
        };
        Ok(Self(Arc::new(Inner { source, outcome })))
    }
    pub fn bind(
        &self,
        ledger: &impl AccountView,
        tx: &Transaction,
        policy: Policy,
        key: impl FnOnce() -> Result<Option<Vec<u8>>>,
    ) -> Result<KeyBinding> {
        if tx.hash().map_err(unavailable)? != self.transaction_hash() {
            let Error::Rejected(f) = crate::private_error::failure(
                "key_switch_artifact_rejected",
                "key switch artifact transaction mismatch",
                None,
            ) else {
                unreachable!()
            };
            return Ok(KeyBinding::Invalid(f));
        }
        if !Self::eligible(tx, &policy) || ledger.account(&tx.from).is_none() {
            return Ok(KeyBinding::SourceChanged);
        }
        if Source::capture(ledger, tx, policy, key()?)? != self.0.source {
            return Ok(KeyBinding::SourceChanged);
        }
        Ok(match &self.0.outcome {
            Outcome::Verified(_) => KeyBinding::Ready(KeyBound(self.clone())),
            Outcome::Rejected(f) => KeyBinding::Invalid(f.clone()),
        })
    }
}
impl KeyBound {
    fn plan(&self) -> &private_key::Verified {
        let Outcome::Verified(plan) = &self.0 .0.outcome else {
            unreachable!("only verified key artifacts bind Ready")
        };
        plan
    }
    pub fn current_cipher(&self) -> &[u8] {
        self.plan().current_cipher()
    }
    pub fn transition_hash(&self) -> String {
        self.plan().transition_hash()
    }
    pub(crate) fn apply(
        &self,
        ledger: &mut octra_node_protocol::state::Ledger,
        state: &mut crate::state_batch::StateBatch,
        tx: &Transaction,
        persist: impl FnOnce(&[u8]) -> std::result::Result<(), crate::execution::Error>,
    ) -> Result<()> {
        self.plan().apply(ledger, state, tx, persist)
    }
}
