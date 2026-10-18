// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Local proof artifacts, independent of a root/epoch receipt. Only actual
//! verification constructs these capabilities; peer/QC bytes cannot decode one.
use crate::{
    private_balance::{self, AccountView, Error, Failure, Profile},
    private_transfer,
    state_batch::StateBatch,
};
use octra_node_protocol::transaction::{OpType, Transaction};
use sha2::{Digest, Sha256};
use std::sync::Arc;
mod key;
pub use key::{KeyArtifact, KeyBinding, KeyBound};
#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, Error>;
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string())
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
#[derive(Clone, PartialEq, Eq)]
enum Account {
    Missing,
    Cipher([u8; 32]),
}
#[derive(Clone, PartialEq, Eq)]
enum Claim {
    None,
    Invalid,
    Missing(i64),
    Output(i64, [u8; 32]),
}
#[derive(Clone)]
struct Source {
    transaction: [u8; 32],
    operation: OpType,
    account: Account,
    public: Option<Vec<u8>>,
    claim: Claim,
    profile: Profile,
    verifier: &'static str,
}
impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        self.transaction == other.transaction
            && self.operation == other.operation
            && self.account == other.account
            && self.public == other.public
            && self.claim == other.claim
            && self.profile.fields == other.profile.fields
            && self.profile.strict == other.profile.strict
            && self.profile.math == other.profile.math
            && self.profile.result == other.profile.result
            && self.verifier == other.verifier
    }
}
impl Source {
    fn capture(
        ledger: &impl AccountView,
        state: &StateBatch,
        tx: &Transaction,
        profile: Profile,
        public: Option<Vec<u8>>,
    ) -> Result<Self> {
        if !Artifact::eligible(tx) {
            return Err(crate::private_error::failure(
                "private_artifact_rejected",
                "private artifact operation is not supported",
                None,
            ));
        }
        let account = ledger
            .account(&tx.from)
            .map_or(Account::Missing, |account| {
                Account::Cipher(hash(account.encrypted_balance.as_deref().unwrap_or(b"0")))
            });
        let claim = if tx.op_type == OpType::Claim {
            match private_transfer::artifact_claim_source(tx, profile.fields, state)? {
                None => Claim::Invalid,
                Some((id, None)) => Claim::Missing(id),
                Some((id, Some(output))) => Claim::Output(id, hash(&output.to_bytes())),
            }
        } else {
            Claim::None
        };
        Ok(Self {
            transaction: tx.hash().map_err(unavailable)?,
            operation: tx.op_type,
            account,
            public,
            claim,
            profile,
            verifier: "pvac_private_preverify",
        })
    }
}
enum Plan {
    Balance(private_balance::Verified),
    Transfer(Box<private_transfer::Verified>),
}
impl Plan {
    fn current(&self) -> &[u8] {
        match self {
            Self::Balance(p) => p.current_cipher(),
            Self::Transfer(p) => p.current_cipher(),
        }
    }
    fn transition(&self) -> String {
        match self {
            Self::Balance(p) => p.transition_hash(),
            Self::Transfer(p) => p.transition_hash(),
        }
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Balance(p) => p.retained_bytes(),
            Self::Transfer(p) => p.retained_bytes(),
        }
    }
}
enum Outcome {
    Verified(Plan),
    Rejected(Failure),
}
struct Inner {
    source: Source,
    outcome: Outcome,
}
/// Opaque local evidence. Clone shares the immutable prepared plan, not a receipt.
#[derive(Clone)]
pub struct Artifact(Arc<Inner>);
/// Rebound proof capability. Its application remains private to the epoch host.
#[derive(Clone)]
pub struct Bound(Artifact);
pub enum Binding {
    Ready(Bound),
    SourceChanged,
    Invalid(Failure),
}
impl Artifact {
    pub fn eligible(tx: &Transaction) -> bool {
        matches!(
            tx.op_type,
            OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim
        )
    }
    pub fn transaction_hash(&self) -> [u8; 32] {
        self.0.source.transaction
    }
    pub fn estimated_bytes(&self) -> usize {
        std::mem::size_of::<Inner>()
            .saturating_add(self.0.source.public.as_ref().map_or(0, Vec::capacity))
            .saturating_add(match &self.0.outcome {
                Outcome::Verified(plan) => plan.bytes(),
                Outcome::Rejected(f) => f
                    .reason
                    .capacity()
                    .saturating_add(f.user_reason.capacity())
                    .saturating_add(f.preverify_reason.as_ref().map_or(0, Vec::capacity)),
            })
    }
    /// Capture every consumed source before starting any proof. The owner must
    /// bind again against its fresh published account/state/policy after joining.
    pub fn preverify(
        ledger: &impl AccountView,
        state: &StateBatch,
        tx: &Transaction,
        profile: Profile,
        key: impl FnOnce() -> Result<Option<Vec<u8>>>,
    ) -> Result<Self> {
        if !Self::eligible(tx) {
            return Err(crate::private_error::failure(
                "private_artifact_rejected",
                "private artifact operation is not supported",
                None,
            ));
        }
        let source = Source::capture(ledger, state, tx, profile, key()?)?;
        let key = source.public.clone();
        let checked = if matches!(tx.op_type, OpType::Stealth | OpType::Claim) {
            private_transfer::verify(ledger, state, tx, profile, || Ok(key))
                .map(|plan| Plan::Transfer(Box::new(plan)))
        } else {
            private_balance::verify_with_key(ledger, tx, profile, || Ok(key)).map(Plan::Balance)
        };
        let outcome = match checked {
            Ok(plan) => Outcome::Verified(plan),
            Err(Error::Rejected(failure)) => Outcome::Rejected(failure),
            Err(error) => return Err(error),
        };
        Ok(Self(Arc::new(Inner { source, outcome })))
    }
    /// Root, epoch, nonce and public balance are intentionally absent here.
    /// Current nonce/debit/limits still run during the real ordered application.
    pub fn bind(
        &self,
        ledger: &impl AccountView,
        state: &StateBatch,
        tx: &Transaction,
        profile: Profile,
        key: impl FnOnce() -> Result<Option<Vec<u8>>>,
    ) -> Result<Binding> {
        if !Self::eligible(tx) {
            return Err(crate::private_error::failure(
                "private_artifact_rejected",
                "private artifact operation is not supported",
                None,
            ));
        }
        let source = Source::capture(ledger, state, tx, profile, key()?)?;
        if source != self.0.source {
            return Ok(Binding::SourceChanged);
        }
        Ok(match &self.0.outcome {
            Outcome::Verified(_) => Binding::Ready(Bound(self.clone())),
            Outcome::Rejected(failure) => Binding::Invalid(failure.clone()),
        })
    }
}
impl Bound {
    fn plan(&self) -> &Plan {
        let Outcome::Verified(plan) = &self.0 .0.outcome else {
            unreachable!("only verified local artifacts bind Ready")
        };
        plan
    }
    pub fn current_cipher(&self) -> &[u8] {
        self.plan().current()
    }
    pub fn transition_hash(&self) -> String {
        self.plan().transition()
    }
    pub(crate) fn apply(
        &self,
        ledger: &mut octra_node_protocol::state::Ledger,
        state: &mut StateBatch,
        tx: &Transaction,
        epoch: i64,
    ) -> Result<()> {
        match self.plan() {
            Plan::Balance(p) => p.apply(ledger, tx),
            Plan::Transfer(p) => p.apply(ledger, state, tx, epoch),
        }
    }
}
