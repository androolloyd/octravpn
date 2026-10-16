// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Per-attempt native private-operation admission. The caller authenticates the
//! certificate; the outer epoch executor checks receipt source bindings first.
use crate::{
    epoch_execution::{Effect, Refusal},
    execution::Error,
    private_balance::{self as balance, Evidence},
    private_key, private_transfer,
    state_batch::StateBatch,
};
use octra_node_protocol::{
    preverify_commit::{self, Gate},
    preverify_receipt::Binding,
    state::Ledger,
    transaction::{OpType, RuleMode, Transaction},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn refusal(tag: &'static str, reason: impl AsRef<[u8]>) -> Effect {
    Effect::Rejected(Refusal {
        error_type: tag.as_bytes().to_vec(),
        reason: reason.as_ref().to_vec(),
    })
}
fn failed(error: balance::Error) -> Result<Effect, Error> {
    match error {
        balance::Error::Rejected(failure) => Ok(refusal(failure.tag, failure.reason)),
        balance::Error::Unavailable(reason) => Err(Error(reason)),
    }
}
/// Construct a fresh host for each speculative epoch; discard it if that
/// attempt aborts. Counters advance only after a successful ledger application.
#[derive(Clone, Copy)]
pub struct Limits {
    pub max_fhe: usize,
    pub max_stealth: usize,
}
enum Plan {
    Balance(balance::Verified),
    Transfer(private_transfer::Verified),
    Key(private_key::Verified),
}
impl Plan {
    fn transition_hash(&self) -> String {
        match self {
            Self::Balance(plan) => plan.transition_hash(),
            Self::Transfer(plan) => plan.transition_hash(),
            Self::Key(plan) => plan.transition_hash(),
        }
    }
    fn apply(
        &self,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        tx: &Transaction,
        epoch: i64,
        persist: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<(), balance::Error> {
        match self {
            Self::Balance(plan) => plan.apply(ledger, tx),
            Self::Transfer(plan) => plan.apply(ledger, state, tx, epoch),
            Self::Key(plan) => plan.apply(ledger, state, tx, persist),
        }
    }
}
pub struct Epoch<'a> {
    policy: private_key::Policy,
    admission: Option<&'a octra_node_protocol::state_sync::migration::Admission>,
    limits: Limits,
    epoch: i64,
    used: usize,
    stealth: usize,
    debits: BTreeSet<Vec<u8>>,
    gate: Option<&'a Gate>,
}
impl<'a> Epoch<'a> {
    pub fn new(
        policy: private_key::Policy,
        limits: Limits,
        epoch: i64,
        gate: Option<&'a Gate>,
        admission: Option<&'a octra_node_protocol::state_sync::migration::Admission>,
    ) -> Self {
        Self {
            policy,
            admission,
            limits,
            epoch,
            used: 0,
            stealth: 0,
            debits: BTreeSet::new(),
            gate,
        }
    }
    /// The key source resolves content-addressed public blobs outside the
    /// consensus tree. Missing/corrupt blobs abort; they are not peer-invalid.
    pub fn process(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        key_source: impl FnOnce(&[u8]) -> Result<Option<Vec<u8>>, Error>,
        persist: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<Effect, Error> {
        match tx.op_type {
            OpType::Private => {
                return Ok(refusal(
                    "private_disabled",
                    "legacy private operation is disabled",
                ))
            }
            OpType::Recrypt => {
                return Ok(refusal(
                    "recrypt_disabled",
                    "recrypt transaction profile is not released",
                ))
            }
            _ => (),
        }
        let profile = self.policy.balance;
        if tx.op_type == OpType::KeySwitch
            && self.policy.owner != RuleMode::Active
            && private_key::owner_requested(tx, profile.fields)
        {
            return Ok(refusal(
                "pvac_migration_inactive",
                "historical owner migration is not active at this epoch",
            ));
        }
        if !matches!(
            tx.op_type,
            OpType::Encrypt | OpType::Decrypt | OpType::Stealth | OpType::Claim | OpType::KeySwitch
        ) {
            return Err(Error("private epoch operation unavailable".into()));
        }
        if tx.op_type != OpType::Stealth && tx.from != tx.to {
            return Ok(refusal(
                "private_target_rejected",
                "private balance operation must be self-targeted",
            ));
        }
        if self.used >= self.limits.max_fhe {
            return Ok(refusal("fhe_epoch_cap", "private operation cap reached"));
        }
        if tx.op_type == OpType::Stealth && self.stealth >= self.limits.max_stealth {
            return Ok(refusal(
                "stealth_epoch_cap",
                "private operation cap reached",
            ));
        }
        if matches!(tx.op_type, OpType::Decrypt | OpType::Stealth) && self.debits.contains(&tx.from)
        {
            return Ok(refusal(
                "encrypted_op_limit",
                "only one encrypted debit operation per sender per epoch",
            ));
        }
        if tx.op_type == OpType::Stealth && tx.to != b"stealth" {
            return Ok(refusal(
                "invalid_stealth_target",
                "stealth transfer must target stealth",
            ));
        }
        if tx.op_type == OpType::KeySwitch
            && private_key::cipher_requested(tx, profile.fields)
            && (self.policy.cipher != RuleMode::Active || !profile.strict)
        {
            return Ok(refusal(
                "key_switch_rejected",
                "unknown key_switch migration_mode = cipher_proof",
            ));
        }
        let hash = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|hash| *hash != b"none");
        if hash.is_none() && tx.op_type != OpType::KeySwitch {
            return Ok(refusal(
                "pvac_key_unbound",
                "pvac public key is not bound to consensus state",
            ));
        }
        let expected = if let Some(gate) = self.gate {
            let receipt = match gate.receipt(tx) {
                Ok(receipt) => receipt,
                Err(preverify_commit::Error::Invalid(reason)) => {
                    return Ok(refusal("preverify_receipt_missing", reason))
                }
                Err(preverify_commit::Error::Unavailable(reason)) => return Err(Error(reason)),
            };
            let Binding::Private(binding) = &receipt.binding else {
                return Ok(refusal(
                    "preverify_transition_missing",
                    "private transition receipt is not state-bound",
                ));
            };
            binding.transition_hash.as_deref()
        } else {
            None
        };
        let evidence = match (profile.strict, expected) {
            (false, Some(hash)) => Evidence::Certified(hash),
            _ => Evidence::Proof,
        };
        // Native payload parsing precedes blob retrieval. Keep the callback
        // lazy so local key availability cannot mask a malformed payload.
        let key = || {
            let Some(hash) = hash else {
                return Ok(None);
            };
            let blob = key_source(hash)
                .map_err(|error| balance::Error::Unavailable(error.0))?
                .ok_or_else(|| balance::Error::Unavailable("pvac blob unavailable".into()))?;
            if hex::encode(Sha256::digest(&blob)).as_bytes() != hash {
                return Err(balance::Error::Unavailable(
                    "pvac blob hash mismatch".into(),
                ));
            }
            Ok(Some(blob))
        };
        let plan = match if matches!(tx.op_type, OpType::Stealth | OpType::Claim) {
            private_transfer::resolve(ledger, state, tx, profile, evidence, key).map(Plan::Transfer)
        } else if tx.op_type == OpType::KeySwitch {
            private_key::resolve(
                ledger,
                tx,
                self.policy,
                self.epoch,
                self.admission,
                evidence,
                key,
            )
            .map(Plan::Key)
        } else {
            balance::resolve(ledger, tx, profile, evidence, key).map(Plan::Balance)
        } {
            Ok(plan) => plan,
            Err(error) => return failed(error),
        };
        if expected.is_some_and(|hash| hash != plan.transition_hash().as_bytes()) {
            return Ok(refusal(
                "preverify_transition_mismatch",
                "private transition does not match the certified receipt",
            ));
        }
        if let Err(error) = plan.apply(ledger, state, tx, self.epoch, persist) {
            return failed(error);
        }
        self.used += 1;
        if tx.op_type == OpType::Stealth {
            self.stealth += 1;
        }
        if matches!(tx.op_type, OpType::Decrypt | OpType::Stealth) {
            self.debits.insert(tx.from.clone());
        }
        Ok(Effect::Confirmed(tx.ou.clone()))
    }
}
