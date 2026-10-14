// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Per-attempt native private-operation admission. The caller authenticates the
//! certificate; the outer epoch executor checks receipt source bindings first.
use crate::{
    epoch_execution::{Effect, Refusal},
    execution::Error,
    private_balance::{self as balance, Evidence, Profile},
    state_batch::StateBatch,
};
use octra_node_protocol::{
    preverify_commit::{self, Gate},
    preverify_receipt::Binding,
    state::Ledger,
    transaction::{OpType, Transaction},
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
pub struct Epoch<'a> {
    profile: Profile,
    maximum: usize,
    used: usize,
    debits: BTreeSet<Vec<u8>>,
    gate: Option<&'a Gate>,
}
impl<'a> Epoch<'a> {
    pub fn new(profile: Profile, maximum: usize, gate: Option<&'a Gate>) -> Self {
        Self {
            profile,
            maximum,
            used: 0,
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
        state: &StateBatch,
        key_source: impl FnOnce(&[u8]) -> Result<Option<Vec<u8>>, Error>,
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
        if !matches!(tx.op_type, OpType::Encrypt | OpType::Decrypt) {
            return Err(Error("private epoch operation unavailable".into()));
        }
        if tx.from != tx.to {
            return Ok(refusal(
                "private_target_rejected",
                "private balance operation must be self-targeted",
            ));
        }
        if self.used >= self.maximum {
            return Ok(refusal("fhe_epoch_cap", "private operation cap reached"));
        }
        if tx.op_type == OpType::Decrypt && self.debits.contains(&tx.from) {
            return Ok(refusal(
                "encrypted_op_limit",
                "only one encrypted debit operation per sender per epoch",
            ));
        }
        let Some(hash) = state
            .get(&[b"pvac_hashes", &tx.from])
            .filter(|hash| *hash != b"none")
        else {
            return Ok(refusal(
                "pvac_key_unbound",
                "pvac public key is not bound to consensus state",
            ));
        };
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
        let evidence = match (self.profile.strict, expected) {
            (false, Some(hash)) => Evidence::Certified(hash),
            _ => Evidence::Proof,
        };
        // Native payload parsing precedes blob retrieval. Keep the callback
        // lazy so local key availability cannot mask a malformed payload.
        let key = || {
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
        let plan = match balance::resolve(ledger, tx, self.profile, evidence, key) {
            Ok(plan) => plan,
            Err(error) => return failed(error),
        };
        if self.profile.strict
            && expected.is_some_and(|hash| hash != plan.transition_hash().as_bytes())
        {
            return Ok(refusal(
                "preverify_transition_mismatch",
                "private transition does not match the certified receipt",
            ));
        }
        if let Err(error) = plan.apply(ledger, tx) {
            return failed(error);
        }
        self.used += 1;
        if tx.op_type == OpType::Decrypt {
            self.debits.insert(tx.from.clone());
        }
        Ok(Effect::Confirmed(tx.ou.clone()))
    }
}
