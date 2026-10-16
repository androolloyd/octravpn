// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Single sender private gates and native deferral; every applied plan verifies proofs.
use crate::{
    execution::{Completion, Error, Rejection},
    private_balance, private_key, private_transfer,
    state_batch::StateBatch,
};
use octra_node_protocol::{
    single::{self, Gate, Preverify},
    state::Ledger,
    transaction::{OpType, Transaction},
};
use sha2::Digest as _;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deferred {
    pub counts: BTreeMap<String, i64>,
}
/// A local cache capability can only be made by actual range preparation.
/// Historical/certified plans cannot relabel themselves as range evidence.
/// ```compile_fail
/// use octra_node_runtime::{single_private::CacheBinding,private_transfer::Verified,private_balance::Profile};
/// use octra_node_protocol::transaction::Transaction;
/// fn relabel(tx:&Transaction,profile:Profile,plan:&Verified){let _=CacheBinding::verified(tx,profile,plan);}
/// ```
#[derive(Clone)]
pub struct CacheBinding {
    current: Vec<u8>,
    profile: private_balance::Profile,
    key_sha256: [u8; 32],
    transaction: [u8; 32],
    ranges: (bool, bool),
}
impl CacheBinding {
    /// A range-cache token can only be created by actual speculative range work.
    /// False range results remain Ready, and fail at execution in native order.
    pub fn preverify(
        ledger: &Ledger,
        tx: &Transaction,
        profile: private_balance::Profile,
        blob: &[u8],
    ) -> Result<Self, private_balance::Error> {
        if tx.op_type != OpType::Stealth {
            return Err(private_balance::Error::Unavailable(
                "Single range cache route differs".into(),
            ));
        }
        let (current, delta, balance) =
            match private_transfer::single_ranges(ledger, tx, profile, blob) {
                Ok(result) => result,
                Err(private_balance::Error::Rejected(_)) => (
                    ledger
                        .account(&tx.from)
                        .and_then(|account| account.encrypted_balance.as_deref())
                        .unwrap_or_default()
                        .to_vec(),
                    false,
                    false,
                ),
                Err(error) => return Err(error),
            };
        Ok(Self {
            current,
            profile,
            key_sha256: sha2::Sha256::digest(blob).into(),
            transaction: tx
                .hash()
                .map_err(|e| private_balance::Error::Unavailable(e.to_string()))?,
            ranges: (delta, balance),
        })
    }
    pub(crate) fn results(
        &self,
        tx: &Transaction,
        profile: private_balance::Profile,
        current: &[u8],
        blob: &[u8],
    ) -> Option<(bool, bool)> {
        self.matches(tx, profile, current, blob)
            .then_some(self.ranges)
    }
    fn matches(
        &self,
        tx: &Transaction,
        profile: private_balance::Profile,
        current: &[u8],
        blob: &[u8],
    ) -> bool {
        tx.hash().ok() == Some(self.transaction)
            && self.profile.strict == profile.strict
            && self.profile.math == profile.math
            && self.profile.fields == profile.fields
            && self.profile.result == profile.result
            && self.key_sha256 == <[u8; 32]>::from(sha2::Sha256::digest(blob))
            && self.current == current
    }
}
pub struct Epoch {
    pub ready: BTreeMap<String, CacheBinding>,
    pub deferred: Deferred,
    pub preverify: BTreeMap<String, Preverify>,
    pub maximum_fhe: usize,
    pub maximum_stealth: usize,
    pub maximum_defer: i64,
    pub inline: bool,
    used: usize,
    stealth: usize,
    debits: BTreeSet<Vec<u8>>,
}
fn reject(tag: &str, reason: impl AsRef<[u8]>) -> Completion {
    Completion::Rejected(Rejection {
        tag: tag.into(),
        reason: reason.as_ref().to_vec(),
        notify_reason: Some(reason.as_ref().to_vec()),
        consume_nonce: false,
        persist_state: false,
    })
}
fn kat_reject(name: &str) -> Completion {
    let mut completion = reject(
        "aes_kat_mismatch",
        format!(
            "{name}: pubkey registered with incompatible AES - re-register with compatible client"
        ),
    );
    if let Completion::Rejected(ref mut value) = completion {
        value.notify_reason =
            Some(format!("{name}: AES KAT mismatch - re-register pvac pubkey").into_bytes());
    }
    completion
}
fn failure(error: private_balance::Error) -> Result<Completion, Error> {
    match error {
        private_balance::Error::Rejected(f) => Ok(Completion::Rejected(Rejection {
            tag: f.tag.into(),
            reason: f.reason,
            notify_reason: Some(f.user_reason),
            consume_nonce: false,
            persist_state: false,
        })),
        private_balance::Error::Unavailable(reason) => Err(Error(reason)),
    }
}
impl Epoch {
    pub fn new(
        deferred: Deferred,
        preverify: BTreeMap<String, Preverify>,
        fhe: usize,
        stealth: usize,
        maximum_defer: i64,
        inline: bool,
    ) -> Self {
        Self {
            ready: BTreeMap::new(),
            deferred,
            preverify,
            maximum_fhe: fhe,
            maximum_stealth: stealth,
            maximum_defer,
            inline,
            used: 0,
            stealth: 0,
            debits: BTreeSet::new(),
        }
    }
    pub fn process<B: AsRef<[u8]>>(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        policy: private_key::Policy,
        epoch: i64,
        admission: Option<&octra_node_protocol::state_sync::migration::Admission>,
        key: impl FnOnce() -> Result<Option<B>, private_balance::Error>,
        mut kat: impl FnMut(&[u8], &str) -> Result<bool, Error>,
        persist: impl FnOnce(&[u8]) -> Result<(), Error>,
    ) -> Result<Completion, Error> {
        let op = tx.op_type;
        if op == OpType::Stealth {
            let name = if op == OpType::Encrypt {
                "encrypt"
            } else if op == OpType::Decrypt {
                "decrypt"
            } else {
                "stealth"
            };
            if !kat(&tx.from, name)? {
                return Ok(kat_reject(name));
            }
        }
        if matches!(op, OpType::Decrypt | OpType::Stealth) && self.debits.contains(&tx.from) {
            return Ok(reject(
                "encrypted_op_limit",
                "only one encrypted debit operation per sender per epoch",
            ));
        }
        if op != OpType::Claim && self.used >= self.maximum_fhe {
            return Ok(reject(
                "fhe_epoch_cap",
                "FHE operation cap reached for this epoch",
            ));
        }
        if matches!(op, OpType::Encrypt | OpType::Decrypt) {
            let name = if op == OpType::Encrypt {
                "encrypt"
            } else {
                "decrypt"
            };
            if !kat(&tx.from, name)? {
                return Ok(kat_reject(name));
            }
        }
        let hash = hex::encode(tx.hash().map_err(|e| Error(e.to_string()))?);
        if op == OpType::Stealth {
            if tx.to != b"stealth" {
                return Ok(reject(
                    "invalid_stealth_target",
                    "stealth transfer must have to_=\"stealth\"",
                ));
            }
            if self.stealth >= self.maximum_stealth {
                return Ok(Completion::Deferred {
                    consume_nonce: true,
                });
            }
            let status = self.preverify.get(&hash).unwrap_or(&Preverify::Missing);
            match single::preverify_gate(
                status,
                *self.deferred.counts.get(&hash).unwrap_or(&0),
                self.maximum_defer,
            ) {
                Gate::Failed(reason) => {
                    self.deferred.counts.remove(&hash);
                    self.preverify.remove(&hash);
                    return Ok(reject(
                        "pre_verify_failed",
                        [b"reason = ".as_slice(), &reason].concat(),
                    ));
                }
                Gate::Timeout(reason) => {
                    self.deferred.counts.remove(&hash);
                    return Ok(reject(
                        "pre_verify_timeout",
                        [
                            format!("max_epochs = {} reason = ", self.maximum_defer).as_bytes(),
                            &reason,
                        ]
                        .concat(),
                    ));
                }
                Gate::Defer { next_count, .. } | Gate::Unavailable { next_count, .. } => {
                    self.deferred.counts.insert(hash, next_count);
                    return Ok(Completion::Deferred {
                        consume_nonce: true,
                    });
                }
                Gate::Ready => (),
            }
            let mut loaded = None;
            let prepared =
                match private_transfer::prepare_stealth(ledger, state, tx, policy.balance, || {
                    let blob = key()?.map(|value| value.as_ref().to_vec());
                    loaded.clone_from(&blob);
                    Ok(blob)
                }) {
                    Ok(plan) => plan,
                    Err(error) => return failure(error),
                };
            let cached = self
                .ready
                .get(&hash)
                .filter(|binding| {
                    binding.matches(
                        tx,
                        policy.balance,
                        prepared.current_cipher(),
                        loaded.as_deref().unwrap_or_default(),
                    )
                })
                .cloned();
            if cached.is_none() && !self.inline {
                return Ok(Completion::Deferred {
                    consume_nonce: true,
                });
            }
            self.deferred.counts.remove(&hash);
            self.preverify.remove(&hash);
            self.ready.remove(&hash);
            let plan = match private_transfer::verify_single(
                ledger,
                state,
                tx,
                policy.balance,
                cached.as_ref(),
                || Ok(loaded),
            ) {
                Ok(plan) => plan,
                Err(error) => return failure(error),
            };
            if let Err(error) = plan.apply(ledger, state, tx, epoch) {
                return failure(error);
            }
            self.used += 1;
            self.stealth += 1;
            self.debits.insert(tx.from.clone());
            return Ok(Completion::Confirmed {
                created_account: None,
            });
        }
        let result = match op {
            OpType::Encrypt | OpType::Decrypt => {
                private_balance::verify_with_key(ledger, tx, policy.balance, key)
                    .and_then(|plan| plan.apply(ledger, tx))
            }
            OpType::Stealth | OpType::Claim => {
                private_transfer::verify(ledger, state, tx, policy.balance, key)
                    .and_then(|plan| plan.apply(ledger, state, tx, epoch))
            }
            OpType::KeySwitch => private_key::verify(ledger, tx, policy, epoch, admission, key)
                .and_then(|plan| plan.apply(ledger, state, tx, persist)),
            _ => return Err(Error("Single private route mismatch".into())),
        };
        if let Err(error) = result {
            return failure(error);
        }
        if op != OpType::Claim {
            self.used += 1;
        }
        if op == OpType::Stealth {
            self.stealth += 1;
        }
        if matches!(op, OpType::Decrypt | OpType::Stealth) {
            self.debits.insert(tx.from.clone());
        }
        Ok(Completion::Confirmed {
            created_account: None,
        })
    }
}

#[cfg(test)]
mod tests;

/// Isolated trusted range processes, separate from signed consensus history.
pub mod worker;
