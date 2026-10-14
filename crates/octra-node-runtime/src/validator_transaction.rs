// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Validator stake operations inside the native sender/savepoint loop.
//! The trusted epoch fold supplies rule modes and canonical membership.
mod ready;
use crate::{
    execution::{Completion, Error, OperationHost, Rejection, Route},
    state_batch::StateBatch,
};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_node_protocol::{
    control_payload::{self, Bond},
    native_integer::parse_integer,
    state::{Ledger, MAX_SUPPLY},
    transaction::{OpType, Transaction},
    validator::{
        evidence,
        policy::{self, Policy},
        registry::{self, Registry},
    },
};
pub use ready::ReadyEnvironment;

pub use crate::validator_epoch::Fold;
use std::sync::Arc;
pub trait EpochFold {
    /// Resolve from this execution tree, checking the chain's rule anchors.
    /// Failure aborts the application attempt instead of rejecting a transaction.
    fn resolve(&self, epoch: i64, state: &StateBatch) -> Result<Arc<Fold>, Error>;
}
impl<F: Fn(i64, &StateBatch) -> Result<Fold, Error>> EpochFold for F {
    fn resolve(&self, epoch: i64, state: &StateBatch) -> Result<Arc<Fold>, Error> {
        self(epoch, state).map(Arc::new)
    }
}
pub struct Host<'a, F> {
    pub chain: &'a [u8],
    pub epoch: i64,
    pub policy: &'a Policy,
    pub fold: F,
    pub ready: ReadyEnvironment<'a>,
}
enum Failure {
    Rejected(&'static str, String),
    Host(Error),
}
fn rejected(tag: &'static str, error: impl std::fmt::Display) -> Failure {
    Failure::Rejected(tag, error.to_string())
}
fn checked<T>(tag: &'static str, result: Result<T, impl std::fmt::Display>) -> Result<T, Failure> {
    result.map_err(|e| rejected(tag, e))
}
fn load(state: &StateBatch) -> Result<Registry, Failure> {
    match state.get(&[b"meta", registry::META_KEY]) {
        None => Ok(Registry::default()),
        Some(raw) => checked("validator_registry_corrupt", Registry::from_bytes(raw)),
    }
}
fn set(state: &mut StateBatch, key: &[u8], value: Vec<u8>) -> Result<(), Failure> {
    state
        .set(&[b"meta", key], value)
        .map_err(|e| Failure::Host(Error(e.to_string())))
}
fn save(state: &mut StateBatch, value: &Registry) -> Result<(), Failure> {
    set(state, registry::META_KEY, value.to_bytes())
}
fn nonnegative(label: &str, raw: Option<&[u8]>) -> Result<BigInt, String> {
    let raw = raw.ok_or_else(|| format!("{label} is unavailable"))?;
    let value = parse_integer(raw).ok_or_else(|| format!("invalid {label}"))?;
    if value.is_negative() {
        Err(format!("{label} is negative"))
    } else {
        Ok(value)
    }
}
fn supply(state: &StateBatch) -> Result<(BigInt, BigInt), String> {
    let total = nonnegative("total supply", state.get(&[b"meta", b"total_supply"]))?;
    let remaining = nonnegative(
        "emission remaining",
        state.get(&[b"meta", b"emission_remaining"]),
    )?;
    let retired = nonnegative("retired supply", state.get(&[b"meta", b"supply_retired"]))?;
    if &total + remaining + &retired != BigInt::from(MAX_SUPPLY) {
        return Err("validator slash supply envelope mismatch".into());
    }
    Ok((total, retired))
}
impl<F: EpochFold> Host<'_, F> {
    fn resolve(&self, state: &StateBatch) -> Result<Arc<Fold>, Failure> {
        self.fold
            .resolve(self.epoch, state)
            .map_err(|e| Failure::Host(Error(format!("validator set fold rule rejected: {e}"))))
    }
    fn apply(
        &self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<(), Failure> {
        if tx.op_type == OpType::ValidatorReady {
            return self.ready_transaction(tx, ledger, state);
        }
        let tag = match tx.op_type {
            OpType::ValidatorSetUpdate => {
                return Err(rejected(
                    "validator_set_update_rejected",
                    "manual validator updates are disabled",
                ))
            }
            OpType::ValidatorBond => "validator_bond_rejected",
            OpType::ValidatorExit => "validator_exit_rejected",
            OpType::ValidatorWithdraw => "validator_withdraw_rejected",
            OpType::ValidatorEvidence => "validator_evidence_rejected",
            _ => {
                return Err(Failure::Host(Error(
                    "operation requires an unavailable execution host".into(),
                )))
            }
        };
        let Policy::Bonded(policy) = self.policy else {
            return Err(rejected(tag, "validator admission is inactive"));
        };
        let escrow = registry::escrow_address();
        match tx.op_type {
            OpType::ValidatorBond => {
                if tx.to != escrow {
                    return Err(rejected(tag, "recipient must be validator escrow"));
                }
                let payload = checked("malformed_transaction", Bond::parse(tx.message.as_deref()))?;
                let registry = load(state)?;
                let next = checked(
                    tag,
                    registry.apply_bond(
                        &policy.parameters,
                        self.chain,
                        self.epoch,
                        &tx.from,
                        tx.public_key.as_deref().unwrap_or_default(),
                        &tx.amount,
                        tx.nonce,
                        &payload,
                    ),
                )?;
                checked(
                    "insufficient_balance",
                    ledger.debit(&tx.from, &(&tx.amount + &tx.ou), tx.nonce, None),
                )?;
                if ledger.account(&escrow).is_none() {
                    checked(
                        "validator_escrow_rejected",
                        ledger.add_account(&escrow, BigInt::zero(), None),
                    )?;
                }
                checked(
                    "validator_escrow_rejected",
                    ledger.credit(&escrow, &tx.amount, None),
                )?;
                save(state, &next)
            }
            OpType::ValidatorExit | OpType::ValidatorWithdraw => {
                if !tx.amount.is_zero() {
                    return Err(rejected(tag, "amount must be zero"));
                }
                if tx.from != tx.to {
                    return Err(rejected(
                        tag,
                        if tx.op_type == OpType::ValidatorExit {
                            "validator exit must be self-directed"
                        } else {
                            "validator withdrawal must be self-directed"
                        },
                    ));
                }
                // Native withdrawal resolves the fold before reading registry state.
                let fold = if tx.op_type == OpType::ValidatorWithdraw {
                    Some(self.fold.resolve(self.epoch, state).map_err(|e| {
                        Failure::Host(Error(format!("validator set fold rule rejected: {e}")))
                    })?)
                } else {
                    None
                };
                let registry = load(state)?;
                let (next, amount) = match fold {
                    None => (
                        checked(tag, registry.request_exit(self.epoch, &tx.from))?,
                        None,
                    ),
                    Some(fold) => {
                        let (r, amount) = checked(
                            tag,
                            registry.withdraw(
                                &policy::exit_parameters(fold.exit_mode, &policy.parameters),
                                self.epoch,
                                &fold.active_addresses,
                                &tx.from,
                            ),
                        )?;
                        (r, Some(amount))
                    }
                };
                checked(
                    "insufficient_balance",
                    ledger.debit(&tx.from, &tx.ou, tx.nonce, None),
                )?;
                if let Some(amount) = amount {
                    checked(
                        "validator_escrow_rejected",
                        ledger.debit_amount_only(&escrow, &amount),
                    )?;
                    checked(tag, ledger.credit(&tx.from, &amount, None))?;
                }
                save(state, &next)
            }
            OpType::ValidatorEvidence => {
                let fold = self.fold.resolve(self.epoch, state).map_err(|e| {
                    Failure::Host(Error(format!("validator set fold rule rejected: {e}")))
                })?;
                let window = policy::evidence_age(fold.exit_mode, policy.evidence_epochs);
                if self.epoch < policy.activation_epoch {
                    return Err(rejected(tag, "validator admission is not active"));
                }
                if !tx.amount.is_zero() {
                    return Err(rejected(tag, "amount must be zero"));
                }
                let proof = checked(
                    "malformed_transaction",
                    control_payload::evidence(tx.message.as_deref()),
                )?;
                let registry = load(state)?;
                let candidate = registry
                    .find(&tx.to)
                    .ok_or_else(|| rejected(tag, "validator bond not found"))?;
                let evidence = checked(
                    tag,
                    evidence::verify(self.chain, self.epoch, window, candidate, &proof),
                )?;
                let (next, amount) =
                    checked(tag, registry.apply_slash(self.epoch, window, &evidence))?;
                let (total, retired) = checked(tag, supply(state))?;
                if total < amount {
                    return Err(rejected(tag, "validator slash exceeds total supply"));
                }
                checked(
                    "insufficient_balance",
                    ledger.debit(&tx.from, &tx.ou, tx.nonce, None),
                )?;
                checked(
                    "validator_escrow_rejected",
                    ledger.debit_amount_only(&escrow, &amount),
                )?;
                save(state, &next)?;
                set(
                    state,
                    b"total_supply",
                    (total - &amount).to_string().into_bytes(),
                )?;
                set(
                    state,
                    b"supply_retired",
                    (retired + amount).to_string().into_bytes(),
                )
            }
            _ => unreachable!("supported validator operation"),
        }
    }
}
impl<F: EpochFold> OperationHost for Host<'_, F> {
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<Completion, Error> {
        if route != Route::Validator {
            return Err(Error(
                "operation requires an unavailable execution host".into(),
            ));
        }
        match self.apply(tx, ledger, state) {
            Ok(()) => Ok(Completion::Confirmed {
                created_account: None,
            }),
            Err(Failure::Host(e)) => Err(e),
            Err(Failure::Rejected(tag, reason)) => Ok(Completion::Rejected(Rejection {
                tag: tag.into(),
                notify_reason: None,
                reason: reason.into_bytes(),
                consume_nonce: false,
                persist_state: false,
            })),
        }
    }
}
