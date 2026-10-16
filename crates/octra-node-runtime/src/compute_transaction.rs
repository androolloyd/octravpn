// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Compute escrow transitions inside the epoch's coupled ledger/tree savepoint.
//! Settlement requires the native record/session verifier and deterministic
//! replay; signed result certificates alone do not authorize a payment.
mod settlement;
use crate::{
    compute_deposits, compute_input, compute_roots,
    epoch_execution::{Effect, Refusal},
    execution,
    state_batch::{Snapshot, StateBatch},
    validator_transaction::EpochFold,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_node_protocol::{
    resource_compute::{
        bill,
        funding::{self, Deposit},
        Error, Result,
    },
    state::Ledger,
    transaction::{self, Nonce, OpType, RuleMode, Transaction},
};
pub use settlement::{funded, FundingStatus, Settlement};

pub struct Host<'a> {
    pub chain: &'a [u8],
    pub epoch: i64,
    pub fold: &'a dyn EpochFold,
    pub settle: RuleMode,
    pub previous_root: &'a [u8],
    pub committed_head: Option<&'a Snapshot>,
    pub verifier: Option<&'a mut dyn Settlement>,
}
fn operational(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
fn refused(reason: impl AsRef<[u8]>) -> Error {
    Error::rejected(reason)
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn refusal(error: Error) -> Refusal {
    Refusal {
        error_type: b"compute_request_refused".to_vec(),
        reason: error.as_bytes().to_vec(),
    }
}
fn minimum(tx: &Transaction) -> Result<BigInt> {
    Ok(match tx.op_type {
        OpType::ComputeFund => BigInt::from(10_000),
        OpType::ComputeSettle => bill::fee(tx.message.as_deref().unwrap_or_default())?,
        _ => BigInt::from(1000),
    })
}
fn read(state: &StateBatch, id: &[u8]) -> Result<Option<Deposit>> {
    compute_deposits::read(&state.snapshot(), id)
        .map_err(|error| operational(format!("compute deposit unreadable: {error}")))
}
fn save(state: &mut StateBatch, deposit: &Deposit) -> Result<()> {
    compute_deposits::save(state, deposit).map_err(operational)
}
fn debit(ledger: &mut Ledger, tx: &Transaction, amount: &BigInt) -> Result<()> {
    ledger
        .debit(&tx.from, amount, tx.nonce, None)
        .map_err(|error| refused(error.0.as_bytes()))
}
fn required(
    result: std::result::Result<(), octra_node_protocol::transaction::Error>,
) -> Result<()> {
    result.map_err(|error| operational(format!("compute transfer failed: {error}")))
}
fn escrow_funds(ledger: &Ledger, amount: &BigInt) -> Result<()> {
    let balance = ledger
        .account(funding::escrow())
        .map(|account| account.balance.clone())
        .unwrap_or_default();
    if balance < *amount {
        Err(operational("compute escrow balance missing"))
    } else {
        Ok(())
    }
}
impl Host<'_> {
    pub fn process(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> std::result::Result<Effect, execution::Error> {
        let mode = self.fold.resolve(self.epoch, state)?.vm_bytes;
        if let Err(error) = transaction::check_compute(mode, self.settle, std::slice::from_ref(tx))
        {
            return Ok(Effect::Rejected(refusal(refused(error.0.as_bytes()))));
        }
        if mode != RuleMode::Active {
            return match self.apply(tx, ledger, state, false) {
                Ok(fee) => Ok(Effect::Confirmed(fee)),
                Err(error) if error.is_operational() => Err(execution::Error(error.to_string())),
                Err(error) => Ok(Effect::Rejected(refusal(error))),
            };
        }
        let fee = minimum(tx).map_err(|error| execution::Error(error.to_string()))?;
        let ready = tx.ou >= fee
            && ledger.account(&tx.from).is_some_and(|account| {
                account.nonce < Nonce::MAX
                    && tx.nonce == account.nonce.successor()
                    && account.balance >= tx.ou
            });
        if !ready {
            return Ok(Effect::Rejected(refusal(refused(
                b"compute fee or nonce differs",
            ))));
        }
        let saved = state
            .save()
            .map_err(|error| execution::Error(error.to_string()))?;
        let depth = ledger.journal_depth();
        ledger.begin_journal();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.apply(tx, ledger, state, true)
        }));
        if !matches!(result, Ok(Ok(_))) {
            while ledger.journal_depth() > depth {
                ledger.abort_journal();
            }
            state
                .restore(saved)
                .map_err(|error| execution::Error(error.to_string()))?;
        }
        match result {
            Ok(Ok(fee)) => {
                ledger
                    .commit_journal()
                    .map_err(|error| execution::Error(error.to_string()))?;
                Ok(Effect::Confirmed(fee))
            }
            Ok(Err(error)) if error.is_operational() => Err(execution::Error(error.to_string())),
            Ok(Err(error)) => match debit(ledger, tx, &tx.ou) {
                Ok(()) => Ok(Effect::RejectedAfterFee {
                    fee: tx.ou.clone(),
                    refusal: refusal(error),
                }),
                Err(error) => Ok(Effect::Rejected(refusal(error))),
            },
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    fn apply(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        inputs: bool,
    ) -> Result<BigInt> {
        if tx.to != funding::escrow()
            || tx.from == funding::escrow()
            || tx.encrypted_data.is_some()
            || tx.ou.is_negative()
            || tx.ou < minimum(tx)?
        {
            return Err(refused(b"compute transaction envelope differs"));
        }
        match (tx.op_type, tx.message.as_deref()) {
            (OpType::ComputeFund, Some(raw)) => self.fund(tx, ledger, state, raw, inputs)?,
            (OpType::ComputeReturn, Some(raw)) if tx.amount.is_zero() => {
                self.returned(tx, ledger, state, raw, inputs)?;
            }
            (OpType::ComputeSettle, Some(raw)) if tx.amount.is_zero() => {
                self.payment(tx, ledger, state, raw)?;
            }
            _ => return Err(refused(b"compute transaction body refused")),
        }
        Ok(tx.ou.clone())
    }
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn fund(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        raw: &[u8],
        inputs: bool,
    ) -> Result<()> {
        let (header, permission) = funding::decode_request(raw)?;
        let terms = permission.terms();
        if terms.payer() != tx.from
            || tx.public_key.as_deref() != Some(STANDARD.encode(terms.public_key()).as_bytes())
            || tx.amount != BigInt::from(terms.amount())
        {
            return Err(refused(b"compute funding transaction differs"));
        }
        let deposit = Deposit::reserve(
            self.chain,
            self.epoch,
            tx.nonce.get(),
            &header,
            permission,
            inputs,
        )?;
        let input = if inputs {
            let context = self.fold.resolve(self.epoch, state).map_err(operational)?;
            if let Some(parent) = context.parent.as_ref() {
                compute_roots::remember(
                    state,
                    self.committed_head,
                    self.epoch,
                    self.previous_root,
                    parent,
                )
                .map_err(operational)?;
            }
            Some(compute_input::prepare(state, &tx.ou, &header)?)
        } else {
            None
        };
        if read(state, deposit.request_id())?.is_some() {
            return Err(refused(b"compute deposit exists"));
        }
        debit(ledger, tx, &(&tx.amount + &tx.ou))?;
        required(ledger.credit(funding::escrow(), &tx.amount, None))?;
        save(state, &deposit)?;
        if let Some(input) = input {
            compute_input::commit(state, input)?;
        }
        Ok(())
    }
    // Keep the operation on the exclusive native execution/actor interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn returned(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        raw: &[u8],
        inputs: bool,
    ) -> Result<()> {
        let id = if raw.len() == 64 {
            hex::decode(raw).ok()
        } else {
            None
        }
        .ok_or_else(|| refused(b"compute return id refused"))?;
        let deposit = read(state, &id)?.ok_or_else(|| refused(b"compute deposit missing"))?;
        let terms = deposit.permission().terms();
        if terms.payer() != tx.from
            || tx.public_key.as_deref() != Some(STANDARD.encode(terms.public_key()).as_bytes())
        {
            return Err(refused(b"compute return payer differs"));
        }
        let amount = BigInt::from(terms.amount());
        let deposit = deposit.return_deposit(self.chain, self.epoch)?;
        escrow_funds(ledger, &amount)?;
        debit(ledger, tx, &tx.ou)?;
        required(ledger.debit_amount_only(funding::escrow(), &amount))?;
        required(ledger.credit(&tx.from, &amount, None))?;
        save(state, &deposit)?;
        if inputs {
            compute_input::release(state, &id)?;
        }
        Ok(())
    }
}
