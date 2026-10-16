// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Single sender execution. This produces no certificate or BFT authority.
use crate::{
    account_store, epoch_footer,
    execution::{self, Completion, Error, Executed, OperationHost, Outcome},
    state_batch::{Snapshot, StateBatch},
    validator_epoch,
    validator_transaction::EpochFold,
};
use num_bigint::BigInt;
use octra_node_protocol::{
    epoch_rewards::Attribution,
    transaction::{self, Transaction},
    transaction_outcome,
};
pub trait Host: OperationHost {
    fn charged_rejection_fees(&self) -> BigInt;
}
pub struct Request<'a> {
    pub validators: validator_epoch::Request<'a>,
    pub envelope: transaction_outcome::Rules,
    pub emission: &'a epoch_footer::Policy,
    pub reward: &'a Attribution,
    pub validator_keys: &'a [(Vec<u8>, Vec<u8>)],
}
pub struct Epoch {
    pub tree_state_root: Vec<u8>,
    pub state: Snapshot,
    pub events: Vec<Executed>,
    pub confirmed: Vec<usize>,
    pub processed: Vec<Vec<u8>>,
    pub deferred: Vec<usize>,
    pub fees: BigInt,
    pub footer: epoch_footer::Footer,
    pub validators: validator_epoch::Advanced,
}
fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
/// The selected source remains in native order. In particular the pristine
/// source-order refusal is preserved before any speculative operation runs.
pub fn execute<H: Host>(
    request: &Request<'_>,
    fold: &impl EpochFold,
    txs: &[Transaction],
    state: &mut StateBatch,
    host: &mut H,
) -> Result<Epoch, Error> {
    execute_registered(
        request,
        fold,
        txs,
        state,
        host,
        &std::collections::BTreeMap::new(),
    )
}
/// Existing-account local key registrations affect the native in-memory Ledger,
/// never the published parent root or speculative proof provenance.
pub fn execute_registered<H: Host>(
    request: &Request<'_>,
    fold: &impl EpochFold,
    txs: &[Transaction],
    state: &mut StateBatch,
    host: &mut H,
    registered: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Epoch, Error> {
    octra_node_protocol::single::source(txs).map_err(err)?;
    transaction::check_compute(request.envelope.compute, request.envelope.settle, txs)
        .map_err(err)?;
    transaction::check_envelopes(request.envelope.envelope, txs).map_err(err)?;
    let saved = state.save().map_err(err)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ledger = account_store::ledger(state).map_err(err)?;
        for (address, key) in registered {
            ledger.register_public_key(address, key.clone());
        }
        ledger.clear_spent_nonces();
        let events = execution::execute_checked(txs, &mut ledger, state, host)?;
        let mut confirmed = vec![];
        let mut processed = vec![];
        let mut deferred = vec![];
        for event in &events {
            match &event.outcome {
                Outcome::Completed(Completion::Confirmed { .. }) => {
                    confirmed.push(event.input_index);
                    processed.push(
                        hex::encode(txs[event.input_index].hash().map_err(err)?).into_bytes(),
                    );
                }
                Outcome::Completed(Completion::Deferred { .. }) => deferred.push(event.input_index),
                _ => processed
                    .push(hex::encode(txs[event.input_index].hash().map_err(err)?).into_bytes()),
            }
        }
        processed.reverse();
        let fees = execution::confirmed_fees(txs, &events) + host.charged_rejection_fees();
        let validators = validator_epoch::advance(&request.validators, fold, state)?;
        let context = fold.resolve(request.validators.epoch, state)?;
        let footer = epoch_footer::apply(
            request.emission,
            &epoch_footer::Request {
                epoch: request.validators.epoch,
                reward: request.reward,
                validator_keys: request.validator_keys,
                confirmed_fees: fees.clone(),
            },
            &mut ledger,
            state,
        )
        .map_err(err)?;
        // Ledger.hash calls Store_irmin.state_hash, which reads committed Head,
        // not the active batch (even after speculative footer writes).
        let tree_state_root = hex::encode(state.published_root().map_err(err)?).into_bytes();
        account_store::flush_dirty(&mut ledger, state, context.account_mode).map_err(err)?;
        ledger.clear_spent_nonces();
        Ok(Epoch {
            tree_state_root,
            state: state.snapshot(),
            events,
            confirmed,
            processed,
            deferred,
            fees,
            footer,
            validators,
        })
    }));
    if !matches!(result, Ok(Ok(_))) {
        state.restore(saved).map_err(err)?;
    }
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

impl Epoch {
    /// Native outcome records for local inspection, not BFT admission receipts.
    pub fn outcomes(&self, txs: &[Transaction]) -> Result<Vec<Vec<u8>>, Error> {
        self.events
            .iter()
            .filter_map(|event| {
                let refusal = match &event.outcome {
                    Outcome::Completed(Completion::Rejected(value)) => Some((
                        value.tag.as_bytes().to_vec(),
                        value.reason.clone(),
                        value.persist_state,
                    )),
                    Outcome::NonceMismatch { expected, got } => Some((
                        b"nonce_mismatch".to_vec(),
                        format!(
                            "expected_nonce = {} got_nonce = {}",
                            expected.get(),
                            got.get()
                        )
                        .into_bytes(),
                        false,
                    )),
                    Outcome::Completed(_) => None,
                }?;
                Some(
                    transaction_outcome::encode_rejection(&transaction_outcome::Rejection {
                        position: event.input_index as i64,
                        tx: txs[event.input_index].clone(),
                        error_type: refusal.0,
                        reason: refusal.1,
                        charged: refusal.2,
                    })
                    .map_err(err),
                )
            })
            .collect()
    }
}
