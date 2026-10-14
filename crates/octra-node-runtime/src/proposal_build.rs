// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Ordered Consensus_proposal.make_proposal recovery. Selection, proof work,
//! execution and epoch-bound queue mutation are supplied by the local host.
//! Every preview starts from the same immutable parent, never the prior preview.
use crate::{epoch_execution::Artifacts, execution::Error};
use octra_node_protocol::{
    transaction::{Nonce, Transaction},
    transaction_outcome::{self as outcome, Rejection},
};
use std::collections::{BTreeMap, BTreeSet};

pub struct Selection {
    /// Admitted staging inputs before proof/slot/size selection.
    pub inputs: Vec<Transaction>,
    pub selected: Vec<Transaction>,
}
pub struct Preview<T> {
    pub artifacts: Artifacts,
    pub value: T,
}
pub enum Failure {
    /// Only a locally attributed resource failure may exclude a transaction.
    Exhausted([u8; 32]),
    Failed(Error),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}
pub trait Host {
    type Value;
    fn current(&self) -> bool;
    fn select(&mut self, inputs: &[Transaction]) -> Result<Selection, Error>;
    fn preview(&mut self, inputs: &[Transaction]) -> Result<Preview<Self::Value>, Failure>;
    fn refuse(&mut self, tx: &Transaction);
    fn hold(&mut self, tx: &Transaction);
}
pub struct Built<T> {
    pub confirmed: Vec<Transaction>,
    pub rejections: Vec<Rejection>,
    /// The last successful preview, containing only confirmed/charged effects.
    pub value: T,
}
#[derive(Clone)]
struct Refusal {
    tx: Transaction,
    error_type: Vec<u8>,
    reason: Vec<u8>,
}
fn hashes(txs: &[Transaction]) -> Result<BTreeSet<[u8; 32]>, Error> {
    txs.iter().map(|tx| tx.hash().map_err(error)).collect()
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn cutoffs(txs: &[Transaction]) -> BTreeMap<&[u8], Nonce> {
    let mut limits = BTreeMap::new();
    for tx in txs {
        limits
            .entry(tx.from.as_slice())
            .and_modify(|n: &mut Nonce| *n = (*n).min(tx.nonce))
            .or_insert(tx.nonce);
    }
    limits
}
fn first(txs: &[Transaction]) -> Vec<Transaction> {
    let limits = cutoffs(txs);
    txs.iter()
        .filter(|tx| limits[tx.from.as_slice()] == tx.nonce)
        .cloned()
        .collect()
}
fn before(excluded: &[Transaction], inputs: &[Transaction]) -> Vec<Transaction> {
    let limits = cutoffs(excluded);
    inputs
        .iter()
        .filter(|tx| limits.get(tx.from.as_slice()).is_none_or(|n| tx.nonce < *n))
        .cloned()
        .collect()
}
fn through(rejected: &[Transaction], inputs: Vec<Transaction>) -> Vec<Transaction> {
    let limits = cutoffs(rejected);
    inputs
        .into_iter()
        .filter(|tx| {
            limits
                .get(tx.from.as_slice())
                .is_none_or(|n| tx.nonce <= *n)
        })
        .collect()
}
fn transactions(rows: &[Refusal]) -> Vec<Transaction> {
    rows.iter().map(|r| r.tx.clone()).collect()
}

#[derive(Default)]
struct Recovery {
    deferred: Vec<Transaction>,
    refusals: Vec<Transaction>,
    removed: Vec<Transaction>,
    held: BTreeSet<[u8; 32]>,
}
impl Recovery {
    fn hold(&mut self, host: &mut impl Host) -> Result<(), Error> {
        let removed = hashes(&self.removed)?;
        for tx in first(&self.refusals) {
            let hash = tx.hash().map_err(error)?;
            if !removed.contains(&hash) && self.held.insert(hash) {
                host.hold(&tx);
            }
        }
        Ok(())
    }
    fn defer(
        &mut self,
        excluded: Vec<Transaction>,
        accumulated: &[Refusal],
        inputs: &[Transaction],
    ) -> Vec<Transaction> {
        self.deferred = first(&[excluded.clone(), self.deferred.clone()].concat());
        before(&[excluded, transactions(accumulated)].concat(), inputs)
    }

    fn attempt<H: Host>(
        &mut self,
        host: &mut H,
        staged: &[Transaction],
        steps: &mut usize,
        refill: bool,
    ) -> Result<Built<H::Value>, Error> {
        if !host.current() {
            return Err(error("proposal context changed"));
        }
        let selection = host.select(staged)?;
        let mut inputs = selection.selected.clone();
        let mut remaining = inputs.clone();
        let mut accumulated = Vec::<Refusal>::new();
        loop {
            if !host.current() {
                return Err(error("proposal context changed"));
            }
            if *steps == 0 {
                return Err(error("preview_work_limit"));
            }
            *steps -= 1;
            let preview = host.preview(&remaining);
            if !host.current() {
                return Err(error("proposal context changed"));
            }
            let preview = match preview {
                Err(Failure::Failed(e)) => return Err(e),
                Err(Failure::Exhausted(hash)) => {
                    let excluded = remaining
                        .iter()
                        .filter(|tx| tx.hash().ok() == Some(hash))
                        .cloned()
                        .collect::<Vec<_>>();
                    if excluded.is_empty() {
                        return Err(error("preview_resource_identity"));
                    }
                    inputs = self.defer(excluded, &accumulated, &inputs);
                    remaining.clone_from(&inputs);
                    accumulated.clear();
                    continue;
                }
                Ok(preview) => preview,
            };
            let at = |index: usize| {
                remaining
                    .get(index)
                    .cloned()
                    .ok_or_else(|| error("preview_partition_mismatch"))
            };
            let confirmed = preview
                .artifacts
                .confirmed
                .iter()
                .map(|(i, _)| at(*i))
                .collect::<Result<Vec<_>, _>>()?;
            let mut paid = Vec::new();
            let mut unpaid = Vec::new();
            for row in &preview.artifacts.rejected {
                let refusal = Refusal {
                    tx: at(row.input_index)?,
                    error_type: row.refusal.error_type.clone(),
                    reason: row.refusal.reason.clone(),
                };
                if row.charged {
                    paid.push(refusal);
                } else {
                    unpaid.push(refusal);
                }
            }
            let charged = transactions(&paid);
            let retained = outcome::executed(&[confirmed.clone(), charged.clone()].concat(), &[])
                .map_err(error)?;
            let output = [retained.clone(), transactions(&unpaid)].concat();
            let input_hashes = hashes(&remaining)?;
            let output_hashes = hashes(&output)?;
            if input_hashes.len() != remaining.len()
                || output_hashes.len() != output.len()
                || input_hashes != output_hashes
            {
                return Err(error("preview_partition_mismatch"));
            }
            if unpaid.is_empty() {
                let refused = transactions(&accumulated);
                let rows = accumulated
                    .iter()
                    .chain(&paid)
                    .map(|r| (r.tx.clone(), r.error_type.clone(), r.reason.clone()))
                    .collect::<Vec<_>>();
                let rejections = outcome::build(&inputs, &rows, &charged).map_err(error)?;
                for tx in &refused {
                    host.refuse(tx);
                    self.removed.push(tx.clone());
                }
                if !host.current() {
                    return Err(error("proposal context changed"));
                }
                let next = before(&refused, &selection.inputs);
                let included = hashes(&selection.selected)?;
                if refill
                    && *steps >= 2
                    && !refused.is_empty()
                    && next.len() < selection.inputs.len()
                    && next
                        .iter()
                        .any(|tx| tx.hash().is_ok_and(|h| !included.contains(&h)))
                {
                    return self.attempt(host, &next, steps, false);
                }
                return Ok(Built {
                    confirmed,
                    rejections,
                    value: preview.value,
                });
            }
            let unavailable = |r: &&Refusal| {
                matches!(
                    r.error_type.as_slice(),
                    b"vm_transition_incomplete" | b"vm_transition_exception"
                )
            };
            let excluded = unpaid
                .iter()
                .filter(unavailable)
                .map(|r| r.tx.clone())
                .collect::<Vec<_>>();
            self.refusals = first(
                &[
                    unpaid
                        .iter()
                        .filter(|r| !unavailable(r))
                        .map(|r| r.tx.clone())
                        .collect(),
                    self.refusals.clone(),
                ]
                .concat(),
            );
            if !excluded.is_empty() {
                inputs = self.defer(excluded, &accumulated, &inputs);
                remaining.clone_from(&inputs);
                accumulated.clear();
                continue;
            }
            let count = inputs.len();
            if accumulated.is_empty() {
                let rejected = first(&transactions(&unpaid));
                let rejected_hashes = hashes(&rejected)?;
                unpaid.retain(|r| r.tx.hash().is_ok_and(|h| rejected_hashes.contains(&h)));
                let retained = hashes(&[retained.clone(), rejected.clone()].concat())?;
                inputs.retain(|tx| tx.hash().is_ok_and(|h| retained.contains(&h)));
                inputs = through(&rejected, inputs);
            }
            if inputs.len() != count {
                remaining.clone_from(&inputs);
                accumulated.clear();
            } else if accumulated.is_empty() {
                remaining = retained;
                accumulated = unpaid;
            } else {
                inputs = before(&transactions(&unpaid), &inputs);
                remaining.clone_from(&inputs);
                accumulated.clear();
            }
        }
    }
}

/// Four ordered previews, at most one refill, then two reserved previews after
/// sender cutoffs. Unavailable work is deferred; ordinary refusals are held only
/// after exhausting the first budget. No failed preview state can escape.
pub fn build<H: Host>(host: &mut H, inputs: &[Transaction]) -> Result<Built<H::Value>, Error> {
    let mut recovery = Recovery::default();
    let mut steps = 4;
    let result = recovery.attempt(host, inputs, &mut steps, true);
    if result.is_ok() || steps != 0 || !host.current() {
        return result;
    }
    let excluded = [
        recovery.removed.clone(),
        recovery.refusals.clone(),
        recovery.deferred.clone(),
    ]
    .concat();
    recovery.hold(host)?;
    let retained = before(&excluded, inputs);
    let result = recovery.attempt(host, &retained, &mut 2, false);
    if host.current() {
        recovery.hold(host)?;
    }
    result
}
