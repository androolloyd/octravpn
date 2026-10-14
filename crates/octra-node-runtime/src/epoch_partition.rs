// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native proposal outcome checks and finalized execution selection. Ordinary
//! rejections belong to the candidate preview only, even if that preview paid a
//! VM fee. Final state replays confirmed transactions and charged compute errors.
use crate::{
    epoch_execution::{self, Artifacts, Effect, Executed, Request},
    execution::Error,
    state_batch::StateBatch,
    validator_transaction::EpochFold,
};
use octra_node_protocol::{
    state::Ledger,
    transaction::{self, Transaction},
    transaction_outcome::{self as outcome, Rejection, Rules},
};

pub struct Partition {
    inputs: Vec<Transaction>,
    confirmed: Vec<Transaction>,
    rejections: Vec<Rejection>,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
impl Partition {
    /// Proposal verification executes all candidates with locally prepared
    /// preverification receipts. Never publish the result of this preview.
    pub fn candidates(confirmed: &[Transaction], rejections: &[Rejection]) -> Result<Self, Error> {
        Ok(Self {
            inputs: outcome::merge(confirmed, rejections).map_err(error)?,
            confirmed: confirmed.to_vec(),
            rejections: rejections.to_vec(),
        })
    }

    /// Finalized replay checks the complete input envelope before removing
    /// ordinary refusals. Charged rejection positions are rebuilt for this
    /// smaller input set, as in Consensus_proposal.verify_preview_partition.
    pub fn finalized(
        confirmed: &[Transaction],
        rejections: &[Rejection],
        rules: Rules,
    ) -> Result<Self, Error> {
        let all = outcome::merge(confirmed, rejections).map_err(error)?;
        outcome::check_charged(rules.compute, rejections).map_err(error)?;
        transaction::check_compute(rules.compute, rules.settle, &all).map_err(error)?;
        transaction::check_envelopes(rules.envelope, &all).map_err(error)?;
        let inputs = outcome::executed(confirmed, rejections).map_err(error)?;
        let charged = rejections.iter().filter(|r| r.charged).collect::<Vec<_>>();
        let rejections = outcome::build(
            &inputs,
            &charged
                .iter()
                .map(|r| (r.tx.clone(), r.error_type.clone(), r.reason.clone()))
                .collect::<Vec<_>>(),
            &charged.iter().map(|r| r.tx.clone()).collect::<Vec<_>>(),
        )
        .map_err(error)?;
        Ok(Self {
            inputs,
            confirmed: confirmed.to_vec(),
            rejections,
        })
    }
    pub fn transactions(&self) -> &[Transaction] {
        &self.inputs
    }
    /// Compare hashes in their native order, then normalized rejection bytes.
    /// Positions in execution artifacts are not used by the native verifier.
    pub fn verify(&self, result: Result<&Artifacts, &Error>) -> Result<(), Error> {
        self.verify_order(&self.inputs, result)
    }
    /// Staging chooses by fee priority; execution returns canonical outcomes.
    /// Input indices still refer to the staging order on an initial preview.
    pub fn verify_input_order(
        &self,
        inputs: &[Transaction],
        artifacts: &Artifacts,
    ) -> Result<(), Error> {
        if outcome::executed(inputs, &[]).map_err(error)? != self.inputs {
            return Err(error("preview_partition_mismatch"));
        }
        self.verify_order(inputs, Ok(artifacts))
    }
    fn verify_order(
        &self,
        inputs: &[Transaction],
        result: Result<&Artifacts, &Error>,
    ) -> Result<(), Error> {
        let artifacts = result.map_err(|e| error(format!("preview_failed:{e}")))?;
        let tx = |index| {
            inputs
                .get(index)
                .ok_or_else(|| error("execution artifact input index is invalid"))
        };
        let actual = artifacts
            .confirmed
            .iter()
            .map(|(index, _)| tx(*index)?.hash().map_err(error))
            .collect::<Result<Vec<_>, _>>()?;
        let expected = self
            .confirmed
            .iter()
            .map(|tx| tx.hash().map_err(error))
            .collect::<Result<Vec<_>, _>>()?;
        if actual != expected {
            return Err(error("preview_confirmed_mismatch"));
        }
        let mut rejected = Vec::new();
        let mut charged = Vec::new();
        for r in &artifacts.rejected {
            let tx = tx(r.input_index)?;
            rejected.push((
                tx.clone(),
                r.refusal.error_type.clone(),
                r.refusal.reason.clone(),
            ));
            if r.charged {
                charged.push(tx.clone());
            }
        }
        let actual = outcome::build(&self.inputs, &rejected, &charged)
            .map_err(|e| error(format!("preview_outcome_invalid:{e}")))?;
        if outcome::encode(&[], &actual).map_err(error)?
            != outcome::encode(&[], &self.rejections).map_err(error)?
        {
            return Err(error("preview_rejection_mismatch"));
        }
        Ok(())
    }

    /// Check outcomes inside the epoch savepoint: an unexpected refusal or
    /// confirmation restores accounts, fees, validator/footer writes and keys.
    /// The caller must also discard its operation-local auxiliary artifacts on
    /// error. This stages state only; canonical publication is a separate gate.
    pub fn execute(
        &self,
        request: &Request<'_>,
        fold: &impl EpochFold,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        process: impl FnMut(&Transaction, &mut Ledger, &mut StateBatch) -> Result<Effect, Error>,
    ) -> Result<Executed, Error> {
        epoch_execution::execute_checked(
            request,
            fold,
            &self.inputs,
            ledger,
            state,
            process,
            |executed| self.verify(Ok(&executed.artifacts)),
        )
    }
}
