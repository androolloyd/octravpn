//! Verify locally before voting: proof preparation, Circle capture, candidate
//! outcomes, then the committed partition and native state/index commitment.
use super::{admission, proofs, run_worker, stage::Stage, Native};
use crate::proposal::Candidate;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::transaction::Transaction;
use octra_node_protocol::{
    consensus::reward_attribution, preverify_commit::Gate, preverify_receipt::Receipt,
    transaction_outcome,
};
use octra_node_runtime::{account_store, consensus_bundle::Rules, finality::ExecutedEpoch};
use octra_node_runtime::{
    canonical,
    consensus_bundle::{self, Accepted, RawBundle},
    epoch_partition::Partition,
    state_batch::StateBatch,
};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug)]
pub enum ProposalError {
    Invalid(String),
    Unavailable(String),
}
impl std::fmt::Display for ProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid proposal: {e}"),
            Self::Unavailable(e) => write!(f, "proposal execution unavailable: {e}"),
        }
    }
}
impl std::error::Error for ProposalError {}
pub(super) fn invalid(e: impl std::fmt::Display) -> ProposalError {
    ProposalError::Invalid(e.to_string())
}
pub(super) fn unavailable(e: impl std::fmt::Display) -> ProposalError {
    ProposalError::Unavailable(e.to_string())
}

/// Local execution evidence, without finality privileges. The host must recheck
/// Node::proposal_current after verification and immediately before precommit.
pub struct Prepared {
    candidate: Arc<Candidate>,
    bundle: RawBundle,
    execution: ExecutedEpoch,
}
impl Prepared {
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }
    pub fn bundle(&self) -> &RawBundle {
        &self.bundle
    }
    pub fn execution(&self) -> &ExecutedEpoch {
        &self.execution
    }
}
impl Native {
    pub fn proposal_rules(&self, candidate: &Candidate) -> Result<Rules> {
        let context = candidate.context();
        self.bundle_rules(
            context.parent(),
            &context.proposal().header,
            &context.authority().receipts,
        )
    }

    /// Shares the finalized import worker: cancellation cannot let a second
    /// proof/VM job overlap the first job's unpublished execution state.
    pub async fn verify_proposal(
        &self,
        candidate: Arc<Candidate>,
        raw: &RawBundle,
    ) -> Result<Prepared, ProposalError> {
        let context = candidate.context();
        let proposal = context.proposal();
        let rules = self.proposal_rules(&candidate).map_err(unavailable)?;
        let bundle = consensus_bundle::proposal_wire(proposal, raw, &rules).map_err(invalid)?;
        let inputs =
            transaction_outcome::merge(&bundle.txs, &bundle.rejections).map_err(invalid)?;
        let roots = self
            .ready_roots(context.parent(), context.rules(), &inputs)
            .await
            .map_err(unavailable)?;
        let host = self.clone();
        run_worker(self.worker.clone(), move || {
            Ok(host.prepare(candidate, bundle, &inputs, &rules, &roots))
        })
        .await
        .map_err(unavailable)?
    }

    fn prepare(
        &self,
        candidate: Arc<Candidate>,
        bundle: Accepted,
        inputs: &[Transaction],
        rules: &Rules,
        roots: &BTreeMap<i64, Option<Vec<u8>>>,
    ) -> Result<Prepared, ProposalError> {
        let context = candidate.context();
        let proposal = context.proposal();
        let header = &proposal.header;
        let parent = context.parent();
        let bound = context.rules();
        let state = StateBatch::from_snapshot(candidate.state().clone());
        let ledger = account_store::ledger(&state).map_err(unavailable)?;
        admission::check(
            &self.config.profile,
            &self.config.bundle,
            rules,
            &bundle,
            &ledger,
        )
        .map_err(invalid)?;
        let local = self.proposal_proofs(parent, candidate.state(), bound, inputs, rules)?;
        let keys = context
            .authority()
            .validators
            .validators
            .iter()
            .map(|v| (v.address.clone(), STANDARD.encode(&v.pubkey).into_bytes()))
            .collect::<Vec<_>>();
        let reward = reward_attribution::resolve(
            &header.chain_id,
            header.epoch_id,
            self.config.protocol,
            &header.creator_addr,
            &keys,
            proposal.parent_commit.as_ref(),
        )
        .map_err(unavailable)?;
        let capture = |partition: &Partition| {
            let gate = Gate {
                receipts: proofs::select(&local, partition.transactions())?,
            };
            self.stage(
                Stage {
                    parent,
                    state: StateBatch::from_snapshot(candidate.state().clone()),
                    header,
                    context: bound,
                    rules,
                    validators: &context.authority().validators,
                    reward: &reward,
                    transactions: partition.transactions(),
                    gate: &gate,
                    capture: true,
                },
                roots,
            )
        };
        let final_partition = Partition::finalized(&bundle.txs, &bundle.rejections, rules.envelope)
            .map_err(invalid)?;
        let staged = capture(&final_partition).map_err(unavailable)?;
        let receipts = proofs::select(&staged.gate.receipts, &bundle.txs)
            .map_err(unavailable)?
            .iter()
            .map(Receipt::canonical)
            .collect::<Vec<_>>();
        let received = transaction_outcome::split(&bundle.receipts_json, true).map_err(invalid)?;
        if receipts != received.preverify {
            return Err(invalid("local_preverify_receipt_mismatch"));
        }
        if !bundle.rejections.is_empty() {
            let all = Partition::candidates(&bundle.txs, &bundle.rejections).map_err(invalid)?;
            let outcomes = capture(&all).map_err(unavailable)?;
            all.verify(Ok(&outcomes.artifacts)).map_err(invalid)?;
        }
        final_partition
            .verify(Ok(&staged.artifacts))
            .map_err(invalid)?;
        let root = canonical::execution_root(
            parent,
            u64::try_from(header.epoch_id).map_err(invalid)?,
            &staged.state,
            &staged.transactions,
        )
        .map_err(unavailable)?;
        if root.0.as_slice() != header.proposed_state_root {
            return Err(invalid("proposal state root mismatch"));
        }
        let txid = parent
            .txid_hi
            .checked_add(i64::try_from(staged.transactions.len()).map_err(invalid)?)
            .ok_or_else(|| invalid("transaction index exhausted"))?;
        if txid != header.txid_hi {
            return Err(invalid("proposal transaction index mismatch"));
        }
        let raw = bundle.to_raw().map_err(unavailable)?;
        let execution = ExecutedEpoch {
            epoch_observation: Some(staged.epoch_observation),
            metrics: staged.metrics,
            state: staged.state,
            transactions: staged.transactions,
            vm_receipts: staged.vm_receipts,
            consensus_receipts: bundle.receipts_json,
            reward_source: reward_attribution::to_source(&reward).map_err(unavailable)?,
            date: header.epoch_id,
            message: b"prepared proposal".to_vec(),
        };
        Ok(Prepared {
            candidate,
            bundle: raw,
            execution,
        })
    }
}
