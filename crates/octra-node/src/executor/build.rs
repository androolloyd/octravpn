//! Construct commitments from local execution of selected staging candidates.
//! Queue ownership and round freezing belong to the driver host.
use super::{
    admission, proofs,
    proposal::{invalid, unavailable},
    run_worker,
    stage::{Stage, Staged},
    Native, ProposalError,
};
use crate::proposal::Draft;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{engine::tx_list_hash_for_header, hash, reward_attribution},
    preverify_commit::Gate,
    preverify_receipt::Receipt,
    transaction::Transaction,
    transaction_outcome,
};
use octra_node_runtime::{
    account_store, canonical,
    consensus_bundle::{Accepted, RawBundle, Rules},
    consensus_driver::ProposalPlan,
    epoch_partition::Partition,
    finality::ExecutedEpoch,
    proposal_build::{self, Failure, Host, Preview, Selection},
    state_batch::StateBatch,
};
use std::{collections::BTreeMap, sync::Arc};

/// A speculative result. Recheck Node::draft_current before caching/signing and
/// durable precommit. This local execution evidence grants no finality authority.
pub struct Built {
    draft: Arc<Draft>,
    plan: ProposalPlan,
    bundle: RawBundle,
    execution: ExecutedEpoch,
    refused: Vec<Transaction>,
    held: Vec<Transaction>,
}
impl Built {
    pub fn draft(&self) -> &Draft {
        &self.draft
    }
    pub fn plan(&self) -> &ProposalPlan {
        &self.plan
    }
    pub fn bundle(&self) -> &RawBundle {
        &self.bundle
    }
    pub fn execution(&self) -> &ExecutedEpoch {
        &self.execution
    }
    /// Queue changes are valid only while this draft is current.
    pub fn refused(&self) -> &[Transaction] {
        &self.refused
    }
    pub fn held(&self) -> &[Transaction] {
        &self.held
    }
    pub fn into_plan(self) -> ProposalPlan {
        self.plan
    }
}

impl Native {
    /// Execute a selected staging batch and derive its native header, receipts
    /// and outcome partition, using native bounded replay for changing outcomes.
    /// Unavailable proofs defer construction; no fallback root is used.
    pub async fn build_proposal(
        &self,
        draft: Arc<Draft>,
        inputs: Vec<Transaction>,
    ) -> Result<Built, ProposalError> {
        if !draft.live() {
            return Err(unavailable("proposal snapshot was revoked"));
        }
        let context = draft.context();
        let rules = self
            .bundle_rules(
                context.parent(),
                context.header(),
                &context.authority().receipts,
            )
            .map_err(unavailable)?;
        let roots = self
            .ready_roots(context.parent(), context.rules(), &inputs)
            .await
            .map_err(unavailable)?;
        let host = self.clone();
        run_worker(self.worker.clone(), move || {
            Ok(host.build(draft, &inputs, &rules, &roots))
        })
        .await
        .map_err(unavailable)?
    }

    fn build(
        &self,
        draft: Arc<Draft>,
        inputs: &[Transaction],
        rules: &Rules,
        roots: &BTreeMap<i64, Option<Vec<u8>>>,
    ) -> Result<Built, ProposalError> {
        if !draft.live() {
            return Err(unavailable("proposal snapshot was revoked"));
        }
        let context = draft.context();
        let parent = context.parent();
        let header = context.header();
        let ledger = account_store::ledger(&StateBatch::from_snapshot(draft.state().clone()))
            .map_err(unavailable)?;
        let mut bundle = Accepted {
            tx_hashes: vec![],
            txs: inputs.to_vec(),
            receipts_json: vec![],
            rejections: vec![],
        };
        admission::check(
            &self.config.profile,
            &self.config.bundle,
            rules,
            &bundle,
            &ledger,
        )
        .map_err(invalid)?;
        for tx in inputs {
            octra_node_protocol::transaction_payload::admit(rules.payload, tx).map_err(invalid)?;
        }
        let local = self.proposal_proofs(parent, draft.state(), context.rules(), inputs, rules)?;
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
            context.parent_commit(),
        )
        .map_err(unavailable)?;
        let capture = |txs: &[Transaction]| {
            let gate = Gate {
                receipts: proofs::select(&local, txs)?,
            };
            self.stage(
                Stage {
                    parent,
                    state: StateBatch::from_snapshot(draft.state().clone()),
                    header,
                    context: context.rules(),
                    rules,
                    validators: &context.authority().validators,
                    reward: &reward,
                    transactions: txs,
                    gate: &gate,
                    capture: true,
                },
                roots,
            )
        };
        let mut recovery = Capture {
            draft: &draft,
            capture,
            refused: vec![],
            held: vec![],
        };
        let stable = proposal_build::build(&mut recovery, inputs).map_err(unavailable)?;
        let refused = recovery.refused;
        let held = recovery.held;
        bundle.txs = stable.confirmed;
        bundle.rejections = stable.rejections;
        let staged = stable.value;
        // The last preview contains only confirmed/charged effects. Verify its
        // partition before allowing any locally built commitments to escape.
        Partition::finalized(&bundle.txs, &bundle.rejections, rules.envelope)
            .map_err(unavailable)?
            .verify(Ok(&staged.artifacts))
            .map_err(unavailable)?;
        let receipts = proofs::select(&staged.gate.receipts, &bundle.txs)
            .map_err(unavailable)?
            .iter()
            .map(Receipt::canonical)
            .collect::<Vec<_>>();
        bundle.receipts_json =
            transaction_outcome::encode(&receipts, &bundle.rejections).map_err(unavailable)?;
        bundle.tx_hashes = bundle
            .txs
            .iter()
            .map(|tx| tx.hash().map(|h| hex::encode(h).into_bytes()))
            .collect::<Result<_, _>>()
            .map_err(unavailable)?;
        let mut header = header.clone();
        header.tx_list_hash = tx_list_hash_for_header(&bundle.tx_hashes).to_vec();
        header.receipt_root = hash::receipt_root(&bundle.receipts_json)
            .map_err(unavailable)?
            .to_vec();
        header.proposed_state_root = canonical::execution_root(
            parent,
            header.epoch_id as u64,
            &staged.state,
            &staged.transactions,
        )
        .map_err(unavailable)?
        .0
        .to_vec();
        header.txid_hi = parent
            .txid_hi
            .checked_add(i64::try_from(staged.transactions.len()).map_err(unavailable)?)
            .ok_or_else(|| unavailable("transaction index exhausted"))?;
        let raw = bundle.to_raw().map_err(unavailable)?;
        // Keep the admission path bidirectional: a locally built bundle must
        // satisfy the same structural/receipt commitments as an imported one.
        octra_node_runtime::consensus_bundle::finalized(&header, &raw, rules)
            .map_err(unavailable)?;
        let plan = ProposalPlan {
            header,
            tx_hashes: raw.tx_hashes.clone(),
            parent_commit: context.parent_commit().cloned(),
        };
        let execution = ExecutedEpoch {
            state: staged.state,
            transactions: staged.transactions,
            consensus_receipts: raw.receipts_json.clone(),
            reward_source: reward_attribution::to_source(&reward).map_err(unavailable)?,
            date: plan.header.epoch_id,
            message: b"built proposal".to_vec(),
        };
        if !draft.live() {
            return Err(unavailable("proposal snapshot was revoked"));
        }
        Ok(Built {
            draft,
            plan,
            bundle: raw,
            execution,
            refused,
            held,
        })
    }
}

struct Capture<'a, F> {
    draft: &'a Draft,
    capture: F,
    refused: Vec<Transaction>,
    held: Vec<Transaction>,
}
impl<F: FnMut(&[Transaction]) -> anyhow::Result<Staged>> Host for Capture<'_, F> {
    type Value = Staged;
    fn current(&self) -> bool {
        self.draft.live()
    }
    fn select(
        &mut self,
        inputs: &[Transaction],
    ) -> Result<Selection, octra_node_runtime::execution::Error> {
        // This API receives an already admitted/selected batch. The staging
        // host supplies queue shaping and refill for the general runtime API.
        Ok(Selection {
            inputs: inputs.to_vec(),
            selected: inputs.to_vec(),
        })
    }
    fn preview(&mut self, inputs: &[Transaction]) -> Result<Preview<Staged>, Failure> {
        let staged = (self.capture)(inputs)
            .map_err(|e| Failure::Failed(octra_node_runtime::execution::Error(e.to_string())))?;
        Ok(Preview {
            artifacts: staged.artifacts.clone(),
            value: staged,
        })
    }
    fn refuse(&mut self, tx: &Transaction) {
        self.refused.push(tx.clone());
    }
    fn hold(&mut self, tx: &Transaction) {
        self.held.push(tx.clone());
    }
}
