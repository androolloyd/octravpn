//! Construct commitments from local execution of selected staging candidates.
//! Queue ownership and round freezing belong to the driver host.
use super::{
    admission, proofs,
    proposal::{invalid, unavailable},
    run_worker,
    stage::{Stage, Staged},
    Native, Pending, ProposalError,
};
use crate::proposal::Draft;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{engine::tx_list_hash_for_header, hash, reward_attribution},
    preverify_commit::Gate,
    preverify_receipt::Receipt,
    transaction::{RuleMode, Transaction},
    transaction_outcome,
};
use octra_node_runtime::{
    account_store, canonical,
    consensus_bundle::{Accepted, RawBundle, Rules},
    consensus_driver::ProposalPlan,
    epoch_partition::Partition,
    finality::ExecutedEpoch,
    proposal_build::{self, Failure, Host, Preview, Selection},
    proposal_select,
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
    pub fn draft_rules(&self, draft: &Draft) -> anyhow::Result<Rules> {
        let context = draft.context();
        self.bundle_rules(
            context.parent(),
            context.header(),
            &context.authority().receipts,
        )
    }
    /// Execute a selected staging batch and derive its native header, receipts
    /// and outcome partition, using native bounded replay for changing outcomes.
    /// Unavailable proofs defer construction; no fallback root is used.
    pub async fn build_proposal(
        &self,
        draft: Arc<Draft>,
        inputs: Vec<Transaction>,
    ) -> Result<Built, ProposalError> {
        self.start_build(draft, inputs, None).await
    }

    /// Select nonce-ready work from the native queue and apply epoch-bound
    /// preview refusals/holds. Capacity and stealth slots are startup limits.
    pub async fn build_pending(
        &self,
        draft: Arc<Draft>,
        queue: Arc<Pending>,
        capacity: num_bigint::BigInt,
        stealth: usize,
    ) -> Result<Built, ProposalError> {
        let context = draft.context();
        let rules = self
            .bundle_rules(
                context.parent(),
                context.header(),
                &context.authority().receipts,
            )
            .map_err(unavailable)?;
        let captured = draft.clone();
        let selected = queue.clone();
        let (inputs, ordinary) = run_worker(self.worker.clone(), move || {
            selected.capture(&captured, &rules, &capacity)
        })
        .await
        .map_err(unavailable)?;
        let previous = self.previous_circle(&draft).await.map_err(unavailable)?;
        self.start_build(
            draft,
            inputs,
            Some(PendingBuild {
                queue,
                ordinary: Some(ordinary),
                previous,
                stealth,
            }),
        )
        .await
    }

    async fn start_build(
        &self,
        draft: Arc<Draft>,
        inputs: Vec<Transaction>,
        pending: Option<PendingBuild>,
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
            Ok(host.build(draft, &inputs, &rules, &roots, pending))
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
        pending: Option<PendingBuild>,
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
        let local = if pending.is_none() {
            admission::check(
                &self.config.profile,
                &self.config.bundle,
                rules,
                &bundle,
                &ledger,
            )
            .map_err(invalid)?;
            for tx in inputs {
                octra_node_protocol::transaction_payload::admit(rules.payload, tx)
                    .map_err(invalid)?;
            }
            self.proposal_proofs(parent, draft.state(), context.rules(), inputs, rules)?
        } else {
            vec![]
        };
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
        let mut recovery = Capture {
            executor: self,
            draft: &draft,
            rules,
            roots,
            reward: &reward,
            pending,
            receipts: local,
            refused: vec![],
            held: vec![],
        };
        let stable = proposal_build::build(&mut recovery, inputs).map_err(unavailable)?;
        let refused = recovery.refused;
        let held = recovery.held;
        bundle.txs = stable.confirmed;
        bundle.rejections = stable.rejections;
        let (preview_inputs, staged) = stable.value;
        // The last preview contains only confirmed/charged effects. Verify its
        // partition before allowing any locally built commitments to escape.
        Partition::finalized(&bundle.txs, &bundle.rejections, rules.envelope)
            .map_err(unavailable)?
            .verify_input_order(&preview_inputs, &staged.artifacts)
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
            epoch_observation: Some(staged.epoch_observation),
            metrics: staged.metrics,
            state: staged.state,
            transactions: staged.transactions,
            vm_receipts: staged.vm_receipts,
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

struct PendingBuild {
    queue: Arc<Pending>,
    ordinary: Option<Vec<Transaction>>,
    previous: Option<bool>,
    stealth: usize,
}
struct Capture<'a> {
    executor: &'a Native,
    draft: &'a Draft,
    rules: &'a Rules,
    roots: &'a BTreeMap<i64, Option<Vec<u8>>>,
    reward: &'a octra_node_protocol::epoch_rewards::Attribution,
    pending: Option<PendingBuild>,
    receipts: Vec<Receipt>,
    refused: Vec<Transaction>,
    held: Vec<Transaction>,
}
fn execution_error(e: impl std::fmt::Display) -> octra_node_runtime::execution::Error {
    octra_node_runtime::execution::Error(e.to_string())
}
impl Host for Capture<'_> {
    type Value = (Vec<Transaction>, Staged);
    fn current(&self) -> bool {
        self.draft.live()
    }
    fn select(
        &mut self,
        inputs: &[Transaction],
    ) -> Result<Selection, octra_node_runtime::execution::Error> {
        let Some(pending) = &mut self.pending else {
            return Ok(Selection {
                inputs: inputs.to_vec(),
                selected: inputs.to_vec(),
            });
        };
        let ordinary = pending
            .ordinary
            .take()
            .unwrap_or_else(|| proposal_select::without(inputs));
        let admits = |tx: &&Transaction| self.executor.admits_pending(self.draft, self.rules, tx);
        let ordinary = ordinary.iter().filter(admits).cloned().collect::<Vec<_>>();
        let mut inputs = inputs.iter().filter(admits).cloned().collect::<Vec<_>>();
        let context = self.draft.context();
        if context.rules().fold.context().ready_exec_mode == RuleMode::Active
            && inputs
                .iter()
                .any(|tx| octra_node_runtime::preverify_batch::snapshot_transition(tx.op_type))
        {
            inputs = proposal_select::turn(
                true,
                context.header().epoch_id,
                pending.previous,
                &ordinary,
                &inputs,
            );
        }
        let batch = self
            .executor
            .prepare_proofs(
                context.parent(),
                self.draft.state(),
                context.rules(),
                &inputs,
                self.rules,
            )
            .map_err(execution_error)?;
        let ready = batch
            .ready
            .iter()
            .map(|r| inputs[r.index].clone())
            .collect::<Vec<_>>();
        let ready = if self.rules.envelope.envelope == RuleMode::Active {
            proposal_select::Slots::new(self.executor.config.max_fhe, pending.stealth)
                .select(&inputs, &ready)?
        } else {
            ready
        };
        let selected = self
            .executor
            .config
            .bundle
            .cap(&ready, &self.rules.stealth_minimum)?;
        let canonical = transaction_outcome::executed(&selected, &[]).map_err(execution_error)?;
        let ledger = account_store::ledger(&StateBatch::from_snapshot(self.draft.state().clone()))
            .map_err(execution_error)?;
        let bundle = Accepted {
            tx_hashes: vec![],
            txs: canonical,
            receipts_json: vec![],
            rejections: vec![],
        };
        admission::check(
            &self.executor.config.profile,
            &self.executor.config.bundle,
            self.rules,
            &bundle,
            &ledger,
        )
        .map_err(execution_error)?;
        for tx in &selected {
            octra_node_protocol::transaction_payload::admit(self.rules.payload, tx)
                .map_err(execution_error)?;
        }
        self.receipts = batch.ready.into_iter().filter_map(|r| r.receipt).collect();
        Ok(Selection { inputs, selected })
    }
    fn preview(&mut self, inputs: &[Transaction]) -> Result<Preview<Self::Value>, Failure> {
        let context = self.draft.context();
        let gate = Gate {
            receipts: proofs::select(&self.receipts, inputs).map_err(execution_error)?,
        };
        let staged = self
            .executor
            .stage(
                Stage {
                    parent: context.parent(),
                    state: StateBatch::from_snapshot(self.draft.state().clone()),
                    header: context.header(),
                    context: context.rules(),
                    rules: self.rules,
                    validators: &context.authority().validators,
                    reward: self.reward,
                    transactions: inputs,
                    gate: &gate,
                    capture: true,
                },
                self.roots,
            )
            .map_err(execution_error)?;
        Ok(Preview {
            artifacts: staged.artifacts.clone(),
            value: (inputs.to_vec(), staged),
        })
    }
    fn refuse(&mut self, tx: &Transaction) -> Result<(), octra_node_runtime::execution::Error> {
        if let Some(pending) = &self.pending {
            pending
                .queue
                .refuse(self.draft, tx)
                .map_err(execution_error)?;
        }
        self.refused.push(tx.clone());
        Ok(())
    }
    fn hold(&mut self, tx: &Transaction) -> Result<(), octra_node_runtime::execution::Error> {
        if let Some(pending) = &self.pending {
            pending
                .queue
                .hold(self.draft, tx)
                .map_err(execution_error)?;
        }
        self.held.push(tx.clone());
        Ok(())
    }
}
