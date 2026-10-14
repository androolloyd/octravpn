//! One historical rule context for a speculative epoch. Startup configuration
//! supplies the graph; finalized history supplies anchors and parent membership.
use crate::{
    canonical::Head,
    circle::{WasmProfile, WasmRules},
    circle_transaction,
    execution::Error,
    finality::{history::History, EpochRules, ReceiptRules},
    validator_epoch::BoundFold,
};
use octra_node_protocol::{
    consensus::{EpochHeader, Finalize, ParentCommit, ValidatorSet},
    rules::{Graph, RootRead, Rule},
    transaction::RuleMode,
};
use std::{cell::RefCell, collections::BTreeMap};

pub struct Bound {
    pub circle: circle_transaction::Rules,
    pub object_cost: bool,
    pub owner_migration: RuleMode,
    pub cipher_migration: RuleMode,
    pub private_payload: RuleMode,
    pub fold: BoundFold,
    authority: Option<Authority>,
}
/// The membership and receipt policy used to authenticate this execution's
/// certificate. Captured by the publisher, never resolved again by execution.
pub struct Authority {
    pub validators: ValidatorSet,
    pub receipts: ReceiptRules,
}
impl Bound {
    pub fn authority(&self) -> Result<&Authority, Error> {
        self.authority
            .as_ref()
            .ok_or_else(|| Error("execution authority was not authenticated".into()))
    }
    pub(crate) fn capture(mut self, rules: &EpochRules) -> Self {
        self.authority = Some(Authority {
            validators: rules.validators.clone(),
            receipts: rules.receipts.clone(),
        });
        self
    }
    /// Consensus_proposal_preview_shell resolves these policies before opening
    /// State_preview. Preserve its fault priority, including policy fields that
    /// the public WASM path does not itself consume.
    pub fn resolve(
        graph: &Graph,
        epoch: i64,
        parent: Option<ParentCommit>,
        legacy: &[Vec<u8>],
        root_at: &impl Fn(i64) -> RootRead,
    ) -> Result<Self, Error> {
        let mode = |rule| {
            graph
                .mode(rule, epoch, root_at)
                .map_err(|e| Error(e.to_string()))
        };
        let circle = mode(Rule::Circle)?;
        let compute = mode(Rule::WasmCompute)?;
        let object_cost = mode(Rule::ObjectCost);
        let owner_migration = mode(Rule::OwnerMigration);
        let cipher_migration = mode(Rule::CipherMigration);
        let object_cost = object_cost? == RuleMode::Active;
        let owner_migration = owner_migration?;
        let cipher_migration = cipher_migration?;
        let private_payload = mode(Rule::PrivatePayload)?;
        let fold = BoundFold::bind(graph, graph.chain_id(), epoch, parent, legacy, root_at)?;
        let ctx = fold.context();
        Ok(Self {
            circle: circle_transaction::Rules {
                wasm: WasmRules {
                    math: ctx.math,
                    proof_exec: ctx.proof_exec == RuleMode::Active,
                    wasm_float: ctx.wasm_float == RuleMode::Active,
                },
                manifest: if compute == RuleMode::Active {
                    WasmProfile::Manifest
                } else {
                    WasmProfile::Compute
                },
                update_policy: circle == RuleMode::Active,
                inspect: ctx.vm_bytes == RuleMode::Active,
                storage_proof: ctx.standard_mode == RuleMode::Active,
                fhe_work: ctx.fhe_work == RuleMode::Active,
            },
            object_cost,
            owner_migration,
            cipher_migration,
            private_payload,
            fold,
            authority: None,
        })
    }

    /// Use only after authenticating the certificate. Anchor reads are limited
    /// to this parent, and its consensus root must belong to the same retained
    /// history. Concurrent advancement cannot change this immutable prefix.
    pub async fn canonical(
        graph: &Graph,
        parent: &Head,
        finalized: &Finalize,
        legacy: &[Vec<u8>],
        history: &dyn History,
    ) -> Result<Self, Error> {
        let header = &finalized.header;
        if finalized.chain_id != header.chain_id || finalized.epoch_id != header.epoch_id {
            return Err(Error(
                "execution rule context differs from canonical parent".into(),
            ));
        }
        Self::canonical_header(
            graph,
            parent,
            header,
            finalized.parent_commit.clone(),
            legacy,
            history,
        )
        .await
    }

    /// A proposal has authenticated framing but no finality authority. Keep
    /// its historical rule binding separate from certificate authentication.
    pub(crate) async fn canonical_header(
        graph: &Graph,
        parent: &Head,
        header: &EpochHeader,
        parent_commit: Option<ParentCommit>,
        legacy: &[Vec<u8>],
        history: &dyn History,
    ) -> Result<Self, Error> {
        if header.chain_id != graph.chain_id()
            || parent.cursor.epoch.0.checked_add(1) != u64::try_from(header.epoch_id).ok()
            || header.epoch_id >= 1_i64 << 62
            || header.prev_state_root != parent.cursor.state_root.0
        {
            return Err(Error(
                "execution rule context differs from canonical parent".into(),
            ));
        }
        let parent_epoch = i64::try_from(parent.cursor.epoch.0)
            .map_err(|_| Error("execution parent epoch exceeds limit".into()))?;
        let root = history
            .root(parent_epoch)
            .await
            .map_err(|e| Error(e.to_string()))?;
        if root.as_deref() != Some(parent.cursor.state_root.0.as_slice()) {
            return Err(Error(
                "execution rule history differs from canonical parent".into(),
            ));
        }
        Self::anchored(
            graph,
            header.epoch_id,
            parent.cursor.epoch.0,
            parent_commit,
            legacy,
            history,
        )
        .await
    }

    async fn anchored(
        graph: &Graph,
        epoch: i64,
        captured: u64,
        parent: Option<ParentCommit>,
        legacy: &[Vec<u8>],
        history: &dyn History,
    ) -> Result<Self, Error> {
        let mut roots = BTreeMap::new();
        loop {
            // Bind is synchronous. Discover only the roots actually requested
            // by that native path, then retry with each authenticated result.
            // Missing/unreadable results are cached too; they are never retried
            // into a successful context during the same execution attempt.
            let pending = RefCell::new(Vec::new());
            let result = Self::resolve(graph, epoch, parent.clone(), legacy, &|height| {
                roots.get(&height).cloned().unwrap_or_else(|| {
                    if !pending.borrow().contains(&height) {
                        pending.borrow_mut().push(height);
                    }
                    RootRead::Missing
                })
            });
            let Some(height) = pending.into_inner().into_iter().next() else {
                return result;
            };
            let read = if u64::try_from(height).is_ok_and(|e| e <= captured) {
                match history.root(height).await {
                    Ok(Some(bytes)) => RootRead::Root(hex::encode(bytes).into_bytes()),
                    Ok(None) => RootRead::Missing,
                    Err(e) => RootRead::Unreadable(e.to_string().into_bytes()),
                }
            } else {
                RootRead::Missing
            };
            roots.insert(height, read);
        }
    }
}
