// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Epoch-bound validator rules, finalized duty and scheduled membership.
mod advance;
mod context;
use crate::{execution::Error, state_batch::StateBatch, validator_transaction::EpochFold};
pub use advance::{advance, Advanced, Request};
pub use context::Fold;
use octra_node_protocol::{
    consensus::ParentCommit,
    rules::{Graph, RootRead, Rule},
    transaction::RuleMode,
    validator::set_fold::{self, CapMode},
};
use std::sync::Arc;
pub const CONSENSUS_ID: &str = "set_fold:standard_then_participating";
/// Native Set_rule.bind: every transaction sees one authenticated epoch context.
#[derive(Clone)]
pub struct BoundFold {
    epoch: i64,
    context: Arc<Fold>,
}
impl EpochFold for BoundFold {
    fn resolve(&self, epoch: i64, _state: &StateBatch) -> Result<Arc<Fold>, Error> {
        if epoch == self.epoch {
            Ok(self.context.clone())
        } else {
            Err(Error("validator set fold epoch mismatch".into()))
        }
    }
}
impl BoundFold {
    pub fn context(&self) -> &Fold {
        &self.context
    }
    /// Parent selection and legacy active membership come from canonical history.
    pub fn bind(
        graph: &Graph,
        chain: &[u8],
        epoch: i64,
        parent: Option<ParentCommit>,
        legacy: &[Vec<u8>],
        root_at: &impl Fn(i64) -> RootRead,
    ) -> Result<Self, Error> {
        let mut ctx = Fold::prior();
        let mode = |rule| {
            graph
                .mode(rule, epoch, root_at)
                .map_err(|e| Error(e.to_string()))
        };
        // Native policy faults precede a duty-rule fault. Keep validation order.
        let fold = mode(Rule::SetFold);
        mode(Rule::TxEnvelope)?;
        ctx.exit_mode = mode(Rule::Exit)?;
        ctx.ready_exec_mode = mode(Rule::ReadyExecution)?;
        ctx.program_mode = mode(Rule::ProgramSource)?;
        ctx.program_overlap = graph
            .program_overlap(epoch, root_at)
            .map_err(|e| Error(e.to_string()))?;
        ctx.fhe_work = mode(Rule::FheWork)?;
        ctx.proof_exec = mode(Rule::ProofExecution)?;
        ctx.vm_bytes = mode(Rule::VmBytes)?;
        ctx.wasm_float = mode(Rule::WasmFloat)?;
        ctx.math = mode(Rule::Math)? == RuleMode::Active;
        ctx.ready_mode = mode(Rule::ValidatorReady)?;
        ctx.ready_ref_mode = mode(Rule::ReadyReference)?;
        ctx.live_mode = mode(Rule::LiveSet)?;
        ctx.seat_mode = mode(Rule::SeatCap)?;
        ctx.open_mode = mode(Rule::OpenSet)?;
        ctx.account_mode = mode(Rule::AccountPack)?;
        ctx.standard_mode = mode(Rule::Standard)?;
        ctx.plan_mode = mode(Rule::SetPlan)?;
        ctx.cap_mode = if ctx.seat_mode == RuleMode::Active {
            CapMode::Prune
        } else {
            CapMode::Reject
        };
        ctx.mode = fold?;
        ctx.ready_config_hash = graph.ready_config_hash().map(<[u8]>::to_vec);
        ctx.start = graph
            .activation(Rule::SetFold)
            .map_or(0, |v| v.activation_epoch);
        ctx.profile_start = graph
            .activation(Rule::Standard)
            .map_or(ctx.start, |v| v.activation_epoch);
        if ctx.mode == RuleMode::Active {
            ctx.members = set_fold::read_parent(
                chain,
                parent
                    .as_ref()
                    .ok_or_else(|| Error("validator set fold parent commit missing".into()))?,
            )
            .map_err(|e| Error(e.to_string()))?
            .active;
        }
        ctx.parent = parent;
        ctx.active_addresses = if ctx.standard_mode == RuleMode::Prior {
            legacy.to_vec()
        } else {
            ctx.members.clone()
        };
        Ok(Self {
            epoch,
            context: Arc::new(ctx),
        })
    }
}
