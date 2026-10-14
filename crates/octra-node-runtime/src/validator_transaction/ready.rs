// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{checked, load, rejected, save, set, EpochFold, Failure, Fold, Host};
use crate::state_batch::StateBatch;
use num_traits::Zero;
use octra_node_protocol::{
    control_payload::{BondedReady, LegacyReady, ValidatorUpdate},
    duty,
    state::Ledger,
    transaction::{RuleMode, Transaction},
    validator::{
        policy::Policy,
        ready,
        set_fold::{self, Proof, State},
        update,
    },
};
/// Historical roots are read from the caller's canonical snapshot.
pub struct ReadyEnvironment<'a> {
    pub prev_state_root: &'a [u8],
    pub max_lag: i64,
    pub root_at: Option<&'a dyn Fn(i64) -> Option<Vec<u8>>>,
}
fn word(v: i64) -> i64 {
    (v << 1) >> 1
}
fn normalized(v: &[u8]) -> Vec<u8> {
    match v.len() {
        32 => hex::encode(v).into_bytes(),
        n if n >= 64 => v[..64].to_vec(),
        _ => v.to_vec(),
    }
}
fn load_fold(state: &StateBatch) -> Result<State, Failure> {
    match state.get(&[b"meta", set_fold::META_KEY]) {
        None => Ok(State::default()),
        Some(v) => checked("validator_ready_rejected", State::from_bytes(v)),
    }
}
impl<F: EpochFold> Host<'_, F> {
    fn reference(
        &self,
        ctx: &Fold,
        state: &State,
        head: i64,
        proposal: Option<&[u8]>,
        root: &[u8],
    ) -> Result<(), Failure> {
        const TAG: &str = "validator_ready_rejected";
        if ctx.ready_exec_mode == RuleMode::Active {
            return checked(
                TAG,
                ready::reference(self.epoch, head, proposal, ctx.parent.as_ref(), state),
            );
        }
        let current = word(self.epoch.wrapping_sub(1));
        let head = word(head);
        if head > current {
            return Err(rejected(TAG, "head_epoch is in the future"));
        }
        if self.ready.max_lag >= 0 && word(current.wrapping_sub(head)) > self.ready.max_lag {
            return Err(rejected(TAG, "head_epoch too stale"));
        }
        let expected = match self.ready.root_at {
            Some(lookup) => lookup(head),
            None => (head == current).then(|| self.ready.prev_state_root.to_vec()),
        }
        .ok_or_else(|| rejected(TAG, "state_root reference unavailable"))?;
        if normalized(root) != normalized(&expected) {
            return Err(rejected(
                TAG,
                "state_root does not match referenced chain head",
            ));
        }
        Ok(())
    }
    fn ready_policy(&self, ctx: &Fold, payload: &BondedReady) -> Result<(), Failure> {
        const TAG: &str = "validator_ready_rejected";
        if ctx.ready_mode == RuleMode::Prior {
            return Ok(());
        }
        let config = ctx
            .ready_config_hash
            .as_deref()
            .ok_or_else(|| rejected(TAG, "validator ready config hash missing"))?;
        if ctx.ready_ref_mode == RuleMode::Active
            && ctx.ready_exec_mode == RuleMode::Prior
            && payload.head_epoch != word(self.epoch.wrapping_sub(1))
        {
            return Err(rejected(TAG, "head_epoch mismatch"));
        }
        checked(
            TAG,
            ready::validate(
                self.chain,
                config,
                payload.head_epoch,
                &payload.extra,
                ctx.ready_ref_mode == RuleMode::Prior,
            ),
        )
    }
    fn update_ready(
        &self,
        state: &StateBatch,
        head: i64,
        address: &[u8],
        proof: Option<&Proof>,
    ) -> Result<Option<State>, Failure> {
        let ctx = self.resolve(state)?;
        if ctx.mode == RuleMode::Prior {
            return Ok(None);
        }
        let state = load_fold(state)?;
        let cfg = ctx.config();
        let active = ctx.members.iter().any(|m| m == address);
        checked(
            "validator_ready_rejected",
            match proof {
                Some(proof) => state.apply_proof(
                    &cfg,
                    ctx.cap_mode,
                    self.chain,
                    self.epoch,
                    active,
                    address,
                    proof,
                ),
                None => state.note_pulse(
                    &cfg,
                    ctx.cap_mode,
                    (ctx.ready_exec_mode == RuleMode::Active).then(|| head.wrapping_add(1)),
                    self.epoch,
                    active,
                    address,
                ),
            },
        )
        .map(Some)
    }
    fn bonded_ready(
        &self,
        ctx: &Fold,
        payload: &BondedReady,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<(), Failure> {
        const TAG: &str = "validator_ready_rejected";
        if tx.from != tx.to {
            return Err(rejected(
                TAG,
                "bonded validator readiness must be self-directed",
            ));
        }
        let proof = if ctx.mode == RuleMode::Prior {
            None
        } else {
            checked(TAG, duty::proof_of_message(tx.message.as_deref()))?
        };
        if proof.as_ref().is_some_and(|p| p.vote.validator != tx.from) {
            return Err(rejected(TAG, "validator set fold proof owner mismatch"));
        }
        let reference = if ctx.ready_exec_mode == RuleMode::Prior {
            State::default()
        } else {
            load_fold(state)?
        };
        self.reference(
            ctx,
            &reference,
            payload.head_epoch,
            payload.head_proposal_id.as_deref(),
            &payload.state_root,
        )?;
        self.ready_policy(ctx, payload)?;
        let prior = load(state)?;
        let marked = checked(
            TAG,
            prior.mark_ready(self.epoch, &tx.from, &payload.consensus_public_key),
        )?;
        let fold = self.update_ready(state, payload.head_epoch, &tx.from, proof.as_ref())?;
        let mode = if ctx.standard_mode == RuleMode::Prior {
            ctx.ready_ref_mode
        } else {
            ctx.live_mode
        };
        let next = if mode == RuleMode::Active
            && fold
                .as_ref()
                .is_some_and(|s| !s.allows(&ctx.config(), ctx.start(), self.epoch, &tx.from))
        {
            prior
        } else {
            marked
        };
        checked(
            "insufficient_balance",
            ledger.debit(&tx.from, &tx.ou, tx.nonce, None),
        )?;
        save(state, &next)?;
        if let Some(fold) = fold {
            set(state, set_fold::META_KEY, fold.to_bytes())?;
        }
        Ok(())
    }
    fn legacy_ready(
        &self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<(), Failure> {
        const TAG: &str = "validator_ready_rejected";
        let payload = checked(
            "malformed_transaction",
            LegacyReady::parse(tx.message.as_deref()),
        )?;
        let pending = state
            .get(&[b"meta", update::PENDING_KEY])
            .ok_or_else(|| rejected(TAG, "no pending validator set update"))?;
        let pending = checked(TAG, ValidatorUpdate::parse(Some(pending)))?;
        if !pending.validators.iter().any(|v| v.address == tx.from) {
            return Err(rejected(TAG, "sender is not in pending validator set"));
        }
        if payload.fingerprint != pending.fingerprint.as_bytes() {
            return Err(rejected(
                TAG,
                "fingerprint does not match pending validator set",
            ));
        }
        let ctx = self.resolve(state)?;
        self.reference(
            &ctx,
            &State::default(),
            payload.head_epoch,
            None,
            &payload.state_root,
        )?;
        checked(
            "insufficient_balance",
            ledger.debit(&tx.from, &tx.ou, tx.nonce, None),
        )?;
        set(
            state,
            &update::ready_key(pending.fingerprint.as_bytes(), &tx.from),
            payload.to_bytes(),
        )
    }
    pub(super) fn ready_transaction(
        &self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
    ) -> Result<(), Failure> {
        if !tx.amount.is_zero() {
            return Err(rejected("validator_ready_rejected", "amount must be zero"));
        }
        if matches!(self.policy, Policy::Inactive) {
            return self.legacy_ready(tx, ledger, state);
        }
        let ctx = self.resolve(state)?;
        match BondedReady::parse(tx.message.as_deref()) {
            Ok(payload) => self.bonded_ready(&ctx, &payload, tx, ledger, state),
            Err(_) if ctx.ready_mode == RuleMode::Prior => self.legacy_ready(tx, ledger, state),
            Err(e) => Err(rejected("validator_ready_rejected", e)),
        }
    }
}
