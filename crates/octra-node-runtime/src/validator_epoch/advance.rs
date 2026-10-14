// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::Fold;
use crate::{
    compute_roots,
    execution::Error,
    state_batch::{Snapshot, StateBatch},
    validator_transaction::EpochFold,
};
use octra_node_protocol::{
    control_payload::ValidatorUpdate,
    transaction::RuleMode,
    validator::{
        admission,
        policy::{Active, Policy},
        registry::{self, Registry},
        set_fold::{self, State},
        update,
    },
};
pub struct Request<'a> {
    pub chain: &'a [u8],
    pub epoch: i64,
    pub policy: &'a Policy,
    pub legacy_members: &'a [Vec<u8>],
    pub previous_root: &'a [u8],
    pub committed_head: Option<&'a Snapshot>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Advanced {
    pub delayed: Option<String>,
    pub promoted: Option<Vec<Vec<u8>>>,
    pub scheduled: Option<ValidatorUpdate>,
    pub insufficient_members: bool,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn tagged<T>(tag: &str, value: Result<T, impl std::fmt::Display>) -> Result<T, Error> {
    value.map_err(|e| error(format!("{tag}: {e}")))
}
fn load(state: &StateBatch) -> Result<State, Error> {
    state.get(&[b"meta", set_fold::META_KEY]).map_or_else(
        || Ok(State::default()),
        |raw| tagged("validator set fold state corrupt", State::from_bytes(raw)),
    )
}
fn save(state: &mut StateBatch, fold: &State) -> Result<(), Error> {
    set(state, set_fold::META_KEY, fold.to_bytes())
}
fn set(state: &mut StateBatch, key: &[u8], value: Vec<u8>) -> Result<(), Error> {
    state.set(&[b"meta", key], value).map_err(error)
}
fn pending(state: &StateBatch) -> Result<Option<ValidatorUpdate>, Error> {
    state
        .get(&[b"meta", update::PENDING_KEY])
        .map(|raw| {
            tagged(
                "pending validator set corrupt",
                ValidatorUpdate::parse(Some(raw)),
            )
        })
        .transpose()
}
fn promote(epoch: i64, state: &mut StateBatch) -> Result<Option<Vec<Vec<u8>>>, Error> {
    match pending(state)? {
        Some(p) if p.weighted && p.activate_epoch <= epoch => {
            // Preserve the exact stored bytes, including native accepted field order.
            let raw = state
                .get(&[b"meta", update::PENDING_KEY])
                .expect("loaded pending set")
                .to_vec();
            set(state, update::ACTIVE_KEY, raw)?;
            Ok(Some(p.validators.into_iter().map(|v| v.address).collect()))
        }
        _ => Ok(None),
    }
}
struct SnapshotInput {
    parameters: admission::Parameters,
    candidates: Vec<admission::Candidate>,
    incumbents: Vec<Vec<u8>>,
}
fn fold_input(
    ctx: &Fold,
    request: &Request<'_>,
    policy: &Active,
    registry: &Registry,
    promoted: Option<&[Vec<u8>]>,
    state: &mut StateBatch,
) -> Result<SnapshotInput, Error> {
    if ctx.mode == RuleMode::Prior {
        return Ok(SnapshotInput {
            parameters: policy.parameters.clone(),
            candidates: registry.candidates().to_vec(),
            incumbents: vec![],
        });
    }
    let active = if ctx.live_mode == RuleMode::Prior {
        request.legacy_members
    } else {
        promoted.unwrap_or(request.legacy_members)
    };
    let cfg = ctx.config();
    let mut fold = load(state)?;
    if ctx.live_mode == RuleMode::Active {
        let next = tagged(
            "validator set fold active set rejected",
            fold.note_set(&cfg, request.epoch, active),
        )?;
        if next != fold {
            save(state, &next)?;
        }
        fold = next;
    }
    let (candidates, _) = fold.filter(&cfg, ctx.start(), request.epoch, registry.candidates());
    let (max_validators, incumbents) = if ctx.seat_mode == RuleMode::Prior {
        (cfg.max_members, vec![])
    } else {
        let seats = fold
            .seats()
            .ok_or_else(|| error("validator seat limit is missing"))?;
        if ctx.open_mode == RuleMode::Prior {
            (seats, active.to_vec())
        } else {
            (cfg.max_members, vec![])
        }
    };
    let activation_delay = if ctx.standard_mode == RuleMode::Prior {
        policy.parameters.activation_delay
    } else {
        cfg.delay
    };
    Ok(SnapshotInput {
        parameters: admission::Parameters {
            max_validators,
            activation_delay,
            ..policy.parameters.clone()
        },
        candidates,
        incumbents,
    })
}
fn inner(
    request: &Request<'_>,
    resolver: &impl EpochFold,
    state: &mut StateBatch,
) -> Result<Advanced, Error> {
    let resolve = |s: &StateBatch| {
        tagged(
            "validator set fold rule rejected",
            resolver.resolve(request.epoch, s),
        )
    };
    let ctx = resolve(state)?;
    let parent = resolve(state)?;
    if let (RuleMode::Active, Some(parent)) = (ctx.vm_bytes, parent.parent.as_ref()) {
        compute_roots::remember(
            state,
            request.committed_head,
            request.epoch,
            request.previous_root,
            parent,
        )?;
    }
    let ctx = resolve(state)?;
    let mut result = Advanced::default();
    if ctx.mode == RuleMode::Active {
        let cfg = ctx.config();
        let (mut next, reason, changed) = tagged(
            "validator set fold update rejected",
            load(state)?.advance(
                &cfg,
                ctx.cap_mode,
                request.chain,
                ctx.start(),
                request.epoch,
                ctx.parent.as_ref(),
            ),
        )?;
        let locked = if ctx.seat_mode == RuleMode::Active {
            let active = if ctx.standard_mode == RuleMode::Prior {
                request.legacy_members
            } else {
                &ctx.members
            };
            let (state, locked) = tagged("validator seat lock rejected", next.lock(&cfg, active))?;
            next = state;
            locked
        } else {
            false
        };
        result.delayed = reason;
        if changed || locked {
            save(state, &next)?;
        }
    }
    result.promoted = promote(request.epoch, state)?;
    let ctx = resolve(state)?;
    let cfg = ctx.config();
    let activate = if ctx.standard_mode == RuleMode::Prior {
        request.policy.snapshot_activation(request.epoch)
    } else {
        request
            .policy
            .snapshot_at(request.epoch, cfg.cadence, cfg.delay)
    }
    .map_err(error)?;
    let Some(activate) = activate else {
        return Ok(result);
    };
    if ctx.plan_mode == RuleMode::Active
        && !update::snapshot_slot(request.epoch, pending(state)?.as_ref())
    {
        return Ok(result);
    }
    let registry = state.get(&[b"meta", registry::META_KEY]).map_or_else(
        || Ok(Registry::default()),
        |raw| tagged("validator registry corrupt", Registry::from_bytes(raw)),
    )?;
    let Policy::Bonded(policy) = request.policy else {
        return Ok(result);
    };
    let ctx = resolve(state)?;
    let input = fold_input(
        &ctx,
        request,
        policy,
        &registry,
        result.promoted.as_deref(),
        state,
    )?;
    let snapshot = match admission::snapshot(
        &input.parameters,
        activate,
        &input.candidates,
        &input.incumbents,
    ) {
        Ok(s) => s,
        Err(e) if e.0 == "validator snapshot has fewer than four eligible members" => {
            result.insufficient_members = true;
            return Ok(result);
        }
        Err(e) => return Err(error(format!("validator snapshot rejected: {e}"))),
    };
    let update = tagged(
        "validator snapshot rejected",
        ValidatorUpdate::make_weighted(
            snapshot.source_epoch,
            snapshot.activate_epoch,
            &snapshot.validators,
        ),
    )?;
    set(state, update::PENDING_KEY, update.to_bytes())?;
    result.scheduled = Some(update);
    Ok(result)
}
/// Run after transactions and before the reward footer. Failure restores the
/// tree, and the caller's enclosing epoch journal must roll back transactions.
pub fn advance(
    request: &Request<'_>,
    resolver: &impl EpochFold,
    state: &mut StateBatch,
) -> Result<Advanced, Error> {
    let saved = state.save().map_err(error)?;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        inner(request, resolver, state)
    })) {
        Ok(Ok(result)) => Ok(result),
        failed => {
            state.restore(saved).map_err(error)?;
            match failed {
                Ok(Err(e)) => Err(e),
                Err(e) => std::panic::resume_unwind(e),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}
