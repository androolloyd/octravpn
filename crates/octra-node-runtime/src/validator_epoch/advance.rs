// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::Fold;
use crate::{
    compute_roots,
    execution::Error,
    state_batch::{Snapshot, StateBatch},
    validator_transaction::EpochFold,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{
        codec::Wire,
        validators::{EvictionChoice, SetChoice},
        ValidatorSet,
    },
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
    /// The set that finalized this epoch (`backend.voting_set`).
    pub voting_set: Option<&'a ValidatorSet>,
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
                ValidatorUpdate::of_string(raw),
            )
        })
        .transpose()
}
fn seatless(request: &Request<'_>) -> bool {
    update::seatless_at(request.chain, request.epoch)
}
fn remove(state: &mut StateBatch, key: &[u8]) -> Result<(), Error> {
    state.remove(&[b"meta", key]).map_err(error)
}
fn load_registry(state: &StateBatch, tag: &str) -> Result<Registry, Error> {
    state.get(&[b"meta", registry::META_KEY]).map_or_else(
        || Ok(Registry::default()),
        |raw| tagged(tag, Registry::from_bytes(raw)),
    )
}
/// Native `current_voting_set`: the finalizing set, structurally valid for
/// this epoch, with exactly this epoch's members.
pub(crate) fn current_voting_set(request: &Request<'_>) -> Result<ValidatorSet, Error> {
    let set = request
        .voting_set
        .ok_or_else(|| error("epoch voting set is missing"))?;
    let set = set
        .structural_for_epoch(request.chain, request.epoch)
        .map_err(|e| error(e.message()))?;
    let mut members: Vec<_> = set.validators.iter().map(|v| v.address.clone()).collect();
    members.sort();
    let mut legacy = request.legacy_members.to_vec();
    legacy.sort();
    if members != legacy {
        return Err(error("epoch voting set members differ"));
    }
    Ok(set)
}
/// Native `remember_validator_penalties`: once, at the first seatless epoch
/// that reaches it, every slash applied by then becomes a lasting penalty.
pub(crate) fn remember_penalties(
    request: &Request<'_>,
    registry: &Registry,
    state: &mut StateBatch,
) -> Result<(), Error> {
    remember_penalties_at(request.chain, request.epoch, registry, state)
}
/// [`remember_penalties`] for a chain and epoch.
pub(crate) fn remember_penalties_at(
    chain: &[u8],
    epoch: i64,
    registry: &Registry,
    state: &mut StateBatch,
) -> Result<(), Error> {
    use crate::epoch_footer::{penalty_key, PENALTY_EPOCH};
    if !update::seatless_at(chain, epoch) {
        return Ok(());
    }
    if let Some(raw) = state.get(&[b"meta", PENALTY_EPOCH]) {
        let applied: i64 = std::str::from_utf8(raw)
            .ok()
            .and_then(|text| text.parse().ok())
            .ok_or_else(|| error("validator penalty epoch is invalid"))?;
        return if applied < 0 || applied > epoch {
            Err(error("validator penalty epoch differs"))
        } else {
            Ok(())
        };
    }
    for record in registry.slashes() {
        if record.applied_epoch <= epoch {
            let key = penalty_key(&record.offender);
            if state.get(&[b"meta", &key]).is_none() {
                set(state, &key, record.id.clone())?;
            }
        }
    }
    set(state, PENALTY_EPOCH, epoch.to_string().into_bytes())
}
/// Native `prepare_validator_penalties`, run before an epoch's transactions.
pub fn prepare_penalties(request: &Request<'_>, state: &mut StateBatch) -> Result<(), Error> {
    if !seatless(request) {
        return Ok(());
    }
    let registry = load_registry(state, "validator penalty registry corrupt")?;
    remember_penalties(request, &registry, state)
}
/// Native `validator_promotion`.
fn promotion(
    request: &Request<'_>,
    active: Option<&ValidatorSet>,
    update: &ValidatorUpdate,
) -> Result<SetChoice, String> {
    let pending = update.validator_set().map_err(|e| e.to_string())?;
    if update.eviction.is_some() {
        update
            .check_set_at(request.chain, request.epoch)
            .map_err(|e| e.to_string())?;
        return Ok(SetChoice::Pending(pending));
    }
    pending
        .pending_for_policy(
            octra_node_protocol::consensus::policy::QuorumPolicy::for_chain(request.chain),
            request.epoch,
            active,
        )
        .map_err(|e| e.message().to_string())
}
fn promote(request: &Request<'_>, state: &mut StateBatch) -> Result<Option<Vec<Vec<u8>>>, Error> {
    let Some(p) = pending(state)? else {
        return Ok(None);
    };
    if !p.weighted || p.activate_epoch > request.epoch {
        return Ok(None);
    }
    let decision = if seatless(request) {
        let active = match request.voting_set {
            None => None,
            Some(_) => Some(current_voting_set(request)?),
        };
        promotion(request, active.as_ref(), &p)
    } else {
        p.validator_set()
            .map(SetChoice::Pending)
            .map_err(|e| e.to_string())
    }
    .map_err(|reason| error(format!("pending validator set rejected: {reason}")))?;
    match decision {
        SetChoice::Active(active) => {
            remove(state, update::PENDING_KEY)?;
            Ok(Some(
                active
                    .validators
                    .iter()
                    .map(|v| v.address.clone())
                    .collect(),
            ))
        }
        SetChoice::Pending(_) => {
            // Preserve the exact stored bytes, including native accepted field order.
            let raw = state
                .get(&[b"meta", update::PENDING_KEY])
                .expect("loaded pending set")
                .to_vec();
            set(state, update::ACTIVE_KEY, raw)?;
            if p.eviction.is_some() {
                remove(state, update::PENDING_KEY)?;
            }
            Ok(Some(p.validators.into_iter().map(|v| v.address).collect()))
        }
    }
}
pub const EVICTION_WAIT_KEY: &[u8] = b"validator_eviction_wait";
fn write_eviction_wait(
    state: &mut StateBatch,
    current: &ValidatorSet,
    offenders: &[Vec<u8>],
    weight: &num_bigint::BigInt,
) -> Result<(), Error> {
    let mut value = br#"{"source":"#.to_vec();
    let source = STANDARD.encode(current.encode().map_err(error)?);
    octra_node_protocol::transaction::json_string(&mut value, source.as_bytes());
    value.extend_from_slice(br#","offenders":["#);
    for (index, offender) in offenders.iter().enumerate() {
        if index > 0 {
            value.push(b',');
        }
        octra_node_protocol::transaction::json_string(&mut value, offender);
    }
    value.extend_from_slice(br#"],"weight":""#);
    value.extend_from_slice(weight.to_string().as_bytes());
    value.extend_from_slice(br#""}"#);
    if state.get(&[b"meta", EVICTION_WAIT_KEY]) != Some(value.as_slice()) {
        set(state, EVICTION_WAIT_KEY, value)?;
    }
    remove(state, update::PENDING_KEY)
}
fn cancel_penalized_pending(request: &Request<'_>, state: &mut StateBatch) -> Result<bool, Error> {
    let Some(p) = pending(state)? else {
        return Ok(false);
    };
    if p.activate_epoch <= request.epoch {
        return Ok(false);
    }
    let members: Vec<_> = p.validators.iter().map(|v| v.address.clone()).collect();
    if crate::epoch_footer::penalties(seatless(request), state, &members).is_empty() {
        return Ok(false);
    }
    remove(state, update::PENDING_KEY)?;
    Ok(true)
}
/// Native `schedule_validator_eviction`: under seatless, a slashed member of
/// the current voting set is removed for the next epoch, or, while removing
/// it would leave too little weight, the wait is recorded.
fn schedule_eviction(request: &Request<'_>, state: &mut StateBatch) -> Result<bool, Error> {
    if !seatless(request) {
        return Ok(false);
    }
    let registry = load_registry(state, "validator eviction registry corrupt")?;
    if registry.slashes().is_empty() {
        return cancel_penalized_pending(request, state);
    }
    remember_penalties(request, &registry, state)?;
    let current = current_voting_set(request)?;
    let offenders = tagged(
        "validator eviction source rejected",
        update::eviction_offenders(request.chain, request.epoch, &registry, &current),
    )?;
    if offenders.is_empty() {
        remove(state, EVICTION_WAIT_KEY)?;
        return cancel_penalized_pending(request, state);
    }
    let offenders_wire: Vec<_> = offenders.iter().map(|o| o.as_slice().into()).collect();
    match tagged(
        "validator eviction source rejected",
        current.plan_eviction(&offenders_wire),
    )? {
        EvictionChoice::Retain(weight) => {
            write_eviction_wait(state, &current, &offenders, &weight)?;
            Ok(true)
        }
        EvictionChoice::Remove(..) => {
            let (next, _) = tagged(
                "validator eviction rejected",
                ValidatorUpdate::make_eviction(
                    request.epoch,
                    request.epoch + 1,
                    &offenders,
                    &current,
                ),
            )?;
            tagged(
                "validator eviction state rejected",
                next.check_eviction_state(request.chain, request.epoch, &registry, &current),
            )?;
            set(state, update::PENDING_KEY, next.to_bytes())?;
            remove(state, EVICTION_WAIT_KEY)?;
            Ok(true)
        }
    }
}
/// Registry candidates without a recorded penalty.
fn unpenalized(
    request: &Request<'_>,
    registry: &Registry,
    state: &StateBatch,
) -> Vec<admission::Candidate> {
    let addresses: Vec<_> = registry
        .candidates()
        .iter()
        .map(|c| c.address.clone())
        .collect();
    let penalized = crate::epoch_footer::penalties(seatless(request), state, &addresses);
    registry
        .candidates()
        .iter()
        .filter(|c| !penalized.contains(&c.address))
        .cloned()
        .collect()
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
            candidates: unpenalized(request, registry, state),
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
    let candidates = unpenalized(request, registry, state);
    let (candidates, _) = fold.filter(&cfg, ctx.start(), request.epoch, &candidates);
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
            load(state)?.advance_with_marks(
                &cfg,
                ctx.cap_mode,
                request.chain,
                ctx.start(),
                request.epoch,
                ctx.parent.as_ref(),
                ctx.duty_marks == RuleMode::Active,
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
    result.promoted = promote(request, state)?;
    if schedule_eviction(request, state)? {
        return Ok(result);
    }
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
    let registry = load_registry(state, "validator registry corrupt")?;
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
    if update.check_set_at(request.chain, request.epoch).is_err() {
        return Ok(result);
    }
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
