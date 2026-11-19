// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native `Epoch_exec.check_registry_change`: under seatless voting a
//! registry change (bond, readiness, exit) must not give any member of the
//! set it would schedule a new or larger blocking share of weight.
use super::{EpochFold, Failure, Fold, Host};
use crate::{epoch_footer, execution::Error, state_batch::StateBatch};
use octra_node_protocol::{
    consensus::{policy::QuorumPolicy, validators::SetChoice, ValidatorSet},
    control_payload::ValidatorUpdate,
    transaction::RuleMode,
    validator::{
        admission::{self, Member},
        policy::Active,
        registry::Registry,
        set_fold::{self, State},
        update,
    },
};

fn host(error: impl std::fmt::Display) -> Failure {
    Failure::Host(Error(error.to_string()))
}

impl<F: EpochFold> Host<'_, F> {
    /// `next_set_fold`: the fold after this epoch's advance and seat lock.
    fn next_fold(&self, ctx: &Fold, base: &State) -> Result<State, String> {
        let cfg = ctx.config();
        let (next, _, changed) = base
            .advance_with_marks(
                &cfg,
                ctx.cap_mode,
                self.chain,
                ctx.start(),
                self.epoch,
                ctx.parent.as_ref(),
                ctx.duty_marks == RuleMode::Active,
            )
            .map_err(|e| e.to_string())?;
        let _ = changed;
        if ctx.seat_mode == RuleMode::Prior {
            return Ok(next);
        }
        let active = if ctx.standard_mode == RuleMode::Prior {
            self.members
        } else {
            &ctx.members
        };
        next.lock(&cfg, active)
            .map(|(state, _)| state)
            .map_err(|e| e.to_string())
    }
    /// Native `current_voting_set` for transaction processing.
    fn voting_set(&self) -> Result<ValidatorSet, String> {
        let set = self.voting_set.ok_or("epoch voting set is missing")?;
        let set = set
            .structural_for_epoch(self.chain, self.epoch)
            .map_err(|e| e.message().to_string())?;
        let mut members: Vec<_> = set.validators.iter().map(|v| v.address.clone()).collect();
        members.sort();
        let mut legacy = self.members.to_vec();
        legacy.sort();
        if members != legacy {
            return Err("epoch voting set members differ".into());
        }
        Ok(set)
    }
    /// `snapshot_parameters`.
    fn snapshot_parameters(
        ctx: &Fold,
        policy: &Active,
        active: &[Vec<u8>],
        state: &State,
    ) -> Result<(admission::Parameters, Vec<Vec<u8>>), Failure> {
        let cfg = ctx.config();
        let (max_validators, incumbents) = if ctx.seat_mode == RuleMode::Prior {
            (cfg.max_members, vec![])
        } else {
            let seats = state
                .seats()
                .ok_or_else(|| host("validator seat limit is missing"))?;
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
        Ok((
            admission::Parameters {
                max_validators,
                activation_delay,
                ..policy.parameters.clone()
            },
            incumbents,
        ))
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn check_registry_change(
        &self,
        policy: &Active,
        before: &Registry,
        after: &Registry,
        fold: Option<&State>,
        state: &StateBatch,
    ) -> Result<Result<(), String>, Failure> {
        if !update::seatless_at(self.chain, self.epoch) {
            return Ok(Ok(()));
        }
        let ctx = self.resolve(state)?;
        let cfg = ctx.config();
        let at = self.epoch;
        let stored = state
            .get(&[b"meta", set_fold::META_KEY])
            .map_or_else(|| Ok(State::default()), State::from_bytes)
            .map_err(|e| e.to_string());
        let pending = state
            .get(&[b"meta", update::PENDING_KEY])
            .map(ValidatorUpdate::of_string)
            .transpose()
            .map_err(|e| e.to_string());
        let entries: Vec<_> = before
            .candidates()
            .iter()
            .chain(after.candidates())
            .map(|c| c.address.clone())
            .collect();
        let pending_addresses: Vec<_> = match &pending {
            Ok(Some(update)) => update
                .validators
                .iter()
                .map(|v| v.address.clone())
                .collect(),
            _ => vec![],
        };
        let penalized =
            epoch_footer::penalties(true, state, &[pending_addresses, entries].concat());
        let checked = (|| -> Result<Result<(), String>, Failure> {
            macro_rules! attempt {
                ($e:expr) => {
                    match $e {
                        Ok(value) => value,
                        Err(reason) => return Ok(Err(reason)),
                    }
                };
            }
            let base = attempt!(stored);
            let state_now = attempt!(self.next_fold(&ctx, &base));
            let next = match fold {
                None => state_now.clone(),
                Some(changed) => attempt!(self.next_fold(&ctx, changed)),
            };
            let pending = attempt!(pending);
            let active = attempt!(self.voting_set());
            let cadence = if ctx.standard_mode == RuleMode::Prior {
                policy.snapshot_interval
            } else {
                cfg.cadence
            };
            let delay = if ctx.standard_mode == RuleMode::Prior {
                policy.parameters.activation_delay
            } else {
                cfg.delay
            };
            let first_source = policy.activation_epoch - delay;
            let align = |epoch: i64| {
                let epoch = first_source.max(at.max(epoch));
                let rest = (epoch - first_source) % cadence;
                if rest == 0 {
                    epoch
                } else {
                    epoch + (cadence - rest)
                }
            };
            let promotion = match &pending {
                Some(update)
                    if update.weighted
                        && !update
                            .validators
                            .iter()
                            .any(|m| penalized.contains(&m.address)) =>
                {
                    let source = at.max(update.activate_epoch);
                    let pending_set = attempt!(update.validator_set().map_err(|e| e.to_string()));
                    let choice = if update.eviction.is_some() {
                        attempt!(update
                            .check_set_at(self.chain, source)
                            .map_err(|e| e.to_string()));
                        SetChoice::Pending(pending_set)
                    } else {
                        attempt!(pending_set
                            .pending_for_policy(
                                QuorumPolicy::for_chain(self.chain),
                                source,
                                Some(&active)
                            )
                            .map_err(|e| e.message().to_string()))
                    };
                    let (SetChoice::Active(set) | SetChoice::Pending(set)) = choice;
                    Some((
                        source,
                        set.validators
                            .iter()
                            .map(|v| v.address.clone())
                            .collect::<Vec<_>>(),
                    ))
                }
                _ => None,
            };
            let source = align(promotion.as_ref().map_or(at, |(epoch, _)| *epoch));
            let fold_set =
                |epoch: i64, active: &[Vec<u8>], state: State| -> Result<State, String> {
                    if ctx.live_mode == RuleMode::Prior {
                        Ok(state)
                    } else {
                        state
                            .note_set(&cfg, epoch, active)
                            .map_err(|e| e.to_string())
                    }
                };
            let advance = |folded: State| -> Result<(State, Vec<Vec<u8>>), String> {
                let folded = fold_set(at, self.members, folded)?;
                match &promotion {
                    Some((epoch, members)) if *epoch <= source => {
                        Ok((fold_set(*epoch, members, folded)?, members.clone()))
                    }
                    _ => Ok((folded, self.members.to_vec())),
                }
            };
            let select = |registry: &Registry,
                          (folded, members): &(State, Vec<Vec<u8>>)|
             -> Result<Vec<Member>, Failure> {
                let (parameters, incumbents) =
                    Self::snapshot_parameters(&ctx, policy, members, folded)?;
                let (entries, _) = folded.filter(&cfg, ctx.start(), source, registry.candidates());
                let entries: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| !penalized.contains(&entry.address))
                    .collect();
                Ok(admission::select_members(
                    &parameters,
                    source,
                    &entries,
                    &incumbents,
                ))
            };
            let state_now = attempt!(advance(state_now));
            let next = attempt!(advance(next));
            let after_members = select(after, &next)?;
            let before_members = select(before, &state_now)?;
            Ok(
                admission::check_weight_change(&before_members, &after_members)
                    .map_err(|e| e.to_string()),
            )
        })();
        checked
    }
}

impl<F: EpochFold> Host<'_, F> {
    /// Native `validator_penalties` for one address.
    pub(super) fn penalized(&self, address: &[u8], state: &StateBatch) -> bool {
        !epoch_footer::penalties(
            update::seatless_at(self.chain, self.epoch),
            state,
            &[address.to_vec()],
        )
        .is_empty()
    }
    pub(super) fn voting_set_now(&self) -> Result<ValidatorSet, String> {
        self.voting_set()
    }
    /// Native `check_evidence_set`: a slash may not leave the current voting
    /// set with an eviction it cannot plan.
    pub(super) fn check_evidence_set(&self, registry: &Registry) -> Result<(), String> {
        if !update::seatless_at(self.chain, self.epoch) {
            return Ok(());
        }
        let current = self.voting_set()?;
        let offenders = update::eviction_offenders(self.chain, self.epoch, registry, &current)
            .map_err(|e| e.to_string())?;
        if offenders.is_empty() {
            return Ok(());
        }
        let offenders: Vec<_> = offenders.iter().map(|o| o.as_slice().into()).collect();
        current
            .plan_eviction(&offenders)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}
