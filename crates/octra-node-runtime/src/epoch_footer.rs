// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native reward/emission footer over speculative state. The authenticated host
//! supplies policy and reward attribution; failure restores both journals.
use crate::state_batch::StateBatch;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use octra_node_protocol::{
    emission::{self, Schedule},
    epoch_rewards::{self, Attribution, Credit, Input, Plan},
    native_integer::parse_integer,
    state::{Ledger, MAX_SUPPLY},
    transaction::Error,
};

pub struct Policy {
    pub emission_guard: bool,
    pub schedule: Schedule,
    pub legacy_total: Option<Vec<u8>>,
}
pub struct Request<'a> {
    pub epoch: i64,
    pub reward: &'a Attribution,
    pub validator_keys: &'a [(Vec<u8>, Vec<u8>)],
    pub confirmed_fees: BigInt,
}
pub struct Footer {
    pub plan: Plan,
    pub credits: Vec<Credit>,
}
fn error(reason: impl std::fmt::Display) -> Error {
    Error(reason.to_string())
}
fn amount(label: &str, raw: Option<&[u8]>) -> Result<BigInt, Error> {
    let raw = raw.ok_or_else(|| error(format!("missing {label}")))?;
    parse_integer(raw).ok_or_else(|| error(format!("invalid {label}")))
}
fn set(state: &mut StateBatch, key: &[u8], value: &impl ToString) -> Result<(), Error> {
    state
        .set(&[b"meta", key], value.to_string().into_bytes())
        .map_err(error)
}
/// Apply only after transaction effects, before account flush and canonical root
/// computation. This wrapper adds operational rollback to the native footer;
/// it does not publish or derive validator authority from an incoming epoch.
pub fn apply(
    policy: &Policy,
    request: &Request<'_>,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<Footer, Error> {
    let saved = state.save().map_err(error)?;
    let depth = ledger.journal_depth();
    ledger.begin_journal();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        apply_inner(policy, request, ledger, state)
    }));
    match result {
        Ok(Ok(footer)) => {
            ledger.commit_journal()?;
            Ok(footer)
        }
        failure => {
            while ledger.journal_depth() > depth {
                ledger.abort_journal();
            }
            state.restore(saved).map_err(error)?;
            match failure {
                Ok(Err(e)) => Err(e),
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(Ok(_)) => unreachable!(),
            }
        }
    }
}
fn apply_inner(
    policy: &Policy,
    request: &Request<'_>,
    ledger: &mut Ledger,
    state: &mut StateBatch,
) -> Result<Footer, Error> {
    let emission = state
        .get(&[b"meta", b"emission_remaining"])
        .map(<[u8]>::to_vec);
    let total = state.get(&[b"meta", b"total_supply"]).map(<[u8]>::to_vec);
    let remaining = emission.as_deref().map_or(Ok(BigInt::zero()), |s| {
        amount("emission_remaining", Some(s))
    })?;
    let stored_total = total.as_deref().or({
        if policy.emission_guard {
            policy.legacy_total.as_deref()
        } else {
            None
        }
    });
    let prev_supply = amount("total_supply", stored_total)?;
    if ledger.total_supply().is_negative() {
        return Err(error("negative public supply"));
    }
    if ledger.total_supply() > &prev_supply {
        return Err(error("public supply exceeds total supply"));
    }
    epoch_rewards::validate_supply(&BigInt::zero(), &prev_supply)?;
    let headroom = epoch_rewards::validate_supply(&remaining, &prev_supply)?;
    if let Some(raw) = state.get(&[b"meta", b"supply_retired"]) {
        if amount("supply_retired", Some(raw))?.is_negative() {
            return Err(error("negative retired supply"));
        }
    }
    let binding = emission::bind(
        policy.schedule,
        request.epoch,
        &remaining,
        &headroom,
        emission::KEYS.map(|key| state.get(&[b"meta", key])),
    )?;
    let base = emission::reward(policy.schedule, request.epoch, &binding)?;
    let plan = epoch_rewards::build(
        &Input {
            fee_burn_active: binding.active,
            supply_retired: binding.retired.clone(),
            validator_count: i64::try_from(request.reward.validators.len()).map_err(error)?,
            emission_remaining: binding.remaining.clone(),
            confirmed_fees: request.confirmed_fees.clone(),
            prev_supply,
        },
        Some(base),
    )?;
    let credits = epoch_rewards::credits(request.reward, &plan)?;
    if policy.emission_guard && plan.base_reward.is_positive() {
        return Err(error("emission guard rejected positive base reward"));
    }
    if plan.total_reward.is_positive() {
        if ledger.total_supply() + &plan.total_reward > BigInt::from(MAX_SUPPLY) {
            return Err(error("reward supply cap rejected"));
        }
        let before = ledger.total_supply().clone();
        for credit in &credits {
            let key = request
                .reward
                .public_key(&credit.address, request.validator_keys);
            match ledger.account(&credit.address) {
                Some(account) => {
                    if account.public_key.is_none() {
                        if let Some(key) = key {
                            ledger.register_public_key(&credit.address, key);
                        }
                    }
                }
                None => ledger.add_account(&credit.address, BigInt::zero(), key)?,
            }
        }
        for credit in &credits {
            ledger.credit(&credit.address, &credit.amount, None)?;
        }
        if *ledger.total_supply() != before + &plan.total_reward {
            return Err(error("reward credit mismatch"));
        }
        if plan.base_reward.is_positive() || plan.fees_burned.is_positive() {
            set(state, b"emission_remaining", &plan.new_emission_remaining)?;
            set(state, b"total_supply", &plan.new_total_supply)?;
            if plan.supply_tracking_active {
                set(state, b"supply_retired", &plan.new_supply_retired)?;
            }
        }
    }
    set(state, b"last_epoch", &request.epoch)?;
    set(
        state,
        b"current_epoch",
        &((request.epoch.wrapping_add(1) << 1) >> 1),
    )?;
    for (key, value) in binding.writes {
        state.set(&[b"meta", &key], value).map_err(error)?;
    }
    if binding.activated || emission.is_none() {
        set(state, b"emission_remaining", &plan.new_emission_remaining)?;
    }
    if total.is_none() {
        set(state, b"total_supply", &plan.new_total_supply)?;
    }
    if plan.supply_tracking_active {
        set(state, b"supply_retired", &plan.new_supply_retired)?;
    }
    Ok(Footer { plan, credits })
}
