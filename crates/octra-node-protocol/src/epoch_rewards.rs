// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native epoch reward plans and weighted attribution. These consume the
//! independently selected epoch policy; they do not choose its activation.
use crate::{state::MAX_SUPPLY, transaction::Error};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::collections::BTreeMap;

pub const EMISSION_DIVISOR: u64 = 18_198_732;
pub const EMISSION_FLOOR: u64 = 10_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub base_reward: BigInt,
    pub fees_burned: BigInt,
    pub fees_rewarded: BigInt,
    pub total_reward: BigInt,
    /// Reward withheld from slashed validators under seatless and burned.
    pub reward_burned: BigInt,
    /// Addresses whose reward is burned, ordered and unique.
    pub excluded: Vec<Vec<u8>>,
    pub proposer_total: BigInt,
    pub each_validator: BigInt,
    pub remainder: BigInt,
    pub new_emission_remaining: BigInt,
    pub new_total_supply: BigInt,
    pub new_supply_retired: BigInt,
    pub supply_tracking_active: bool,
}
pub struct Input {
    pub fee_burn_active: bool,
    pub supply_retired: BigInt,
    pub validator_count: i64,
    pub emission_remaining: BigInt,
    pub confirmed_fees: BigInt,
    pub prev_supply: BigInt,
}
fn error(reason: &str) -> Error {
    Error(reason.into())
}
pub fn compute_base(emission_remaining: &BigInt) -> BigInt {
    if emission_remaining <= &BigInt::zero() {
        return BigInt::zero();
    }
    (emission_remaining / EMISSION_DIVISOR)
        .max(EMISSION_FLOOR.into())
        .min(emission_remaining.clone())
}
pub fn validate_supply(
    emission_remaining: &BigInt,
    total_supply: &BigInt,
) -> Result<BigInt, Error> {
    if emission_remaining.is_negative() {
        return Err(error("negative emission_remaining"));
    }
    if total_supply.is_negative() {
        return Err(error("negative total_supply"));
    }
    if total_supply > &BigInt::from(MAX_SUPPLY) {
        return Err(error("total_supply exceeds hard cap"));
    }
    let headroom = BigInt::from(MAX_SUPPLY) - total_supply;
    if emission_remaining > &headroom {
        return Err(error("emission_remaining exceeds supply headroom"));
    }
    Ok(headroom)
}
pub fn build(input: &Input, base_reward: Option<BigInt>) -> Result<Plan, Error> {
    let base_reward = base_reward.unwrap_or_else(|| compute_base(&input.emission_remaining));
    if input.validator_count <= 0 {
        return Err(error("reward plan requires active validators"));
    }
    if input.supply_retired.is_negative() {
        return Err(error("negative retired supply"));
    }
    if input.confirmed_fees.is_negative() {
        return Err(error("negative confirmed fees"));
    }
    let fees_burned = if input.fee_burn_active {
        &input.confirmed_fees / 5
    } else {
        BigInt::zero()
    };
    let fees_rewarded = &input.confirmed_fees - &fees_burned;
    let headroom = validate_supply(&input.emission_remaining, &input.prev_supply)?;
    if base_reward.is_negative() {
        return Err(error("negative base reward"));
    }
    if base_reward > input.emission_remaining {
        return Err(error("base reward exceeds emission reserve"));
    }
    if base_reward > headroom {
        return Err(error("base reward exceeds supply headroom"));
    }
    let total_reward = &base_reward + &fees_rewarded;
    let proposer_cut = &total_reward * 7 / 10;
    let validator_pool = &total_reward - &proposer_cut;
    let each_validator = &validator_pool / input.validator_count;
    let remainder = validator_pool - &each_validator * input.validator_count;
    let proposer_total = proposer_cut + &remainder;
    let new_emission_remaining = &input.emission_remaining - &base_reward;
    let new_total_supply = &input.prev_supply + &base_reward - &fees_burned;
    let new_supply_retired = &input.supply_retired + &fees_burned;
    if new_total_supply.is_negative() {
        return Err(error("fee burn exceeds total supply"));
    }
    if input.fee_burn_active
        && &new_total_supply + &new_emission_remaining + &new_supply_retired != MAX_SUPPLY.into()
    {
        return Err(error("supply envelope transition mismatch"));
    }
    Ok(Plan {
        base_reward,
        fees_burned,
        fees_rewarded,
        total_reward,
        reward_burned: BigInt::zero(),
        excluded: vec![],
        proposer_total,
        each_validator,
        remainder,
        new_emission_remaining,
        new_total_supply,
        new_supply_retired,
        supply_tracking_active: input.fee_burn_active,
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribution {
    pub proposer: Vec<u8>,
    pub proposer_public_key: Option<Vec<u8>>,
    pub validators: Vec<Validator>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credit {
    pub address: Vec<u8>,
    pub proposer: bool,
    pub validator: bool,
    pub amount: BigInt,
}
pub fn credits(reward: &Attribution, plan: &Plan) -> Result<Vec<Credit>, Error> {
    let mut validators = reward.validators.iter().collect::<Vec<_>>();
    validators.sort_by(|a, b| a.address.cmp(&b.address));
    if validators.is_empty() {
        return Err(error("reward distribution requires validators"));
    }
    if validators.windows(2).any(|v| v[0].address == v[1].address) {
        return Err(error("reward distribution has duplicate validators"));
    }
    if validators.iter().any(|v| v.weight <= BigInt::zero()) {
        return Err(error("reward distribution has non-positive weight"));
    }
    let total_weight: BigInt = validators.iter().map(|v| &v.weight).sum();
    let validator_pool = &plan.each_validator * validators.len() + &plan.remainder;
    let proposer_base = &plan.proposer_total - &plan.remainder;
    if proposer_base.is_negative() {
        return Err(error("reward proposer base is negative"));
    }
    let mut table = BTreeMap::new();
    let mut distributed = BigInt::zero();
    for validator in validators {
        let amount = &validator_pool * &validator.weight / &total_weight;
        distributed += &amount;
        table.insert(
            validator.address.clone(),
            Credit {
                address: validator.address.clone(),
                proposer: false,
                validator: true,
                amount,
            },
        );
    }
    let proposer = table
        .entry(reward.proposer.clone())
        .or_insert_with(|| Credit {
            address: reward.proposer.clone(),
            proposer: false,
            validator: false,
            amount: BigInt::zero(),
        });
    proposer.proposer = true;
    proposer.amount += proposer_base + validator_pool - distributed;
    let credits = table
        .into_values()
        .filter(|c| c.amount.is_positive())
        .collect::<Vec<_>>();
    net_credits(plan, credits)
}
fn sum(credits: &[Credit]) -> BigInt {
    credits.iter().map(|c| &c.amount).sum()
}
/// Native `net_reward_credits`: the gross distribution covers the paid and
/// the burned reward; excluded addresses' credits are the burn.
fn net_credits(plan: &Plan, credits: Vec<Credit>) -> Result<Vec<Credit>, Error> {
    if plan.total_reward.is_negative() || plan.reward_burned.is_negative() {
        return Err(error("reward amounts are negative"));
    }
    if plan.excluded.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(error("reward exclusions are not ordered and unique"));
    }
    if sum(&credits) != &plan.total_reward + &plan.reward_burned {
        return Err(error("reward distribution total mismatch"));
    }
    let (burned, credits): (Vec<_>, Vec<_>) = credits
        .into_iter()
        .partition(|credit| plan.excluded.contains(&credit.address));
    if sum(&burned) != plan.reward_burned || sum(&credits) != plan.total_reward {
        return Err(error("reward burn distribution mismatch"));
    }
    Ok(credits)
}
/// The proposer, then every rewarded validator.
pub fn reward_addresses(reward: &Attribution) -> Vec<Vec<u8>> {
    std::iter::once(reward.proposer.clone())
        .chain(reward.validators.iter().map(|v| v.address.clone()))
        .collect()
}
/// Native `reward_exclusions`: under seatless, rewarded addresses with a
/// slash applied by this epoch, or a recorded penalty, earn nothing.
pub fn exclusions(
    seatless: bool,
    epoch: i64,
    registry: Option<&[u8]>,
    reward: &Attribution,
    penalized: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, Error> {
    if !seatless {
        return Ok(vec![]);
    }
    let registry = match registry {
        None => crate::validator::registry::Registry::default(),
        Some(raw) => crate::validator::registry::Registry::from_bytes(raw)
            .map_err(|e| Error(e.to_string()))?,
    };
    let addresses = reward_addresses(reward);
    let mut excluded: Vec<Vec<u8>> = registry
        .slashes()
        .iter()
        .filter(|record| record.applied_epoch <= epoch && addresses.contains(&record.offender))
        .map(|record| record.offender.clone())
        .chain(penalized.iter().filter(|a| addresses.contains(a)).cloned())
        .collect();
    excluded.sort();
    excluded.dedup();
    Ok(excluded)
}
/// Native `prepare_reward_plan`: burn the excluded validators' share.
pub fn prepare(
    seatless: bool,
    epoch: i64,
    registry: Option<&[u8]>,
    reward: &Attribution,
    penalized: &[Vec<u8>],
    plan: Plan,
) -> Result<Plan, Error> {
    if !plan.reward_burned.is_zero() || !plan.excluded.is_empty() {
        return Err(error("reward plan is already prepared"));
    }
    let excluded = exclusions(seatless, epoch, registry, reward, penalized)?;
    if excluded.is_empty() {
        return Ok(plan);
    }
    let gross = credits(reward, &plan)?;
    let burned: BigInt = gross
        .iter()
        .filter(|credit| excluded.contains(&credit.address))
        .map(|credit| &credit.amount)
        .sum();
    let next = Plan {
        excluded,
        total_reward: &plan.total_reward - &burned,
        new_total_supply: &plan.new_total_supply - &burned,
        new_supply_retired: &plan.new_supply_retired + &burned,
        reward_burned: burned,
        ..plan
    };
    if next.new_total_supply.is_negative() {
        return Err(error("reward burn exceeds total supply"));
    }
    credits(reward, &next)?;
    Ok(next)
}
/// Native `reward_credits_at`: the plan's exclusions must be the ones the
/// state implies.
pub fn credits_at(
    seatless: bool,
    epoch: i64,
    registry: Option<&[u8]>,
    reward: &Attribution,
    penalized: &[Vec<u8>],
    plan: &Plan,
) -> Result<Vec<Credit>, Error> {
    if exclusions(seatless, epoch, registry, reward, penalized)? != plan.excluded {
        return Err(error("reward exclusions differ from applied slashes"));
    }
    credits(reward, plan)
}
impl Attribution {
    /// Native proposer priority and ordered fallback key lookup. Existing
    /// account keys are retained by the runtime's reward application.
    pub fn public_key(&self, address: &[u8], fallback: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<u8>> {
        if address == self.proposer {
            return self.proposer_public_key.clone();
        }
        self.validators
            .iter()
            .find(|v| v.address == address)
            .and_then(|v| v.public_key.clone())
            .or_else(|| {
                fallback
                    .iter()
                    .find(|(a, _)| a == address)
                    .map(|(_, key)| key.clone())
            })
    }
}
