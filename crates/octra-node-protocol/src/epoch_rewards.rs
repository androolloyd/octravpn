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
    if credits.iter().map(|c| &c.amount).sum::<BigInt>() != plan.total_reward {
        return Err(error("reward distribution total mismatch"));
    }
    Ok(credits)
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
