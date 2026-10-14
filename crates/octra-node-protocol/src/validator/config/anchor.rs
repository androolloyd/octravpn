// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Trusted validator selection for proposal, pending-lock and finality checks.
use super::{entries, pending_entries, Build, Config};
use crate::{
    consensus::{
        relief::{Mark, Plan},
        ValidatorSet,
    },
    native_integer::parse_int64,
};
type Result<T> = std::result::Result<T, Vec<u8>>;
fn error(e: impl std::fmt::Display) -> Vec<u8> {
    e.to_string().into_bytes()
}
/// Environment is captured at boot; metadata belongs to one canonical HEAD.
/// The caller authenticates the head and loads relief from the durable journal.
pub struct Source<'a> {
    pub chain: &'a [u8],
    pub height: i64,
    pub current: Option<&'a [u8]>,
    pub next: Option<&'a [u8]>,
    pub activate: Option<&'a [u8]>,
    pub fallback_activate: Option<&'a [u8]>,
    pub active: Option<&'a [u8]>,
    pub pending: Option<&'a [u8]>,
}
impl Source<'_> {
    pub fn config(&self) -> Result<Config> {
        let current = entries::from_value(self.current);
        let next = entries::from_value(self.next);
        let pending = pending_entries(self.pending);
        // Consensus_validator_anchor retries the fallback on malformed primary
        // input, unlike Validators.activation_epoch_int64. Preserve both APIs.
        let activate = self
            .activate
            .and_then(parse_int64)
            .or_else(|| self.fallback_activate.and_then(parse_int64));
        let base = Config::build(Build {
            chain: self.chain,
            consensus: true,
            height: self.height,
            current: &current,
            next: &next,
            chain_pending: &pending,
            activate,
            program_trust: None,
            runtime_profile: None,
        })
        .map_err(error)?;
        if let Some(e) = base.identity_errors.first() {
            return Err(e.clone());
        }
        base.bind(self.chain, true, self.height, self.active, self.pending)
            .map_err(error)
    }
    pub fn stake_set(&self, epoch: i64) -> Result<ValidatorSet> {
        select(&self.config()?, epoch)
    }
    pub fn expected_set(
        &self,
        epoch: i64,
        round: Option<i64>,
        relief: &impl Fn(i64) -> Result<Option<Mark>>,
    ) -> Result<ValidatorSet> {
        expected_set(self.chain, &self.config()?, epoch, round, relief)
    }
}
/// Select from an already bound canonical configuration. This also allows an
/// asynchronous host to load the journal only after configuration validation.
pub fn expected_set(
    chain: &[u8],
    config: &Config,
    epoch: i64,
    round: Option<i64>,
    relief: &impl Fn(i64) -> Result<Option<Mark>>,
) -> Result<ValidatorSet> {
    let current = select(config, epoch)?
        .for_epoch(chain, epoch)
        .map_err(error)?;
    let Some(plan) = config
        .scheduled
        .as_ref()
        .filter(|p| epoch < p.activate_epoch)
    else {
        return Ok(current);
    };
    let Some(mark) = relief(epoch)? else {
        return Ok(current);
    };
    if epoch >= mark.activate_epoch {
        return Ok(current);
    }
    let target = plan
        .validators
        .for_epoch(chain, plan.activate_epoch)
        .map_err(error)?;
    let selected = Plan {
        chain_id: chain,
        height: epoch,
        current: &current,
        activate_epoch: plan.activate_epoch,
        target: &target,
        fingerprint: plan.fingerprint.as_bytes(),
    }
    .restore(&mark)
    .map_err(error)?
    .cloned();
    match round {
        Some(r) if r < 0 => Err(b"pending round is negative".to_vec()),
        Some(r) if epoch == mark.height && r <= mark.round => Ok(current),
        _ => Ok(selected.unwrap_or(current)),
    }
}

fn select(config: &Config, epoch: i64) -> Result<ValidatorSet> {
    if let Some(next) = config
        .scheduled
        .as_ref()
        .filter(|s| epoch >= s.activate_epoch)
    {
        Ok(next.validators.clone())
    } else if config.active.n == 0 {
        Err(b"trusted validator set is empty".to_vec())
    } else {
        Ok(config.stake.clone())
    }
}
