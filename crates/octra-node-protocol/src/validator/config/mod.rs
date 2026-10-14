// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native validator startup identity and durable membership binding.
pub mod anchor;
pub mod entries;
mod startup;
use super::Error;
use crate::{
    consensus::{hash, Bytes, Validator, ValidatorSet},
    control_payload::ValidatorUpdate,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
pub use startup::{Admission, Event, Membership, Quorum};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheduled {
    pub activate_epoch: i64,
    pub validators: ValidatorSet,
    pub fingerprint: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transition {
    None,
    Active(i64),
    Scheduled {
        epoch: i64,
        n: i64,
        quorum: i64,
        fingerprint: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub allowed_pubkeys: Vec<Bytes>,
    pub identity_errors: Vec<Bytes>,
    pub program_trust: Option<Bytes>,
    pub runtime_profile: Option<Bytes>,
    pub current: Vec<Validator>,
    pub next: Vec<Validator>,
    pub active_members: Vec<Validator>,
    pub stake: ValidatorSet,
    pub active: ValidatorSet,
    pub scheduled: Option<Scheduled>,
    pub light_scheduled: Option<(i64, ValidatorSet)>,
    pub hash: [u8; 32],
    pub transition: Transition,
}
pub struct Build<'a> {
    pub chain: &'a [u8],
    pub consensus: bool,
    pub height: i64,
    pub current: &'a [Bytes],
    pub next: &'a [Bytes],
    pub chain_pending: &'a [Bytes],
    pub activate: Option<i64>,
    pub program_trust: Option<Bytes>,
    pub runtime_profile: Option<Bytes>,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn validators(entries: &[Bytes]) -> Vec<Validator> {
    entries.iter().filter_map(|e| entries::parse(e)).collect()
}
pub fn fingerprint(set: &ValidatorSet) -> String {
    let entries = set
        .validators
        .iter()
        .map(|v| {
            [
                v.address.as_slice(),
                b":",
                STANDARD.encode(&v.pubkey).as_bytes(),
            ]
            .concat()
        })
        .collect::<Vec<_>>();
    hex::encode(Sha256::digest(entries.join(&b',')))[..16].into()
}
pub fn scheduled(update: &ValidatorUpdate) -> Option<Scheduled> {
    update.validator_set().ok().map(|validators| Scheduled {
        activate_epoch: update.activate_epoch,
        validators,
        fingerprint: update.fingerprint.clone(),
    })
}
pub fn pending_entries(raw: Option<&[u8]>) -> Vec<Bytes> {
    raw.and_then(|r| ValidatorUpdate::parse(Some(r)).ok())
        .filter(|u| u.weighted)
        .map_or_else(Vec::new, |u| {
            u.validators
                .into_iter()
                .map(|v| [v.address.as_slice(), b":", &v.public_key].concat())
                .collect()
        })
}
/// The caller logs the returned error; malformed dynamic plans are not installed.
pub fn load_pending(raw: Option<&[u8]>) -> Result<Option<Scheduled>, Error> {
    let Some(raw) = raw else { return Ok(None) };
    let update = ValidatorUpdate::parse(Some(raw)).map_err(error)?;
    if !update.weighted {
        return Err("manual validator updates are disabled".into());
    }
    scheduled(&update)
        .map(Some)
        .ok_or_else(|| "weighted validator set is invalid".into())
}
fn light(
    chain: &[u8],
    scheduled: Option<&Scheduled>,
) -> Result<Option<(i64, ValidatorSet)>, Error> {
    scheduled
        .map(|s| {
            s.validators
                .for_epoch(chain, s.activate_epoch)
                .map(|v| (s.activate_epoch, v))
                .map_err(error)
        })
        .transpose()
}
fn transition(active: Option<&Scheduled>, next: Option<&Scheduled>) -> Transition {
    next.map_or_else(
        || active.map_or(Transition::None, |s| Transition::Active(s.activate_epoch)),
        |s| Transition::Scheduled {
            epoch: s.activate_epoch,
            n: s.validators.n,
            quorum: s.validators.quorum,
            fingerprint: s.fingerprint.clone(),
        },
    )
}
impl Config {
    fn rehash(&mut self, chain: &[u8], consensus: bool) -> Result<(), Error> {
        self.hash = if consensus && !self.active_members.is_empty() {
            hash::config_hash(
                chain,
                &self.active,
                self.light_scheduled.as_ref().map(|(e, s)| (*e, s)),
                self.program_trust.as_ref(),
                self.runtime_profile.as_ref(),
            )
            .map_err(error)?
        } else {
            [0; 32]
        };
        Ok(())
    }
    pub fn build(input: Build<'_>) -> Result<Self, Error> {
        let current = validators(input.current);
        let next = validators(input.next);
        let (active_members, scheduled, transition) = match (next.is_empty(), input.activate) {
            (true, _) | (_, None) => (current.clone(), None, Transition::None),
            (false, Some(epoch)) if input.height >= epoch => {
                (next.clone(), None, Transition::Active(epoch))
            }
            (false, Some(epoch)) => {
                let validators = ValidatorSet::unweighted(next.clone());
                let s = Scheduled {
                    activate_epoch: epoch,
                    fingerprint: fingerprint(&validators),
                    validators,
                };
                let t = transition(None, Some(&s));
                (current.clone(), Some(s), t)
            }
        };
        let stake = ValidatorSet::unweighted(active_members.clone());
        let mut cfg = Self {
            allowed_pubkeys: input
                .current
                .iter()
                .chain(input.next)
                .chain(input.chain_pending)
                .filter_map(|e| entries::parse(e).map(|v| v.pubkey))
                .collect(),
            identity_errors: [
                entries::errors(b"current", input.current),
                entries::errors(b"next", input.next),
                entries::errors(b"pending", input.chain_pending),
            ]
            .concat(),
            program_trust: input.program_trust,
            runtime_profile: input.runtime_profile,
            current,
            next,
            active_members,
            active: stake.for_epoch(input.chain, input.height).map_err(error)?,
            stake,
            light_scheduled: light(input.chain, scheduled.as_ref())?,
            scheduled,
            hash: [0; 32],
            transition,
        };
        cfg.rehash(input.chain, input.consensus)?;
        Ok(cfg)
    }
    /// Native boot/recovery binding. Inputs must come from authenticated
    /// canonical state; pending data supplied by a peer is not authority.
    pub fn bind(
        &self,
        chain: &[u8],
        consensus: bool,
        height: i64,
        active: Option<&[u8]>,
        pending: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let parse = |label: &str, raw: Option<&[u8]>| {
            raw.map(|r| {
                ValidatorUpdate::parse(Some(r))
                    .map_err(|e| error(format!("{label} validator set is invalid: {e}")))
            })
            .transpose()
        };
        let active = parse("active", active)?;
        let pending = parse("pending", pending)?;
        if pending.as_ref().is_some_and(|p| !p.weighted) {
            return Err("manual validator updates are disabled".into());
        }
        if active.is_none() && pending.is_none() {
            return Ok(self.clone());
        }
        let required = |label: &str, u: &ValidatorUpdate| {
            scheduled(u).ok_or_else(|| {
                error(format!(
                    "{label} validator set cannot build consensus config"
                ))
            })
        };
        let active_cfg = active
            .as_ref()
            .map(|u| {
                if !u.weighted {
                    Err("active validator set must use bonded weights".into())
                } else if u.activate_epoch > height {
                    Err("active validator set activation is in the future".into())
                } else {
                    required("active", u)
                }
            })
            .transpose()?;
        let pending_cfg = match pending.as_ref() {
            None => None,
            Some(p) => match active.as_ref() {
                None if p.activate_epoch < height => {
                    return Err(
                        "activated pending validator set has no durable active marker".into(),
                    )
                }
                Some(a) if p.fingerprint == a.fingerprint => None,
                Some(a) if p.activate_epoch <= a.activate_epoch => {
                    return Err("pending validator set does not follow durable active set".into())
                }
                Some(_) if p.activate_epoch <= height => {
                    return Err("pending validator set activation is not durable".into())
                }
                _ => Some(required("pending", p)?),
            },
        };
        let mut cfg = self.clone();
        if let Some(active) = &active_cfg {
            cfg.stake = active.validators.clone();
        }
        cfg.active = cfg.stake.for_epoch(chain, height).map_err(error)?;
        cfg.scheduled = match pending_cfg {
            Some(p) => Some(p),
            None if active_cfg.is_some() => None,
            None => cfg.scheduled,
        };
        cfg.light_scheduled = light(chain, cfg.scheduled.as_ref())?;
        cfg.active_members = cfg.active.validators.clone();
        cfg.current = cfg.active_members.clone();
        cfg.next = cfg
            .scheduled
            .as_ref()
            .map_or_else(Vec::new, |s| s.validators.validators.clone());
        cfg.allowed_pubkeys = cfg
            .active
            .validators
            .iter()
            .map(|v| v.pubkey.clone())
            .collect();
        if let Some(s) = &cfg.scheduled {
            let mut keys = s
                .validators
                .validators
                .iter()
                .map(|v| v.pubkey.clone())
                .collect::<Vec<_>>();
            keys.sort();
            keys.dedup();
            cfg.allowed_pubkeys.extend(keys);
        }
        cfg.transition = transition(active_cfg.as_ref(), cfg.scheduled.as_ref());
        cfg.rehash(chain, consensus)?;
        Ok(cfg)
    }
    /// Query the effective set without discarding uncapped bonded stake.
    pub fn validators_at(&self, chain: &[u8], epoch: i64) -> Result<ValidatorSet, Error> {
        self.scheduled
            .as_ref()
            .filter(|s| epoch >= s.activate_epoch)
            .map_or(&self.stake, |s| &s.validators)
            .for_epoch(chain, epoch)
            .map_err(error)
    }
    pub fn transition_message(&self, height: i64) -> Option<String> {
        match &self.transition {
            Transition::None=>None,
            Transition::Active(epoch)=>Some(format!("validator_set transition already active at height = {height} activate_epoch = {epoch}")),
            Transition::Scheduled{epoch,n,quorum,fingerprint}=>Some(format!("validator_set transition scheduled activate_epoch = {epoch} n = {n} quorum = {quorum} fingerprint = {fingerprint}")),
        }
    }
}
