// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Finalized validator duty, participation and readiness state. Sparse marks
//! preserve native bitset semantics without allocating across empty epoch spans.
mod json;
mod proof;
use super::{admission::Candidate, Error};
use crate::consensus::ParentCommit;
pub use crate::duty::Proof;
pub use proof::read_parent;
use std::collections::{BTreeMap, BTreeSet};

pub const META_KEY: &[u8] = b"bft.validator_duty";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Minimum {
    Any,
    Share { numerator: i64, denominator: i64 },
}
fn word(value: i64) -> i64 {
    (value << 1) >> 1
}
impl Minimum {
    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Any => Ok(()),
            Self::Share {
                numerator,
                denominator,
            } if numerator > 0 && denominator > 0 && numerator <= denominator => Ok(()),
            Self::Share { .. } => Err("validator participation share is invalid".into()),
        }
    }
    /// Configurations must have passed validate before becoming runtime policy.
    pub fn required(self, epochs: i64) -> i64 {
        if epochs <= 0 {
            return 0;
        }
        match self {
            Self::Any => 1,
            Self::Share {
                numerator,
                denominator,
            } => word(
                word(
                    epochs
                        .wrapping_mul(numerator)
                        .wrapping_add(denominator)
                        .wrapping_sub(1),
                )
                .wrapping_div(denominator),
            ),
        }
    }
    pub fn consensus_id(self) -> String {
        match self {
            Self::Any => "any".into(),
            Self::Share {
                numerator,
                denominator,
            } => format!("share:{numerator}:{denominator}"),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub window: i64,
    pub challenge: i64,
    pub rejoin_span: i64,
    pub pulse_gap: i64,
    pub cadence: i64,
    pub delay: i64,
    pub max_members: i64,
    pub minimum: Minimum,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            window: 96,
            challenge: 16,
            rejoin_span: 64,
            pulse_gap: 8,
            cadence: 64,
            delay: 64,
            max_members: 200,
            minimum: Minimum::Any,
        }
    }
}
impl Config {
    pub fn participating() -> Self {
        Self {
            window: 32,
            cadence: 4,
            delay: 8,
            minimum: Minimum::Share {
                numerator: 1,
                denominator: 2,
            },
            ..Self::default()
        }
    }
    pub fn validate(&self) -> Result<(), Error> {
        let reason = if !(8..=128).contains(&self.window) {
            Some("validator duty window is outside limits")
        } else if self.challenge < 1 {
            Some("validator duty challenge is not positive")
        } else if self.challenge >= self.window {
            Some("validator duty challenge is not below window")
        } else if self.rejoin_span > 128 {
            Some("validator duty rejoin span exceeds limit")
        } else if self.pulse_gap < 1 {
            Some("validator duty pulse gap is not positive")
        } else if self.pulse_gap > self.rejoin_span {
            Some("validator duty pulse gap exceeds rejoin span")
        } else if self.cadence < 1 {
            Some("validator duty cadence is not positive")
        } else if self.delay < 1 {
            Some("validator duty activation delay is not positive")
        } else if !(4..=200).contains(&self.max_members) {
            Some("validator duty member limit is outside limits")
        } else {
            None
        };
        if let Some(reason) = reason {
            Err(reason.into())
        } else {
            self.minimum.validate()
        }
    }
    pub fn consensus_id(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.window,
            self.challenge,
            self.rejoin_span,
            self.pulse_gap,
            self.cadence,
            self.delay,
            self.max_members,
            self.minimum.consensus_id()
        )
    }
    pub fn replacement_limit(&self) -> i64 {
        self.window
            .wrapping_add(self.challenge)
            .wrapping_add(self.cadence.wrapping_sub(1))
            .wrapping_add(self.delay)
    }
    fn floor_epoch(&self, at: i64) -> i64 {
        let span = self.window.wrapping_add(self.challenge).wrapping_add(2);
        if at < span {
            0
        } else {
            at.wrapping_sub(span)
        }
    }
    fn range(&self, source: i64) -> (i64, i64) {
        let high = source.wrapping_sub(self.challenge);
        (high.wrapping_add(1).wrapping_sub(self.window), high)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pulse {
    first: i64,
    last: i64,
    count: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Live(i64),
    Shadow(Option<Pulse>),
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Marks {
    floor: i64,
    epochs: BTreeSet<i64>,
}
impl Marks {
    fn prune(&mut self, cfg: &Config, at: i64) {
        let floor = cfg.floor_epoch(at);
        if floor > self.floor {
            self.epochs.retain(|n| *n >= floor);
            self.floor = floor;
        }
    }
    fn add(&mut self, cfg: &Config, epoch: i64) {
        self.prune(cfg, epoch);
        if epoch.wrapping_sub(self.floor) >= 0 {
            self.epochs.insert(epoch);
        }
    }
    fn count(&self, low: i64, high: i64) -> i64 {
        let low = low.max(self.floor);
        if low > high {
            0
        } else {
            self.epochs.range(low..=high).count() as i64
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Member {
    address: Vec<u8>,
    phase: Phase,
    marks: Marks,
}
impl Member {
    fn live(epoch: i64, address: Vec<u8>) -> Self {
        Self {
            address,
            phase: Phase::Live(epoch),
            marks: Marks::default(),
        }
    }
    fn shadow(address: Vec<u8>) -> Self {
        Self {
            address,
            phase: Phase::Shadow(None),
            marks: Marks::default(),
        }
    }
    fn retain(&self, cfg: &Config, epoch: i64) -> bool {
        match &self.phase {
            Phase::Live(_) => true,
            Phase::Shadow(None) => !self.marks.epochs.is_empty(),
            Phase::Shadow(Some(p)) => {
                !self.marks.epochs.is_empty()
                    || p.last > epoch
                    || epoch.wrapping_sub(p.last) <= cfg.pulse_gap
            }
        }
    }
    fn shadow_epoch(&self) -> Option<i64> {
        let last = self.marks.epochs.last().copied();
        match &self.phase {
            Phase::Live(_) => None,
            Phase::Shadow(None) => last,
            Phase::Shadow(Some(p)) => Some(last.map_or(p.last, |m| m.max(p.last))),
        }
    }
    fn allows(&self, cfg: &Config, start: i64, source: i64, safe_after: i64) -> bool {
        match &self.phase {
            Phase::Live(_)
                if source < safe_after
                    || source < start.wrapping_add(cfg.window).wrapping_add(cfg.challenge) =>
            {
                true
            }
            Phase::Live(since) => {
                let (low, high) = cfg.range(source);
                *since > low
                    || self.marks.count(low, high)
                        >= cfg
                            .minimum
                            .required(word(high.wrapping_sub(low).wrapping_add(1)))
            }
            Phase::Shadow(None) => false,
            Phase::Shadow(Some(p)) => {
                p.last <= source
                    && source.wrapping_sub(p.last) <= cfg.pulse_gap
                    && p.last.wrapping_sub(p.first) >= cfg.rejoin_span
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Final {
    pub epoch: i64,
    pub proposal_id: Vec<u8>,
    pub set_hash: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentEvidence {
    pub finality: Final,
    pub signers: Vec<Vec<u8>>,
    pub active: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    members: Vec<Member>,
    finals: Vec<Final>,
    safe_after: i64,
    applied: Option<i64>,
    seats: Option<i64>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapMode {
    #[default]
    Reject,
    Prune,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub marked: Vec<i64>,
    pub pulse: Option<i64>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub live: usize,
    pub shadow: usize,
    pub allowed: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exclusion {
    MemberMissing,
    PulseMissing,
    PulseFuture(i64),
    PulseOld(i64),
    PulseShort {
        first: i64,
        last: i64,
    },
    MarksShort {
        low: i64,
        high: i64,
        signed: i64,
        required: i64,
    },
}
type Table = BTreeMap<Vec<u8>, Member>;
fn table(members: &[Member]) -> Table {
    members
        .iter()
        .map(|m| (m.address.clone(), m.clone()))
        .collect()
}
fn limit(cfg: &Config, cap: CapMode, epoch: i64, mut table: Table) -> Result<Table, Error> {
    let limit = word(cfg.max_members.wrapping_mul(4));
    if cap == CapMode::Reject {
        return if table.len() as i64 > limit {
            Err("validator duty state exceeds member limit".into())
        } else {
            Ok(table)
        };
    }
    for member in table.values_mut() {
        member.marks.prune(cfg, epoch);
    }
    table.retain(|_, member| member.retain(cfg, epoch));
    let overflow = table.len() as i64 - limit;
    if overflow <= 0 {
        return Ok(table);
    }
    let mut shadows: Vec<_> = table
        .iter()
        .filter(|(_, m)| matches!(m.phase, Phase::Shadow(_)))
        .map(|(a, m)| (m.shadow_epoch(), a.clone()))
        .collect();
    shadows.sort();
    if (shadows.len() as i64) < overflow {
        return Err("validator duty live state exceeds member limit".into());
    }
    for (_, address) in shadows.into_iter().take(overflow as usize) {
        table.remove(&address);
    }
    Ok(table)
}
enum FinalStep {
    Applied(State),
    Held(State, Error),
}
impl State {
    pub fn seats(&self) -> Option<i64> {
        self.seats
    }
    pub fn find_final(&self, epoch: i64) -> Option<&Final> {
        self.finals.iter().find(|f| f.epoch == epoch)
    }
    fn sync(&self, cfg: &Config, epoch: i64, active: &[Vec<u8>]) -> Result<Self, Error> {
        let active: BTreeSet<_> = active.iter().cloned().collect();
        if active.len() as i64 > cfg.max_members {
            return Err("validator duty active set exceeds limit".into());
        }
        let mut members = table(&self.members);
        for member in members.values_mut() {
            member.phase = match (active.contains(&member.address), &member.phase) {
                (true, Phase::Live(since)) => Phase::Live(*since),
                (true, Phase::Shadow(_)) => Phase::Live(epoch),
                (false, Phase::Live(_)) => Phase::Shadow(None),
                (false, Phase::Shadow(p)) => Phase::Shadow(p.clone()),
            };
            member.marks.prune(cfg, epoch);
        }
        for address in active {
            members
                .entry(address.clone())
                .or_insert_with(|| Member::live(epoch, address));
        }
        Ok(Self {
            members: members
                .into_values()
                .filter(|m| m.retain(cfg, epoch))
                .collect(),
            ..self.clone()
        })
    }
    pub fn note_set(&self, cfg: &Config, epoch: i64, active: &[Vec<u8>]) -> Result<Self, Error> {
        cfg.validate()?;
        if epoch < 0 {
            return Err("validator duty set epoch is negative".into());
        }
        self.sync(cfg, epoch, active)
    }
    pub fn lock(&self, cfg: &Config, active: &[Vec<u8>]) -> Result<(Self, bool), Error> {
        cfg.validate()?;
        let seats = self
            .seats
            .unwrap_or_else(|| active.iter().collect::<BTreeSet<_>>().len() as i64);
        if seats < 4 || seats > cfg.max_members {
            return Err("validator seat limit is outside limits".into());
        }
        Ok((
            Self {
                seats: Some(seats),
                ..self.clone()
            },
            self.seats.is_none(),
        ))
    }
    pub fn receipt(&self, address: &[u8]) -> Receipt {
        self.members.iter().find(|m| m.address == address).map_or(
            Receipt {
                marked: vec![],
                pulse: None,
            },
            |m| Receipt {
                marked: m.marks.epochs.iter().copied().collect(),
                pulse: match &m.phase {
                    Phase::Shadow(Some(p)) => Some(p.last),
                    _ => None,
                },
            },
        )
    }
    pub fn delay(&self, cfg: &Config, at: i64) -> Result<Self, Error> {
        cfg.validate()?;
        if at < 0 {
            return Err("validator duty delay epoch is negative".into());
        }
        Ok(Self {
            safe_after: self
                .safe_after
                .max(at.wrapping_add(cfg.window).wrapping_add(cfg.challenge)),
            ..self.clone()
        })
    }
    fn put_final(&self, cfg: &Config, at: i64, finality: &Final) -> Result<Vec<Final>, Error> {
        let prior = self.find_final(finality.epoch);
        if prior.is_some_and(|p| p != finality) {
            return Err("validator duty finality conflict".into());
        }
        let span = cfg.challenge.wrapping_add(1);
        let floor = if at < span { 0 } else { at.wrapping_sub(span) };
        let mut finals = self.finals.clone();
        if prior.is_none() {
            finals.push(finality.clone());
            finals.sort_by_key(|f| f.epoch);
        }
        finals.retain(|f| f.epoch >= floor);
        Ok(finals)
    }
    fn note_final_step(
        &self,
        cfg: &Config,
        cap: CapMode,
        at: i64,
        active: &[Vec<u8>],
        finality: &Final,
        signers: &[Vec<u8>],
    ) -> FinalStep {
        let held = |e: Error| FinalStep::Held(self.clone(), e);
        if let Err(e) = cfg.validate() {
            return held(e);
        }
        if at <= 0 {
            return held("validator duty apply epoch is not positive".into());
        }
        if finality.epoch.wrapping_add(1) != at {
            return held("validator duty finality epoch is not parent".into());
        }
        let mut state = match self.sync(cfg, at, active) {
            Ok(s) => s,
            Err(e) => return held(e),
        };
        let mut members = table(&state.members);
        // Repeated signers set the same mark in the same address-keyed entry.
        for signer in signers {
            members
                .entry(signer.clone())
                .or_insert_with(|| Member::shadow(signer.clone()))
                .marks
                .add(cfg, finality.epoch);
        }
        let members = match limit(cfg, cap, at, members) {
            Ok(t) => t,
            Err(e) => return FinalStep::Held(state, e),
        };
        state.members = members.into_values().collect();
        match state.put_final(cfg, at, finality) {
            Ok(finals) => {
                state.finals = finals;
                FinalStep::Applied(state)
            }
            Err(e) => FinalStep::Held(state, e),
        }
    }
    pub fn note_final(
        &self,
        cfg: &Config,
        cap: CapMode,
        at: i64,
        active: &[Vec<u8>],
        finality: &Final,
        signers: &[Vec<u8>],
    ) -> Result<Self, Error> {
        match self.note_final_step(cfg, cap, at, active, finality, signers) {
            FinalStep::Applied(s) => Ok(s),
            FinalStep::Held(_, e) => Err(e),
        }
    }
    pub fn note_pulse(
        &self,
        cfg: &Config,
        cap: CapMode,
        credit: Option<i64>,
        epoch: i64,
        active: bool,
        address: &[u8],
    ) -> Result<Self, Error> {
        cfg.validate()?;
        let credit = credit.unwrap_or(epoch);
        if address.is_empty() {
            return Err("validator duty pulse address is empty".into());
        }
        if epoch < 0 {
            return Err("validator duty pulse epoch is negative".into());
        }
        if credit < 0 || credit > epoch {
            return Err("validator duty pulse credit is outside execution epoch".into());
        }
        if active {
            return Ok(self.clone());
        }
        let mut members = table(&self.members);
        let member = members
            .entry(address.to_vec())
            .or_insert_with(|| Member::shadow(address.to_vec()));
        let prior = match &member.phase {
            Phase::Live(_) => None,
            Phase::Shadow(p) => p.as_ref(),
        };
        let pulse = match prior {
            Some(p) if epoch < p.last => {
                return Err("validator duty pulse epoch moved backward".into())
            }
            Some(p) if epoch == p.last => p.clone(),
            Some(p) if epoch.wrapping_sub(p.last) <= cfg.pulse_gap => {
                if credit <= p.last {
                    p.clone()
                } else {
                    Pulse {
                        last: credit,
                        count: word(p.count.wrapping_add(1)),
                        ..p.clone()
                    }
                }
            }
            None | Some(_) => Pulse {
                first: epoch,
                last: epoch,
                count: 1,
            },
        };
        member.phase = Phase::Shadow(Some(pulse));
        member.marks.prune(cfg, epoch);
        Ok(Self {
            members: limit(cfg, cap, epoch, members)?.into_values().collect(),
            ..self.clone()
        })
    }
    pub fn advance(
        &self,
        cfg: &Config,
        cap: CapMode,
        chain: &[u8],
        start: i64,
        at: i64,
        parent: Option<&ParentCommit>,
    ) -> Result<(Self, Option<String>, bool), Error> {
        if self.applied == Some(at) {
            return Ok((self.clone(), None, false));
        }
        if self.applied.is_some_and(|e| e > at) {
            return Err("validator duty apply epoch moved backward".into());
        }
        let gap = self.applied.map_or(at > start, |e| at > e.wrapping_add(1));
        let ParentEvidence {
            finality,
            signers,
            active,
        } = proof::read_parent(chain, parent.ok_or("validator duty parent commit missing")?)?;
        let (mut state, mut reason) =
            match self.note_final_step(cfg, cap, at, &active, &finality, &signers) {
                FinalStep::Applied(s) => (s, None),
                FinalStep::Held(s, e) => (s.delay(cfg, at)?, Some(e.0)),
            };
        if gap {
            state = state.delay(cfg, at)?;
            reason = Some("epoch_gap".into());
        }
        state.applied = Some(at);
        Ok((state, reason, true))
    }
    #[allow(clippy::too_many_arguments)] // A duty proof binds chain, epoch, owner and membership.
    pub fn apply_proof(
        &self,
        cfg: &Config,
        cap: CapMode,
        chain: &[u8],
        epoch: i64,
        active: bool,
        address: &[u8],
        proof: &Proof,
    ) -> Result<Self, Error> {
        proof::verify(cfg, chain, epoch, address, proof, self)?;
        let mut members = table(&self.members);
        let member = members.entry(address.to_vec()).or_insert_with(|| {
            if active {
                Member::live(proof.vote.epoch_id, address.to_vec())
            } else {
                Member::shadow(address.to_vec())
            }
        });
        member.marks.add(cfg, proof.vote.epoch_id);
        Ok(Self {
            members: limit(cfg, cap, epoch, members)?.into_values().collect(),
            ..self.clone()
        })
    }
    pub fn allows(&self, cfg: &Config, start: i64, source: i64, address: &[u8]) -> bool {
        self.members
            .iter()
            .find(|m| m.address == address)
            .is_some_and(|m| m.allows(cfg, start, source, self.safe_after))
    }
    pub fn exclusion(
        &self,
        cfg: &Config,
        start: i64,
        source: i64,
        address: &[u8],
    ) -> Option<Exclusion> {
        let Some(member) = self.members.iter().find(|m| m.address == address) else {
            return Some(Exclusion::MemberMissing);
        };
        if member.allows(cfg, start, source, self.safe_after) {
            return None;
        }
        Some(match &member.phase {
            Phase::Live(_) => {
                let (low, high) = cfg.range(source);
                Exclusion::MarksShort {
                    low,
                    high,
                    signed: member.marks.count(low, high),
                    required: cfg
                        .minimum
                        .required(word(high.wrapping_sub(low).wrapping_add(1))),
                }
            }
            Phase::Shadow(None) => Exclusion::PulseMissing,
            Phase::Shadow(Some(p)) if p.last > source => Exclusion::PulseFuture(p.last),
            Phase::Shadow(Some(p)) if source.wrapping_sub(p.last) > cfg.pulse_gap => {
                Exclusion::PulseOld(p.last)
            }
            Phase::Shadow(Some(p)) => Exclusion::PulseShort {
                first: p.first,
                last: p.last,
            },
        })
    }
    pub fn filter(
        &self,
        cfg: &Config,
        start: i64,
        source: i64,
        candidates: &[Candidate],
    ) -> (Vec<Candidate>, Counts) {
        let members = table(&self.members);
        let mut allowed = Vec::new();
        let mut counts = Counts::default();
        for candidate in candidates {
            if let Some(member) = members.get(&candidate.address) {
                if member.allows(cfg, start, source, self.safe_after) {
                    allowed.push(candidate.clone());
                    match member.phase {
                        Phase::Live(_) => counts.live += 1,
                        Phase::Shadow(_) => counts.shadow += 1,
                    }
                } else {
                    counts.shadow += 1;
                }
            }
        }
        counts.allowed = allowed.len();
        (allowed, counts)
    }
}
