// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
pub use super::measure::quota as quorum_weight;
use super::measure::{self, Ask, Space};
use super::{policy, Bytes, Error, Proposal, Validator, ValidatorSet};
use crate::oce1::Writer;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
/// Why a validator set cannot vote at an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetError {
    /// The set is not a well-formed declared-weight set.
    Shape(Error),
    /// One member alone holds blocking weight under seatless voting.
    SeatCap,
}
impl SetError {
    pub fn message(&self) -> Error {
        match self {
            Self::Shape(reason) => reason.clone(),
            Self::SeatCap => "validator weight reaches blocking threshold".into(),
        }
    }
}
impl From<SetError> for Error {
    fn from(error: SetError) -> Self {
        error.message()
    }
}
/// What removing offenders does to a set: the reduced set, or the set kept
/// as it is because the offenders hold blocking weight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictionChoice {
    Remove(ValidatorSet, BigInt),
    Retain(BigInt),
}
/// Which set votes when a scheduled set is offered at an epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetChoice {
    Active(ValidatorSet),
    Pending(ValidatorSet),
}
fn build(weighted: bool, mut entries: Vec<(Validator, BigInt)>) -> ValidatorSet {
    entries.sort_by(|a, b| a.0.address.cmp(&b.0.address));
    let measure::Shape {
        n,
        f,
        quorum,
        total_weight,
        quorum_weight,
    } = measure::shape(
        entries.len() as i64,
        entries.iter().map(|entry| &entry.1).sum(),
    );
    ValidatorSet {
        validators: entries.iter().map(|e| e.0.clone()).collect(),
        weights: entries.into_iter().map(|(v, w)| (v.address, w)).collect(),
        n,
        f,
        quorum,
        quorum_weight,
        total_weight,
        weighted,
        authors: None,
    }
}
impl ValidatorSet {
    pub fn unweighted(validators: Vec<Validator>) -> Self {
        build(
            false,
            validators.into_iter().map(|v| (v, BigInt::one())).collect(),
        )
    }
    pub fn weighted(entries: Vec<(Validator, BigInt)>) -> Result<Self, Error> {
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for (validator, weight) in &entries {
            if validator.address.is_empty() {
                return Err("validator address is empty".into());
            }
            if validator.pubkey.len() != 32 {
                return Err("validator public key must contain 32 bytes".into());
            }
            if weight <= &BigInt::zero() {
                return Err("validator weight must be positive".into());
            }
            if !addresses.insert(&validator.address) {
                return Err("duplicate validator address".into());
            }
            if !keys.insert(&validator.pubkey) {
                return Err("duplicate validator public key".into());
            }
        }
        if entries.is_empty() {
            return Err("validator set is empty".into());
        }
        Ok(build(true, entries))
    }
    pub fn public_key(&self, address: &[u8]) -> Option<&[u8]> {
        self.validators
            .iter()
            .find(|v| v.address == address)
            .map(|v| v.pubkey.as_slice())
    }
    pub fn is_validator(&self, address: &[u8]) -> bool {
        self.public_key(address).is_some()
    }
    pub fn weight(&self, address: &[u8]) -> Option<&BigInt> {
        self.weights.iter().find(|v| v.0 == address).map(|v| &v.1)
    }
    pub fn entries(&self) -> Result<Vec<(Validator, BigInt)>, Error> {
        self.validators
            .iter()
            .map(|v| {
                self.weight(&v.address)
                    .map(|w| (v.clone(), w.clone()))
                    .ok_or_else(|| "validator weight missing".into())
            })
            .collect()
    }
    fn live_at_cap(&self, cap: &BigInt, entries: &[(Validator, BigInt)]) -> bool {
        let mut weights: Vec<_> = entries.iter().map(|(_, w)| w.min(cap).clone()).collect();
        let total: BigInt = weights.iter().sum();
        weights.sort_by(|a, b| b.cmp(a));
        let unavailable: BigInt = weights.iter().take(self.f.max(0) as usize).sum();
        measure::live(&total, &unavailable)
    }
    pub fn count_weight_cap(&self) -> Result<BigInt, Error> {
        let entries = self.entries()?;
        let Some(maximum) = entries.iter().map(|(_, w)| w).max() else {
            return Ok(BigInt::zero());
        };
        if self.f <= 0 || self.live_at_cap(maximum, &entries) {
            return Ok(maximum.clone());
        }
        let mut lower = BigInt::one();
        let mut upper = maximum.clone();
        while lower < upper {
            let middle = (&lower + &upper + 1) / 2;
            if self.live_at_cap(&middle, &entries) {
                lower = middle;
            } else {
                upper = middle - 1;
            }
        }
        Ok(lower)
    }
    pub fn count_capped(&self) -> Result<Self, Error> {
        if !self.weighted || self.n < 4 {
            return Ok(self.clone());
        }
        let cap = self.count_weight_cap()?;
        Ok(build(
            true,
            self.entries()?
                .into_iter()
                .map(|(v, w)| (v, w.min(cap.clone())))
                .collect(),
        ))
    }
    pub fn for_rule(&self, rule: policy::Rule) -> Result<Self, Error> {
        match rule {
            policy::Rule::Capped => self.count_capped(),
            _ => Ok(self.clone()),
        }
    }
    pub fn for_policy(&self, policy: policy::QuorumPolicy, epoch: i64) -> Result<Self, Error> {
        let rule = policy.select(epoch);
        let mut set = self.clone();
        if set
            .authors
            .as_ref()
            .is_some_and(|(height, _)| *height != epoch || rule != policy::Rule::Stake)
        {
            set.authors = None;
        }
        set.for_rule(rule)
    }
    pub fn for_epoch(&self, chain_id: &[u8], epoch_id: i64) -> Result<Self, Error> {
        self.for_policy(policy::QuorumPolicy::for_chain(chain_id), epoch_id)
    }
    /// The set rebuilt from its own members and weights, if it is exactly the
    /// declared-weight set those members and weights describe.
    pub fn validate_shape(&self) -> Result<Self, SetError> {
        if !self.weighted {
            return Err(SetError::Shape("validator weights are not declared".into()));
        }
        let mut members: Vec<_> = self.validators.iter().collect();
        members.sort_by(|left, right| left.address.cmp(&right.address));
        let mut weights: Vec<_> = self.weights.iter().collect();
        weights.sort_by(|left, right| left.0.cmp(&right.0));
        if members.len() != weights.len()
            || members
                .iter()
                .zip(&weights)
                .any(|(member, (address, _))| &member.address != address)
        {
            return Err(SetError::Shape(
                "validator weight membership differs".into(),
            ));
        }
        let entries: Vec<_> = members
            .into_iter()
            .zip(weights)
            .map(|(member, (_, weight))| (member.clone(), weight.clone()))
            .collect();
        let mut checked = Self::weighted(entries.clone()).map_err(SetError::Shape)?;
        if self.n != checked.n
            || self.f != checked.f
            || self.quorum != checked.quorum
            || self.total_weight != checked.total_weight
            || self.quorum_weight != checked.quorum_weight
        {
            return Err(SetError::Shape("validator set shape differs".into()));
        }
        if let Some((height, authors)) = &self.authors {
            let authors = Self::weighted(authors.clone())
                .and_then(|set| set.entries())
                .map_err(SetError::Shape)?;
            let mut combined = entries;
            combined.extend(authors.iter().cloned());
            Self::weighted(combined).map_err(SetError::Shape)?;
            checked.authors = Some((*height, authors));
        }
        Ok(checked)
    }
    /// Same members, keys and weights, ignoring any one-epoch authors.
    pub fn same_voting_set(&self, other: &Self) -> bool {
        let voting = |set: &Self| {
            Self {
                authors: None,
                ..set.clone()
            }
            .validate_shape()
        };
        matches!((voting(self), voting(other)), (Ok(left), Ok(right)) if left == right)
    }
    /// The set that votes at `epoch`; under seatless voting it must also be
    /// a well-formed declared-weight set.
    pub fn structural_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
    ) -> Result<Self, SetError> {
        let effective = self.for_policy(policy, epoch).map_err(SetError::Shape)?;
        if !policy.seatless(epoch) {
            return Ok(effective);
        }
        self.validate_shape()?;
        effective.validate_shape()
    }
    pub fn structural_for_epoch(&self, chain: &[u8], epoch: i64) -> Result<Self, SetError> {
        self.structural_for_policy(policy::QuorumPolicy::for_chain(chain), epoch)
    }
    /// [`Self::structural_for_policy`], and under seatless voting no single
    /// member may hold blocking weight.
    pub fn validate_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
    ) -> Result<Self, SetError> {
        let checked = self.structural_for_policy(policy, epoch)?;
        if !policy.seatless(epoch) {
            return Ok(checked);
        }
        let limit = measure::minority(&measure::shape(checked.n, checked.total_weight.clone()));
        if checked.weights.iter().any(|(_, weight)| weight >= &limit) {
            return Err(SetError::SeatCap);
        }
        Ok(checked)
    }
    pub fn checked_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
    ) -> Result<Self, Error> {
        self.validate_for_policy(policy, epoch)
            .map_err(|error| error.message())
    }
    pub fn checked_for_epoch(&self, chain: &[u8], epoch: i64) -> Result<Self, Error> {
        self.checked_for_policy(policy::QuorumPolicy::for_chain(chain), epoch)
    }
    pub fn plan_eviction(&self, offenders: &[Bytes]) -> Result<EvictionChoice, Error> {
        let checked = self.validate_shape().map_err(|error| error.message())?;
        let unique: BTreeSet<_> = offenders.iter().collect();
        if unique.is_empty() {
            return Err("validator eviction requires offenders".into());
        }
        if unique.len() != offenders.len() {
            return Err("duplicate eviction offender".into());
        }
        if unique
            .iter()
            .any(|address| checked.weight(address).is_none())
        {
            return Err("eviction offender is not an active validator".into());
        }
        let (removed, remaining): (Vec<_>, Vec<_>) = checked
            .entries()?
            .into_iter()
            .partition(|(member, _)| unique.contains(&member.address));
        let weight: BigInt = removed.iter().map(|(_, weight)| weight).sum();
        if !measure::live(&checked.total_weight, &weight) {
            return Ok(EvictionChoice::Retain(weight));
        }
        Ok(EvictionChoice::Remove(Self::weighted(remaining)?, weight))
    }
    pub fn evict(&self, offenders: &[Bytes]) -> Result<(Self, BigInt), Error> {
        match self.plan_eviction(offenders)? {
            EvictionChoice::Remove(next, weight) => Ok((next, weight)),
            EvictionChoice::Retain(_) => Err("evicted weight reaches blocking threshold".into()),
        }
    }
    /// The set that votes when `self` is scheduled for `epoch`: itself, or —
    /// when it would hand one member blocking weight — the still-active set.
    pub fn pending_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        active: Option<&Self>,
    ) -> Result<SetChoice, SetError> {
        let active = match active {
            Some(active) if policy.seatless(epoch) => {
                Some(active.structural_for_policy(policy, epoch)?)
            }
            _ => None,
        };
        match self.validate_for_policy(policy, epoch) {
            Ok(set) => Ok(SetChoice::Pending(set)),
            Err(SetError::SeatCap) => active
                .map(SetChoice::Active)
                .ok_or_else(|| SetError::Shape("active validator set is missing".into())),
            Err(error) => Err(error),
        }
    }
    pub fn space_for_rule(&self, rule: policy::Rule) -> Space {
        measure::ruled(rule, self.weighted, &self.weights)
    }
    pub fn space(&self, policy: policy::QuorumPolicy, epoch: i64) -> Space {
        measure::space(policy, epoch, self.weighted, &self.weights)
    }
    pub fn space_at(&self, chain: &[u8], epoch: i64) -> Space {
        self.space(policy::QuorumPolicy::for_chain(chain), epoch)
    }
    pub fn author_entry(
        &self,
        chain: &[u8],
        epoch: i64,
        address: &[u8],
    ) -> Option<(&Validator, &BigInt)> {
        if let Some(member) = self.validators.iter().find(|v| v.address == address) {
            return self.weight(address).map(|weight| (member, weight));
        }
        self.authors
            .as_ref()
            .filter(|(height, _)| {
                *height == epoch && policy::quorum_rule(chain, epoch) == policy::Rule::Stake
            })
            .and_then(|(_, entries)| entries.iter().find(|(member, _)| member.address == address))
            .map(|(member, weight)| (member, weight))
    }
    pub fn is_author(&self, chain: &[u8], epoch: i64, address: &[u8]) -> bool {
        self.author_entry(chain, epoch, address).is_some()
    }
    pub fn source_set(&self, chain: &[u8], epoch: i64) -> Option<Self> {
        let (_, authors) = self.authors.as_ref().filter(|(height, _)| {
            *height == epoch && policy::quorum_rule(chain, epoch) == policy::Rule::Stake
        })?;
        let mut entries = self.entries().ok()?;
        entries.extend(authors.clone());
        Self::weighted(entries).ok()
    }
    pub fn weights_valid(&self, rule: policy::Rule) -> bool {
        self.space_for_rule(rule).valid()
    }
    pub fn signed_weight(&self, signers: &[Bytes]) -> Option<BigInt> {
        let mut seen = BTreeSet::new();
        let mut total = BigInt::zero();
        for signer in signers {
            if seen.insert(signer) {
                total += self.weight(signer)?;
            }
        }
        Some(total)
    }
    fn unique_signers(signers: &[Bytes]) -> i64 {
        signers.iter().collect::<BTreeSet<_>>().len() as i64
    }
    pub fn has_quorum_at(
        &self,
        chain: &[u8],
        epoch: i64,
        signers: &[Bytes],
    ) -> Result<bool, Error> {
        self.has_quorum_for_policy(policy::QuorumPolicy::for_chain(chain), epoch, signers)
    }
    pub fn has_quorum_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        signers: &[Bytes],
    ) -> Result<bool, Error> {
        let effective = self.for_rule(policy.select(epoch))?;
        Ok(effective.signed_weight(signers).is_some_and(|weight| {
            effective.space(policy, epoch).meets(
                Ask::Quorum,
                Self::unique_signers(signers),
                &weight,
            )
        }))
    }
    /// Signers of this exact set that both finality and the next set's
    /// authority can rest on.
    pub fn pair_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        signers: &[Bytes],
    ) -> bool {
        self.signed_weight(signers).is_some_and(|weight| {
            self.space(policy, epoch)
                .meets(Ask::Pair, Self::unique_signers(signers), &weight)
        })
    }
    pub fn pair_at(&self, chain: &[u8], epoch: i64, signers: &[Bytes]) -> bool {
        self.pair_for_policy(policy::QuorumPolicy::for_chain(chain), epoch, signers)
    }
    /// Whether enough peers answered to promise the local vote floor. Unknown
    /// responders count as seats but carry no weight, as upstream counts them.
    pub fn promise_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        responders: &[Bytes],
    ) -> bool {
        let weight: BigInt = responders
            .iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|address| self.weight(address))
            .sum();
        self.space(policy, epoch)
            .meets(Ask::Promise, responders.len() as i64, &weight)
    }
    pub fn promise_at(&self, chain: &[u8], epoch: i64, responders: &[Bytes]) -> bool {
        self.promise_for_policy(policy::QuorumPolicy::for_chain(chain), epoch, responders)
    }
    pub fn quorum_reached_at(&self, chain: &[u8], epoch: i64, count: i64, weight: &BigInt) -> bool {
        self.quorum_reached_for_policy(policy::QuorumPolicy::for_chain(chain), epoch, count, weight)
    }
    pub fn quorum_reached_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        count: i64,
        weight: &BigInt,
    ) -> bool {
        self.space(policy, epoch).meets(Ask::Quorum, count, weight)
    }
    pub fn round_skip_weight(&self) -> BigInt {
        measure::minority(&measure::shape(self.n, self.total_weight.clone()))
    }
    pub fn round_skip_reached_at(
        &self,
        chain: &[u8],
        epoch: i64,
        count: i64,
        weight: &BigInt,
    ) -> bool {
        self.round_skip_reached_for_policy(
            policy::QuorumPolicy::for_chain(chain),
            epoch,
            count,
            weight,
        )
    }
    pub fn round_skip_reached_for_policy(
        &self,
        policy: policy::QuorumPolicy,
        epoch: i64,
        count: i64,
        weight: &BigInt,
    ) -> bool {
        self.space(policy, epoch).meets(Ask::Skip, count, weight)
    }
    pub fn leader(&self, epoch_id: i64, round: i64) -> Result<&Validator, Error> {
        if self.n <= 0 {
            return Err("validator set is empty".into());
        }
        if round < 0 {
            return Err("consensus round is negative".into());
        }
        if !self.weighted {
            let index = epoch_id % self.n;
            let added = index.wrapping_add(round).wrapping_shl(1) >> 1;
            let index = added % self.n;
            if index < 0 {
                return Err("List.nth".into());
            }
            return self
                .validators
                .get(index as usize)
                .ok_or_else(|| "nth".into());
        }
        let mut writer = Writer::new();
        writer.put_bytes(b"octra:weighted_leader:v1")?;
        writer.put_u64(epoch_id as u64)?;
        writer.put_u32(round as u32)?;
        writer.put_list(&self.validators, |writer, v| {
            writer.put_bytes(&v.address)?;
            writer.put_raw(&v.pubkey)?;
            let weight = self
                .weight(&v.address)
                .ok_or_else(|| Error::from("validator weight missing"))?;
            writer.put_bytes(weight.to_string().as_bytes())
        })?;
        if self.total_weight.is_zero() {
            return Err("Division_by_zero".into());
        }
        let target = BigInt::from_bytes_be(Sign::Plus, &Sha256::digest(writer.into_bytes()))
            % &self.total_weight;
        let mut offset = BigInt::zero();
        for validator in &self.validators {
            offset += self
                .weight(&validator.address)
                .ok_or_else(|| Error::from("validator weight missing"))?;
            if target < offset {
                return Ok(validator);
            }
        }
        Err("validator leader selection failed".into())
    }
    pub fn proposal_well_formed(
        &self,
        chain_id: &[u8],
        protocol: policy::Protocol,
        proposal: &Proposal,
    ) -> Result<bool, Error> {
        Ok(self.n > 0
            && proposal.round >= 0
            && proposal.chain_id == chain_id
            && proposal.header.proto_version == protocol.version_at(proposal.epoch_id)
            && proposal.header.chain_id == proposal.chain_id
            && proposal.header.epoch_id == proposal.epoch_id
            && super::valid_round_is_well_formed(proposal.round, proposal.valid_round)
            && self.leader(proposal.epoch_id, proposal.round)?.address == proposal.proposer
            && if proposal.valid_round.is_none() {
                proposal.header.creator_addr == proposal.proposer
            } else {
                self.is_author(chain_id, proposal.epoch_id, &proposal.header.creator_addr)
            })
    }
}
