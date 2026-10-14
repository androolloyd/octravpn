// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{policy, Bytes, Error, Proposal, Validator, ValidatorSet};
use crate::oce1::Writer;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub fn quorum_weight(total: &BigInt) -> BigInt {
    (total * 2) / 3 + 1
}
fn build(weighted: bool, mut entries: Vec<(Validator, BigInt)>) -> ValidatorSet {
    entries.sort_by(|a, b| a.0.address.cmp(&b.0.address));
    let total_weight: BigInt = entries.iter().map(|e| &e.1).sum();
    let n = entries.len() as i64;
    let f = (n - 1) / 3;
    let quorum = if n <= 0 {
        0
    } else if n < 4 {
        n
    } else {
        n - f
    };
    ValidatorSet {
        validators: entries.iter().map(|e| e.0.clone()).collect(),
        weights: entries.into_iter().map(|(v, w)| (v.address, w)).collect(),
        n,
        f,
        quorum,
        quorum_weight: if total_weight > BigInt::zero() {
            quorum_weight(&total_weight)
        } else {
            BigInt::zero()
        },
        total_weight,
        weighted,
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
        &total - unavailable >= quorum_weight(&total)
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
    pub fn for_epoch(&self, chain_id: &[u8], epoch_id: i64) -> Result<Self, Error> {
        if policy::quorum_active(chain_id, epoch_id) {
            self.count_capped()
        } else {
            Ok(self.clone())
        }
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
    pub fn has_weight_quorum(&self, signers: &[Bytes]) -> bool {
        self.signed_weight(signers)
            .is_some_and(|weight| weight >= self.quorum_weight)
    }
    pub fn has_quorum_values(&self, count: i64, weight: &BigInt) -> bool {
        count >= self.quorum && weight >= &self.quorum_weight
    }
    pub fn has_quorum(&self, signers: &[Bytes]) -> bool {
        self.signed_weight(signers).is_some_and(|weight| {
            self.has_quorum_values(
                signers.iter().collect::<BTreeSet<_>>().len() as i64,
                &weight,
            )
        })
    }
    pub fn has_quorum_at(
        &self,
        chain_id: &[u8],
        epoch_id: i64,
        signers: &[Bytes],
    ) -> Result<bool, Error> {
        let effective = self.for_epoch(chain_id, epoch_id)?;
        Ok(if policy::quorum_active(chain_id, epoch_id) {
            effective.has_quorum(signers)
        } else {
            effective.has_weight_quorum(signers)
        })
    }
    pub fn quorum_reached_at(
        &self,
        chain_id: &[u8],
        epoch_id: i64,
        count: i64,
        weight: &BigInt,
    ) -> bool {
        weight >= &self.quorum_weight
            && (!policy::quorum_active(chain_id, epoch_id) || count >= self.quorum)
    }
    pub fn round_skip_weight(&self) -> BigInt {
        &self.total_weight - &self.quorum_weight + 1
    }
    pub fn round_skip_reached_at(
        &self,
        chain_id: &[u8],
        epoch_id: i64,
        count: i64,
        weight: &BigInt,
    ) -> bool {
        weight >= &self.round_skip_weight()
            && (!policy::quorum_active(chain_id, epoch_id) || count > self.f)
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
                self.is_validator(&proposal.header.creator_addr)
            })
    }
}
