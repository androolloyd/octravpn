// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{put_string, Error};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub address: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub bond: BigInt,
    pub bonded_epoch: i64,
    pub ready_epoch: Option<i64>,
    pub exit_epoch: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub address: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub min_bond: BigInt,
    pub max_validators: i64,
    pub activation_delay: i64,
    pub unbonding_epochs: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub source_epoch: i64,
    pub activate_epoch: i64,
    pub validators: Vec<Member>,
    pub total_weight: BigInt,
    pub quorum_weight: BigInt,
    pub fingerprint: String,
}
impl Parameters {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.min_bond.is_positive() {
            Err("validator minimum bond must be positive".into())
        } else if self.max_validators < 4 {
            Err("validator set requires at least four slots".into())
        } else if self.activation_delay <= 0 {
            Err("validator activation delay must be positive".into())
        } else if self.unbonding_epochs <= 0 {
            Err("validator unbonding period must be positive".into())
        } else {
            Ok(())
        }
    }
    pub fn source_epoch(&self, activate_epoch: i64) -> Result<i64, Error> {
        if activate_epoch < self.activation_delay {
            Err("validator activation epoch precedes snapshot delay".into())
        } else {
            Ok(activate_epoch.wrapping_sub(self.activation_delay))
        }
    }
    pub fn withdraw_epoch(&self, candidate: &Candidate) -> Result<i64, Error> {
        self.validate()?;
        candidate.validate()?;
        add_epoch(
            candidate
                .exit_epoch
                .ok_or("validator exit was not requested")?,
            self.unbonding_epochs,
        )
    }
}
impl Candidate {
    pub fn validate(&self) -> Result<(), Error> {
        if self.address.is_empty() {
            Err("validator address is empty".into())
        } else if self.pubkey.len() != 32 {
            Err("validator public key must contain 32 bytes".into())
        } else if !self.bond.is_positive() {
            Err("validator bond must be positive".into())
        } else if self.bonded_epoch < 0 {
            Err("validator bonded epoch is negative".into())
        } else if self.ready_epoch.is_some_and(|v| v < self.bonded_epoch) {
            Err("validator readiness predates bond".into())
        } else if self.exit_epoch.is_some_and(|v| v < self.bonded_epoch) {
            Err("validator exit predates bond".into())
        } else {
            Ok(())
        }
    }
    pub fn eligible(&self, parameters: &Parameters, source_epoch: i64) -> bool {
        self.bond >= parameters.min_bond
            && self.bonded_epoch <= source_epoch
            && self.ready_epoch.is_some_and(|v| v <= source_epoch)
            && self.exit_epoch.is_none()
    }
}
pub fn quorum_weight(total: &BigInt) -> Result<BigInt, Error> {
    if !total.is_positive() {
        return Err("validator total weight must be positive".into());
    }
    Ok(total * 2 / 3 + 1)
}
pub(crate) fn validate_unique(candidates: &[Candidate], key_error: &str) -> Result<(), Error> {
    let mut addresses = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for candidate in candidates {
        if !addresses.insert(&candidate.address) {
            return Err("duplicate validator address".into());
        }
        if !keys.insert(&candidate.pubkey) {
            return Err(key_error.into());
        }
    }
    Ok(())
}
pub fn snapshot(
    parameters: &Parameters,
    activate_epoch: i64,
    candidates: &[Candidate],
    incumbents: &[Vec<u8>],
) -> Result<Snapshot, Error> {
    parameters.validate()?;
    let source_epoch = parameters.source_epoch(activate_epoch)?;
    for candidate in candidates {
        candidate.validate()?;
    }
    validate_unique(candidates, "duplicate validator public key")?;
    let incumbents: BTreeSet<_> = incumbents.iter().collect();
    let mut selected: Vec<_> = candidates
        .iter()
        .filter(|c| c.eligible(parameters, source_epoch))
        .collect();
    selected.sort_by(|l, r| {
        incumbents
            .contains(&r.address)
            .cmp(&incumbents.contains(&l.address))
            .then_with(|| r.bond.cmp(&l.bond))
            .then_with(|| l.address.cmp(&r.address))
            .then_with(|| l.pubkey.cmp(&r.pubkey))
    });
    selected.truncate(parameters.max_validators as usize);
    if selected.len() < 4 {
        return Err("validator snapshot has fewer than four eligible members".into());
    }
    let validators: Vec<_> = selected
        .into_iter()
        .map(|c| Member {
            address: c.address.clone(),
            pubkey: c.pubkey.clone(),
            weight: c.bond.clone(),
        })
        .collect();
    let total_weight = validators.iter().map(|v| &v.weight).sum();
    let quorum_weight = quorum_weight(&total_weight)?;
    let fingerprint = snapshot_fingerprint(source_epoch, activate_epoch, &validators);
    Ok(Snapshot {
        source_epoch,
        activate_epoch,
        validators,
        total_weight,
        quorum_weight,
        fingerprint,
    })
}
pub fn snapshot_fingerprint(
    source_epoch: i64,
    activate_epoch: i64,
    validators: &[Member],
) -> String {
    let mut bytes = Vec::new();
    for value in [
        b"octra:validator_snapshot:v1".as_slice(),
        source_epoch.to_string().as_bytes(),
        activate_epoch.to_string().as_bytes(),
    ] {
        put_string(&mut bytes, value);
    }
    for member in validators {
        for value in [
            member.address.as_slice(),
            member.pubkey.as_slice(),
            member.weight.to_string().as_bytes(),
        ] {
            put_string(&mut bytes, value);
        }
    }
    hex::encode(Sha256::digest(bytes))
}
impl Snapshot {
    pub fn signed_weight(&self, signers: &[Vec<u8>]) -> Result<BigInt, Error> {
        // Hashtbl.add selects the most recently inserted value on duplicate keys.
        let weights: BTreeMap<_, _> = self
            .validators
            .iter()
            .map(|v| (&v.address, &v.weight))
            .collect();
        let mut seen = BTreeSet::new();
        let mut total = BigInt::zero();
        for signer in signers {
            if seen.insert(signer) {
                total += *weights
                    .get(signer)
                    .ok_or("validator signature is not in snapshot")?;
            }
        }
        Ok(total)
    }
    pub fn has_quorum(&self, signers: &[Vec<u8>]) -> Result<bool, Error> {
        let weight = self.signed_weight(signers)?;
        let count = self.validators.len();
        let quorum = if count < 4 {
            count
        } else {
            count - (count - 1) / 3
        };
        Ok(signers.iter().collect::<BTreeSet<_>>().len() >= quorum && weight >= self.quorum_weight)
    }
    pub fn leader(&self, seed: &[u8], epoch: i64, round: i64) -> Result<&Member, Error> {
        if seed.is_empty() {
            return Err("validator leader seed is empty".into());
        }
        if epoch < 0 {
            return Err("validator leader epoch is negative".into());
        }
        if round < 0 {
            return Err("validator leader round is negative".into());
        }
        if self.validators.is_empty() || !self.total_weight.is_positive() {
            return Err("validator snapshot is empty".into());
        }
        let mut bytes = Vec::new();
        for value in [
            b"octra:validator_leader:v1".as_slice(),
            seed,
            epoch.to_string().as_bytes(),
            round.to_string().as_bytes(),
        ] {
            put_string(&mut bytes, value);
        }
        let target = BigInt::from_bytes_be(Sign::Plus, &Sha256::digest(bytes)) % &self.total_weight;
        let mut offset = BigInt::zero();
        for member in &self.validators {
            offset += &member.weight;
            if target < offset {
                return Ok(member);
            }
        }
        Err("validator leader selection failed".into())
    }
}
pub fn add_epoch(left: i64, right: i64) -> Result<i64, Error> {
    if right < 0 {
        return Err("epoch delta is negative".into());
    }
    let result = left.wrapping_add(right);
    if result < left {
        Err("epoch arithmetic overflow".into())
    } else {
        Ok(result)
    }
}
