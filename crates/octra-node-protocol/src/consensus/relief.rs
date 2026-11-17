// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated scheduled validator-set relief with native overlap thresholds.
use super::measure::Gap;
use super::policy::{QuorumPolicy, DEVNET};
use super::{hash, Bytes, Error, RoundSync, ValidatorSet};
use num_bigint::BigInt;
use num_traits::Zero;

pub const ACTIVATION_EPOCH: i64 = 1_380_000;
pub const MIN_ROUND: i64 = 64;
pub const MAX_LEAD: i64 = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mark {
    pub height: i64,
    pub round: i64,
    pub activate_epoch: i64,
    pub source_hash: Bytes,
    pub target_hash: Bytes,
    pub fingerprint: Bytes,
    pub proof: Vec<RoundSync>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Wait,
    Refuse(Error),
    Apply(Mark),
}
pub struct Plan<'a> {
    pub chain_id: &'a [u8],
    pub height: i64,
    pub current: &'a ValidatorSet,
    pub activate_epoch: i64,
    pub target: &'a ValidatorSet,
    pub fingerprint: &'a [u8],
}
pub fn active(chain_id: &[u8], height: i64) -> bool {
    chain_id == DEVNET && height >= ACTIVATION_EPOCH
}
pub fn valid_fingerprint(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
pub fn same_plan(left: &Mark, right: &Mark) -> bool {
    left.height == right.height
        && left.activate_epoch == right.activate_epoch
        && left.source_hash == right.source_hash
        && left.target_hash == right.target_hash
        && left.fingerprint == right.fingerprint
}
fn policy_for(policy: Option<QuorumPolicy>, chain_id: &[u8]) -> QuorumPolicy {
    policy.unwrap_or_else(|| QuorumPolicy::for_chain(chain_id))
}
pub fn check_intersection(
    policy: Option<QuorumPolicy>,
    chain_id: &[u8],
    height: i64,
    current: &ValidatorSet,
    target: &ValidatorSet,
) -> Result<(), Error> {
    current
        .space(policy_for(policy, chain_id), height)
        .overlap(&target.weights)
        .map_err(|gap| {
            match gap {
                Gap::FewSeats => "validator relief count intersection is unsafe",
                Gap::LowWeight => "validator relief weight intersection is unsafe",
                Gap::NoProof => "validator relief has no weight-only intersection proof",
            }
            .into()
        })
}
pub fn check_set(
    policy: Option<QuorumPolicy>,
    chain_id: &[u8],
    height: i64,
    current: &ValidatorSet,
    target: &ValidatorSet,
) -> Result<(), Error> {
    let quorum = policy_for(policy, chain_id);
    current.checked_for_policy(quorum, height)?;
    target.checked_for_policy(quorum, height)?;
    if !current.weighted || !target.weighted {
        Err("validator relief requires weighted sets".into())
    } else if current.n < 4 || target.n < 4 {
        Err("validator relief set is too small".into())
    } else if target.n >= current.n {
        Err("validator relief target must shrink".into())
    } else if !target.validators.iter().all(|member| {
        current.public_key(&member.address) == Some(member.pubkey.as_slice())
            && current
                .weight(&member.address)
                .is_some_and(|old| target.weight(&member.address).is_some_and(|new| old == new))
    }) {
        Err("validator relief target changes a retained member".into())
    } else {
        check_intersection(policy, chain_id, height, current, target)
    }
}
pub fn check_proof(
    policy: Option<QuorumPolicy>,
    chain_id: &[u8],
    height: i64,
    current: &ValidatorSet,
    proof: &[RoundSync],
) -> Result<(i64, Vec<RoundSync>), Error> {
    let round = proof
        .first()
        .ok_or("validator relief proof is empty")?
        .round;
    let mut sorted = proof.to_vec();
    sorted.sort_by(|a, b| a.validator.cmp(&b.validator));
    let mut prior: Option<&[u8]> = None;
    let mut weight = BigInt::zero();
    for sync in &sorted {
        if prior == Some(sync.validator.as_slice()) {
            return Err("validator relief proof repeats a signer".into());
        }
        if sync.chain_id != chain_id {
            return Err("validator relief proof chain differs".into());
        }
        if sync.epoch_id != height {
            return Err("validator relief proof height differs".into());
        }
        if sync.round != round || round < MIN_ROUND {
            return Err("validator relief proof round is invalid".into());
        }
        let public = current
            .public_key(&sync.validator)
            .ok_or("validator relief proof signer is unknown")?;
        if !hash::verify_round_sync(public, sync)? {
            return Err("validator relief proof signature is invalid".into());
        }
        prior = Some(&sync.validator);
    }
    // Preserve the native error order: weight lookup follows every signature.
    for sync in &sorted {
        weight += current
            .weight(&sync.validator)
            .ok_or("validator relief proof weight is invalid")?;
    }
    if !current.round_skip_reached_for_policy(
        policy_for(policy, chain_id),
        height,
        sorted.len() as i64,
        &weight,
    ) {
        return Err("validator relief proof is below threshold".into());
    }
    Ok((round, sorted))
}
impl Plan<'_> {
    pub fn check(&self) -> Result<(), Error> {
        self.check_for_policy(None)
    }
    pub fn check_for_policy(&self, policy: Option<QuorumPolicy>) -> Result<(), Error> {
        let lead = self.activate_epoch.wrapping_sub(self.height);
        if lead <= 0 {
            Err("validator relief plan is not ahead".into())
        } else if lead > MAX_LEAD {
            Err("validator relief plan is too far ahead".into())
        } else if !valid_fingerprint(self.fingerprint) {
            Err("validator relief fingerprint is invalid".into())
        } else {
            check_set(
                policy,
                self.chain_id,
                self.height,
                self.current,
                self.target,
            )
        }
    }
    pub fn clock_limit(&self) -> Option<i64> {
        (active(self.chain_id, self.height) && self.check().is_ok()).then_some(MIN_ROUND)
    }
    pub fn restore_with_authors(&self, mark: &Mark) -> Result<Option<ValidatorSet>, Error> {
        self.restore_with_authors_for_policy(None, mark)
    }
    pub fn restore_with_authors_for_policy(
        &self,
        policy: Option<QuorumPolicy>,
        mark: &Mark,
    ) -> Result<Option<ValidatorSet>, Error> {
        let Some(target) = self.restore_for_policy(policy, mark)? else {
            return Ok(None);
        };
        let mut target = target.clone();
        if self.height == mark.height
            && super::policy::quorum_rule(self.chain_id, self.height) == super::policy::Rule::Stake
        {
            target.authors = Some((
                self.height,
                self.current
                    .entries()?
                    .into_iter()
                    .filter(|(member, _)| !target.is_validator(&member.address))
                    .collect(),
            ));
        }
        Ok(Some(target))
    }
    pub fn decide(&self, proof: &[RoundSync]) -> Result<Decision, Error> {
        if !active(self.chain_id, self.height) || self.height >= self.activate_epoch {
            return Ok(Decision::Wait);
        }
        if let Err(error) = self.check() {
            return Ok(Decision::Refuse(error));
        }
        if proof.is_empty() {
            return Ok(Decision::Wait);
        }
        match check_proof(None, self.chain_id, self.height, self.current, proof) {
            Err(error) => Ok(Decision::Refuse(error)),
            Ok((round, proof)) => Ok(Decision::Apply(Mark {
                height: self.height,
                round,
                activate_epoch: self.activate_epoch,
                source_hash: hash::validator_set_hash(self.current)?.to_vec(),
                target_hash: hash::validator_set_hash(self.target)?.to_vec(),
                fingerprint: self.fingerprint.to_vec(),
                proof,
            })),
        }
    }
    pub fn restore(&self, mark: &Mark) -> Result<Option<&ValidatorSet>, Error> {
        self.restore_for_policy(None, mark)
    }
    pub fn restore_for_policy(
        &self,
        policy: Option<QuorumPolicy>,
        mark: &Mark,
    ) -> Result<Option<&ValidatorSet>, Error> {
        let quorum = policy_for(policy, self.chain_id);
        for set in [self.current, self.target] {
            set.structural_for_policy(quorum, self.height)
                .map_err(|error| error.message())?;
        }
        if self.height >= mark.activate_epoch {
            return Ok(None);
        }
        if self.height < mark.height {
            return Err("validator relief marker is ahead of local height".into());
        }
        if !active(self.chain_id, mark.height) {
            return Err("validator relief marker predates activation".into());
        }
        if self.activate_epoch != mark.activate_epoch {
            return Err("validator relief activation differs".into());
        }
        if self.fingerprint != mark.fingerprint {
            return Err("validator relief fingerprint differs".into());
        }
        if hash::validator_set_hash(self.target)?.as_slice() != mark.target_hash {
            return Err("validator relief target set differs".into());
        }
        if hash::validator_set_hash(self.current)?.as_slice() != mark.source_hash {
            // Once the scheduled set is the voting set, the marker's source
            // no longer has to be the local one.
            return if self.height > mark.height
                && quorum.seatless(self.height)
                && self.current.same_voting_set(self.target)
            {
                Ok(None)
            } else {
                Err("validator relief source set differs".into())
            };
        }
        Self {
            height: mark.height,
            ..*self
        }
        .check_for_policy(policy)?;
        let (round, _) = check_proof(
            policy,
            self.chain_id,
            mark.height,
            self.current,
            &mark.proof,
        )?;
        if round != mark.round {
            return Err("validator relief marker round differs".into());
        }
        Ok(Some(self.target))
    }
}
