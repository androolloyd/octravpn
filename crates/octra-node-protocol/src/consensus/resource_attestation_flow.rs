// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Optional resource committee projection; production activation is unchanged.
use super::{resource_attestations as resource, Validator, ValidatorSet};
use crate::{
    network::domain_hash,
    oce1::{Error, Reader, Writer},
};
use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSeed {
    pub chain_id: Vec<u8>,
    pub epoch_id: i64,
    pub prev_state_root: Vec<u8>,
    pub prev_qc_randomness: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gossip {
    pub chain_id: Vec<u8>,
    pub seen_epoch: i64,
    pub attestation: resource::Attestation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeSnapshot {
    pub target_epoch: i64,
    pub source_epoch: i64,
    pub challenge: Vec<u8>,
    pub committee: Vec<resource::Attestation>,
    pub committee_root: Vec<u8>,
    pub total_weight: BigInt,
    pub quorum_weight: BigInt,
}
pub const MAX_CHAIN_ID_BYTES: usize = 128;
pub const MAX_ATTESTATION_BYTES: usize = 256 * 1024;
pub fn encode_gossip(gossip: &Gossip) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.put_bytes(&gossip.chain_id)?;
    w.put_u64(gossip.seen_epoch as u64)?;
    w.put_bytes(&resource::encode_attestation(&gossip.attestation)?)?;
    Ok(w.into_bytes())
}
pub fn decode_gossip(raw: &[u8]) -> Result<Gossip, Error> {
    let mut r = Reader::new(raw);
    let chain_id = r.get_bytes_bounded(MAX_CHAIN_ID_BYTES)?.to_vec();
    let seen_epoch = r.get_u64()? as i64;
    let encoded = r.get_bytes_bounded(MAX_ATTESTATION_BYTES)?;
    let attestation = resource::decode_attestation(encoded)?;
    r.finish()?;
    Ok(Gossip {
        chain_id,
        seen_epoch,
        attestation,
    })
}
pub fn challenge(seed: &EpochSeed) -> Result<[u8; 32], Error> {
    let mut w = Writer::new();
    w.put_bytes(&seed.chain_id)?;
    w.put_u64(seed.epoch_id as u64)?;
    w.put_hash32(&seed.prev_state_root)?;
    w.put_hash32(&seed.prev_qc_randomness)?;
    Ok(domain_hash(b"octra:resource_challenge:v1", &w.into_bytes()))
}
pub fn activated_source_epoch(delay: i64, target: i64) -> Result<Option<i64>, Error> {
    if delay < 0 {
        return Err("activation_delay".into());
    }
    Ok((target >= delay).then(|| target.wrapping_sub(delay)))
}
pub fn matches_epoch_challenge(
    source_epoch: i64,
    challenge: &[u8],
    a: &resource::Attestation,
) -> Result<bool, Error> {
    Ok(a.epoch_id == source_epoch
        && resource::is_well_formed(a)
        && a.score == resource::attestation_score(challenge, a)?)
}
pub fn eligible_attestations(
    source_epoch: i64,
    challenge: &[u8],
    values: &[resource::Attestation],
) -> Result<Vec<resource::Attestation>, Error> {
    let mut eligible = vec![];
    for a in values {
        if matches_epoch_challenge(source_epoch, challenge, a)? {
            eligible.push(a.clone());
        }
    }
    Ok(eligible)
}
pub fn committee_root(
    target_epoch: i64,
    source_epoch: i64,
    challenge: &[u8],
    committee: &[resource::Attestation],
) -> Result<[u8; 32], Error> {
    let mut w = Writer::new();
    w.put_u64(target_epoch as u64)?;
    w.put_u64(source_epoch as u64)?;
    w.put_hash32(challenge)?;
    w.put_hash32(&resource::attestations_root(committee)?)?;
    Ok(domain_hash(
        b"octra:resource_committee_root:v1",
        &w.into_bytes(),
    ))
}
pub fn select_snapshot(
    delay: i64,
    size: i64,
    target: i64,
    seed: &EpochSeed,
    values: &[resource::Attestation],
) -> Result<Option<CommitteeSnapshot>, Error> {
    let Some(source) = activated_source_epoch(delay, target)? else {
        return Ok(None);
    };
    if source != seed.epoch_id {
        return Ok(None);
    }
    let challenge = challenge(seed)?.to_vec();
    let committee =
        resource::select_committee(size, &eligible_attestations(source, &challenge, values)?);
    let total_weight = resource::sum_weight(&committee);
    let quorum_weight = if total_weight <= BigInt::zero() {
        BigInt::zero()
    } else {
        resource::quorum_weight(&total_weight)
    };
    Ok(Some(CommitteeSnapshot {
        target_epoch: target,
        source_epoch: source,
        committee_root: committee_root(target, source, &challenge, &committee)?.to_vec(),
        challenge,
        committee,
        total_weight,
        quorum_weight,
    }))
}
pub fn validator_set_of_committee(
    pubkey: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
    committee: &[resource::Attestation],
) -> Option<ValidatorSet> {
    let mut validators = vec![];
    for a in committee {
        validators.push(Validator {
            address: a.node_id.clone(),
            pubkey: pubkey(&a.node_id)?,
        });
    }
    Some(ValidatorSet::unweighted(validators))
}
pub fn ready_for_voting(minimum_weight: i64, snapshot: &CommitteeSnapshot) -> bool {
    snapshot.total_weight >= BigInt::from(minimum_weight) && !snapshot.committee.is_empty()
}
pub fn rewards_for_snapshot(
    budget: i64,
    snapshot: &CommitteeSnapshot,
) -> Result<Vec<resource::Payout>, Error> {
    resource::distribute_resource_rewards(budget, &snapshot.committee)
}
