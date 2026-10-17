// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{codec::Wire, hash, Error, Vote};
use crate::{
    network::domain_hash,
    oce1::{Reader, Writer},
};
use std::collections::BTreeMap;

pub const WINDOW: i64 = 128;
const CAPACITY: usize = 4096;

/// Native admission uses the current head, not the arrival age of the bytes.
pub fn in_window(current: i64, evidence: &VoteConflict) -> bool {
    let epoch = evidence.second.epoch_id;
    epoch <= current.saturating_add(1) && epoch >= current.wrapping_sub(WINDOW)
}

/// Process-local signing-slot bound from C_driver. Distinct pairs proving one
/// equivocation slot do not repeatedly persist or relay that evidence.
#[derive(Default)]
pub struct Pool(BTreeMap<[u8; 32], VoteConflict>);
impl Pool {
    pub fn remember(&mut self, evidence: &VoteConflict) -> Result<bool, Error> {
        let oldest = evidence.second.epoch_id.wrapping_sub(WINDOW);
        self.0.retain(|_, stored| stored.second.epoch_id >= oldest);
        let slot = vote_slot_id(&evidence.second)?;
        if self.0.contains_key(&slot) || self.0.len() >= CAPACITY {
            return Ok(false);
        }
        self.0.insert(slot, evidence.clone());
        Ok(true)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteConflict {
    pub first: Vote,
    pub second: Vote,
}
pub fn same_slot(left: &Vote, right: &Vote) -> bool {
    left.chain_id == right.chain_id
        && left.epoch_id == right.epoch_id
        && left.round == right.round
        && left.vote_type == right.vote_type
        && left.validator == right.validator
}
pub fn vote_conflict(left: &Vote, right: &Vote) -> Option<VoteConflict> {
    if !same_slot(left, right) || left.proposal_id == right.proposal_id {
        return None;
    }
    let (first, second) =
        if (&left.proposal_id, &left.signature) <= (&right.proposal_id, &right.signature) {
            (left, right)
        } else {
            (right, left)
        };
    Some(VoteConflict {
        first: first.clone(),
        second: second.clone(),
    })
}
impl Wire for VoteConflict {
    fn put(&self, w: &mut Writer) -> Result<(), Error> {
        w.put_bytes(&self.first.encode()?)?;
        w.put_bytes(&self.second.encode()?)
    }
    fn get(r: &mut Reader<'_>) -> Result<Self, Error> {
        let first = Vote::decode(r.get_bytes_bounded(1024)?)?;
        let second = Vote::decode(r.get_bytes_bounded(1024)?)?;
        vote_conflict(&first, &second).ok_or_else(|| "vote evidence is not a conflict".into())
    }
}
impl VoteConflict {
    pub fn id(&self) -> Result<[u8; 32], Error> {
        Ok(domain_hash(b"octra:vote_conflict:v1", &self.encode()?))
    }
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, Error> {
        Ok(
            vote_conflict(&self.first, &self.second).as_ref() == Some(self)
                && hash::verify_vote(public_key, &self.first)?
                && hash::verify_vote(public_key, &self.second)?,
        )
    }
}
pub fn root(evidence: &[VoteConflict]) -> Result<[u8; 32], Error> {
    let mut ids = evidence
        .iter()
        .map(VoteConflict::id)
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    ids.dedup();
    let mut w = Writer::new();
    w.put_list(&ids, |w, id| w.put_hash32(id))?;
    Ok(domain_hash(b"octra:vote_conflict_root:v1", &w.into_bytes()))
}
pub fn vote_slot_id(vote: &Vote) -> Result<[u8; 32], Error> {
    let mut w = Writer::new();
    w.put_bytes(&vote.chain_id)?;
    w.put_u64(vote.epoch_id as u64)?;
    w.put_u32(vote.round as u32)?;
    w.put_u8(vote.vote_type as u8)?;
    w.put_bytes(&vote.validator)?;
    Ok(domain_hash(b"octra:vote_slot:v1", &w.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::VoteType;

    fn conflict(epoch: i64, round: i64, value: u8) -> VoteConflict {
        let vote = Vote {
            chain_id: b"evidence-fixture".to_vec(),
            epoch_id: epoch,
            round,
            vote_type: VoteType::Prevote,
            proposal_id: vec![0; 32],
            validator: b"validator".to_vec(),
            signature: vec![0; 64],
        };
        let mut second = vote.clone();
        second.proposal_id = vec![value; 32];
        vote_conflict(&vote, &second).unwrap()
    }

    #[test]
    fn bounded_slot_admission_deduplicates_pairs_and_prunes_native_epoch_window() {
        let mut pool = Pool::default();
        assert!(pool.is_empty());
        for round in 0..CAPACITY as i64 {
            assert!(pool.remember(&conflict(200, round, 1)).unwrap());
        }
        assert_eq!(pool.len(), CAPACITY);
        assert!(!pool.remember(&conflict(200, 0, 2)).unwrap());
        assert!(!pool.remember(&conflict(200, CAPACITY as i64, 1)).unwrap());
        assert!(!pool.remember(&conflict(328, CAPACITY as i64, 1)).unwrap());
        assert!(pool.remember(&conflict(329, CAPACITY as i64, 1)).unwrap());
        assert_eq!(pool.len(), 1);
    }
}
