// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{codec::Wire, hash, Error, Vote};
use crate::{
    network::domain_hash,
    oce1::{Reader, Writer},
};
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
