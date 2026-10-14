// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Vote aggregation after validator authentication by the engine boundary.
use super::{Bytes, ValidatorSet, Vote, NIL};
use num_bigint::BigInt;
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum VoteAdd {
    Duplicate,
    Rejected,
    Added,
    QuorumAny,
    QuorumOf(Bytes),
}
#[derive(Clone, Debug, Default)]
pub(crate) struct VoteSet {
    pub votes: BTreeMap<Bytes, Vote>,
    pub by_pid: BTreeMap<Bytes, i64>,
    pub by_pid_weight: BTreeMap<Bytes, BigInt>,
    pub count_nil: i64,
    pub count_total: i64,
    pub weight_nil: BigInt,
    pub weight_total: BigInt,
}
impl VoteSet {
    pub(super) fn count(&self, pid: &[u8]) -> i64 {
        self.by_pid.get(pid).copied().unwrap_or(0)
    }
    pub(super) fn weight(&self, pid: &[u8]) -> BigInt {
        self.by_pid_weight.get(pid).cloned().unwrap_or_default()
    }
    pub(super) fn nil_quorum(&self, chain: &[u8], epoch: i64, set: &ValidatorSet) -> bool {
        set.quorum_reached_at(chain, epoch, self.count_nil, &self.weight_nil)
    }
    pub(super) fn add(&mut self, vote: Vote, set: &ValidatorSet) -> VoteAdd {
        if self.votes.contains_key(&vote.validator) {
            return VoteAdd::Duplicate;
        }
        let Some(weight) = set.weight(&vote.validator) else {
            return VoteAdd::Rejected;
        };
        self.count_total += 1;
        self.weight_total += weight;
        let count;
        let signed;
        if vote.proposal_id == NIL {
            self.count_nil += 1;
            self.weight_nil += weight;
            count = self.count_nil;
            signed = self.weight_nil.clone();
        } else {
            count = self.count(&vote.proposal_id) + 1;
            signed = self.weight(&vote.proposal_id) + weight;
            self.by_pid.insert(vote.proposal_id.clone(), count);
            self.by_pid_weight
                .insert(vote.proposal_id.clone(), signed.clone());
        }
        let result = if set.quorum_reached_at(&vote.chain_id, vote.epoch_id, count, &signed) {
            VoteAdd::QuorumOf(vote.proposal_id.clone())
        } else if set.quorum_reached_at(
            &vote.chain_id,
            vote.epoch_id,
            self.count_total,
            &self.weight_total,
        ) {
            VoteAdd::QuorumAny
        } else {
            VoteAdd::Added
        };
        self.votes.insert(vote.validator.clone(), vote);
        result
    }
    pub(super) fn quorum_pid(&self, chain: &[u8], epoch: i64, set: &ValidatorSet) -> Option<Bytes> {
        self.by_pid_weight
            .iter()
            .find(|(pid, w)| {
                pid.as_slice() != NIL && set.quorum_reached_at(chain, epoch, self.count(pid), w)
            })
            .map(|(p, _)| p.clone())
    }
    pub(super) fn quorum(&self, chain: &[u8], epoch: i64, set: &ValidatorSet) -> VoteAdd {
        if let Some(pid) = self.quorum_pid(chain, epoch, set) {
            VoteAdd::QuorumOf(pid)
        } else if self.nil_quorum(chain, epoch, set) {
            VoteAdd::QuorumOf(NIL.to_vec())
        } else if set.quorum_reached_at(chain, epoch, self.count_total, &self.weight_total) {
            VoteAdd::QuorumAny
        } else {
            VoteAdd::Added
        }
    }
    pub(super) fn project(&self, set: &ValidatorSet) -> Self {
        let mut out = Self::default();
        for v in self.votes.values() {
            out.add(v.clone(), set);
        }
        out
    }
}
