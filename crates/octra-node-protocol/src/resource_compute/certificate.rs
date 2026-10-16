// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native compute agreement: one distinct vote per signer, grouped by complete
//! result evidence. Multiple qualified result groups remain conflicting.
use super::{
    hash, nonempty,
    request::{Request, MAX_RESPONSE},
    Error, Result,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{catch_unwind, AssertUnwindSafe},
};
pub const MAX_SELECTED: usize = 64;
pub const MAX_VOTES: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub request_id: Vec<u8>,
    pub node_id: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub trace_root: Vec<u8>,
    pub output_bytes: i64,
    pub steps: i64,
    pub operations: i64,
    pub signature: Vec<u8>,
}
impl Vote {
    pub fn shape(&self) -> bool {
        self.request_id.len() == 32
            && nonempty(&self.node_id, 128)
            && self.output_hash.len() == 32
            && self.trace_root.len() == 32
            && (1..=MAX_RESPONSE).contains(&self.output_bytes)
            && self.steps > 0
            && self.operations > 0
            && self.signature.len() == 64
    }
    pub fn within_budget(&self, request: &Request) -> bool {
        request
            .limits
            .fuel_limit
            .is_none_or(|limit| self.steps > 0 && self.steps <= limit)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"resource compute vote"));
        }
        hash(b"octra:resource_compute_vote", |out| {
            out.put_hash32(&self.request_id)?;
            out.put_bytes(&self.node_id)?;
            out.put_hash32(&self.output_hash)?;
            out.put_hash32(&self.trace_root)?;
            out.put_u32(self.output_bytes as u32)?;
            out.put_u64(self.steps as u64)?;
            out.put_u64(self.operations as u64)
        })
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        let signed = self.sign_bytes()?;
        hash(b"octra:resource_compute_vote_id", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.signature)
        })
    }
    fn result_key(&self) -> Result<[u8; 32]> {
        hash(b"octra:resource_compute_result", |out| {
            out.put_hash32(&self.output_hash)?;
            out.put_hash32(&self.trace_root)?;
            out.put_u32(self.output_bytes as u32)?;
            out.put_u64(self.steps as u64)?;
            out.put_u64(self.operations as u64)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    pub node_id: Vec<u8>,
    pub weight: BigInt,
    pub vote_id: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub request_id: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub trace_root: Vec<u8>,
    pub output_bytes: i64,
    pub steps: i64,
    pub operations: i64,
    pub votes: Vec<Vote>,
    pub signers: Vec<Signer>,
    pub signed_weight: BigInt,
    pub root: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    RequestMalformed,
    ChainMismatch,
    EpochMismatch,
    SelectionMalformed,
    ThresholdMalformed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Rejected(Reject),
    Insufficient,
    Conflicting,
    Agreed(Box<Certificate>),
}
pub struct Policy<'a> {
    pub chain_id: &'a [u8],
    pub current_epoch: i64,
    pub max_ttl: i64,
    pub selected: &'a [Vec<u8>],
    pub signer_floor: i64,
    pub weight_floor: &'a BigInt,
}
fn validate(policy: &Policy<'_>, request: &Request) -> std::result::Result<(), Reject> {
    if !request.shape() {
        Err(Reject::RequestMalformed)
    } else if request.chain_id.as_slice() != policy.chain_id {
        Err(Reject::ChainMismatch)
    } else if policy.max_ttl <= 0
        || policy.current_epoch < request.epoch_id
        || policy.current_epoch > request.expires_epoch
        || request.expires_epoch.wrapping_sub(request.epoch_id) > policy.max_ttl
    {
        Err(Reject::EpochMismatch)
    } else {
        Ok(())
    }
}
fn total(values: &[(&Vote, BigInt)]) -> BigInt {
    values.iter().map(|(_, weight)| weight).sum()
}
fn certificate(request_id: &[u8], mut values: Vec<(&Vote, BigInt)>) -> Result<Certificate> {
    values.sort_by(|(left, _), (right, _)| left.node_id.cmp(&right.node_id));
    let vote = values
        .first()
        .ok_or_else(|| Error::rejected(b"resource compute certificate votes"))?
        .0;
    let signers = values
        .iter()
        .map(|(vote, weight)| {
            Ok(Signer {
                node_id: vote.node_id.clone(),
                weight: weight.clone(),
                vote_id: vote.id()?.to_vec(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signed_weight = total(&values);
    let root = hash(b"octra:resource_compute_certificate", |out| {
        out.put_hash32(request_id)?;
        out.put_hash32(&vote.output_hash)?;
        out.put_hash32(&vote.trace_root)?;
        out.put_u32(vote.output_bytes as u32)?;
        out.put_u64(vote.steps as u64)?;
        out.put_u64(vote.operations as u64)?;
        out.put_bytes(signed_weight.to_string().as_bytes())?;
        out.put_list(&signers, |out, signer| {
            out.put_bytes(&signer.node_id)?;
            out.put_bytes(signer.weight.to_string().as_bytes())?;
            out.put_hash32(&signer.vote_id)
        })
    })?;
    Ok(Certificate {
        request_id: request_id.to_vec(),
        output_hash: vote.output_hash.clone(),
        trace_root: vote.trace_root.clone(),
        output_bytes: vote.output_bytes,
        steps: vote.steps,
        operations: vote.operations,
        votes: values.iter().map(|(vote, _)| (*vote).clone()).collect(),
        signers,
        signed_weight,
        root: root.to_vec(),
    })
}
pub fn decide(
    policy: &Policy<'_>,
    request: &Request,
    votes: &[Vote],
    mut weight_of: impl FnMut(&[u8]) -> Option<BigInt>,
    mut verify_signature: impl FnMut(&Vote) -> bool,
) -> Result<Decision> {
    if let Err(reason) = validate(policy, request) {
        return Ok(Decision::Rejected(reason));
    }
    let selected = policy
        .selected
        .iter()
        .map(Vec::as_slice)
        .collect::<BTreeSet<_>>();
    if policy.selected.is_empty()
        || policy.selected.len() > MAX_SELECTED
        || selected.len() != policy.selected.len()
        || selected.iter().any(|id| !nonempty(id, 128))
    {
        return Ok(Decision::Rejected(Reject::SelectionMalformed));
    }
    if policy.signer_floor <= 0
        || policy.signer_floor as u64 > policy.selected.len() as u64
        || policy.weight_floor <= &BigInt::zero()
    {
        return Ok(Decision::Rejected(Reject::ThresholdMalformed));
    }
    if votes.len() > MAX_VOTES {
        return Ok(Decision::Rejected(Reject::SelectionMalformed));
    }
    let expected = request.id()?;
    let mut by_node = BTreeMap::<&[u8], Vec<&Vote>>::new();
    for vote in votes {
        if vote.shape()
            && vote.within_budget(request)
            && vote.request_id.as_slice() == expected.as_slice()
            && vote.output_bytes <= request.max_output_bytes
            && selected.contains(vote.node_id.as_slice())
            && catch_unwind(AssertUnwindSafe(|| verify_signature(vote))).unwrap_or(false)
        {
            by_node.entry(&vote.node_id).or_default().push(vote);
        }
    }
    let mut groups = BTreeMap::<[u8; 32], Vec<(&Vote, BigInt)>>::new();
    for (node, votes) in by_node {
        // The native tuple evaluates its weight callback before vote-ID work,
        // including for equivocating nodes whose votes are later discarded.
        let weight = catch_unwind(AssertUnwindSafe(|| weight_of(node)))
            .ok()
            .flatten()
            .filter(|weight| weight > &BigInt::zero());
        let mut distinct = BTreeMap::new();
        for vote in votes.into_iter().rev() {
            distinct.insert(vote.id()?, vote);
        }
        if let (1, Some(weight)) = (distinct.len(), weight) {
            let vote = distinct.into_values().next().expect("one distinct vote");
            groups
                .entry(vote.result_key()?)
                .or_default()
                .push((vote, weight));
        }
    }
    let mut qualified = groups.into_values().filter(|values| {
        values.len() as u64 >= policy.signer_floor as u64 && total(values) >= *policy.weight_floor
    });
    let Some(values) = qualified.next() else {
        return Ok(Decision::Insufficient);
    };
    if qualified.next().is_some() {
        return Ok(Decision::Conflicting);
    }
    Ok(Decision::Agreed(Box::new(certificate(&expected, values)?)))
}
