// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native commit/reveal provider selection, including duplicate evidence and
//! equivocation exclusion. Callers authenticate challenge finality separately.
use super::{hash, nonempty, protected, Error, Result};
use crate::network::domain_hash;
use std::collections::BTreeMap;
pub const MAX_CANDIDATES: usize = 256;
pub const MAX_COMMITTEE: i64 = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub chain_id: Vec<u8>,
    pub offer_id: Vec<u8>,
    pub commit_epoch: i64,
    pub node_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub nonce_hash: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub chain_id: Vec<u8>,
    pub offer_id: Vec<u8>,
    pub commit_epoch: i64,
    pub reveal_epoch: i64,
    pub node_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub nonce: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Malformed,
    ChainMismatch,
    OfferMismatch,
    EpochMismatch,
    IdentityMismatch,
    ModelMismatch,
    ProgramMismatch,
    NonceMismatch,
    CommitmentSignature,
    RevealSignature,
    Evidence,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub node_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub score: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub offer_id: Vec<u8>,
    pub target_epoch: i64,
    pub challenge: Vec<u8>,
    pub members: Vec<Member>,
    pub root: Vec<u8>,
}
pub fn nonce_hash(nonce: &[u8]) -> [u8; 32] {
    domain_hash(b"octra:resource_compute_nonce", nonce)
}
impl Commitment {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && self.offer_id.len() == 32
            && self.commit_epoch >= 0
            && nonempty(&self.node_id, 128)
            && [
                &self.graph_root,
                &self.model_root,
                &self.program_root,
                &self.executor_root,
                &self.nonce_hash,
            ]
            .iter()
            .all(|v| v.len() == 32)
            && self.signature.len() == 64
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        // Native signing helpers frame these fields without a shape precheck.
        hash(b"octra:resource_compute_commitment", |out| {
            out.put_bytes(&self.chain_id)?;
            out.put_hash32(&self.offer_id)?;
            out.put_u64(self.commit_epoch as u64)?;
            out.put_bytes(&self.node_id)?;
            out.put_hash32(&self.graph_root)?;
            out.put_hash32(&self.model_root)?;
            out.put_hash32(&self.program_root)?;
            out.put_hash32(&self.executor_root)?;
            out.put_hash32(&self.nonce_hash)
        })
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        let signed = self.sign_bytes()?;
        hash(b"octra:resource_compute_commitment_id", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.signature)
        })
    }
}
impl Reveal {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && self.offer_id.len() == 32
            && self.commit_epoch >= 0
            && self.reveal_epoch >= 0
            && nonempty(&self.node_id, 128)
            && self.graph_root.len() == 32
            && nonempty(&self.nonce, 128)
            && [
                &self.model_root,
                &self.program_root,
                &self.executor_root,
                &self.evidence_root,
            ]
            .iter()
            .all(|v| v.len() == 32)
            && self.signature.len() == 64
    }
    pub fn sign_bytes(&self, commitment: &Commitment) -> Result<[u8; 32]> {
        let id = commitment.id()?;
        hash(b"octra:resource_compute_reveal", |out| {
            out.put_hash32(&id)?;
            out.put_u64(self.reveal_epoch as u64)?;
            out.put_bytes(&self.nonce)?;
            out.put_hash32(&self.evidence_root)
        })
    }
    pub fn id(&self, commitment: &Commitment) -> Result<[u8; 32]> {
        let signed = self.sign_bytes(commitment)?;
        hash(b"octra:resource_compute_reveal_id", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.signature)
        })
    }
}
pub fn challenge(chain: &[u8], source_epoch: i64, finality_hash: &[u8]) -> Result<[u8; 32]> {
    if !nonempty(chain, 128) || source_epoch < 0 || finality_hash.len() != 32 {
        return Err(Error::rejected(b"resource compute challenge parameters"));
    }
    hash(b"octra:resource_compute_challenge", |out| {
        out.put_bytes(chain)?;
        out.put_u64(source_epoch as u64)?;
        out.put_hash32(finality_hash)
    })
}
pub struct Policy<'a> {
    pub chain: &'a [u8],
    pub target_epoch: i64,
    pub minimum_delay: i64,
}
// These intentionally compare distinct native fields/length units.
#[allow(clippy::suspicious_operation_groupings)]
fn scope(
    policy: &Policy<'_>,
    commitment: &Commitment,
    reveal: &Reveal,
) -> std::result::Result<(), Reject> {
    if reveal.offer_id != commitment.offer_id {
        Err(Reject::OfferMismatch)
    } else if reveal.commit_epoch != commitment.commit_epoch
        || commitment.commit_epoch >= policy.target_epoch
        || reveal.reveal_epoch >= policy.target_epoch
        || reveal.reveal_epoch < commitment.commit_epoch
        || reveal.reveal_epoch.wrapping_sub(commitment.commit_epoch) < policy.minimum_delay
    {
        Err(Reject::EpochMismatch)
    } else if reveal.node_id != commitment.node_id {
        Err(Reject::IdentityMismatch)
    } else if reveal.graph_root != commitment.graph_root
        || reveal.model_root != commitment.model_root
    {
        Err(Reject::ModelMismatch)
    } else if reveal.program_root != commitment.program_root
        || reveal.executor_root != commitment.executor_root
    {
        Err(Reject::ProgramMismatch)
    } else if nonce_hash(&reveal.nonce).as_slice() != commitment.nonce_hash {
        Err(Reject::NonceMismatch)
    } else {
        Ok(())
    }
}
fn after_commitment<'a>(
    policy: &Policy<'_>,
    commitment: &Commitment,
    reveal: &'a Reveal,
    verify_reveal: &mut impl FnMut(&Commitment, &Reveal) -> bool,
    verify_evidence: &mut impl FnMut(&Reveal) -> bool,
) -> std::result::Result<&'a Reveal, Reject> {
    if !reveal.shape() {
        return Err(Reject::Malformed);
    }
    if reveal.chain_id != policy.chain {
        return Err(Reject::ChainMismatch);
    }
    scope(policy, commitment, reveal)?;
    if !protected(|| verify_reveal(commitment, reveal)) {
        Err(Reject::RevealSignature)
    } else if !protected(|| verify_evidence(reveal)) {
        Err(Reject::Evidence)
    } else {
        Ok(reveal)
    }
}
pub fn validate<'a>(
    policy: &Policy<'_>,
    commitment: &Commitment,
    reveal: &'a Reveal,
    mut verify_commitment: impl FnMut(&Commitment) -> bool,
    mut verify_reveal: impl FnMut(&Commitment, &Reveal) -> bool,
    mut verify_evidence: impl FnMut(&Reveal) -> bool,
) -> std::result::Result<&'a Reveal, Reject> {
    if !commitment.shape() || !reveal.shape() {
        return Err(Reject::Malformed);
    }
    if commitment.chain_id != policy.chain || reveal.chain_id != policy.chain {
        return Err(Reject::ChainMismatch);
    }
    scope(policy, commitment, reveal)?;
    if !protected(|| verify_commitment(commitment)) {
        return Err(Reject::CommitmentSignature);
    }
    after_commitment(
        policy,
        commitment,
        reveal,
        &mut verify_reveal,
        &mut verify_evidence,
    )
}
pub fn selection_root(
    offer_id: &[u8],
    target_epoch: i64,
    challenge: &[u8],
    members: &[Member],
) -> Result<[u8; 32]> {
    hash(b"octra:resource_compute_selection", |out| {
        out.put_hash32(offer_id)?;
        out.put_u64(target_epoch as u64)?;
        out.put_hash32(challenge)?;
        out.put_list(members, |out, member| {
            out.put_bytes(&member.node_id)?;
            out.put_hash32(&member.graph_root)?;
            out.put_hash32(&member.model_root)?;
            out.put_hash32(&member.program_root)?;
            out.put_hash32(&member.executor_root)?;
            out.put_hash32(&member.evidence_root)?;
            out.put_hash32(&member.score)
        })
    })
}
pub fn select(
    policy: &Policy<'_>,
    offer_id: &[u8],
    challenge: &[u8],
    committee_size: i64,
    commitments: &[Commitment],
    reveals: &[Reveal],
    mut verify_commitment: impl FnMut(&Commitment) -> bool,
    mut verify_reveal: impl FnMut(&Commitment, &Reveal) -> bool,
    mut verify_evidence: impl FnMut(&Reveal) -> bool,
) -> Result<Selection> {
    if !(1..=MAX_COMMITTEE).contains(&committee_size)
        || policy.minimum_delay <= 0
        || policy.target_epoch <= 0
        || !nonempty(policy.chain, 128)
        || offer_id.len() != 32
        || challenge.len() != 32
        || commitments.len() > MAX_CANDIDATES
        || reveals.len() > MAX_CANDIDATES
    {
        return Err(Error::rejected(b"resource compute selection parameters"));
    }
    let mut unique = BTreeMap::new();
    for commitment in commitments {
        if commitment.shape()
            && commitment.chain_id == policy.chain
            && commitment.offer_id == offer_id
            && commitment.commit_epoch < policy.target_epoch
            && protected(|| verify_commitment(commitment))
        {
            unique.insert(commitment.id()?, commitment);
        }
    }
    let mut by_node: BTreeMap<&[u8], Vec<&Commitment>> = BTreeMap::new();
    for commitment in unique.into_values() {
        by_node
            .entry(&commitment.node_id)
            .or_default()
            .insert(0, commitment);
    }
    let mut reveals_by_node: BTreeMap<&[u8], Vec<&Reveal>> = BTreeMap::new();
    for reveal in reveals.iter().filter(|r| r.shape()) {
        reveals_by_node
            .entry(&reveal.node_id)
            .or_default()
            .insert(0, reveal);
    }
    let mut members = Vec::new();
    for (node, commitments) in by_node {
        let ([commitment], Some(reveals)) = (commitments.as_slice(), reveals_by_node.get(node))
        else {
            continue;
        };
        let mut unique = BTreeMap::new();
        for reveal in reveals {
            if after_commitment(
                policy,
                commitment,
                reveal,
                &mut verify_reveal,
                &mut verify_evidence,
            )
            .is_ok()
            {
                unique.insert(reveal.id(commitment)?, *reveal);
            }
        }
        if unique.len() != 1 {
            continue;
        }
        let reveal = unique.into_values().next().expect("one reveal");
        let id = commitment.id()?;
        let score = hash(b"octra:resource_compute_score", |out| {
            out.put_hash32(challenge)?;
            out.put_hash32(&id)
        })?;
        members.push(Member {
            node_id: commitment.node_id.clone(),
            graph_root: commitment.graph_root.clone(),
            model_root: commitment.model_root.clone(),
            program_root: commitment.program_root.clone(),
            executor_root: commitment.executor_root.clone(),
            evidence_root: reveal.evidence_root.clone(),
            score: score.to_vec(),
        });
    }
    members.sort_by(|a, b| a.score.cmp(&b.score).then(a.node_id.cmp(&b.node_id)));
    members.truncate(committee_size as usize);
    let root = selection_root(offer_id, policy.target_epoch, challenge, &members)?.to_vec();
    Ok(Selection {
        offer_id: offer_id.to_vec(),
        target_epoch: policy.target_epoch,
        challenge: challenge.to_vec(),
        members,
        root,
    })
}
