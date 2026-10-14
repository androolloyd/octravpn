// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Config, Error, Final, ParentEvidence, Proof, State};
use crate::consensus::{hash, qc, ParentCommit, Vote, VoteType};
use std::collections::BTreeSet;
fn verify_commit(chain: &[u8], commit: &ParentCommit) -> Result<(), Error> {
    qc::validate_certificate(chain, &commit.validator_set, &commit.certificate, false)
        .map_err(|e| format!("validator duty commit is invalid: {e}").into())
}
fn verify_vote(
    chain: &[u8],
    address: &[u8],
    commit: &ParentCommit,
    vote: &Vote,
) -> Result<(), Error> {
    let cert = &commit.certificate;
    if vote.chain_id != chain {
        return Err("validator duty vote chain mismatch".into());
    }
    if vote.validator != address {
        return Err("validator duty vote owner mismatch".into());
    }
    if vote.vote_type != VoteType::Precommit {
        return Err("validator duty vote is not precommit".into());
    }
    if vote.epoch_id != cert.epoch_id {
        return Err("validator duty vote epoch mismatch".into());
    }
    if vote.round != cert.commit_round {
        return Err("validator duty vote round mismatch".into());
    }
    if vote.proposal_id != cert.proposal_id {
        return Err("validator duty vote proposal mismatch".into());
    }
    let public = commit
        .validator_set
        .public_key(address)
        .ok_or("validator duty vote signer is not in set")?;
    if !hash::verify_vote(public, vote).unwrap_or(false) {
        return Err("validator duty vote signature is invalid".into());
    }
    Ok(())
}
pub fn read_parent(chain: &[u8], commit: &ParentCommit) -> Result<ParentEvidence, Error> {
    verify_commit(chain, commit)?;
    let finality = Final {
        epoch: commit.certificate.epoch_id,
        proposal_id: commit.certificate.proposal_id.clone(),
        set_hash: hash::validator_set_hash(&commit.validator_set)
            .map_err(|e| Error(e.to_string()))?
            .to_vec(),
    };
    let signers = commit
        .certificate
        .precommits
        .iter()
        .map(|v| v.validator.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let active = commit
        .validator_set
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ParentEvidence {
        finality,
        signers,
        active,
    })
}
pub(super) fn verify(
    cfg: &Config,
    chain: &[u8],
    epoch: i64,
    address: &[u8],
    proof: &Proof,
    state: &State,
) -> Result<(), Error> {
    let vote = &proof.vote;
    let commit = &proof.commit;
    if vote.epoch_id > epoch {
        return Err("validator duty proof is from the future".into());
    }
    if epoch.wrapping_sub(vote.epoch_id) > cfg.challenge {
        return Err("validator duty proof challenge expired".into());
    }
    let finality = state
        .find_final(vote.epoch_id)
        .ok_or("validator duty finalized reference is missing")?;
    let set_hash =
        hash::validator_set_hash(&commit.validator_set).map_err(|e| Error(e.to_string()))?;
    if commit.certificate.proposal_id != finality.proposal_id {
        return Err("validator duty finalized proposal mismatch".into());
    }
    if set_hash.as_slice() != finality.set_hash {
        return Err("validator duty finalized set mismatch".into());
    }
    verify_vote(chain, address, commit, vote)?;
    verify_commit(chain, commit)
}
