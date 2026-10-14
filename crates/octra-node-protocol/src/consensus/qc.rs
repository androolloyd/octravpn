// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Quorum certificates are accepted only after field, membership and signature checks.
use super::{
    hash, policy,
    types::{Bytes, CommitCertificate, Finalize, ParentCommit, ValidatorSet, VoteType, NIL},
    Error,
};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityMode {
    Live(policy::Protocol),
    Persisted,
    StrictPersisted,
}
pub fn validate_certificate(
    chain_id: &[u8],
    set: &ValidatorSet,
    certificate: &CommitCertificate,
    strict: bool,
) -> Result<(), Error> {
    if certificate.chain_id != chain_id {
        return Err("chain_id".into());
    }
    let effective = set.for_epoch(chain_id, certificate.epoch_id)?;
    if certificate.header.chain_id != certificate.chain_id {
        return Err("header_chain_id".into());
    }
    if certificate.header.epoch_id != certificate.epoch_id {
        return Err("header_epoch".into());
    }
    if !policy::supported_version(certificate.header.proto_version) {
        return Err("header_proto_version".into());
    }
    if !effective.is_validator(&certificate.header.creator_addr) {
        return Err("header_creator".into());
    }
    if certificate.proposal_id == NIL {
        return Err("nil_proposal".into());
    }
    if certificate.proposal_id != hash::proposal_id(&certificate.header)? {
        return Err("proposal_id".into());
    }
    let signers: Vec<_> = certificate
        .precommits
        .iter()
        .map(|v| v.validator.clone())
        .collect();
    if signers.iter().collect::<BTreeSet<_>>().len() != signers.len() {
        return Err("duplicate_validator".into());
    }
    let policy_ok = set.has_quorum_at(chain_id, certificate.epoch_id, &signers)?;
    let strict_ok = !strict
        || !policy::quorum_active(chain_id, certificate.epoch_id)
        || effective.has_quorum(&signers);
    if !(policy_ok && strict_ok) {
        return Err("quorum".into());
    }
    #[allow(clippy::suspicious_operation_groupings)] // Votes bind the certificate commit round.
    let bad_vote = certificate.precommits.iter().any(|vote| {
        vote.chain_id != certificate.chain_id
            || vote.epoch_id != certificate.epoch_id
            || vote.round != certificate.commit_round
            || vote.vote_type != VoteType::Precommit
            || vote.proposal_id != certificate.proposal_id
    });
    if bad_vote {
        return Err("vote_fields".into());
    }
    if certificate
        .precommits
        .iter()
        .any(|v| !effective.is_validator(&v.validator))
    {
        return Err("validator".into());
    }
    for vote in &certificate.precommits {
        let Some(public) = effective.public_key(&vote.validator) else {
            return Err("validator".into());
        };
        if !hash::verify_vote(public, vote)? {
            return Err("signature".into());
        }
    }
    Ok(())
}
pub fn validate_finalize(
    chain_id: &[u8],
    set: &ValidatorSet,
    finalize: &Finalize,
    mode: FinalityMode,
) -> Result<(), Error> {
    let valid_version = match mode {
        FinalityMode::Live(protocol) => {
            finalize.header.proto_version == protocol.version_at(finalize.epoch_id)
        }
        _ => policy::supported_version(finalize.header.proto_version),
    };
    if !valid_version {
        return Err("header_proto_version".into());
    }
    if hash::parent_commit_hash_opt(finalize.parent_commit.as_ref())?
        != finalize.header.parent_commit_hash.as_slice()
    {
        return Err("parent_commit_hash".into());
    }
    validate_certificate(
        chain_id,
        set,
        &finalize.certificate(),
        mode == FinalityMode::StrictPersisted,
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedParent {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub proposal_id: Bytes,
    pub state_root: Bytes,
    pub validator_set_hash: Bytes,
}
pub fn validate_parent(expected: &ExpectedParent, parent: &ParentCommit) -> Result<(), Error> {
    let certificate = &parent.certificate;
    if certificate.chain_id != expected.chain_id {
        return Err("chain_id".into());
    }
    if certificate.epoch_id != expected.epoch_id {
        return Err("epoch_id".into());
    }
    if certificate.proposal_id != expected.proposal_id {
        return Err("proposal_id".into());
    }
    if certificate.header.proposed_state_root != expected.state_root {
        return Err("state_root".into());
    }
    if hash::validator_set_hash(&parent.validator_set)? != expected.validator_set_hash.as_slice() {
        return Err("validator_set".into());
    }
    validate_certificate(
        &expected.chain_id,
        &parent.validator_set,
        certificate,
        false,
    )
    .map_err(|e| Error::from(format!("qc_{e}")))
}
