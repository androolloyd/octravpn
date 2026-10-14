// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native driver admission and scheduling predicates. Time is supplied by the host.
use super::{
    engine, hash, policy::Protocol, Bytes, CatchupEpochRecord, CatchupResponse, Error, Finalize,
    Proposal, RoundFetch, RoundStep, RoundSync, ValidatorSet, Vote, VoteType, NIL,
};
use crate::network::handshake;
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeightStatus {
    Current,
    Stale,
    Future,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalError {
    UnknownValidator,
    BadSignature,
    Envelope,
    TransactionRoot,
    ParentCommitHash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultSource {
    Unresolved,
    Sender,
    Signer,
}
impl ProposalError {
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnknownValidator => "unknown_validator",
            Self::BadSignature => "bad_signature",
            Self::Envelope => "envelope",
            Self::TransactionRoot => "tx_list_hash",
            Self::ParentCommitHash => "parent_commit_hash",
        }
    }
    pub const fn peer_reason(self) -> &'static str {
        match self {
            Self::UnknownValidator => "unknown_validator_propose",
            Self::BadSignature => "bad_signature_propose",
            Self::Envelope => "invalid_frame_propose_envelope",
            Self::TransactionRoot => "invalid_frame_propose_tx_list_hash",
            Self::ParentCommitHash => "invalid_frame_propose_parent_commit",
        }
    }
    pub const fn source(self) -> FaultSource {
        match self {
            Self::UnknownValidator => FaultSource::Unresolved,
            Self::Envelope => FaultSource::Signer,
            _ => FaultSource::Sender,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryWindow {
    pub from_epoch: i64,
    pub max_epochs: i64,
}
impl QueryWindow {
    pub fn contains(&self, epoch: i64) -> bool {
        self.max_epochs > 0
            && epoch >= self.from_epoch
            && epoch.wrapping_sub(self.from_epoch) < self.max_epochs
    }
    pub fn contains_records(&self, records: &[CatchupEpochRecord]) -> bool {
        self.max_epochs >= 0
            && records.len() as u64 <= self.max_epochs as u64
            && records.iter().all(|r| self.contains(r.epoch_id))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalBuild {
    pub generation: i64,
    pub height: i64,
    pub round: i64,
    pub step: RoundStep,
    pub started_at: i64,
}
impl ProposalBuild {
    pub fn current(&self, generation: i64, height: i64, round: i64, step: RoundStep) -> bool {
        self.generation == generation
            && self.height == height
            && self.round == round
            && self.step == step
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalFetch {
    pub height: i64,
    pub round: i64,
    pub proposal_id: Bytes,
    pub generation: i64,
}
impl ProposalFetch {
    #[allow(clippy::fn_params_excessive_bools)] // Native fetch cancellation predicate.
    pub fn should_send(
        &self,
        running: bool,
        height: i64,
        round: i64,
        generation: i64,
        proposal_known: bool,
        attempts_left: i64,
    ) -> bool {
        running
            && attempts_left > 0
            && height == self.height
            && round == self.round
            && generation == self.generation
            && !proposal_known
    }
}
pub fn catchup_record_complete(record: &CatchupEpochRecord) -> bool {
    record.reward_source.is_some() && record.finality.is_some()
}
pub fn catchup_records_complete(records: &[CatchupEpochRecord]) -> bool {
    !records.is_empty() && records.iter().all(catchup_record_complete)
}
pub fn normalize_legacy_range_response(response: &CatchupResponse) -> Option<CatchupResponse> {
    let last = response.records.last()?;
    if !catchup_records_complete(&response.records) {
        return None;
    }
    Some(CatchupResponse {
        status: b"ok".to_vec(),
        error_code: None,
        next_epoch: Some(last.epoch_id.wrapping_add(1)),
        ..response.clone()
    })
}
pub fn response_source_matches(set: &ValidatorSet, peer_id: &[u8], responder: &[u8]) -> bool {
    set.public_key(responder)
        .is_some_and(|public| handshake::node_id(public).as_slice() == peer_id)
}
pub fn catchup_response_key(response: &CatchupResponse) -> Result<Option<Bytes>, Error> {
    if !response.records.iter().all(catchup_record_complete) {
        return Ok(None);
    }
    let mut key = response.status.clone();
    key.push(b'|');
    key.extend_from_slice(
        response
            .next_epoch
            .map_or_else(|| "-".into(), |e| e.to_string())
            .as_bytes(),
    );
    key.push(b'|');
    key.extend_from_slice(&hash::catchup_records_root(&response.records)?);
    Ok(Some(key))
}
pub fn catchup_source_agreement_reached(
    set: &ValidatorSet,
    count_floor: bool,
    signer_count: i64,
    signed_weight: &BigInt,
) -> bool {
    *signed_weight >= set.round_skip_weight() && (!count_floor || signer_count > set.f)
}
pub fn catchup_agreement_epoch(from_epoch: i64, records: &[CatchupEpochRecord]) -> i64 {
    records.last().map_or(from_epoch, |r| r.epoch_id)
}
pub fn within_grace(now: i64, started_at: i64, grace_ms: i64) -> bool {
    let elapsed = now.wrapping_sub(started_at);
    elapsed >= 0 && elapsed < grace_ms.wrapping_mul(1_000_000)
}
pub fn bounded_timeout(value: f64) -> f64 {
    if !value.is_finite() || value <= 0.0 {
        0.0
    } else {
        value.min(300.0)
    }
}
pub fn deadline_after(now: i64, seconds: f64) -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    let ns = (bounded_timeout(seconds) * 1e9) as i64;
    now.wrapping_add(ns)
}
pub fn proposal_height_status(current: i64, proposal: i64) -> HeightStatus {
    match proposal.cmp(&current) {
        std::cmp::Ordering::Equal => HeightStatus::Current,
        std::cmp::Ordering::Less => HeightStatus::Stale,
        std::cmp::Ordering::Greater => HeightStatus::Future,
    }
}
pub fn proposal_local_status(engine_head: i64, local_head: i64, proposal: i64) -> HeightStatus {
    if proposal <= local_head {
        HeightStatus::Stale
    } else {
        proposal_height_status(engine_head, proposal)
    }
}
pub fn vote_relay_relevant(height: i64, round: i64, vote: &Vote) -> bool {
    vote.epoch_id == height
        && vote.round >= round
        && vote.round <= int63_add(round, engine::MAX_ROUND_AHEAD)
}
pub fn next_height_relay_relevant(height: i64, epoch: i64, round: i64) -> bool {
    height != i64::MAX
        && epoch == height.wrapping_add(1)
        && (0..=engine::MAX_ROUND_AHEAD).contains(&round)
}
pub fn future_vote_relay_relevant(height: i64, vote: &Vote) -> bool {
    next_height_relay_relevant(height, vote.epoch_id, vote.round)
}
pub fn round_sync_relay_relevant(height: i64, round: i64, sync: &RoundSync) -> bool {
    !sync.request
        && sync.epoch_id == height
        && sync.round >= round
        && sync.round <= int63_add(round, engine::MAX_ROUND_AHEAD)
}
pub fn round_sync_allowed(round: i64, sync: &RoundSync) -> bool {
    sync.round >= 0 && sync.round <= int63_add(round, engine::MAX_SYNC_AHEAD)
}
pub fn validate_proposal_frame(
    chain: &[u8],
    set: &ValidatorSet,
    protocol: Protocol,
    proposal: &Proposal,
) -> Result<Option<ProposalError>, Error> {
    let Some(public) = set.public_key(&proposal.proposer) else {
        return Ok(Some(ProposalError::UnknownValidator));
    };
    Ok(if !hash::verify_proposal(public, proposal)? {
        Some(ProposalError::BadSignature)
    } else if !set.proposal_well_formed(chain, protocol, proposal)? {
        Some(ProposalError::Envelope)
    } else if engine::tx_list_hash_for_header(&proposal.tx_hashes).as_slice()
        != proposal.header.tx_list_hash
    {
        Some(ProposalError::TransactionRoot)
    } else if hash::parent_commit_hash_opt(proposal.parent_commit.as_ref())?.as_slice()
        != proposal.header.parent_commit_hash
    {
        Some(ProposalError::ParentCommitHash)
    } else {
        None
    })
}
pub fn proposal_verify_relevant(round: i64, step: RoundStep, proposal_round: i64) -> bool {
    proposal_round >= round
        && int63_add(proposal_round, -round) <= engine::MAX_ROUND_AHEAD
        && (proposal_round > round || step == RoundStep::Propose)
}
pub fn vote_key(v: &Vote) -> Bytes {
    let mut key = format!(
        "{}|{}|{}|",
        if v.vote_type == VoteType::Prevote {
            "PREVOTE"
        } else {
            "PRECOMMIT"
        },
        v.epoch_id,
        v.round
    )
    .into_bytes();
    key.extend_from_slice(&v.validator);
    key.push(b'|');
    key.extend_from_slice(hex::encode(&v.proposal_id).as_bytes());
    key
}
pub fn future_vote_key(v: &Vote) -> Bytes {
    let mut key = format!(
        "{}|{}|{}|",
        if v.vote_type == VoteType::Prevote {
            "PREVOTE"
        } else {
            "PRECOMMIT"
        },
        v.epoch_id,
        v.round
    )
    .into_bytes();
    key.extend_from_slice(&v.validator);
    key
}
pub fn finalized_vote(
    height: i64,
    address: &[u8],
    pending: Option<&Finalize>,
    vote: &Vote,
) -> bool {
    pending.is_some_and(|f| {
        vote.validator == address
            && vote.vote_type == VoteType::Precommit
            && vote.proposal_id != NIL
            && vote.epoch_id == height
            && vote.epoch_id == f.epoch_id
            && vote.chain_id == f.chain_id
            && vote.round == f.commit_round
            && vote.proposal_id == f.proposal_id
    })
}
pub fn proposal_binds_vote(vote: &Vote, proposal: &Proposal) -> Result<bool, Error> {
    Ok(proposal.chain_id == vote.chain_id
        && proposal.epoch_id == vote.epoch_id
        && proposal.round == vote.round
        && proposal.header.chain_id == proposal.chain_id
        && proposal.header.epoch_id == proposal.epoch_id
        && hash::proposal_id(&proposal.header)?.as_slice() == vote.proposal_id)
}
pub fn round_fetch_valid(chain: &[u8], height: i64, round: i64, fetch: &RoundFetch) -> bool {
    fetch.chain_id == chain
        && fetch.epoch_id == height
        && fetch.after_round >= int63_add(round, -engine::MAX_SYNC_AHEAD).max(0)
        && fetch.after_round < fetch.through_round
        && fetch.through_round <= round
        && int63_add(fetch.through_round, -fetch.after_round) <= engine::ROUND_HISTORY_LIMIT
}
fn int63_add(a: i64, b: i64) -> i64 {
    (a.wrapping_add(b) << 1) >> 1
}
