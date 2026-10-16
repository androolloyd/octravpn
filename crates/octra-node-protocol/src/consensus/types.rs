// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::Error;
use num_bigint::BigInt;
pub const LEGACY_VERSION: i64 = 3;
pub const CURRENT_VERSION: i64 = 4;
pub const NIL: [u8; 32] = [0; 32];
pub type Bytes = Vec<u8>;
#[derive(Clone, Debug, PartialEq)]
pub struct EpochHeader {
    pub proto_version: i64,
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub prev_state_root: Bytes,
    pub tx_list_hash: Bytes,
    pub receipt_root: Bytes,
    pub proposed_state_root: Bytes,
    pub parent_commit_hash: Bytes,
    pub creator_addr: Bytes,
    pub txid_hi: i64,
    pub ts: f64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VoteType {
    Prevote = 1,
    Precommit = 2,
}
impl VoteType {
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Prevote),
            2 => Ok(Self::Precommit),
            _ => Err("bad vote_type".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofKind {
    Zero = 1,
    Bound = 2,
    Range = 3,
}
impl ProofKind {
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Zero),
            2 => Ok(Self::Bound),
            3 => Ok(Self::Range),
            _ => Err("bad proof_kind".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RoundStep {
    Propose = 1,
    Prevote = 2,
    Precommit = 3,
}
impl RoundStep {
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Propose),
            2 => Ok(Self::Prevote),
            3 => Ok(Self::Precommit),
            _ => Err("bad round_step".into()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub round: i64,
    pub vote_type: VoteType,
    pub proposal_id: Bytes,
    pub validator: Bytes,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub address: Bytes,
    pub pubkey: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub weights: Vec<(Bytes, BigInt)>,
    pub n: i64,
    pub f: i64,
    pub quorum: i64,
    pub total_weight: BigInt,
    pub quorum_weight: BigInt,
    pub weighted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardMember {
    pub reward_address: Bytes,
    pub reward_public_key: Option<Bytes>,
    pub reward_weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardSource {
    pub reward_proposer_addr: Bytes,
    pub reward_proposer_public_key: Option<Bytes>,
    pub reward_members: Vec<RewardMember>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CommitCertificate {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub commit_round: i64,
    pub header: EpochHeader,
    pub proposal_id: Bytes,
    pub precommits: Vec<Vote>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct ParentCommit {
    pub certificate: CommitCertificate,
    pub validator_set: ValidatorSet,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub round: i64,
    pub valid_round: Option<i64>,
    pub header: EpochHeader,
    pub tx_hashes: Vec<Bytes>,
    pub parent_commit: Option<ParentCommit>,
    pub proposer: Bytes,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Finalize {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub commit_round: i64,
    pub header: EpochHeader,
    pub proposal_id: Bytes,
    pub precommits: Vec<Vote>,
    pub parent_commit: Option<ParentCommit>,
}
impl Finalize {
    pub fn certificate(&self) -> CommitCertificate {
        CommitCertificate {
            chain_id: self.chain_id.clone(),
            epoch_id: self.epoch_id,
            commit_round: self.commit_round,
            header: self.header.clone(),
            proposal_id: self.proposal_id.clone(),
            precommits: self.precommits.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCertificate {
    pub task_id: Bytes,
    pub result: bool,
    pub validator: Bytes,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofQc {
    pub task_id: Bytes,
    pub result: bool,
    pub certs: Vec<(Bytes, Bytes)>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct EngineState {
    pub height: i64,
    pub round: i64,
    pub step: RoundStep,
    pub locked_round: i64,
    pub locked_value: Option<EpochHeader>,
    pub valid_round: i64,
    pub valid_value: Option<EpochHeader>,
}
impl EngineState {
    pub const fn initial(height: i64) -> Self {
        Self {
            height,
            round: 0,
            step: RoundStep::Propose,
            locked_round: -1,
            locked_value: None,
            valid_round: -1,
            valid_value: None,
        }
    }
}
pub fn valid_round_is_well_formed(round: i64, valid_round: Option<i64>) -> bool {
    valid_round.is_none_or(|valid| valid >= 0 && valid < round)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundSync {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub round: i64,
    pub step: RoundStep,
    pub request: bool,
    pub validator: Bytes,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundFetch {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub after_round: i64,
    pub through_round: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRootQuery {
    pub chain_id: Bytes,
    pub epoch_id: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRootResponse {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub state_root: Option<Bytes>,
    pub responder_addr: Bytes,
    pub responder_head_epoch: i64,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleQuery {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub proposal_id: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleResponse {
    pub chain_id: Bytes,
    pub epoch_id: i64,
    pub proposal_id: Bytes,
    pub responder_addr: Bytes,
    pub tx_hashes: Vec<Bytes>,
    pub txs_json: Vec<Bytes>,
    pub receipts_json: Vec<Bytes>,
    pub signature: Bytes,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CatchupEpochRecord {
    pub epoch_id: i64,
    pub prev_state_root: Bytes,
    pub state_root: Bytes,
    pub tx_list_hash: Bytes,
    pub tx_hashes: Vec<Bytes>,
    pub txs_json: Vec<Bytes>,
    pub receipt_root: Bytes,
    pub receipts_json: Vec<Bytes>,
    pub epoch_ts: f64,
    pub creator_addr: Bytes,
    pub commit_round: i64,
    pub reward_source: Option<RewardSource>,
    pub finality: Option<CatchupFinality>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CatchupFinality {
    pub finalize: Finalize,
    pub validator_set: ValidatorSet,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatchupQuery {
    pub chain_id: Bytes,
    pub request_id: Bytes,
    pub from_epoch: i64,
    pub max_epochs: i64,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CatchupResponse {
    pub chain_id: Bytes,
    pub request_id: Bytes,
    pub status: Bytes,
    pub error_code: Option<Bytes>,
    pub records: Vec<CatchupEpochRecord>,
    pub next_epoch: Option<i64>,
    pub responder_addr: Bytes,
    pub signature: Bytes,
}
