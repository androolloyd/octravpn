// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native BFT transitions. Peer inputs pass signature/QC checks before mutation.
//! The host supplies execution and durable-signing callbacks and acknowledges finalization.
use super::votes::{VoteAdd, VoteSet};
use super::{
    hash, policy::Protocol, qc, Bytes, EngineState, EpochHeader, Error, Finalize, ParentCommit,
    Proposal, RoundStep, RoundSync, ValidatorSet, Vote, VoteType, NIL,
};
use crate::native_integer;
use num_bigint::BigInt;
use std::collections::BTreeMap;
pub const MAX_ROUND_AHEAD: i64 = 64;
pub const MAX_SYNC_AHEAD: i64 = 1024;
pub const ROUND_HISTORY_LIMIT: i64 = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeoutConfig {
    pub base: i64,
    pub propose: i64,
    pub per_round: i64,
}
impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            base: 3000,
            propose: 3000,
            per_round: 1000,
        }
    }
}
impl TimeoutConfig {
    pub fn from_values(
        base: Option<&[u8]>,
        propose: Option<&[u8]>,
        per_round: Option<&[u8]>,
    ) -> Self {
        let parse = |raw: Option<&[u8]>, default, limit| {
            raw.and_then(native_integer::parse_int63)
                .filter(|n| *n >= 100 && *n <= limit)
                .unwrap_or(default)
        };
        let base = parse(base, 3000, 120_000);
        Self {
            base,
            propose: parse(propose, base, 300_000),
            per_round: parse(per_round, 1000, 30_000),
        }
    }
    pub fn milliseconds(self, round: i64, step: RoundStep) -> i64 {
        let (base, cap) = if step == RoundStep::Propose {
            (self.propose.max(15_000), 300_000)
        } else {
            (self.base, 120_000)
        };
        let raw = base.wrapping_add(round.max(0).wrapping_mul(self.per_round));
        (raw.min(cap) << 1) >> 1
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum Output {
    SendProposal(Proposal),
    SendVote(Vote, Option<Proposal>),
    SendFinalize(Finalize),
    RequestProposal {
        round: i64,
        proposal_id: Bytes,
    },
    RequestRoundEvidence(i64),
    ScheduleTimeout {
        step: RoundStep,
        round: i64,
        delay_ms: i64,
        generation: i64,
    },
    Finalized {
        epoch_id: i64,
        finalize: Finalize,
    },
}
#[derive(Clone, Debug)]
struct CachedProposal {
    header: EpochHeader,
    tx_hashes: Option<Vec<Bytes>>,
    parent_commit: Option<ParentCommit>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum LocalVote {
    Cast(VoteAdd),
    AlreadySame,
    Conflict,
    Deferred,
}
/// Signers must durably prevent conflicting signatures before returning a signature.
pub type Signer<'a> = dyn FnMut(&[u8]) -> Result<Bytes, Error> + 'a;
/// Execution must validate the full proposal against the host's canonical state.
pub type Execute<'a> = dyn FnMut(&Proposal) -> Result<bool, Error> + 'a;
pub struct Engine {
    chain_id: Bytes,
    my_addr: Bytes,
    validators: ValidatorSet,
    state: EngineState,
    protocol: Protocol,
    timeouts: TimeoutConfig,
    prevotes: BTreeMap<i64, VoteSet>,
    precommits: BTreeMap<i64, VoteSet>,
    current_proposal: Option<Proposal>,
    pending_prevote: Option<(i64, i64, Bytes)>,
    cache: BTreeMap<Bytes, CachedProposal>,
    messages: BTreeMap<(Bytes, i64), Proposal>,
    polc: BTreeMap<i64, Bytes>,
    requests: BTreeMap<i64, i64>,
    higher_rounds: BTreeMap<Bytes, i64>,
    outputs: Vec<Output>,
    finalized_height: i64,
    pending_finalized: Option<Finalize>,
    generation: i64,
    can_vote: bool,
    round_skip_ready: bool,
}
impl Engine {
    pub fn new(
        chain_id: Bytes,
        my_addr: Bytes,
        validators: ValidatorSet,
        start_height: i64,
        protocol: Protocol,
        timeouts: TimeoutConfig,
    ) -> Self {
        Self {
            chain_id,
            my_addr,
            validators,
            state: EngineState::initial(start_height),
            protocol,
            timeouts,
            prevotes: BTreeMap::from([(0, VoteSet::default())]),
            precommits: BTreeMap::from([(0, VoteSet::default())]),
            current_proposal: None,
            pending_prevote: None,
            cache: BTreeMap::new(),
            messages: BTreeMap::new(),
            polc: BTreeMap::new(),
            requests: BTreeMap::new(),
            higher_rounds: BTreeMap::new(),
            outputs: Vec::new(),
            finalized_height: start_height.wrapping_sub(1),
            pending_finalized: None,
            generation: 0,
            can_vote: false,
            round_skip_ready: true,
        }
    }
    pub const fn state(&self) -> &EngineState {
        &self.state
    }
    pub const fn protocol(&self) -> Protocol {
        self.protocol
    }
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn address(&self) -> &[u8] {
        &self.my_addr
    }
    pub const fn generation(&self) -> i64 {
        self.generation
    }
    pub const fn finalized_height(&self) -> i64 {
        self.finalized_height
    }
    pub fn pending_finalized(&self) -> Option<&Finalize> {
        self.pending_finalized.as_ref()
    }
    pub const fn validators(&self) -> &ValidatorSet {
        &self.validators
    }
    pub fn set_voting_ready(&mut self, ready: bool) {
        self.can_vote = ready;
    }
    pub fn set_round_skip_ready(&mut self, ready: bool) {
        self.round_skip_ready = ready;
    }
    pub fn replace_validator_set(&mut self, validators: ValidatorSet) {
        self.validators = validators;
    }
    pub fn is_pristine(&self) -> bool {
        self.generation == 0
            && self.state.round == 0
            && self.state.step == RoundStep::Propose
            && self.current_proposal.is_none()
            && self.current(VoteType::Prevote).votes.is_empty()
            && self.current(VoteType::Precommit).votes.is_empty()
            && self.pending_finalized.is_none()
            && self.outputs.is_empty()
    }
    fn current(&self, kind: VoteType) -> &VoteSet {
        self.rounds(kind)
            .get(&self.state.round)
            .expect("current round vote set")
    }
    fn rounds(&self, kind: VoteType) -> &BTreeMap<i64, VoteSet> {
        if kind == VoteType::Prevote {
            &self.prevotes
        } else {
            &self.precommits
        }
    }
    fn add_vote(&mut self, vote: Vote) -> VoteAdd {
        let vs = &self.validators;
        let rounds = if vote.vote_type == VoteType::Prevote {
            &mut self.prevotes
        } else {
            &mut self.precommits
        };
        rounds.entry(vote.round).or_default().add(vote, vs)
    }
    fn quorum(&self, kind: VoteType) -> VoteAdd {
        self.current(kind)
            .quorum(&self.chain_id, self.state.height, &self.validators)
    }
    fn voting_allowed(&self) -> bool {
        self.can_vote && self.validators.is_validator(&self.my_addr)
    }
    fn can_prevote(&self) -> bool {
        self.state.step != RoundStep::Precommit
    }
    fn emit(&mut self, out: Output) {
        self.outputs.push(out);
    }
    fn timeout(&mut self, step: RoundStep) {
        self.emit(Output::ScheduleTimeout {
            step,
            round: self.state.round,
            delay_ms: self.timeouts.milliseconds(self.state.round, step),
            generation: self.generation,
        });
    }
    pub fn drain_outputs(&mut self) -> Vec<Output> {
        let mut out = std::mem::take(&mut self.outputs);
        if let Some(f) = &self.pending_finalized {
            if !out
                .iter()
                .any(|o| matches!(o,Output::Finalized{finalize,..}if same_finalize(finalize,f)))
            {
                out.push(Output::Finalized {
                    epoch_id: f.epoch_id,
                    finalize: f.clone(),
                });
            }
        }
        out
    }
    pub fn ack_finalized(&mut self, f: &Finalize) -> bool {
        if self
            .pending_finalized
            .as_ref()
            .is_some_and(|p| same_finalize(p, f))
        {
            self.pending_finalized = None;
            true
        } else {
            false
        }
    }
    fn cache_bundle(
        &mut self,
        pid: Bytes,
        header: EpochHeader,
        hashes: Vec<Bytes>,
        parent: Option<ParentCommit>,
    ) {
        self.cache.insert(
            pid,
            CachedProposal {
                header,
                tx_hashes: Some(hashes),
                parent_commit: parent,
            },
        );
    }
    fn cache_header(&mut self, pid: Bytes, header: EpochHeader) {
        self.cache.entry(pid).or_insert(CachedProposal {
            header,
            tx_hashes: None,
            parent_commit: None,
        });
    }
    pub fn find_header(&self, pid: &[u8]) -> Option<&EpochHeader> {
        self.cache.get(pid).map(|v| &v.header)
    }
    pub fn find_tx_hashes(&self, pid: &[u8]) -> Option<&[Bytes]> {
        self.cache.get(pid).and_then(|v| v.tx_hashes.as_deref())
    }
    pub fn find_parent_commit(&self, pid: &[u8]) -> Option<&ParentCommit> {
        self.cache.get(pid).and_then(|v| v.parent_commit.as_ref())
    }
    pub fn find_proposal(&self, pid: &[u8], round: i64) -> Option<&Proposal> {
        self.messages.get(&(pid.to_vec(), round))
    }
    pub fn current_proposal(&self) -> Option<&Proposal> {
        self.current_proposal
            .as_ref()
            .filter(|p| p.epoch_id == self.state.height && p.round == self.state.round)
    }
    pub fn current_votes(&self) -> Vec<Vote> {
        let mut votes = [VoteType::Prevote, VoteType::Precommit]
            .into_iter()
            .flat_map(|kind| self.current(kind).votes.values())
            .filter(|v| v.epoch_id == self.state.height && v.round == self.state.round)
            .cloned()
            .collect::<Vec<_>>();
        votes.sort_by(|a, b| {
            (a.vote_type as u8)
                .cmp(&(b.vote_type as u8))
                .then_with(|| a.validator.cmp(&b.validator))
        });
        votes
    }
    fn promote_header(&mut self, round: i64, pid: &[u8]) {
        if round > self.state.valid_round {
            if let Some(header) = self.find_header(pid).cloned() {
                self.state.valid_round = round;
                self.state.valid_value = Some(header);
            }
        }
    }
    fn record_polc(&mut self, round: i64, pid: &[u8]) {
        if pid != NIL {
            self.polc.insert(round, pid.to_vec());
            self.requests.remove(&round);
            self.promote_header(round, pid);
        }
    }
    fn cache_message(&mut self, p: Proposal) -> Result<(), Error> {
        let pid = hash::proposal_id(&p.header)?.to_vec();
        self.cache_bundle(
            pid.clone(),
            p.header.clone(),
            p.tx_hashes.clone(),
            p.parent_commit.clone(),
        );
        self.messages.insert((pid.clone(), p.round), p);
        let rounds: Vec<_> = self
            .polc
            .iter()
            .filter(|(_, p)| **p == pid)
            .map(|(r, _)| *r)
            .collect();
        for r in rounds {
            self.promote_header(r, &pid);
        }
        Ok(())
    }
    pub fn conflicting_vote(&self, v: &Vote) -> Option<&Vote> {
        if v.epoch_id != self.state.height {
            return None;
        }
        self.rounds(v.vote_type)
            .get(&v.round)
            .and_then(|set| set.votes.get(&v.validator))
            .filter(|old| old.proposal_id != v.proposal_id)
    }
    fn cast(
        &mut self,
        sign: &mut Signer<'_>,
        kind: VoteType,
        pid: &[u8],
    ) -> Result<LocalVote, Error> {
        if let Some(prior) = self.current(kind).votes.get(&self.my_addr) {
            return Ok(if prior.proposal_id == pid {
                LocalVote::AlreadySame
            } else {
                LocalVote::Conflict
            });
        }
        let proposal = if kind == VoteType::Precommit && pid != NIL {
            self.find_proposal(pid, self.state.round).cloned()
        } else {
            None
        };
        if kind == VoteType::Precommit && pid != NIL && proposal.is_none() {
            self.emit(Output::RequestProposal {
                round: self.state.round,
                proposal_id: pid.to_vec(),
            });
            return Ok(LocalVote::Deferred);
        }
        let mut vote = Vote {
            chain_id: self.chain_id.clone(),
            epoch_id: self.state.height,
            round: self.state.round,
            vote_type: kind,
            proposal_id: pid.to_vec(),
            validator: self.my_addr.clone(),
            signature: vec![0; 64],
        };
        vote.signature = sign(&hash::vote_sign_bytes(&vote)?)?;
        let result = self.add_vote(vote.clone());
        self.emit(Output::SendVote(vote, proposal));
        Ok(LocalVote::Cast(result))
    }
    fn precommits_for(&self, round: i64, pid: &[u8]) -> Vec<Vote> {
        self.precommits
            .get(&round)
            .map(|v| {
                v.votes
                    .values()
                    .filter(|v| v.vote_type == VoteType::Precommit && v.proposal_id == pid)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    fn emit_finalized(&mut self, f: Finalize, send: bool) -> bool {
        if let Some(p) = &self.pending_finalized {
            return same_finalize(p, &f);
        }
        self.finalized_height = f.epoch_id;
        self.pending_finalized = Some(f.clone());
        if send {
            self.emit(Output::SendFinalize(f));
        }
        true
    }
    fn local_finalize(
        &mut self,
        header: EpochHeader,
        pid: Bytes,
        round: i64,
    ) -> Result<bool, Error> {
        let parent = self.find_parent_commit(&pid).cloned();
        if hash::parent_commit_hash_opt(parent.as_ref())?.as_slice() != header.parent_commit_hash {
            self.emit(Output::RequestProposal {
                round,
                proposal_id: pid,
            });
            return Ok(false);
        }
        let f = Finalize {
            chain_id: self.chain_id.clone(),
            epoch_id: self.state.height,
            commit_round: round,
            header,
            proposal_id: pid.clone(),
            precommits: self.precommits_for(round, &pid),
            parent_commit: parent,
        };
        Ok(self.emit_finalized(f, true))
    }
    pub fn am_i_leader(&self) -> Result<bool, Error> {
        Ok(self
            .validators
            .leader(self.state.height, self.state.round)?
            .address
            == self.my_addr)
    }
    fn retained(&self, round: i64) -> bool {
        round >= (self.state.round - ROUND_HISTORY_LIMIT).max(0)
            || round == self.state.locked_round
            || round == self.state.valid_round
            || self.requests.contains_key(&round)
    }
    fn remember_request(&mut self, round: i64) -> bool {
        if round < 0
            || round >= self.state.round
            || round <= self.state.locked_round
            || self.polc.contains_key(&round)
        {
            return false;
        }
        if self.requests.contains_key(&round) {
            return true;
        }
        if self.requests.len() >= ROUND_HISTORY_LIMIT as usize {
            self.requests.pop_first();
        }
        self.requests.insert(round, -1);
        true
    }
    fn request_polc(&mut self, round: i64) {
        if self.remember_request(round)
            && self
                .requests
                .get(&round)
                .is_some_and(|last| *last < self.state.round)
        {
            self.requests.insert(round, self.state.round);
            self.emit(Output::RequestRoundEvidence(round));
        }
    }
    fn retry_request(&mut self, except: Option<i64>) {
        if let Some((&round, _)) = self
            .requests
            .iter()
            .filter(|(r, s)| Some(**r) != except && **s < self.state.round)
            .min_by(|(ra, sa), (rb, sb)| sa.cmp(sb).then_with(|| rb.cmp(ra)))
        {
            self.requests.insert(round, self.state.round);
            self.emit(Output::RequestRoundEvidence(round));
        }
    }
    pub fn start_round(&mut self, round: i64) {
        self.state.round = round;
        self.state.step = RoundStep::Propose;
        let previous = (round > 0).then_some(round - 1);
        if let Some(p) = previous {
            self.request_polc(p);
        }
        self.retry_request(previous);
        self.prevotes.insert(round, VoteSet::default());
        self.precommits.insert(round, VoteSet::default());
        let floor = (round - ROUND_HISTORY_LIMIT).max(0);
        let keep = |r: &i64, _: &mut VoteSet| {
            *r >= floor
                || *r == self.state.locked_round
                || *r == self.state.valid_round
                || self.requests.contains_key(r)
        };
        self.prevotes.retain(keep);
        self.precommits.retain(keep);
        self.current_proposal = None;
        self.pending_prevote = None;
        self.timeout(RoundStep::Propose);
    }
    pub fn realign_round(&mut self, round: i64) -> Result<(), Error> {
        if round <= self.state.round {
            return Err("consensus round must advance".into());
        }
        self.generation = int63_add(self.generation, 1);
        self.start_round(round);
        Ok(())
    }
    pub fn start_height(&mut self, height: i64) {
        self.generation = int63_add(self.generation, 1);
        self.outputs.clear();
        self.state = EngineState::initial(height);
        self.cache.clear();
        self.messages.clear();
        self.polc.clear();
        self.requests.clear();
        self.prevotes.clear();
        self.precommits.clear();
        self.higher_rounds.clear();
        self.start_round(0);
    }
    pub fn polc_matches(&self, round: i64, pid: &[u8]) -> bool {
        self.polc.get(&round).is_some_and(|p| p == pid)
    }
    pub fn polc_request_pending(&self, round: i64) -> bool {
        self.requests.contains_key(&round)
    }
    pub fn historical_prevote_known(&self, round: i64, validator: &[u8]) -> bool {
        self.prevotes
            .get(&round)
            .is_some_and(|v| v.votes.contains_key(validator))
    }
    pub fn polc_votes(&self, round: i64) -> Vec<Vote> {
        match (self.polc.get(&round), self.prevotes.get(&round)) {
            (Some(pid), Some(set)) => set
                .votes
                .values()
                .filter(|v| v.proposal_id == *pid)
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }
    fn record_historical_prevote(&mut self, v: Vote) {
        if v.round >= 0 && v.round < self.state.round && self.retained(v.round) {
            let round = v.round;
            if let VoteAdd::QuorumOf(pid) = self.add_vote(v) {
                self.record_polc(round, &pid);
            }
        }
    }
    pub fn restored_precommit_lock(&self, p: &Proposal) -> Result<bool, Error> {
        let pid = hash::proposal_id(&p.header)?;
        Ok(p.epoch_id == self.state.height
            && self.state.locked_round == p.round
            && self.state.round >= int63_add(p.round, 1)
            && match &self.state.locked_value {
                Some(h) => hash::proposal_id(h)? == pid,
                None => false,
            })
    }
    /// Restore a proposal previously persisted by the durable signing journal.
    pub fn restore_precommit_lock(&mut self, p: Proposal) -> Result<(), Error> {
        if p.chain_id != self.chain_id {
            return Err("pending proposal chain mismatch".into());
        }
        if p.epoch_id != self.state.height {
            return Err("pending proposal height mismatch".into());
        }
        if p.header.proto_version != self.protocol.version_at(p.epoch_id) {
            return Err("pending proposal protocol mismatch".into());
        }
        if p.header.chain_id != p.chain_id {
            return Err("pending proposal header chain mismatch".into());
        }
        if p.header.epoch_id != p.epoch_id {
            return Err("pending proposal header height mismatch".into());
        }
        if self.restored_precommit_lock(&p)? {
            return Ok(());
        }
        if !self.is_pristine() {
            return Err("consensus engine is not pristine".into());
        }
        let pid = hash::proposal_id(&p.header)?;
        self.cache_message(p.clone())?;
        self.record_polc(p.round, &pid);
        self.state.locked_round = p.round;
        self.state.locked_value = Some(p.header.clone());
        self.state.valid_round = p.round;
        self.state.valid_value = Some(p.header);
        self.realign_round(int63_add(p.round, 1))
    }
    fn record_higher_round(&mut self, limit: i64, round: i64, validator: &[u8]) {
        if self.validators.is_validator(validator)
            && round > self.state.round
            && round <= int63_add(self.state.round, limit)
            && self.higher_rounds.get(validator).is_none_or(|v| *v < round)
        {
            self.higher_rounds.insert(validator.to_vec(), round);
        }
    }
    pub fn round_skip_target(&self) -> Option<i64> {
        let mut reports: Vec<_> = self
            .higher_rounds
            .iter()
            .filter(|(_, r)| **r > self.state.round)
            .filter_map(|(v, r)| self.validators.weight(v).map(|w| (*r, w)))
            .collect();
        reports.sort_by_key(|v| std::cmp::Reverse(v.0));
        let mut weight = BigInt::default();
        for (index, (round, w)) in reports.into_iter().enumerate() {
            weight += w;
            if self.validators.round_skip_reached_at(
                &self.chain_id,
                self.state.height,
                index as i64 + 1,
                &weight,
            ) {
                return Some(round);
            }
        }
        None
    }
    fn try_round_skip(&mut self) -> Result<bool, Error> {
        if !self.round_skip_ready || self.state.height <= self.finalized_height {
            return Ok(false);
        }
        if let Some(target) = self.round_skip_target() {
            self.higher_rounds.clear();
            self.realign_round(target)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn on_round_sync(&mut self, sync: &RoundSync) -> Result<bool, Error> {
        if sync.chain_id != self.chain_id || sync.epoch_id != self.state.height {
            return Ok(false);
        }
        let Some(public) = self.validators.public_key(&sync.validator) else {
            return Ok(false);
        };
        if !hash::verify_round_sync(public, sync)? {
            return Ok(false);
        }
        if sync.round > self.state.round {
            self.record_higher_round(MAX_SYNC_AHEAD, sync.round, &sync.validator);
            self.try_round_skip()
        } else {
            Ok(false)
        }
    }
    fn lock_allows(&self, pid: &[u8], valid_round: Option<i64>) -> Result<bool, Error> {
        if self.state.locked_round < 0 {
            return Ok(true);
        }
        let locked = match &self.state.locked_value {
            Some(h) => hash::proposal_id(h)?.to_vec(),
            None => Vec::new(),
        };
        Ok(pid == locked
            || valid_round.is_some_and(|r| {
                r > self.state.locked_round && r < self.state.round && self.polc_matches(r, pid)
            }))
    }
    fn remember_prevote(&mut self, pid: Bytes) {
        if self.pending_prevote.is_none()
            && !self
                .current(VoteType::Prevote)
                .votes
                .contains_key(&self.my_addr)
        {
            self.pending_prevote = Some((self.state.height, self.state.round, pid));
        }
    }
    fn finalize_quorum(&mut self, pid: Bytes) -> Result<bool, Error> {
        if let Some(header) = self.find_header(&pid).cloned() {
            self.local_finalize(header, pid, self.state.round)
        } else {
            Ok(false)
        }
    }
    fn lock(&mut self, header: EpochHeader) {
        self.state.locked_round = self.state.round;
        self.state.locked_value = Some(header.clone());
        self.state.valid_round = self.state.round;
        self.state.valid_value = Some(header);
    }
    fn precommit_nil(&mut self, sign: &mut Signer<'_>) -> Result<(), Error> {
        if self.voting_allowed()
            && self.state.step == RoundStep::Prevote
            && self.current(VoteType::Prevote).nil_quorum(
                &self.chain_id,
                self.state.height,
                &self.validators,
            )
        {
            self.state.step = RoundStep::Precommit;
            if self.cast(sign, VoteType::Precommit, &NIL)? != LocalVote::Conflict {
                self.timeout(RoundStep::Precommit);
            }
        }
        Ok(())
    }
    pub fn on_ready(&mut self, sign: &mut Signer<'_>) -> Result<(), Error> {
        if !self.voting_allowed() {
            return Ok(());
        }
        if let Some((height, round, pid)) = self.pending_prevote.take() {
            if height == self.state.height && round == self.state.round && self.can_prevote() {
                self.state.step = RoundStep::Prevote;
                if matches!(
                    self.cast(sign, VoteType::Prevote, &pid)?,
                    LocalVote::Cast(_) | LocalVote::AlreadySame
                ) {
                    self.timeout(RoundStep::Prevote);
                }
            }
        }
        self.precommit_nil(sign)?;
        if let VoteAdd::QuorumOf(pid) = self.quorum(VoteType::Prevote) {
            if self.state.step != RoundStep::Precommit && pid != NIL {
                if let Some(p) = self.find_proposal(&pid, self.state.round).cloned() {
                    self.record_polc(self.state.round, &pid);
                    self.lock(p.header);
                    self.state.step = RoundStep::Precommit;
                    if self.cast(sign, VoteType::Precommit, &pid)? != LocalVote::Conflict {
                        self.timeout(RoundStep::Precommit);
                    }
                }
            }
        }
        if self.state.height > self.finalized_height {
            if let VoteAdd::QuorumOf(pid) = self.quorum(VoteType::Precommit) {
                if pid != NIL {
                    self.finalize_quorum(pid)?;
                }
            }
        }
        Ok(())
    }
    pub fn do_propose(
        &mut self,
        header: EpochHeader,
        tx_hashes: Vec<Bytes>,
        parent_commit: Option<ParentCommit>,
        sign: &mut Signer<'_>,
    ) -> Result<(), Error> {
        if !self.voting_allowed()
            || !self.am_i_leader()?
            || header.epoch_id != self.state.height
            || header.chain_id != self.chain_id
            || header.proto_version != self.protocol.version_at(header.epoch_id)
            || self.state.step != RoundStep::Propose
        {
            return Ok(());
        }
        let (header, tx_hashes, valid_round, parent_commit) =
            if self.validators.quorum >= 1 && self.state.valid_round >= 0 {
                if let Some(header) = self.state.valid_value.clone() {
                    let pid = hash::proposal_id(&header)?;
                    let Some(hashes) = self.find_tx_hashes(&pid).map(<[Bytes]>::to_vec) else {
                        return Ok(());
                    };
                    if tx_list_hash_for_header(&hashes) != header.tx_list_hash.as_slice() {
                        return Ok(());
                    }
                    let parent = self.find_parent_commit(&pid).cloned();
                    (header, hashes, Some(self.state.valid_round), parent)
                } else {
                    (header, tx_hashes, None, parent_commit)
                }
            } else {
                (header, tx_hashes, None, parent_commit)
            };
        if hash::parent_commit_hash_opt(parent_commit.as_ref())?.as_slice()
            != header.parent_commit_hash
        {
            return Ok(());
        }
        let pid = hash::proposal_id(&header)?;
        self.cache_bundle(
            pid.to_vec(),
            header.clone(),
            tx_hashes.clone(),
            parent_commit.clone(),
        );
        let mut proposal = Proposal {
            chain_id: self.chain_id.clone(),
            epoch_id: self.state.height,
            round: self.state.round,
            valid_round,
            header: header.clone(),
            tx_hashes,
            parent_commit,
            proposer: self.my_addr.clone(),
            signature: vec![0; 64],
        };
        proposal.signature = sign(&hash::propose_sign_bytes(&proposal)?)?;
        self.cache_message(proposal.clone())?;
        self.current_proposal = Some(proposal.clone());
        self.emit(Output::SendProposal(proposal));
        self.state.step = RoundStep::Prevote;
        match self.cast(sign, VoteType::Prevote, &pid)? {
            LocalVote::Cast(VoteAdd::QuorumOf(_)) => {
                self.lock(header.clone());
                self.state.step = RoundStep::Precommit;
                if matches!(
                    self.cast(sign, VoteType::Precommit, &pid)?,
                    LocalVote::Cast(VoteAdd::QuorumOf(_))
                ) {
                    self.local_finalize(header, pid.to_vec(), self.state.round)?;
                } else {
                    self.timeout(RoundStep::Precommit);
                }
            }
            LocalVote::Cast(_) | LocalVote::AlreadySame => self.timeout(RoundStep::Prevote),
            LocalVote::Conflict | LocalVote::Deferred => {}
        }
        Ok(())
    }
    pub fn on_proposal(
        &mut self,
        p: Proposal,
        execute: &mut Execute<'_>,
        sign: &mut Signer<'_>,
    ) -> Result<(), Error> {
        // The native driver authenticates before calling c_engine.on_propose.
        if p.chain_id != self.chain_id {
            return Ok(());
        }
        let Some(public) = self.validators.public_key(&p.proposer) else {
            return Ok(());
        };
        if !hash::verify_proposal(public, &p)? {
            return Ok(());
        }
        if p.epoch_id <= self.finalized_height
            || p.epoch_id != self.state.height
            || p.round > int63_add(self.state.round, MAX_ROUND_AHEAD)
        {
            return Ok(());
        }
        if p.round > self.state.round {
            self.record_higher_round(MAX_ROUND_AHEAD, p.round, &p.proposer);
            self.try_round_skip()?;
        }
        if p.round != self.state.round {
            return Ok(());
        }
        let pid = hash::proposal_id(&p.header)?;
        let envelope = self
            .validators
            .proposal_well_formed(&self.chain_id, self.protocol, &p)?
            && hash::parent_commit_hash_opt(p.parent_commit.as_ref())?.as_slice()
                == p.header.parent_commit_hash;
        let valid = envelope && execute(&p)?;
        let accept = valid && self.lock_allows(&pid, p.valid_round)?;
        if valid {
            self.cache_message(p.clone())?;
            if accept {
                self.current_proposal = Some(p.clone());
            } else if let Some(round) = p.valid_round {
                self.request_polc(round);
            }
        }
        let finalized = valid
            && self.voting_allowed()
            && matches!(self.quorum(VoteType::Precommit),VoteAdd::QuorumOf(ref got)if *got==pid)
            && self.finalize_quorum(pid.to_vec())?;
        let vote_pid = if accept { pid } else { NIL };
        if finalized || !self.can_prevote() {
            return Ok(());
        }
        if !self.voting_allowed() {
            self.remember_prevote(vote_pid.to_vec());
            return Ok(());
        }
        self.state.step = RoundStep::Prevote;
        let prevote = self.cast(sign, VoteType::Prevote, &vote_pid)?;
        let quorum =
            matches!(self.quorum(VoteType::Prevote),VoteAdd::QuorumOf(ref got)if *got==vote_pid);
        if accept && quorum {
            self.record_polc(self.state.round, &pid);
            self.lock(p.header.clone());
            self.state.step = RoundStep::Precommit;
            if matches!(
                self.cast(sign, VoteType::Precommit, &vote_pid)?,
                LocalVote::Cast(VoteAdd::QuorumOf(_))
            ) {
                self.local_finalize(p.header, vote_pid.to_vec(), self.state.round)?;
            } else {
                self.timeout(RoundStep::Precommit);
            }
        } else {
            if matches!(prevote, LocalVote::Cast(_) | LocalVote::AlreadySame) {
                self.timeout(RoundStep::Prevote);
            }
            self.precommit_nil(sign)?;
        }
        Ok(())
    }
    fn known_header(&self, pid: &[u8]) -> Result<Option<EpochHeader>, Error> {
        if let Some(h) = self.find_header(pid) {
            return Ok(Some(h.clone()));
        }
        for h in [
            self.current_proposal.as_ref().map(|p| &p.header),
            self.state.locked_value.as_ref(),
            self.state.valid_value.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if hash::proposal_id(h)?.as_slice() == pid {
                return Ok(Some(h.clone()));
            }
        }
        Ok(None)
    }
    fn request_missing(&mut self, v: &Vote, result: &VoteAdd) {
        if !matches!(result, VoteAdd::Duplicate | VoteAdd::Rejected)
            && v.proposal_id != NIL
            && self.find_proposal(&v.proposal_id, v.round).is_none()
        {
            self.emit(Output::RequestProposal {
                round: v.round,
                proposal_id: v.proposal_id.clone(),
            });
        }
    }
    fn historical_precommit(&mut self, v: &Vote) -> Result<(), Error> {
        if v.round >= 0 && v.round < self.state.round && self.retained(v.round) {
            let result = self.add_vote(v.clone());
            self.request_missing(v, &result);
            if let VoteAdd::QuorumOf(pid) = result {
                if self.voting_allowed() {
                    if let Some(header) = self.known_header(&pid)? {
                        self.local_finalize(header, pid, v.round)?;
                    }
                }
            }
        }
        Ok(())
    }
    pub fn on_vote(&mut self, v: Vote, sign: &mut Signer<'_>) -> Result<(), Error> {
        if v.chain_id != self.chain_id {
            return Ok(());
        }
        let Some(public) = self.validators.public_key(&v.validator) else {
            return Ok(());
        };
        if !hash::verify_vote(public, &v)? {
            return Ok(());
        }
        if v.epoch_id <= self.finalized_height
            || v.epoch_id != self.state.height
            || v.round < 0
            || v.round > int63_add(self.state.round, MAX_ROUND_AHEAD)
        {
            return Ok(());
        }
        if v.round < self.state.round {
            if v.vote_type == VoteType::Prevote {
                self.record_historical_prevote(v);
            } else {
                self.historical_precommit(&v)?;
            }
            return Ok(());
        }
        if v.round > self.state.round {
            self.record_higher_round(MAX_ROUND_AHEAD, v.round, &v.validator);
            self.try_round_skip()?;
        }
        if v.round != self.state.round {
            return Ok(());
        }
        let result = self.add_vote(v.clone());
        self.request_missing(&v, &result);
        match v.vote_type {
            VoteType::Prevote => match result {
                VoteAdd::QuorumOf(pid) if self.state.step == RoundStep::Prevote => {
                    let nil = pid == NIL;
                    let proposal = if nil {
                        None
                    } else {
                        self.find_proposal(&pid, self.state.round).cloned()
                    };
                    if !nil && proposal.is_none() {
                        return Ok(());
                    }
                    if let Some(p) = proposal {
                        self.record_polc(self.state.round, &pid);
                        self.lock(p.header);
                    }
                    if self.voting_allowed() {
                        self.state.step = RoundStep::Precommit;
                        if self.cast(sign, VoteType::Precommit, &pid)? != LocalVote::Conflict {
                            self.timeout(RoundStep::Precommit);
                        }
                    }
                }
                VoteAdd::QuorumAny if self.state.step == RoundStep::Prevote => {
                    self.timeout(RoundStep::Prevote);
                }
                _ => {}
            },
            VoteType::Precommit => {
                if let VoteAdd::QuorumOf(pid) = result {
                    if self.voting_allowed() {
                        if let Some(h) = self.known_header(&pid)? {
                            self.local_finalize(h, pid, self.state.round)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub fn accept_finalize(&mut self, f: Finalize) -> Result<bool, Error> {
        qc::validate_finalize(
            &self.chain_id,
            &self.validators,
            &f,
            qc::FinalityMode::Live(self.protocol),
        )?;
        if f.epoch_id < self.finalized_height {
            return Ok(false);
        }
        if f.epoch_id == self.finalized_height {
            return Ok(self
                .pending_finalized
                .as_ref()
                .is_some_and(|p| same_finalize(p, &f)));
        }
        if f.epoch_id != self.state.height {
            return Ok(false);
        }
        let pid = hash::proposal_id(&f.header)?;
        if f.proposal_id != pid {
            return Ok(false);
        }
        if let Some(h) = &self.state.locked_value {
            if hash::proposal_id(h)? != pid && f.commit_round <= self.state.locked_round {
                return Ok(false);
            }
        }
        self.cache_header(pid.to_vec(), f.header.clone());
        self.record_polc(f.commit_round, &pid);
        self.state.locked_round = self.state.locked_round.max(f.commit_round);
        self.state.locked_value = Some(f.header.clone());
        self.state.valid_round = f.commit_round;
        self.state.valid_value = Some(f.header.clone());
        Ok(self.emit_finalized(f, false))
    }
    pub fn on_timeout(
        &mut self,
        step: RoundStep,
        round: i64,
        generation: i64,
        sign: &mut Signer<'_>,
    ) -> Result<(), Error> {
        if generation != self.generation || round != self.state.round || step != self.state.step {
            return Ok(());
        }
        match step {
            RoundStep::Propose if self.voting_allowed() => {
                self.state.step = RoundStep::Prevote;
                if matches!(
                    self.cast(sign, VoteType::Prevote, &NIL)?,
                    LocalVote::Cast(_) | LocalVote::AlreadySame
                ) {
                    self.timeout(RoundStep::Prevote);
                }
                self.precommit_nil(sign)?;
            }
            RoundStep::Prevote if self.voting_allowed() => {
                self.state.step = RoundStep::Precommit;
                if matches!(
                    self.cast(sign, VoteType::Precommit, &NIL)?,
                    LocalVote::Cast(_) | LocalVote::AlreadySame
                ) {
                    self.timeout(RoundStep::Precommit);
                }
            }
            _ => self.start_round(int63_add(self.state.round, 1)),
        }
        Ok(())
    }
    pub fn reconfigure_validator_set(
        &mut self,
        round: i64,
        validators: ValidatorSet,
    ) -> Result<(), Error> {
        if round <= self.state.round {
            return Err("consensus reconfiguration round must advance".into());
        }
        let prevotes: BTreeMap<_, _> = self
            .prevotes
            .iter()
            .map(|(r, v)| (*r, v.project(&validators)))
            .collect();
        let precommits: BTreeMap<_, _> = self
            .precommits
            .iter()
            .map(|(r, v)| (*r, v.project(&validators)))
            .collect();
        let polc: BTreeMap<_, _> = prevotes
            .iter()
            .filter_map(|(r, v)| {
                v.quorum_pid(&self.chain_id, self.state.height, &validators)
                    .map(|p| (*r, p))
            })
            .collect();
        let finalize = precommits.iter().rev().find_map(|(r, v)| {
            v.quorum_pid(&self.chain_id, self.state.height, &validators)
                .map(|p| (*r, p))
        });
        let valid = match &self.state.valid_value {
            Some(h) if self.state.valid_round >= 0 => polc
                .get(&self.state.valid_round)
                .is_some_and(|pid| hash::proposal_id(h).is_ok_and(|got| pid.as_slice() == got)),
            _ => false,
        };
        if !valid {
            self.state.valid_round = -1;
            self.state.valid_value = None;
        }
        self.validators = validators;
        self.generation = int63_add(self.generation, 1);
        self.outputs.clear();
        self.polc = polc;
        self.requests.clear();
        self.prevotes = prevotes;
        self.precommits = precommits;
        self.higher_rounds.clear();
        if let Some((commit_round, pid)) = finalize {
            if let Some(header) = self.find_header(&pid).cloned() {
                self.local_finalize(header, pid, commit_round)?;
            } else {
                self.emit(Output::RequestProposal {
                    round: commit_round,
                    proposal_id: pid,
                });
            }
        }
        self.start_round(round);
        Ok(())
    }
}
fn same_finalize(left: &Finalize, right: &Finalize) -> bool {
    left.epoch_id == right.epoch_id && left.proposal_id == right.proposal_id
}
fn int63_add(left: i64, right: i64) -> i64 {
    (left.wrapping_add(right) << 1) >> 1
}
pub fn tx_list_hash_for_header(hashes: &[Bytes]) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    use sha2::Digest;
    digest.update(b"octra:tx_list:v1");
    digest.update([0]);
    for hash in hashes {
        if hash.len() == 64 {
            for byte in hash {
                digest.update([byte.to_ascii_lowercase()]);
            }
        } else {
            digest.update(hex::encode(hash).as_bytes());
        }
    }
    digest.finalize().into()
}
