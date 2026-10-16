// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Result agreement and write-before-admission for the coordinator's vote set.
use super::{CallAdmission, OfferBook, OfferSnapshot, Response, View, MAX_REQUESTS};
use crate::{
    compute_history::{History, Work},
    compute_record::verify_node,
};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::ValidatorSet,
    resource_compute::{
        call::{Call, CALL_TTL},
        certificate::{self, Certificate, Decision},
        message::{self, Output},
        record::{self, Record},
        selection::Selection,
        wire::Message,
        Error, Result,
    },
};
use std::collections::BTreeMap;
mod persistence;
mod restore;
#[derive(Clone, Debug)]
pub struct RequestState {
    call: Call,
    selection: Selection,
    validators: ValidatorSet,
    pinned: bool,
    proof: OfferSnapshot,
    votes: BTreeMap<Vec<u8>, Output>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum CertificateProgress {
    Pending,
    Finished(Response),
    Refused(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Execution {
    Execute,
    Retained(Output),
    Skipped,
}
fn history_error(error: crate::compute_history::Error) -> Error {
    Error::Unavailable(error.0)
}
impl RequestState {
    pub(crate) fn from_admission(call: Call, admission: CallAdmission) -> Self {
        Self {
            call,
            selection: admission.selection,
            validators: admission.validators,
            pinned: true,
            proof: admission.proof,
            votes: BTreeMap::new(),
        }
    }
    pub(super) fn has_vote(&self, node: &[u8]) -> bool {
        self.votes.contains_key(node)
    }
    pub fn call(&self) -> &Call {
        &self.call
    }
    pub fn selection(&self) -> &Selection {
        &self.selection
    }
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }
    pub fn proof(&self) -> &OfferSnapshot {
        &self.proof
    }
    pub fn record(&self, mut results: Vec<Output>) -> Record {
        results.sort_by(|left, right| left.vote.node_id.cmp(&right.vote.node_id));
        Record {
            offer: self.proof.offer.clone(),
            capabilities: self.proof.capabilities.clone(),
            commitments: self.proof.commitments.clone(),
            reveals: self.proof.reveals.clone(),
            call: self.call.clone(),
            results,
            validators: self.pinned.then(|| self.validators.clone()),
        }
    }
    pub fn retained_record(&self) -> Record {
        self.record(self.votes.values().cloned().collect())
    }
    pub fn valid_result(&self, result: &Output) -> Result<bool> {
        if !result.shape()? {
            return Ok(false);
        }
        let vote = &result.vote;
        Ok(vote.request_id == self.call.request.id()?
            && vote.within_budget(&self.call.request)
            && self
                .selection
                .members
                .iter()
                .any(|member| member.node_id == vote.node_id)
            && vote.output_bytes == result.output_json.len() as i64
            && vote.output_bytes <= self.call.request.max_output_bytes
            && vote.sign_bytes().is_ok_and(|bytes| {
                verify_node(&self.validators, &vote.node_id, &bytes, &vote.signature)
            }))
    }
    pub fn record_result(
        &mut self,
        node: &[u8],
        history: Option<&History>,
        result: Output,
    ) -> Result<bool> {
        if !self.valid_result(&result)? {
            return Ok(false);
        }
        let signer = result.vote.node_id.clone();
        if let Some(prior) = self.votes.get(&signer) {
            return Ok(*prior == result);
        }
        if self.call.coordinator != node {
            self.votes.insert(signer, result);
            return Ok(true);
        }
        let before = self.retained_record().encode()?;
        let mut results: Vec<_> = self.votes.values().cloned().collect();
        results.push(result.clone());
        let after = self.record(results).encode()?;
        let Some(history) = history else {
            return Ok(false);
        };
        let request = &self.call.request;
        let id = self.call.intent_id()?;
        let saved = match history.work(&request.caller, &id).map_err(history_error)? {
            None if signer == node => {
                let Some(body) = history
                    .load_job(&request.caller, &id)
                    .map_err(history_error)?
                else {
                    return Ok(false);
                };
                if Record::decode(&body)?.call != self.call {
                    return Ok(false);
                }
                let prior = history
                    .reply(
                        &request.caller,
                        &request.session_id,
                        request.sequence,
                        &request.id()?,
                    )
                    .map_err(history_error)?;
                return Ok(prior.as_deref() == Some(Message::Result(result).encode()?.as_slice()));
            }
            None => false,
            Some(_) => history
                .advance_job(
                    &request.caller,
                    &request.session_id,
                    &id,
                    &Work::Issued(before),
                    &Work::Issued(after),
                    None,
                    None,
                )
                .map_err(history_error)?,
        };
        if saved {
            self.votes.insert(signer, result);
        }
        Ok(saved)
    }
    /// Move just one checked request snapshot into the history worker. The
    /// actor installs the returned snapshot after the worker completes, so no
    /// borrowed registry or host view is retained across that boundary.
    pub fn record_result_owned(
        mut self,
        node: &[u8],
        history: Option<&History>,
        result: Output,
    ) -> Result<(Self, bool)> {
        let accepted = self.record_result(node, history, result)?;
        Ok((self, accepted))
    }
    pub fn decision(&self) -> Result<Decision> {
        let request = &self.call.request;
        let selected: Vec<_> = self
            .selection
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect();
        let total: BigInt = selected
            .iter()
            .filter_map(|node| self.validators.weight(node))
            .sum();
        let weight_floor = (total * 2) / 3 + 1;
        let count = selected.len() as i64;
        let signer_floor = count - ((count - 1) / 3);
        let votes: Vec<_> = self
            .votes
            .values()
            .map(|result| result.vote.clone())
            .collect();
        let policy = certificate::Policy {
            chain_id: &request.chain_id,
            current_epoch: request.epoch_id,
            max_ttl: CALL_TTL,
            selected: &selected,
            signer_floor,
            weight_floor: &weight_floor,
        };
        certificate::decide(
            &policy,
            request,
            &votes,
            |node| self.validators.weight(node).cloned(),
            |vote| {
                vote.sign_bytes().is_ok_and(|bytes| {
                    verify_node(&self.validators, &vote.node_id, &bytes, &vote.signature)
                })
            },
        )
    }
    fn output(&self, certificate: &Certificate) -> Option<Vec<u8>> {
        self.votes
            .values()
            .filter(|result| {
                result.vote.output_hash == certificate.output_hash
                    && result.vote.trace_root == certificate.trace_root
                    && result.vote.output_bytes == certificate.output_bytes
                    && result.vote.steps == certificate.steps
                    && result.vote.operations == certificate.operations
            })
            .map(|result| result.output_json.clone())
            .next_back()
    }
    fn response(&self, certificate: Certificate, output_json: Vec<u8>) -> Response {
        Response {
            output_json,
            request: self.call.request.clone(),
            certificate,
            selection: self.selection.clone(),
        }
    }
    pub fn saved_response(&self) -> Result<Response> {
        match self.decision()? {
            Decision::Agreed(certificate) => match self.output(&certificate) {
                Some(output) => Ok(self.response(*certificate, output)),
                None => Err(Error::rejected(b"compute job output absent")),
            },
            _ => Err(Error::rejected(b"compute job certificate refused")),
        }
    }
    pub fn progress(&self, view: &View<'_>) -> Result<CertificateProgress> {
        let head = match view.current_head() {
            Ok(head) => head,
            Err(error) => return Ok(CertificateProgress::Refused(error.as_bytes().to_vec())),
        };
        let refused = |reason: &[u8]| Ok(CertificateProgress::Refused(reason.to_vec()));
        if head.epoch > self.call.request.expires_epoch {
            return refused(b"resource compute certificate expired");
        }
        match self.decision()? {
            Decision::Agreed(certificate) => match self.output(&certificate) {
                Some(output) => Ok(CertificateProgress::Finished(
                    self.response(*certificate, output),
                )),
                None => refused(b"resource compute output unavailable"),
            },
            Decision::Conflicting => refused(b"resource compute outputs conflict"),
            Decision::Rejected(_) => refused(b"resource compute certificate refused"),
            Decision::Insufficient => Ok(CertificateProgress::Pending),
        }
    }
    /// Blocking transaction for the service's owned worker lane.
    pub fn reserve(&self, history: &History, node: &[u8], provider: bool) -> Result<Execution> {
        if !provider {
            return Ok(Execution::Skipped);
        }
        let request = &self.call.request;
        let id = request.id()?;
        if let Some(raw) = history
            .reply(&request.caller, &request.session_id, request.sequence, &id)
            .map_err(history_error)?
        {
            return match Message::decode(&raw) {
                Ok(Message::Result(result))
                    if result.vote.node_id == node && result.vote.request_id == id =>
                {
                    Ok(Execution::Retained(result))
                }
                Ok(_) => Err(Error::rejected(b"resource compute saved result differs")),
                Err(_) => Err(Error::rejected(b"resource compute saved result unreadable")),
            };
        }
        let scope = record::encode_scope(&self.call, &self.validators)?;
        let room = record::reply_space(&self.call, &self.validators, node)?;
        if history
            .reserve(
                &request.caller,
                &request.session_id,
                request.sequence,
                &id,
                Some(&scope),
                Some(room),
            )
            .map_err(history_error)?
        {
            Ok(Execution::Execute)
        } else {
            Ok(Execution::Skipped)
        }
    }
}
#[derive(Default)]
pub struct RequestBook {
    rows: BTreeMap<Vec<u8>, RequestState>,
}
impl RequestBook {
    /// Native restoration replaces the retained state only after all durable
    /// reads and identity checks have succeeded. Existing IDs still consume a
    /// table slot for the explicit issued-work resumption capacity check.
    pub(crate) fn install_restored(&mut self, state: RequestState) -> Result<()> {
        let key = state.call.request.id()?.to_vec();
        if self.rows.len() >= MAX_REQUESTS && !self.rows.contains_key(&key) {
            return Err(Error::rejected(b"resource compute request table full"));
        }
        self.rows.insert(key, state);
        Ok(())
    }
    /// Protocol admission uses the first accepted state for a request ID.
    /// Retained evidence may instead explicitly replace it via restoration.
    pub(crate) fn state_for_call(
        &self,
        call: Call,
        admission: CallAdmission,
    ) -> Result<RequestState> {
        let id = call.request.id()?;
        Ok(self
            .rows
            .get(id.as_slice())
            .cloned()
            .unwrap_or_else(|| RequestState::from_admission(call, admission)))
    }
    pub(super) fn states(&self) -> impl Iterator<Item = &RequestState> {
        self.rows.values()
    }
    pub fn save_result(
        &self,
        history: &History,
        node: &[u8],
        call: &Call,
        result: &Output,
    ) -> Result<bool> {
        self.prepare_result(node, call, result)?.persist(history)
    }
    pub fn save_completed(&self, history: &History, id: &[u8], response: &Response) -> Result<()> {
        self.prepare_completed(id, response)?.persist(history)
    }
    pub fn admit(
        &mut self,
        view: &View<'_>,
        offers: &OfferBook,
        call: Call,
        funds: &crate::compute_deposits::Funded,
    ) -> Result<bool> {
        Ok(self.admit_checked(view, offers, call, funds)?.is_some())
    }
    pub fn admit_checked(
        &mut self,
        view: &View<'_>,
        offers: &OfferBook,
        call: Call,
        funds: &crate::compute_deposits::Funded,
    ) -> Result<Option<CallAdmission>> {
        let id = call.request.id()?;
        let admission = match self.rows.get(id.as_slice()) {
            Some(state) if state.call == call => CallAdmission {
                proof: state.proof.clone(),
                selection: state.selection.clone(),
                validators: state.validators.clone(),
            },
            _ => match offers.verify_call(view, &call) {
                Ok(value) => value,
                Err(error) if !error.is_operational() => return Ok(None),
                Err(error) => return Err(error),
            },
        };
        if !view.funding_matches(&call, funds) {
            return Ok(None);
        }
        self.insert(call, admission.clone())?;
        Ok(Some(admission))
    }
    pub fn get(&self, id: &[u8]) -> Option<&RequestState> {
        self.rows.get(id)
    }
    pub fn get_mut(&mut self, id: &[u8]) -> Option<&mut RequestState> {
        self.rows.get_mut(id)
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    /// Called by the actor after its funding observation gate. Existing request
    /// IDs preserve their original call, validator snapshot and proof.
    fn insert(&mut self, call: Call, admission: CallAdmission) -> Result<&mut RequestState> {
        let id = call.request.id()?.to_vec();
        if !self.rows.contains_key(&id) {
            if self.rows.len() >= MAX_REQUESTS {
                return Err(Error::rejected(b"resource compute request table full"));
            }
            self.rows.insert(
                id.clone(),
                RequestState {
                    call,
                    selection: admission.selection,
                    validators: admission.validators,
                    pinned: true,
                    proof: admission.proof,
                    votes: BTreeMap::new(),
                },
            );
        }
        self.rows.get_mut(&id).ok_or_else(|| {
            Error::Unavailable(b"resource compute request insertion failed".to_vec())
        })
    }
    pub fn prune(&mut self, epoch: i64) {
        self.rows
            .retain(|_, state| state.call.request.expires_epoch >= epoch);
    }
}
