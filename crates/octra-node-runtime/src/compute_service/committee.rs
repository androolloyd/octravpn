// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Reusable committees bind session/model/validator identity and the minimum
//! capacity and expiry of their selected providers. Method/input may change.
use super::{Head, OfferSnapshot, Request, Response, View, MAX_COMMITTEE_LEASES};
use octra_node_protocol::{
    network::domain_hash,
    oce1::Writer,
    resource_compute::{call::Call, selection::Selection, Result},
};
use std::collections::BTreeMap;
pub fn session_key(caller: &[u8], session: &[u8]) -> Result<[u8; 32]> {
    let mut out = Writer::new();
    out.put_bytes(caller)?;
    out.put_hash32(session)?;
    Ok(domain_hash(
        b"octra:resource_compute_cancel_key",
        &out.into_bytes(),
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeLease {
    pub memory_bytes: i64,
    pub caller: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub validator_set_root: Vec<u8>,
    pub request_head: Head,
    pub expires_epoch: i64,
    pub max_request_bytes: i64,
    pub max_response_bytes: i64,
    pub selection: Selection,
}
impl CommitteeLease {
    pub fn from_response(
        request: &Request,
        snapshot: &OfferSnapshot,
        response: &Response,
    ) -> Result<Option<Self>> {
        let mut capabilities = Vec::new();
        for member in &response.selection.members {
            let mut candidates = Vec::new();
            for value in snapshot.capabilities.iter().filter(|value| {
                value.node_id == member.node_id && value.evidence_root == member.evidence_root
            }) {
                candidates.push((value.id()?, value));
            }
            let Some((_, capability)) = candidates.into_iter().min_by_key(|(id, _)| *id) else {
                return Ok(None);
            };
            capabilities.push(capability);
        }
        if capabilities.is_empty() {
            return Ok(None);
        }
        let expires_epoch = capabilities
            .iter()
            .fold(snapshot.offer.expires_epoch, |expires, value| {
                expires.min(value.valid_until)
            });
        let max_request_bytes = capabilities
            .iter()
            .fold(i64::MAX, |limit, value| limit.min(value.max_request_bytes));
        let max_response_bytes = capabilities
            .iter()
            .fold(i64::MAX, |limit, value| limit.min(value.max_response_bytes));
        let memory_bytes = capabilities
            .iter()
            .fold(i64::MAX, |limit, value| limit.min(value.memory_bytes));
        if expires_epoch < response.request.epoch_id
            || request.input_bytes() > max_request_bytes
            || request.max_output_bytes > max_response_bytes
            || request
                .limits
                .memory_bytes
                .is_some_and(|bytes| bytes > memory_bytes)
        {
            return Ok(None);
        }
        Ok(Some(Self {
            memory_bytes,
            caller: request.caller.clone(),
            caller_public_key: request.caller_public_key.clone(),
            session_id: request.session_id.clone(),
            circle_id: request.circle_id.clone(),
            model_epoch: request.model_epoch,
            model_state_root: request.model_state_root.clone(),
            graph_root: request.graph_root.clone(),
            model_root: request.model_root.clone(),
            program_root: request.program_root.clone(),
            executor_root: request.executor_root.clone(),
            validator_set_root: response.request.validator_set_root.clone(),
            request_head: Head {
                epoch: response.request.epoch_id,
                state_root: response.request.state_root.clone(),
            },
            expires_epoch,
            max_request_bytes,
            max_response_bytes,
            selection: response.selection.clone(),
        }))
    }
    pub fn matches(
        &self,
        view: &View<'_>,
        request: &Request,
        head: &Head,
        validator_root: &[u8],
    ) -> bool {
        self.matches_before_root(request, head, validator_root)
            && (view.state_root_at)(self.request_head.epoch).as_deref()
                == Some(self.request_head.state_root.as_slice())
            && request.input_bytes() <= self.max_request_bytes
            && request.max_output_bytes <= self.max_response_bytes
            && request
                .limits
                .memory_bytes
                .is_none_or(|bytes| bytes <= self.memory_bytes)
    }
    fn matches_before_root(&self, request: &Request, head: &Head, validator_root: &[u8]) -> bool {
        self.caller == request.caller
            && self.caller_public_key == request.caller_public_key
            && self.session_id == request.session_id
            && self.circle_id == request.circle_id
            && self.model_epoch == request.model_epoch
            && self.model_state_root == request.model_state_root
            && self.graph_root == request.graph_root
            && self.model_root == request.model_root
            && self.program_root == request.program_root
            && self.executor_root == request.executor_root
            && self.validator_set_root == validator_root
            && head.epoch <= self.expires_epoch
    }
    pub fn unsigned_call(&self, request: &Request, chain: &[u8], node: &[u8]) -> Result<Call> {
        Ok(Call {
            request: request.unsigned_request_at(
                chain,
                self.request_head.epoch,
                &self.request_head.state_root,
                self.expires_epoch,
                &self.validator_set_root,
                &self.selection.root,
            )?,
            valid_until: request.valid_until,
            method_name: request.method_name.clone(),
            params_json: request.params_json.clone(),
            caller_public_key: request.caller_public_key.clone(),
            caller_signature: request.caller_signature.clone(),
            coordinator: node.to_vec(),
            signature: vec![0; 64],
        })
    }
}
#[derive(Default)]
pub struct CommitteeBook {
    rows: BTreeMap<[u8; 32], CommitteeLease>,
}
impl CommitteeBook {
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub(crate) fn required_epoch(
        &mut self,
        request: &Request,
        head: &Head,
        validator_root: &[u8],
    ) -> Result<Option<i64>> {
        self.prune(head.epoch);
        Ok(self
            .rows
            .get(&session_key(&request.caller, &request.session_id)?)
            .filter(|lease| lease.matches_before_root(request, head, validator_root))
            .map(|lease| lease.request_head.epoch))
    }
    pub fn prune(&mut self, epoch: i64) {
        self.rows.retain(|_, lease| lease.expires_epoch >= epoch);
    }
    pub fn remember(&mut self, view: &View<'_>, lease: CommitteeLease) -> Result<()> {
        let Ok(head) = view.current_head() else {
            return Ok(());
        };
        if head.epoch > lease.expires_epoch {
            return Ok(());
        }
        self.prune(head.epoch);
        let key = session_key(&lease.caller, &lease.session_id)?;
        if self.rows.len() >= MAX_COMMITTEE_LEASES && !self.rows.contains_key(&key) {
            let oldest = self
                .rows
                .iter()
                .min_by(|(left_key, left), (right_key, right)| {
                    left.expires_epoch
                        .cmp(&right.expires_epoch)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.rows.remove(&oldest);
            }
        }
        self.rows.insert(key, lease);
        Ok(())
    }
    pub fn for_request(
        &mut self,
        view: &View<'_>,
        request: &Request,
        head: &Head,
        validator_root: &[u8],
    ) -> Result<Option<CommitteeLease>> {
        self.prune(head.epoch);
        let key = session_key(&request.caller, &request.session_id)?;
        match self.rows.get(&key) {
            Some(lease) if lease.matches(view, request, head, validator_root) => {
                Ok(Some(lease.clone()))
            }
            Some(_) => {
                self.rows.remove(&key);
                Ok(None)
            }
            None => Ok(None),
        }
    }
    pub fn remove(&mut self, caller: &[u8], session: &[u8]) -> Result<()> {
        self.rows.remove(&session_key(caller, session)?);
        Ok(())
    }
}
