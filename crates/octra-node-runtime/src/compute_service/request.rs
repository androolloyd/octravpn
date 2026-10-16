// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Head, OfferBook, OfferSnapshot, View};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    native_json::{Document, ReadMode, Value},
    network::verify_ed25519,
    resource_compute::{
        bill,
        call::{self, Call, Header, CALL_TTL},
        certificate::Certificate,
        message::{self, CancelAck, Offer},
        request::{self, Limits},
        selection::Selection,
        Error, Result,
    },
    transaction::{address_from_public_key, is_valid_address},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub limits: Limits,
    pub valid_until: Option<i64>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub caller: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub caller_signature: Vec<u8>,
    pub session_id: Vec<u8>,
    pub sequence: i64,
    pub method_name: Vec<u8>,
    pub params_json: Vec<u8>,
    pub max_output_bytes: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub output_json: Vec<u8>,
    pub request: request::Request,
    pub certificate: Certificate,
    pub selection: Selection,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelStatus {
    pub selection_root: Vec<u8>,
    pub members: Vec<Vec<u8>>,
    pub missing: Vec<Vec<u8>>,
    pub receipts: Vec<CancelAck>,
    pub expires: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub enum JobStatus {
    Waiting,
    Funding(Header),
    Finished(Response),
    Refused(Vec<u8>),
    Cancelled(CancelStatus),
}
/// A checked coordination view, still requiring a sealed funding observation
/// and canonical origin admission before execution or settlement.
#[derive(Clone, Debug)]
pub struct CallAdmission {
    pub proof: OfferSnapshot,
    pub selection: Selection,
    pub validators: ValidatorSet,
}
pub(crate) struct PlanHeader {
    record: octra_node_protocol::resource_compute::record::Record,
    request: Request,
}
pub(crate) struct PlanOffer {
    record: octra_node_protocol::resource_compute::record::Record,
    request: Request,
}
impl Request {
    pub fn read_plan(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<(Self, Offer)> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::read_plan_header(view, node, caller, id, body)?
                .authenticate(view)?
                .finish(view)
        }))
        .unwrap_or_else(|_| Err(Error::rejected(b"compute saved plan unreadable")))
    }
    /// Native saved-plan predicates before its first historical root lookup.
    pub(crate) fn read_plan_header(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<PlanHeader> {
        // Native read_plan catches every decoder/checking exception at this
        // persisted-byte boundary, including operational decoder failures.
        let unreadable = |_: Error| Error::rejected(b"compute saved plan unreadable");
        let record = octra_node_protocol::resource_compute::record::Record::decode(body)
            .map_err(unreadable)?;
        Self::plan_header(view, node, caller, id, record)
    }
    pub(crate) fn plan_header(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        record: octra_node_protocol::resource_compute::record::Record,
    ) -> Result<PlanHeader> {
        let unreadable = |_: Error| Error::rejected(b"compute saved plan unreadable");
        let call = &record.call;
        let value = &call.request;
        let request = Self::from_call(call);
        let root = validator_set_hash(view.validators)
            .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?;
        let offer = &record.offer;
        let valid = call.valid_until.is_some()
            && value.limits.fuel_limit.is_some()
            && value.limits.guest_bytes.is_some()
            && value.limits.memory_bytes.is_some()
            && value.limits.unit_price.is_some()
            && record.validators.is_none()
            && record.capabilities.is_empty()
            && record.commitments.is_empty()
            && record.reveals.is_empty()
            && record.results.is_empty()
            && call.shape().map_err(unreadable)?
            && request.shape()
            && caller == request.caller
            && id == call.intent_id().map_err(unreadable)?.as_slice()
            && value.chain_id == view.chain
            && call.coordinator == node
            && value.validator_set_root == root
            && value.selection_root.as_slice() == [0_u8; 32]
            && value.epoch_id == offer.offered_epoch;
        if valid {
            Ok(PlanHeader { record, request })
        } else {
            Err(Error::rejected(b"compute saved plan refused"))
        }
    }
    pub fn shape(&self) -> bool {
        let limits = self.limits;
        request::fee_valid(limits.fuel_limit, limits.unit_price, limits.fee_cap)
            && (limits.unit_price.is_none()
                || bill::resource_limits(
                    limits.fuel_limit,
                    limits.memory_bytes,
                    limits.guest_bytes,
                )
                .is_ok())
            && limits.memory_bytes.is_none_or(|bytes| {
                limits.guest_bytes.is_some() && bytes > 0 && bytes <= request::MAX_MEMORY
            })
            && limits.guest_bytes.is_none_or(|bytes| {
                limits.fuel_limit.is_some()
                    && (65_536..=67_108_864).contains(&bytes)
                    && bytes % 65_536 == 0
            })
            && limits
                .fuel_limit
                .is_none_or(|fuel| (1..=2_000_000_000).contains(&fuel))
            && self.valid_until.is_none_or(|epoch| epoch >= 0)
            && self.model_epoch >= 0
            && self.model_state_root.len() == 32
            && is_valid_address(&self.circle_id)
            && self.graph_root.len() == 32
            && self.model_root.len() == 32
            && self.program_root.len() == 32
            && self.executor_root.len() == 32
            && is_valid_address(&self.caller)
            && self.caller_public_key.len() == 32
            && self.caller_signature.len() == 64
            && self.session_id.len() == 32
            && self.sequence >= 0
            && !self.method_name.is_empty()
            && self.method_name.len() <= call::MAX_METHOD
            && self.params_json.len() <= call::MAX_PARAMS
            && (1..=call::MAX_OUTPUT as i64).contains(&self.max_output_bytes)
            && Document::parse_native(&self.params_json, ReadMode::Safe)
                .is_ok_and(|value| matches!(value.root(), Value::List(_)))
    }
    pub fn from_call(call: &Call) -> Self {
        let value = &call.request;
        Self {
            limits: value.limits,
            valid_until: call.valid_until,
            model_epoch: value.model_epoch,
            model_state_root: value.model_state_root.clone(),
            circle_id: value.circle_id.clone(),
            graph_root: value.graph_root.clone(),
            model_root: value.model_root.clone(),
            program_root: value.program_root.clone(),
            executor_root: value.executor_root.clone(),
            caller: value.caller.clone(),
            caller_public_key: call.caller_public_key.clone(),
            caller_signature: call.caller_signature.clone(),
            session_id: value.session_id.clone(),
            sequence: value.sequence,
            method_name: call.method_name.clone(),
            params_json: call.params_json.clone(),
            max_output_bytes: value.max_output_bytes,
        }
    }
    pub fn input_bytes(&self) -> i64 {
        (self.method_name.len() + self.params_json.len()) as i64
    }
    pub fn unsigned_offer(
        &self,
        chain: &[u8],
        node: &[u8],
        head: &Head,
        validator_root: &[u8],
    ) -> Offer {
        let expires = head.epoch.wrapping_add(message::OFFER_TTL);
        Offer {
            chain_id: chain.to_vec(),
            offered_epoch: head.epoch,
            expires_epoch: self.valid_until.map_or(expires, |until| until.min(expires)),
            coordinator: node.to_vec(),
            validator_set_root: validator_root.to_vec(),
            circle_id: self.circle_id.clone(),
            model_epoch: self.model_epoch,
            model_state_root: self.model_state_root.clone(),
            graph_root: self.graph_root.clone(),
            model_root: self.model_root.clone(),
            program_root: self.program_root.clone(),
            executor_root: self.executor_root.clone(),
            min_memory_bytes: self
                .limits
                .memory_bytes
                .unwrap_or(1_073_741_824)
                .max(1_073_741_824),
            request_bytes: self.input_bytes(),
            response_bytes: self.max_output_bytes,
            signature: vec![0; 64],
        }
    }
    pub fn unsigned_request_at(
        &self,
        chain: &[u8],
        epoch: i64,
        state: &[u8],
        expires: i64,
        validator_root: &[u8],
        selection_root: &[u8],
    ) -> Result<request::Request> {
        Ok(request::Request {
            limits: self.limits,
            chain_id: chain.to_vec(),
            epoch_id: epoch,
            state_root: state.to_vec(),
            expires_epoch: self.valid_until.map_or(expires, |until| until.min(expires)),
            validator_set_root: validator_root.to_vec(),
            selection_root: selection_root.to_vec(),
            circle_id: self.circle_id.clone(),
            model_epoch: self.model_epoch,
            model_state_root: self.model_state_root.clone(),
            graph_root: self.graph_root.clone(),
            model_root: self.model_root.clone(),
            program_root: self.program_root.clone(),
            executor_root: self.executor_root.clone(),
            caller: self.caller.clone(),
            session_id: self.session_id.clone(),
            sequence: self.sequence,
            input_hash: call::input_hash(&self.method_name, &self.params_json)?.to_vec(),
            input_bytes: self.input_bytes(),
            max_output_bytes: self.max_output_bytes,
        })
    }
    pub fn unsigned_call(
        &self,
        chain: &[u8],
        node: &[u8],
        head: &Head,
        validator_root: &[u8],
        selection_root: &[u8],
    ) -> Result<Call> {
        Ok(Call {
            request: self.unsigned_request_at(
                chain,
                head.epoch,
                &head.state_root,
                head.epoch.wrapping_add(CALL_TTL),
                validator_root,
                selection_root,
            )?,
            valid_until: self.valid_until,
            method_name: self.method_name.clone(),
            params_json: self.params_json.clone(),
            caller_public_key: self.caller_public_key.clone(),
            caller_signature: self.caller_signature.clone(),
            coordinator: node.to_vec(),
            signature: vec![0; 64],
        })
    }
}
impl PlanHeader {
    pub(crate) fn epoch(&self) -> i64 {
        self.record.call.request.epoch_id
    }
    pub(crate) fn authenticate(self, view: &View<'_>) -> Result<PlanOffer> {
        let unreadable = |_: Error| Error::rejected(b"compute saved plan unreadable");
        let call = &self.record.call;
        let value = &call.request;
        if (view.state_root_at)(value.epoch_id).as_deref() != Some(value.state_root.as_slice())
            || !verify_caller(call).map_err(unreadable)?
            || !crate::compute_record::verify_node(
                view.validators,
                &call.coordinator,
                &call.sign_bytes().map_err(unreadable)?,
                &call.signature,
            )
            || self.record.offer.coordinator != call.coordinator
            || !view
                .offer_preflight_checked(&self.record.offer)
                .map_err(unreadable)?
        {
            return Err(Error::rejected(b"compute saved plan refused"));
        }
        Ok(PlanOffer {
            record: self.record,
            request: self.request,
        })
    }
}
impl PlanOffer {
    pub(crate) fn model_epoch(&self) -> i64 {
        self.record.offer.model_epoch
    }
    pub(crate) fn finish(self, view: &View<'_>) -> Result<(Request, Offer)> {
        let offer = &self.record.offer;
        let request = &self.request;
        if view
            .offer_at_checked(self.record.call.request.epoch_id, offer)
            .map_err(|_| Error::rejected(b"compute saved plan unreadable"))?
            && offer.circle_id == request.circle_id
            && offer.model_epoch == request.model_epoch
            && offer.model_state_root == request.model_state_root
            && offer.graph_root == request.graph_root
            && offer.model_root == request.model_root
            && offer.program_root == request.program_root
            && offer.executor_root == request.executor_root
        {
            Ok((self.request, self.record.offer))
        } else {
            Err(Error::rejected(b"compute saved plan refused"))
        }
    }
}
pub(super) fn verify_caller(call: &Call) -> Result<bool> {
    Ok(call.request.caller
        == address_from_public_key(STANDARD.encode(&call.caller_public_key).as_bytes())
        && verify_ed25519(
            &call.caller_public_key,
            &call.intent_sign_bytes()?,
            &call.caller_signature,
        ))
}
impl OfferBook {
    /// Native gates before the first historical state-root read. Async actor
    /// adapters use this on their captured head/validator view before doing I/O.
    pub fn preflight_call(&self, view: &View<'_>, call: &Call) -> Result<()> {
        let refused = |reason: &[u8]| Error::rejected(reason);
        if !call.shape()? {
            return Err(refused(b"resource compute call shape refused"));
        }
        let request = &call.request;
        if request.limits.unit_price.is_none() {
            return Err(refused(b"resource compute caller fee required"));
        }
        if request.limits.memory_bytes.is_none() {
            return Err(refused(b"resource compute caller memory required"));
        }
        if request.limits.guest_bytes.is_none() {
            return Err(refused(b"resource compute caller pages required"));
        }
        if request.limits.fuel_limit.is_none() {
            return Err(refused(b"resource compute caller fuel required"));
        }
        if call
            .valid_until
            .is_none_or(|epoch| request.expires_epoch > epoch)
        {
            return Err(refused(b"resource compute caller expiry refused"));
        }
        let head = view.current_head()?;
        let _validator_root = validator_set_hash(view.validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        if request.chain_id != view.chain {
            return Err(refused(b"resource compute call chain differs"));
        }
        if request.epoch_id > head.epoch {
            return Err(refused(b"resource compute call epoch differs"));
        }
        Ok(())
    }
    pub fn verify_call(&self, view: &View<'_>, call: &Call) -> Result<CallAdmission> {
        self.preflight_call(view, call)?;
        let refused = |reason: &[u8]| Error::rejected(reason);
        let request = &call.request;
        let head = view.current_head()?;
        let validator_root = validator_set_hash(view.validators)
            .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
        if (view.state_root_at)(request.epoch_id).as_deref() != Some(request.state_root.as_slice())
            || request.expires_epoch < head.epoch
            || request.expires_epoch.wrapping_sub(request.epoch_id) > CALL_TTL
        {
            return Err(refused(b"resource compute call epoch differs"));
        }
        if request.validator_set_root != validator_root {
            return Err(refused(b"resource compute validator set differs"));
        }
        if !view.validators.is_validator(&call.coordinator) {
            return Err(refused(b"resource compute coordinator is not a validator"));
        }
        if !crate::compute_record::verify_node(
            view.validators,
            &call.coordinator,
            &call.sign_bytes()?,
            &call.signature,
        ) {
            return Err(refused(b"resource compute coordinator signature refused"));
        }
        if !verify_caller(call)? {
            return Err(refused(b"resource compute caller signature refused"));
        }
        let Some((state, selection)) = self.find(view, request, head.epoch)? else {
            return Err(refused(b"resource compute offer unavailable"));
        };
        if selection.members.len() as i64 != (message::MAX_MEMBERS as i64).min(view.validators.n)
            || selection.root != request.selection_root
        {
            return Err(refused(b"resource compute selection differs"));
        }
        Ok(CallAdmission {
            proof: state.snapshot(),
            selection,
            validators: view.validators.clone(),
        })
    }
}
