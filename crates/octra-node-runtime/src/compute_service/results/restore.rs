// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    message, verify_node, BTreeMap, Error, OfferSnapshot, Record, RequestState, Result,
    ValidatorSet, View, CALL_TTL,
};
use crate::compute_service::{
    offers::{capability_matches, commitment_matches},
    request::verify_caller,
};
use octra_node_protocol::consensus::hash::validator_set_hash;
use std::collections::BTreeSet;
fn unreadable(_: Error) -> Error {
    // Native restore_state catches decoding/selection exceptions, including
    // operational failures; ordinary failed predicates retain their own errors.
    Error::rejected(b"compute job record unreadable")
}
/// Identity and historical commitments have been checked, but provider
/// capabilities, selection and retained results have not yet been admitted.
pub(crate) struct Restoration {
    record: Record,
    validators: ValidatorSet,
}
pub(crate) struct RestorationHeader {
    record: Record,
    validators: ValidatorSet,
}
pub(crate) struct RestorationOffer {
    record: Record,
    validators: ValidatorSet,
}
impl RequestState {
    /// Recheck retained local coordinator evidence against historical roots and
    /// the saved validator extension. Record decoding alone never restores work.
    pub fn restore(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<Self> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::restore_identity(view, node, caller, id, body)?.finish(view)
        }))
        .unwrap_or_else(|_| Err(Error::rejected(b"compute job record unreadable")))
    }
    pub(crate) fn restore_identity(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<Restoration> {
        Self::restore_header(view, node, caller, id, body)?.identity(view)
    }
    pub(crate) fn restore_header(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        body: &[u8],
    ) -> Result<RestorationHeader> {
        let record = Record::decode(body).map_err(unreadable)?;
        Self::restore_record_header(view, node, caller, id, record)
    }
    pub(crate) fn restore_record_header(
        view: &View<'_>,
        node: &[u8],
        caller: &[u8],
        id: &[u8],
        record: Record,
    ) -> Result<RestorationHeader> {
        let call = &record.call;
        let request = &call.request;
        let validators = record.validators.as_ref().unwrap_or(view.validators);
        let root = validator_set_hash(validators)
            .map_err(|_| Error::rejected(b"compute job record unreadable"))?;
        let valid = call.shape().map_err(unreadable)?
            && caller == request.caller
            && call.intent_id().map_err(unreadable)?.as_slice() == id
            && request.chain_id == view.chain
            && root.as_slice() == request.validator_set_root
            && call.coordinator == node;
        if !valid {
            return Err(Error::rejected(b"compute job identity refused"));
        }
        let validators = validators.clone();
        Ok(RestorationHeader { record, validators })
    }
}
impl RestorationHeader {
    pub(crate) fn roots(&self) -> [(i64, &[u8]); 2] {
        let request = &self.record.call.request;
        [
            (request.epoch_id, &request.state_root),
            (request.model_epoch, &request.model_state_root),
        ]
    }
    pub(crate) fn identity(self, view: &View<'_>) -> Result<Restoration> {
        self.authenticate(view)?.identity(view)
    }
    /// Verify the call before asking the host for the offer's independent
    /// historical model commitment. It need not equal the call's model epoch.
    pub(crate) fn authenticate(self, view: &View<'_>) -> Result<RestorationOffer> {
        let record = self.record;
        let call = &record.call;
        let request = &call.request;
        let validators = &self.validators;
        let retained = View {
            chain: view.chain,
            validators,
            head: view.head,
            state_root_at: view.state_root_at,
            evidence: view.evidence,
        };
        let valid = (view.state_root_at)(request.epoch_id).as_deref()
            == Some(request.state_root.as_slice())
            && (view.state_root_at)(request.model_epoch).as_deref()
                == Some(request.model_state_root.as_slice())
            && verify_caller(call).map_err(unreadable)?
            && verify_node(
                validators,
                &call.coordinator,
                &call.sign_bytes().map_err(unreadable)?,
                &call.signature,
            )
            && retained
                .offer_preflight_checked(&record.offer)
                .map_err(unreadable)?;
        if !valid {
            return Err(Error::rejected(b"compute job identity refused"));
        }
        Ok(RestorationOffer {
            record,
            validators: self.validators,
        })
    }
}
impl RestorationOffer {
    pub(crate) fn model_epoch(&self) -> i64 {
        self.record.offer.model_epoch
    }
    pub(crate) fn identity(self, view: &View<'_>) -> Result<Restoration> {
        let record = self.record;
        let request = &record.call.request;
        let offer = &record.offer;
        let validators = &self.validators;
        let retained = View {
            chain: view.chain,
            validators,
            head: view.head,
            state_root_at: view.state_root_at,
            evidence: view.evidence,
        };
        let model = offer.circle_id == request.circle_id
            && offer.model_epoch == request.model_epoch
            && offer.model_state_root == request.model_state_root
            && offer.graph_root == request.graph_root
            && offer.model_root == request.model_root
            && offer.program_root == request.program_root
            && offer.executor_root == request.executor_root;
        let mut valid = retained
            .offer_at_checked(request.epoch_id, offer)
            .map_err(unreadable)?
            && request.expires_epoch.wrapping_sub(request.epoch_id) <= CALL_TTL
            && model;
        if valid {
            for commitment in &record.commitments {
                if !commitment_matches(offer, commitment).map_err(unreadable)?
                    || !retained.commitment(commitment)
                {
                    valid = false;
                    break;
                }
            }
        }
        if !valid {
            return Err(Error::rejected(b"compute job identity refused"));
        }
        Ok(Restoration {
            record,
            validators: self.validators,
        })
    }
}
impl Restoration {
    /// Native capability iteration does not run a self-test when its first
    /// capability already differs from the offer. Self-test failures otherwise
    /// become capability refusal, after identity rejection had its own priority.
    pub(crate) fn needs_evidence(&self) -> Result<bool> {
        match self.record.capabilities.first() {
            None => Ok(false),
            Some(value) if capability_matches(&self.record.offer, value) => Ok(true),
            Some(_) => Err(Error::rejected(b"compute job capability refused")),
        }
    }
    pub(crate) fn finish(self, view: &View<'_>) -> Result<RequestState> {
        let record = self.record;
        let validators = &self.validators;
        let request = &record.call.request;
        let offer = &record.offer;
        let retained = View {
            chain: view.chain,
            validators,
            head: view.head,
            state_root_at: view.state_root_at,
            evidence: view.evidence,
        };
        if record.capabilities.iter().any(|value| {
            !capability_matches(offer, value) || !retained.capability_at(request.epoch_id, value)
        }) {
            return Err(Error::rejected(b"compute job capability refused"));
        }
        let proof = OfferSnapshot {
            offer: record.offer.clone(),
            capabilities: record.capabilities.clone(),
            commitments: record.commitments.clone(),
            reveals: record.reveals.clone(),
        };
        let selection = proof.selection(&retained, request).map_err(unreadable)?;
        let unique_nodes = record
            .results
            .iter()
            .map(|result| result.vote.node_id.as_slice())
            .collect::<BTreeSet<_>>()
            .len();
        if selection.root != request.selection_root
            || selection.members.len() as i64 != (message::MAX_MEMBERS as i64).min(validators.n)
            || !proof.supports(request, request.epoch_id, &selection)
            || unique_nodes != record.results.len()
        {
            return Err(Error::rejected(b"compute job evidence refused"));
        }
        let mut state = RequestState {
            call: record.call.clone(),
            selection,
            validators: validators.clone(),
            pinned: record.validators.is_some(),
            proof,
            votes: BTreeMap::new(),
        };
        for result in &record.results {
            if !state.valid_result(result).map_err(unreadable)? {
                return Err(Error::rejected(b"compute job evidence refused"));
            }
        }
        for result in record.results {
            state.votes.insert(result.vote.node_id.clone(), result);
        }
        Ok(state)
    }
}
