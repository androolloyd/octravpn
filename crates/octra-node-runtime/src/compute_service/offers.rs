// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bounded offer evidence retains distinct signed records so equivocation is
//! excluded by the native selector rather than overwritten by node identity.
use super::{View, MAX_OFFERS, MAX_PENDING_REVEALS_PER_NODE};
use octra_node_protocol::{
    network::domain_hash,
    resource_compute::{
        capability::Capability,
        message::{self, Offer},
        request::Request,
        selection::{self, Commitment, Reveal, Selection},
        wire::Message,
        Result,
    },
};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferSnapshot {
    pub offer: Offer,
    pub capabilities: Vec<Capability>,
    pub commitments: Vec<Commitment>,
    pub reveals: Vec<Reveal>,
}
#[derive(Clone, Debug)]
pub struct OfferState {
    pub offer: Offer,
    capabilities: BTreeMap<Vec<u8>, Capability>,
    commitments: BTreeMap<Vec<u8>, Commitment>,
    reveals: BTreeMap<Vec<u8>, Reveal>,
    pending: BTreeMap<Vec<u8>, Reveal>,
    pub(crate) local_started: bool,
}
enum RevealValidation {
    Wait,
    Valid(Vec<u8>),
    Invalid,
}
fn add<T: PartialEq>(rows: &mut BTreeMap<Vec<u8>, T>, key: Vec<u8>, value: T) -> bool {
    if let Some(current) = rows.get(&key) {
        return *current == value;
    }
    if rows.len() >= message::MAX_RECORDS {
        return false;
    }
    rows.insert(key, value);
    true
}
fn model_matches(offer: &Offer, capability: &Capability) -> bool {
    offer.circle_id == capability.circle_id
        && offer.model_epoch == capability.model_epoch
        && offer.model_state_root == capability.model_state_root
        && offer.graph_root == capability.graph_root
        && offer.model_root == capability.model_root
        && offer.program_root == capability.program_root
        && offer.executor_root == capability.executor_root
}
pub(super) fn capability_matches(offer: &Offer, capability: &Capability) -> bool {
    model_matches(offer, capability)
        && capability.validator_set_root == offer.validator_set_root
        && capability.observed_epoch >= offer.offered_epoch
        && capability.valid_until <= offer.expires_epoch
        && capability.memory_bytes >= offer.min_memory_bytes
        && capability.max_request_bytes >= offer.request_bytes
        && capability.max_response_bytes >= offer.response_bytes
}
pub(super) fn commitment_matches(offer: &Offer, commitment: &Commitment) -> Result<bool> {
    Ok(commitment.chain_id == offer.chain_id
        && commitment.offer_id == offer.id()?
        && commitment.commit_epoch >= offer.offered_epoch
        && commitment.commit_epoch <= offer.expires_epoch
        && commitment.graph_root == offer.graph_root
        && commitment.model_root == offer.model_root
        && commitment.program_root == offer.program_root
        && commitment.executor_root == offer.executor_root)
}
impl OfferState {
    pub(super) fn reveals(&self) -> impl Iterator<Item = &Reveal> {
        self.reveals.values()
    }
    fn new(offer: Offer) -> Self {
        Self {
            offer,
            capabilities: BTreeMap::new(),
            commitments: BTreeMap::new(),
            reveals: BTreeMap::new(),
            pending: BTreeMap::new(),
            local_started: false,
        }
    }
    pub fn snapshot(&self) -> OfferSnapshot {
        OfferSnapshot {
            offer: self.offer.clone(),
            capabilities: self.capabilities.values().cloned().collect(),
            commitments: self.commitments.values().cloned().collect(),
            reveals: self.reveals.values().cloned().collect(),
        }
    }
    fn validate_pending(&self, view: &View<'_>, reveal: &Reveal) -> Result<RevealValidation> {
        let commitments: Vec<_> = self
            .commitments
            .values()
            .filter(|value| value.node_id == reveal.node_id)
            .collect();
        let matching: Vec<_> = commitments
            .iter()
            .copied()
            .filter(|value| {
                value.offer_id == reveal.offer_id
                    && value.commit_epoch == reveal.commit_epoch
                    && value.graph_root == reveal.graph_root
                    && value.model_root == reveal.model_root
                    && value.program_root == reveal.program_root
                    && value.executor_root == reveal.executor_root
                    && value.nonce_hash == selection::nonce_hash(&reveal.nonce)
            })
            .collect();
        let capabilities: Vec<_> = self
            .capabilities
            .values()
            .filter(|value| value.node_id == reveal.node_id)
            .collect();
        if matching.is_empty() {
            return Ok(if commitments.is_empty() {
                RevealValidation::Wait
            } else {
                RevealValidation::Invalid
            });
        }
        if capabilities.is_empty() {
            return Ok(RevealValidation::Wait);
        }
        if matching.len() > 1 {
            return Ok(RevealValidation::Invalid);
        }
        let Ok(head) = view.current_head() else {
            return Ok(RevealValidation::Wait);
        };
        let policy = selection::Policy {
            chain: view.chain,
            target_epoch: head.epoch.wrapping_add(1),
            minimum_delay: message::REVEAL_DELAY,
        };
        let commitment = matching[0];
        Ok(
            match selection::validate(
                &policy,
                commitment,
                reveal,
                |value| view.commitment(value),
                |commit, value| view.reveal(commit, value),
                |value| {
                    capabilities
                        .iter()
                        .any(|capability| value.evidence_root == capability.evidence_root)
                },
            ) {
                Ok(_) => RevealValidation::Valid(reveal.id(commitment)?.to_vec()),
                Err(selection::Reject::Evidence) => RevealValidation::Wait,
                Err(_) => RevealValidation::Invalid,
            },
        )
    }
    fn promote(&mut self, view: &View<'_>, node: &[u8]) -> Result<()> {
        let pending: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, value)| value.node_id == node)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        for (key, reveal) in pending {
            match self.validate_pending(view, &reveal)? {
                RevealValidation::Wait => {}
                RevealValidation::Valid(id) => {
                    if add(&mut self.reveals, id, reveal) {
                        self.pending.remove(&key);
                    }
                }
                RevealValidation::Invalid => {
                    self.pending.remove(&key);
                }
            }
        }
        Ok(())
    }
    pub fn supports(&self, request: &Request, epoch: i64, selection: &Selection) -> bool {
        supports(self.capabilities.values(), request, epoch, selection)
    }
}
// Compare the distinct native requested/offered/observed epoch fields.
#[allow(clippy::suspicious_operation_groupings)]
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn supports<'a>(
    values: impl Iterator<Item = &'a Capability> + Clone,
    request: &Request,
    epoch: i64,
    selection: &Selection,
) -> bool {
    selection.members.iter().all(|member| {
        values.clone().any(|value| {
            value.node_id == member.node_id
                && value.evidence_root == member.evidence_root
                && value.validator_set_root == request.validator_set_root
                && value.observed_epoch <= request.epoch_id
                && epoch <= value.valid_until
                && value.max_request_bytes >= request.input_bytes
                && value.max_response_bytes >= request.max_output_bytes
                && request
                    .limits
                    .memory_bytes
                    .is_none_or(|bytes| bytes <= value.memory_bytes)
        })
    })
}
impl OfferSnapshot {
    pub fn supports(&self, request: &Request, epoch: i64, selection: &Selection) -> bool {
        supports(self.capabilities.iter(), request, epoch, selection)
    }
    pub fn selection(&self, view: &View<'_>, request: &Request) -> Result<Selection> {
        let challenge = selection::challenge(view.chain, request.epoch_id, &request.state_root)?;
        let policy = selection::Policy {
            chain: view.chain,
            target_epoch: request.epoch_id,
            minimum_delay: message::REVEAL_DELAY,
        };
        selection::select(
            &policy,
            &self.offer.id()?,
            &challenge,
            (message::MAX_MEMBERS as i64).min(view.validators.n),
            &self.commitments,
            &self.reveals,
            |value| view.commitment(value),
            |commit, value| view.reveal(commit, value),
            |value| {
                self.capabilities
                    .iter()
                    .find(|capability| capability.node_id == value.node_id)
                    .is_some_and(|capability| value.evidence_root == capability.evidence_root)
            },
        )
    }
}
#[derive(Default)]
pub struct OfferBook {
    rows: BTreeMap<Vec<u8>, OfferState>,
}
impl OfferBook {
    pub(super) fn states(&self) -> impl Iterator<Item = &OfferState> {
        self.rows.values()
    }
    pub fn get(&self, id: &[u8]) -> Option<&OfferState> {
        self.rows.get(id)
    }
    pub(crate) fn get_mut(&mut self, id: &[u8]) -> Option<&mut OfferState> {
        self.rows.get_mut(id)
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn offer(&mut self, view: &View<'_>, offer: Offer) -> Result<bool> {
        let Ok(head) = view.current_head() else {
            return Ok(false);
        };
        if !view.offer_at_checked(head.epoch, &offer)? {
            return Ok(false);
        }
        let id = offer.id()?.to_vec();
        if self.rows.contains_key(&id) {
            return Ok(true);
        }
        if self.rows.len() >= MAX_OFFERS {
            return Ok(false);
        }
        self.rows.insert(id, OfferState::new(offer));
        Ok(true)
    }
    pub fn capability(&mut self, view: &View<'_>, value: &Capability) -> Result<bool> {
        if !view.capability(value) {
            return Ok(false);
        }
        let mut accepted = false;
        for state in self
            .rows
            .values_mut()
            .filter(|state| capability_matches(&state.offer, value))
        {
            let added = add(&mut state.capabilities, value.id()?.to_vec(), value.clone());
            if added {
                state.promote(view, &value.node_id)?;
            }
            accepted |= added;
        }
        Ok(accepted)
    }
    pub fn commitment(&mut self, view: &View<'_>, value: &Commitment) -> Result<bool> {
        if !view.commitment(value) {
            return Ok(false);
        }
        let Some(state) = self.rows.get_mut(&value.offer_id) else {
            return Ok(false);
        };
        if !commitment_matches(&state.offer, value)? {
            return Ok(false);
        }
        let added = add(&mut state.commitments, value.id()?.to_vec(), value.clone());
        if added {
            state.promote(view, &value.node_id)?;
        }
        Ok(added)
    }
    pub fn reveal(&mut self, view: &View<'_>, value: &Reveal) -> Result<bool> {
        if !value.shape() || !view.validators.is_validator(&value.node_id) {
            return Ok(false);
        }
        let Some(state) = self.rows.get_mut(&value.offer_id) else {
            return Ok(false);
        };
        if state.offer.chain_id != value.chain_id
            || state.offer.graph_root != value.graph_root
            || state.offer.model_root != value.model_root
            || state.offer.program_root != value.program_root
            || state.offer.executor_root != value.executor_root
        {
            return Ok(false);
        }
        let key = domain_hash(
            b"octra:resource_compute_wire",
            &Message::Reveal(value.clone()).encode()?,
        )
        .to_vec();
        let admitted = match state.pending.get(&key) {
            Some(current) => current == value,
            None if state.pending.len() >= message::MAX_RECORDS
                || state
                    .pending
                    .values()
                    .filter(|row| row.node_id == value.node_id)
                    .count()
                    >= MAX_PENDING_REVEALS_PER_NODE =>
            {
                false
            }
            None => {
                state.pending.insert(key, value.clone());
                true
            }
        };
        if admitted {
            state.promote(view, &value.node_id)?;
        }
        Ok(admitted
            && matches!(
                state.validate_pending(view, value)?,
                RevealValidation::Valid(_)
            ))
    }
    // Compare the distinct native requested/offered/observed epoch fields.
    #[allow(clippy::suspicious_operation_groupings)]
    pub fn find(
        &self,
        view: &View<'_>,
        request: &Request,
        epoch: i64,
    ) -> Result<Option<(&OfferState, Selection)>> {
        for state in self.rows.values() {
            let offer = &state.offer;
            if offer.validator_set_root != request.validator_set_root
                || offer.offered_epoch > request.epoch_id
                || request.epoch_id > offer.expires_epoch
                || epoch > offer.expires_epoch
                || offer.circle_id != request.circle_id
                || offer.model_epoch != request.model_epoch
                || offer.model_state_root != request.model_state_root
                || offer.graph_root != request.graph_root
                || offer.model_root != request.model_root
                || offer.program_root != request.program_root
                || offer.executor_root != request.executor_root
            {
                continue;
            }
            let selection = match state.snapshot().selection(view, request) {
                Ok(value) => value,
                Err(error) if !error.is_operational() => continue,
                Err(error) => return Err(error),
            };
            if selection.root == request.selection_root
                && state.supports(request, epoch, &selection)
            {
                return Ok(Some((state, selection)));
            }
        }
        Ok(None)
    }
    pub fn prune(&mut self, epoch: i64) {
        self.rows
            .retain(|_, state| state.offer.expires_epoch >= epoch);
    }
}
