// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Anchored compute selection and session admission. The session seal permits
//! deterministic replay; payments require its measured results and bills.
mod session;
use crate::compute_roots::Root;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    network::verify_ed25519,
    resource_compute::{
        bill::{self, Bill, Measured},
        call::{Call, Header, CALL_TTL},
        capability::Capability,
        funding::{self, Deposit},
        message::{self, Offer},
        record::Record,
        request::Request,
        selection::{self, Commitment, Reveal, Selection},
        wire::Message,
        Error, Result,
    },
    state_sync::anchor,
    transaction::address_from_public_key,
};
pub use session::Session;
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub enum Origin<'a> {
    Finalized(&'a anchor::Origin),
    Pinned(&'a Root),
}
impl Origin<'_> {
    pub fn chain_id(&self) -> &[u8] {
        match self {
            Self::Finalized(v) => v.chain_id(),
            Self::Pinned(v) => v.chain_id(),
        }
    }
    pub fn epoch(&self) -> i64 {
        match self {
            Self::Finalized(v) => v.epoch_id(),
            Self::Pinned(v) => v.epoch(),
        }
    }
    pub fn state(&self) -> &[u8] {
        match self {
            Self::Finalized(v) => v.state_root(),
            Self::Pinned(v) => v.state(),
        }
    }
    pub fn validators(&self) -> &ValidatorSet {
        match self {
            Self::Finalized(v) => v.validators(),
            Self::Pinned(v) => v.validators(),
        }
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn malformed(error: Error) -> Error {
    if error.is_operational() {
        error
    } else {
        refused(b"compute proof malformed")
    }
}
pub fn verify_node(
    validators: &ValidatorSet,
    node: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    validators
        .public_key(node)
        .is_some_and(|key| verify_ed25519(key, message, signature))
}
fn offer_matches(request: &Request, offer: &Offer) -> bool {
    offer.chain_id == request.chain_id
        && offer.validator_set_root == request.validator_set_root
        && offer.circle_id == request.circle_id
        && offer.model_epoch == request.model_epoch
        && offer.model_state_root == request.model_state_root
        && offer.graph_root == request.graph_root
        && offer.model_root == request.model_root
        && offer.program_root == request.program_root
        && offer.executor_root == request.executor_root
}
// Compare the distinct native requested/offered/observed epoch fields.
#[allow(clippy::suspicious_operation_groupings)]
fn capacity_matches(request: &Request, offer: &Offer, epoch: i64, value: &Capability) -> bool {
    value.chain_id == request.chain_id
        && value.validator_set_root == request.validator_set_root
        && value.observed_epoch >= offer.offered_epoch
        && value.observed_epoch <= request.epoch_id
        && epoch <= value.valid_until
        && value.valid_until <= offer.expires_epoch
        && value.valid_until.wrapping_sub(value.observed_epoch) <= message::CAPACITY_TTL
        && value.circle_id == request.circle_id
        && value.model_epoch == request.model_epoch
        && value.model_state_root == request.model_state_root
        && value.graph_root == request.graph_root
        && value.model_root == request.model_root
        && value.program_root == request.program_root
        && value.executor_root == request.executor_root
        && value.memory_bytes >= offer.min_memory_bytes
        && request
            .limits
            .memory_bytes
            .is_some_and(|bytes| bytes <= value.memory_bytes)
        && value.max_request_bytes >= offer.request_bytes.max(request.input_bytes)
        && value.max_response_bytes >= offer.response_bytes.max(request.max_output_bytes)
}
pub fn verify_selection(
    origin: Origin<'_>,
    epoch: i64,
    header: &Header,
    record: &Record,
) -> Result<Selection> {
    let request = header.request();
    let validators = origin.validators();
    let offer = &record.offer;
    if record.capabilities.len() > message::MAX_RECORDS
        || record.commitments.len() > message::MAX_RECORDS
        || record.reveals.len() > message::MAX_RECORDS
    {
        return Err(refused(b"compute proof count exceeds limit"));
    }
    if request.chain_id != origin.chain_id()
        || request.epoch_id != origin.epoch()
        || request.state_root != origin.state()
        || request.validator_set_root
            != validator_set_hash(validators)
                .map_err(Error::from)
                .map_err(malformed)?
                .as_slice()
    {
        return Err(refused(b"compute proof origin differs"));
    }
    if epoch < request.epoch_id
        || request.expires_epoch < epoch
        || request.expires_epoch.wrapping_sub(request.epoch_id) > CALL_TTL
    {
        return Err(refused(b"compute proof epoch outside window"));
    }
    let limits = request.limits;
    if header.valid_until().is_none()
        || limits.unit_price.is_none()
        || limits.memory_bytes.is_none()
        || limits.guest_bytes.is_none()
        || limits.fuel_limit.is_none()
    {
        return Err(refused(b"compute proof terms missing"));
    }
    if request.caller
        != address_from_public_key(STANDARD.encode(header.caller_public_key()).as_bytes())
        || !verify_ed25519(
            header.caller_public_key(),
            &header.intent().map_err(malformed)?,
            header.caller_signature(),
        )
        || !verify_node(
            validators,
            header.coordinator(),
            &header.sign_bytes().map_err(malformed)?,
            header.signature(),
        )
    {
        return Err(refused(b"compute proof call signature refused"));
    }
    if !(offer.shape()
        && offer_matches(request, offer)
        && offer.offered_epoch <= request.epoch_id
        && request.epoch_id <= offer.expires_epoch
        && offer.expires_epoch.wrapping_sub(offer.offered_epoch) <= message::OFFER_TTL
        && verify_node(
            validators,
            &offer.coordinator,
            &offer.sign_bytes().map_err(malformed)?,
            &offer.signature,
        ))
    {
        return Err(refused(b"compute proof offer refused"));
    }
    for capacity in &record.capabilities {
        if !(capacity_matches(request, offer, epoch, capacity)
            && verify_node(
                validators,
                &capacity.node_id,
                &capacity.sign_bytes().map_err(malformed)?,
                &capacity.signature,
            ))
        {
            return Err(refused(b"compute proof capacity refused"));
        }
    }
    let id = offer.id().map_err(malformed)?;
    let commitment_ok = |value: &Commitment| -> Result<bool> {
        Ok(value.chain_id == request.chain_id
            && value.offer_id == id
            && offer.offered_epoch <= value.commit_epoch
            && value.commit_epoch < request.epoch_id
            && value.graph_root == request.graph_root
            && value.model_root == request.model_root
            && value.program_root == request.program_root
            && value.executor_root == request.executor_root
            && verify_node(
                validators,
                &value.node_id,
                &value.sign_bytes()?,
                &value.signature,
            ))
    };
    for commitment in &record.commitments {
        if !commitment_ok(commitment).map_err(malformed)? {
            return Err(refused(b"compute proof commitment refused"));
        }
    }
    let evidence_ok = |value: &Reveal| {
        record.capabilities.iter().any(|capacity| {
            capacity.node_id == value.node_id && capacity.evidence_root == value.evidence_root
        })
    };
    let reveal_signature = |commitment: &Commitment, value: &Reveal| {
        value.sign_bytes(commitment).is_ok_and(|message| {
            verify_node(validators, &value.node_id, &message, &value.signature)
        })
    };
    let policy = selection::Policy {
        chain: &request.chain_id,
        target_epoch: request.epoch_id,
        minimum_delay: message::REVEAL_DELAY,
    };
    for reveal in &record.reveals {
        if !record.commitments.iter().any(|commitment| {
            selection::validate(
                &policy,
                commitment,
                reveal,
                |value| commitment_ok(value).unwrap_or(false),
                reveal_signature,
                evidence_ok,
            )
            .is_ok()
        }) {
            return Err(refused(b"compute proof reveal refused"));
        }
    }
    let mut capacities = BTreeSet::new();
    let mut commitments = BTreeSet::new();
    let mut reveals = BTreeSet::new();
    // Native List.map evaluates every identity before testing cardinality.
    for capacity in &record.capabilities {
        capacities.insert(capacity.id().map_err(malformed)?);
    }
    if capacities.len() != record.capabilities.len() {
        return Err(refused(b"compute proof repeated evidence"));
    }
    for commitment in &record.commitments {
        commitments.insert(commitment.id().map_err(malformed)?);
    }
    if commitments.len() != record.commitments.len() {
        return Err(refused(b"compute proof repeated evidence"));
    }
    for reveal in &record.reveals {
        reveals.insert(
            Message::Reveal(reveal.clone())
                .encode()
                .map_err(malformed)?,
        );
    }
    if reveals.len() != record.reveals.len() {
        return Err(refused(b"compute proof repeated evidence"));
    }
    let size = message::MAX_MEMBERS
        .min(usize::try_from(validators.n).map_err(|_| refused(b"compute proof malformed"))?);
    let challenge = selection::challenge(&request.chain_id, request.epoch_id, &request.state_root)
        .map_err(malformed)?;
    let selection = selection::select(
        &policy,
        &id,
        &challenge,
        size as i64,
        &record.commitments,
        &record.reveals,
        |value| commitment_ok(value).unwrap_or(false),
        reveal_signature,
        evidence_ok,
    )
    .map_err(malformed)?;
    if selection.members.len() != size || selection.root != request.selection_root {
        return Err(refused(b"compute proof selection differs"));
    }
    Ok(selection)
}
pub fn verify_bill(
    origin: Origin<'_>,
    epoch: i64,
    header: &Header,
    record: &Record,
    votes: &[octra_node_protocol::resource_compute::certificate::Vote],
    measured: &Measured,
) -> Result<Bill> {
    let selection = verify_selection(origin, epoch, header, record)?;
    let selected = selection
        .members
        .into_iter()
        .map(|member| member.node_id)
        .collect::<Vec<_>>();
    bill::verify(
        epoch,
        header,
        origin.validators(),
        &selected,
        votes,
        measured,
    )
}
pub fn verify_funding(
    origin: Origin<'_>,
    head: &anchor::Origin,
    epoch: i64,
    header: &Header,
    record: &Record,
    max_bytes: usize,
    ledger_root: &[u8],
    index_root: &[u8],
    proof: &[u8],
) -> Result<(Selection, Deposit)> {
    if max_bytes == 0 || proof.len() > max_bytes {
        return Err(refused(b"state proof size exceeds limit"));
    }
    if epoch != head.epoch_id() {
        return Err(refused(b"compute funding head epoch differs"));
    }
    if origin.chain_id() != head.chain_id() {
        return Err(refused(b"compute funding head chain differs"));
    }
    let selection = verify_selection(origin, epoch, header, record)?;
    let path = funding::deposit_path(&header.request().id()?)?;
    let path = path.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let raw = head
        .read_state(max_bytes, ledger_root, index_root, &path, proof)?
        .ok_or_else(|| refused(b"compute deposit is absent from state"))?;
    let deposit = funding::verify_deposit(&raw, head.chain_id(), epoch, header)?;
    Ok((selection, deposit))
}
