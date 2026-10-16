// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Cancellation authority follows signed caller/session scope and retained
//! validator keys. Receipt signatures alone do not prove committee membership.
mod coordinator;
mod routes;
use super::{
    session_key, CancelStatus, CommitteeBook, HistoryWorker, Jobs, RequestBook, RequestState, View,
};
use crate::{
    compute_history::{History, Notice, Scope},
    compute_record::verify_node,
};
use base64::{engine::general_purpose::STANDARD, Engine};
pub use coordinator::{notice_message, signed_ack, signed_round, Coordinator};
use octra_node_protocol::{
    consensus::{hash::validator_set_hash, ValidatorSet},
    network::{domain_hash, verify_ed25519},
    resource_compute::{
        call::Call,
        message::{CancelAck, CancelRound, Cancellation},
        record,
        wire::Message,
        Error, Result,
    },
    transaction::address_from_public_key,
};
pub use routes::{Delivery, RelayQuota, Routes};
use std::collections::BTreeSet;
fn signed(address: &[u8], key: &[u8], bytes: &[u8], signature: &[u8]) -> bool {
    address == address_from_public_key(STANDARD.encode(key).as_bytes())
        && verify_ed25519(key, bytes, signature)
}
pub fn verify(chain: &[u8], cancel: &Cancellation) -> bool {
    cancel.chain_id == chain
        && cancel.sign_bytes().is_ok_and(|bytes| {
            signed(
                &cancel.caller,
                &cancel.caller_public_key,
                &bytes,
                &cancel.caller_signature,
            )
        })
}
pub fn verify_ack(chain: &[u8], ack: &CancelAck) -> bool {
    let delivery = &ack.delivery;
    ack.shape()
        && delivery.cancel.chain_id == chain
        && verify(chain, &delivery.cancel)
        && delivery.sign_bytes().is_ok_and(|bytes| {
            signed(
                &delivery.origin,
                &ack.origin_key,
                &bytes,
                &delivery.signature,
            )
        })
        && ack
            .sign_bytes()
            .is_ok_and(|bytes| signed(&ack.node_id, &ack.node_key, &bytes, &ack.signature))
}
fn matches(
    chain: &[u8],
    cancel: &Cancellation,
    origin: &[u8],
    call: &Call,
    validators: &ValidatorSet,
    accept: &impl Fn(&ValidatorSet) -> bool,
) -> Result<bool> {
    Ok(call.shape()?
        && call.request.chain_id == chain
        && cancel.chain_id == chain
        && call.request.caller == cancel.caller
        && call.caller_public_key == cancel.caller_public_key
        && call.request.session_id == cancel.session_id
        && call.coordinator == origin
        && validator_set_hash(validators)
            .is_ok_and(|root| root.as_slice() == call.request.validator_set_root)
        && super::request::verify_caller(call)?
        && verify_node(validators, origin, &call.sign_bytes()?, &call.signature)
        && accept(validators))
}
fn decode_scope(
    chain: &[u8],
    cancel: &Cancellation,
    origin: &[u8],
    scope: &Scope,
    accept: &impl Fn(&ValidatorSet) -> bool,
) -> Option<ValidatorSet> {
    let (call, validators) = record::decode_scope(&scope.body).ok()?;
    if scope.sequence == call.request.sequence
        && scope.request.as_slice() == call.request.id().ok()?.as_slice()
        && matches(chain, cancel, origin, &call, &validators, accept).unwrap_or(false)
    {
        Some(validators)
    } else {
        None
    }
}
impl RequestBook {
    pub fn cancel_scope(
        &self,
        chain: &[u8],
        cancel: &Cancellation,
        origin: &[u8],
        accept: impl Fn(&ValidatorSet) -> bool,
    ) -> Result<Option<ValidatorSet>> {
        for state in self.states() {
            if matches(
                chain,
                cancel,
                origin,
                state.call(),
                state.validators(),
                &accept,
            )? {
                return Ok(Some(state.validators().clone()));
            }
        }
        Ok(None)
    }
}
pub fn durable_scope(
    history: &History,
    chain: &[u8],
    cancel: &Cancellation,
    origin: &[u8],
    accept: impl Fn(&ValidatorSet) -> bool,
) -> Option<ValidatorSet> {
    let scope = history
        .find_scope(&cancel.caller, &cancel.session_id, |scope| {
            decode_scope(chain, cancel, origin, scope, &accept).is_some()
        })
        .ok()??;
    decode_scope(chain, cancel, origin, &scope, &accept)
}
pub fn round_signed(
    validators: &ValidatorSet,
    node: &[u8],
    round: &CancelRound,
    member: bool,
) -> bool {
    round
        .sign_bytes()
        .is_ok_and(|bytes| verify_node(validators, &round.origin, &bytes, &round.signature))
        && (!member || validators.public_key(node).is_some())
}
pub fn round_validators(
    current: &ValidatorSet,
    prior: Option<ValidatorSet>,
    node: &[u8],
    round: &CancelRound,
    member: bool,
) -> Option<ValidatorSet> {
    match prior {
        Some(validators) if round_signed(&validators, node, round, member) => Some(validators),
        _ if round_signed(current, node, round, member) => Some(current.clone()),
        _ => None,
    }
}
pub fn verify_notice(chain: &[u8], notice: &Notice, known: impl Fn(&[u8]) -> bool) -> bool {
    let Ok(Message::Cancel(cancel)) = Message::decode(&notice.body) else {
        return false;
    };
    cancel.chain_id == chain
        && cancel.caller == notice.caller
        && cancel.session_id == notice.session
        && cancel.until.is_none_or(|until| until == notice.expires)
        && cancel.shape()
        && (known(&domain_hash(b"octra:resource_compute_wire", &notice.body))
            || verify(chain, &cancel))
}
pub fn receipts(
    history: &History,
    view: &View<'_>,
    node: &[u8],
    caller: &[u8],
    session: &[u8],
    known: impl Fn(&[u8]) -> bool,
) -> Result<Option<(Notice, Vec<CancelAck>)>> {
    let head = view.current_head()?;
    let saved = history
        .cancel_acks(head.epoch, caller, session)
        .map_err(|error| Error::Unavailable(error.0))?;
    validate_receipts(view.chain, node, saved, known)
}
fn validate_receipts(
    chain: &[u8],
    node: &[u8],
    saved: Option<(Notice, Vec<Vec<u8>>)>,
    known: impl Fn(&[u8]) -> bool,
) -> Result<Option<(Notice, Vec<CancelAck>)>> {
    let Some((notice, rows)) = saved else {
        return Ok(None);
    };
    let unreadable = || Error::rejected(b"compute cancel receipts unreadable");
    if !verify_notice(chain, &notice, known) {
        return Err(unreadable());
    }
    let mut receipts = Vec::new();
    for row in rows {
        let Message::CancelAck(ack) = Message::decode(&row).map_err(|_| unreadable())? else {
            return Err(unreadable());
        };
        if !verify_ack(chain, &ack)
            || ack.delivery.origin != node
            || ack.delivery.expires != notice.expires
            || ack.delivery.round > notice.round
            || Message::Cancel(ack.delivery.cancel.clone())
                .encode()
                .map_err(|_| unreadable())?
                != notice.body
        {
            return Err(unreadable());
        }
        receipts.push(ack);
    }
    if receipts
        .iter()
        .map(|ack| &ack.node_id)
        .collect::<BTreeSet<_>>()
        .len()
        != receipts.len()
    {
        return Err(Error::rejected(b"compute cancel receipt repeated"));
    }
    Ok(Some((notice, receipts)))
}
