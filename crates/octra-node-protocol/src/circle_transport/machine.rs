// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native transport transitions. Signatures, state reads, fees and writes are
//! supplied by the execution host, outside this deterministic decision layer.
use super::{Cancel, Claim, Intent, Packet, Reason, Resolution, Status};
use crate::{
    circle_policy::{
        key,
        transport::{Policy, Replacement, Topology},
    },
    circle_program::Refusal,
};
type Result<T> = std::result::Result<T, Refusal>;
fn require(ok: bool, tag: &'static str, reason: &'static [u8]) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Refusal::new(tag, reason))
    }
}
fn mutable_status(status: Status) -> Result<()> {
    match status {
        Status::Fulfilled => Err(Refusal::new(
            "circle_outbox_already_fulfilled",
            b"outbox intent already fulfilled",
        )),
        Status::Cancelled => Err(Refusal::new(
            "circle_outbox_cancelled",
            b"outbox intent is cancelled",
        )),
        Status::Expired => Err(Refusal::new(
            "circle_outbox_expired",
            b"outbox intent already expired",
        )),
        _ => Ok(()),
    }
}
pub fn open_envelope(intent: &Intent, epoch: i64) -> Result<()> {
    require(
        !intent.id.is_empty(),
        "invalid_circle_intent_id",
        b"intent_id must not be empty",
    )?;
    require(
        intent.relay_policy.len() == 64,
        "invalid_circle_relay_policy_hash",
        b"relay_policy_hash must be a 64-char hex string",
    )?;
    require(
        intent.payload.len() == 64,
        "invalid_circle_payload_hash",
        b"payload_hash must be a 64-char hex string",
    )?;
    require(
        intent.expiry > epoch,
        "invalid_circle_expiry_epoch",
        b"expiry_epoch must be in the future",
    )
}
pub fn open(
    intent: &Intent,
    epoch: i64,
    policy: &Policy,
    deliverable: bool,
    exists: bool,
) -> Result<()> {
    open_envelope(intent, epoch)?;
    require(
        deliverable,
        "circle_delivery_key_inactive",
        b"delivery key is not deliverable before intent expiry",
    )?;
    require(
        policy
            .max_response
            .is_none_or(|max| intent.max_response <= max),
        "circle_transport_policy_violation",
        b"max_response_bytes exceeds circle transport policy",
    )?;
    require(
        !exists,
        "circle_outbox_exists",
        b"outbox intent already exists",
    )
}
pub fn claim_envelope(claim: &Claim, sender: &[u8], epoch: i64) -> Result<()> {
    require(
        !claim.intent.is_empty(),
        "invalid_circle_intent_id",
        b"intent_id must not be empty",
    )?;
    require(
        sender == claim.relay,
        "circle_relay_claim_sender_mismatch",
        b"claim relay_id must match tx sender",
    )?;
    require(
        claim.epoch == epoch,
        "circle_relay_claim_epoch_invalid",
        b"claim_epoch must match the current epoch",
    )
}
pub fn claim_policy(claim: &Claim, policy: &Policy) -> Result<()> {
    require(
        policy.relay_allowed(&claim.relay),
        "circle_transport_policy_violation",
        b"relay is not allowed by circle transport policy",
    )?;
    require(
        policy
            .max_window
            .is_none_or(|max| claim.expiry.wrapping_sub(claim.epoch) <= max),
        "circle_transport_policy_violation",
        b"relay claim window exceeds circle transport policy",
    )
}
#[allow(clippy::too_many_arguments)] // Explicit native machine inputs.
pub fn claim(
    claim: &Claim,
    epoch: i64,
    policy: &Policy,
    intent: &Intent,
    status: Status,
    deliverable: bool,
    existing: &[Claim],
    active: &[Claim],
) -> Result<()> {
    require(
        policy.relay_allowed(&claim.relay),
        "circle_transport_policy_violation",
        b"relay is not allowed by circle transport policy",
    )?;
    require(
        deliverable,
        "circle_delivery_key_inactive",
        b"outbox delivery key is not deliverable for the claim window",
    )?;
    require(
        intent.expiry > epoch,
        "circle_outbox_expired",
        b"outbox intent already expired",
    )?;
    require(
        claim.epoch >= epoch && claim.expiry > claim.epoch && claim.expiry <= intent.expiry,
        "circle_relay_claim_window_invalid",
        b"relay claim window is invalid for this intent",
    )?;
    mutable_status(status)?;
    require(
        !active.iter().any(|stored| stored.relay == claim.relay),
        "circle_relay_claim_duplicate",
        b"relay already has an active claim for this intent",
    )?;
    if policy.topology == Topology::Single {
        require(
            active.is_empty(),
            "circle_relay_claim_strategy_rejected",
            b"outbox already has an active relay claim",
        )?;
        let latest = existing.iter().min_by(|left, right| {
            right
                .epoch
                .cmp(&left.epoch)
                .then(right.expiry.cmp(&left.expiry))
                .then(left.relay.cmp(&right.relay))
        });
        let replacement = latest.is_none_or(|stored| {
            epoch >= stored.expiry
                && match policy.replacement {
                    Replacement::Any => true,
                    Replacement::SameRelay => stored.relay == claim.relay,
                    Replacement::None => false,
                }
        });
        require(
            replacement,
            "circle_relay_claim_strategy_rejected",
            b"outbox relay claim strategy rejected this replacement",
        )
    } else {
        require(
            (active.len() as i64) < policy.active_limit(),
            "circle_relay_claim_capacity_exceeded",
            b"outbox active relay claim capacity is exhausted",
        )?;
        match existing.iter().find(|stored| stored.relay == claim.relay) {
            Some(stored) if epoch >= stored.expiry => require(
                policy.replacement != Replacement::None,
                "circle_relay_claim_strategy_rejected",
                b"relay claim strategy rejected this relay re-claim",
            ),
            Some(_) => Err(Refusal::new(
                "circle_relay_claim_duplicate",
                b"relay already has a stored claim for this intent",
            )),
            None => Ok(()),
        }
    }
}
pub fn cancel_envelope(cancel: &Cancel, sender: &[u8], epoch: i64) -> Result<()> {
    require(
        !cancel.intent.is_empty(),
        "invalid_circle_intent_id",
        b"intent_id must not be empty",
    )?;
    require(
        sender == cancel.relay,
        "circle_relay_cancel_sender_mismatch",
        b"cancel relay_id must match tx sender",
    )?;
    require(
        cancel.epoch == epoch,
        "circle_relay_cancel_epoch_invalid",
        b"cancel_epoch must match the current epoch",
    )
}
pub struct CancelPlan {
    pub claim: Resolution,
    pub outbox: Option<Resolution>,
    pub status: Status,
}
pub fn cancel(
    cancel: &Cancel,
    epoch: i64,
    intent: &Intent,
    status: Status,
    key_state: key::State,
    existing: &[Claim],
    active: &[Claim],
) -> Result<CancelPlan> {
    mutable_status(status)?;
    require(
        status != Status::Open,
        "circle_relay_claim_required",
        b"outbox intent has no relay claim to cancel",
    )?;
    let matches_key = Reason::from_key(key_state)
        .is_some_and(|expected| cancel.reason == expected || cancel.reason == Reason::KeyInactive);
    if active.iter().any(|claim| claim.relay == cancel.relay) {
        require(
            cancel.reason == Reason::RelayCancelled || matches_key,
            "circle_relay_cancel_reason_invalid",
            b"active relay cancel reason is not allowed",
        )?;
    } else if let Some(claim) = existing.iter().find(|claim| claim.relay == cancel.relay) {
        if intent.expiry <= epoch {
            require(
                cancel.reason == Reason::IntentExpired,
                "circle_relay_cancel_reason_invalid",
                b"intent expiry requires intent_expired reason",
            )?;
        } else if epoch >= claim.expiry {
            require(
                cancel.reason == Reason::ClaimExpired || matches_key,
                "circle_relay_cancel_reason_invalid",
                b"expired relay cancel reason is not allowed",
            )?;
        } else {
            return Err(Refusal::new(
                "circle_relay_claim_inactive",
                b"relay claim is no longer active for cancellation",
            ));
        }
    } else {
        return Err(Refusal::new(
            "circle_relay_claim_mismatch",
            b"cancel relay does not match a claimed relay",
        ));
    }
    let claim = Resolution::make(
        &cancel.intent,
        epoch,
        Some(&cancel.relay),
        intent.delivery_key.as_deref(),
        cancel.reason,
    );
    let remains = active.iter().any(|claim| claim.relay != cancel.relay);
    Ok(CancelPlan {
        status: if remains {
            Status::Claimed
        } else {
            claim.status
        },
        outbox: (!remains).then(|| claim.clone()),
        claim,
    })
}
pub fn ingress_envelope(packet: &Packet, sender: &[u8]) -> Result<()> {
    require(
        !packet.intent.is_empty(),
        "invalid_circle_intent_id",
        b"intent_id must not be empty",
    )?;
    require(
        sender == packet.relay,
        "circle_ingress_sender_mismatch",
        b"ingress relay_id must match tx sender",
    )?;
    require(
        packet.payload.len() == 64,
        "invalid_circle_response_payload_hash",
        b"response_payload_hash must be a 64-char hex string",
    )?;
    require(
        packet.size >= 0,
        "invalid_circle_response_size_bytes",
        b"response_size_bytes must not be negative",
    )
}
#[allow(clippy::too_many_arguments)] // Explicit native machine inputs.
pub fn ingress(
    packet: &Packet,
    epoch: i64,
    policy: &Policy,
    intent: &Intent,
    status: Status,
    key_state: key::State,
    active: &[Claim],
    exists: bool,
) -> Result<Resolution> {
    require(
        policy.relay_allowed(&packet.relay),
        "circle_transport_policy_violation",
        b"relay is not allowed by circle transport policy",
    )?;
    require(
        key_state == key::State::Live,
        "circle_delivery_key_inactive",
        b"outbox delivery key is not live",
    )?;
    require(
        !policy.require_ciphertext || packet.ciphertext.is_some(),
        "circle_transport_policy_violation",
        b"circle transport policy requires response ciphertext",
    )?;
    require(
        !policy.require_receipt || packet.receipt.is_some(),
        "circle_transport_policy_violation",
        b"circle transport policy requires external receipt",
    )?;
    require(
        policy
            .result_codes
            .as_ref()
            .is_none_or(|codes| codes.contains(&packet.code)),
        "circle_transport_policy_violation",
        b"result_code is not allowed by circle transport policy",
    )?;
    require(
        packet.size <= intent.max_response,
        "circle_transport_policy_violation",
        b"response_size_bytes exceeds outbox intent limit",
    )?;
    require(
        policy.max_response.is_none_or(|max| packet.size <= max),
        "circle_transport_policy_violation",
        b"response_size_bytes exceeds circle transport policy",
    )?;
    require(
        intent.expiry > epoch,
        "circle_outbox_expired",
        b"outbox intent already expired",
    )?;
    match status {
        Status::Open => {
            return Err(Refusal::new(
                "circle_relay_claim_required",
                b"outbox intent requires a live relay claim",
            ))
        }
        Status::Claimed => {
            require(
                !active.is_empty(),
                "circle_relay_claim_inactive",
                b"relay claim is missing or expired",
            )?;
            require(
                policy.ready(active),
                "circle_relay_quorum_pending",
                b"outbox relay quorum is not yet satisfied",
            )?;
            let claim = active
                .iter()
                .find(|claim| claim.relay == packet.relay)
                .ok_or_else(|| {
                    Refusal::new(
                        "circle_relay_claim_mismatch",
                        b"ingress relay does not match an active relay claim",
                    )
                })?;
            require(
                policy.ingress_relay_allowed(active, &packet.relay),
                "circle_relay_primary_required",
                b"ingress relay is not the selected relay for the current claim-set",
            )?;
            require(
                claim.intent == packet.intent,
                "circle_relay_claim_mismatch",
                b"ingress relay does not match the active relay claim",
            )?;
        }
        _ => mutable_status(status)?,
    }
    require(
        !exists,
        "circle_ingress_packet_exists",
        b"ingress packet already exists",
    )?;
    Ok(Resolution::make(
        &packet.intent,
        epoch,
        Some(&packet.relay),
        intent.delivery_key.as_deref(),
        Reason::Fulfilled,
    ))
}
