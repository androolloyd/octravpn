// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated transport projections over the parent's captured snapshot.
use super::private::{boolean, field, string, unavailable};
use crate::{circle_transport_store as store, state_batch::Snapshot};
use octra_node_protocol::{
    circle_policy::{
        key,
        transport::{Quorum, Topology},
    },
    circle_transport::{view, Claim},
    rpc::Fault,
    transaction::json_string,
};
fn missing(message: &[u8]) -> Fault {
    Fault::new(112, b"not found").string_data(message)
}
fn claim_array(claims: &[Claim]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (index, claim) in claims.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&claim.encode());
    }
    out.push(b']');
    out
}
pub(super) fn claims(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    id: &[u8],
    epoch: i64,
) -> Result<(), Fault> {
    let claims = store::claims(state, circle, id).map_err(unavailable)?;
    let active = store::active_claims(state, circle, id, epoch).map_err(unavailable)?;
    if claims.is_empty() {
        return Err(missing(b"circle outbox claim not found"));
    }
    let primary = active.first().or_else(|| {
        claims
            .iter()
            .min_by(|left, right| view::compare_newest(left, right))
    });
    field(
        out,
        b"claim",
        &primary.map_or_else(
            || b"null".to_vec(),
            octra_node_protocol::circle_transport::Claim::encode,
        ),
    );
    field(out, b"claims", &claim_array(&claims));
    field(out, b"active_claims", &claim_array(&active));
    Ok(())
}
pub(super) fn intent(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    id: &[u8],
) -> Result<(), Fault> {
    let intent = store::intent(state, circle, id)
        .map_err(unavailable)?
        .ok_or_else(|| missing(b"circle outbox intent not found"))?;
    field(out, b"intent", &intent.encode());
    Ok(())
}
pub(super) fn packet(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    id: &[u8],
) -> Result<(), Fault> {
    let packet = store::packet(state, circle, id)
        .map_err(unavailable)?
        .ok_or_else(|| missing(b"circle ingress packet not found"))?;
    field(out, b"packet", &packet.encode());
    Ok(())
}
pub(super) fn status(
    out: &mut Vec<u8>,
    state: &Snapshot,
    circle: &[u8],
    id: &[u8],
    epoch: i64,
) -> Result<(), Fault> {
    let intent = store::intent(state, circle, id).map_err(unavailable)?;
    let stored = store::status_opt(state, circle, id);
    let (Some(intent), Some(stored)) = (intent, stored) else {
        return Err(missing(b"circle outbox status not found"));
    };
    let active = store::active_claims(state, circle, id, epoch).map_err(unavailable)?;
    let claims = store::claims(state, circle, id).map_err(unavailable)?;
    let resolution = store::resolution(state, circle, id).map_err(unavailable)?;
    let policy = store::policy(state, circle).map_err(unavailable)?;
    let delivery = store::delivery_state(state, circle, &intent, epoch).map_err(unavailable)?;
    let evaluated = view::evaluate(
        epoch,
        &policy,
        &intent,
        stored,
        resolution.as_ref(),
        &active,
        delivery,
    );
    let eligible = view::eligible(&policy, &active);
    string(out, b"intent_id", id);
    string(out, b"status", evaluated.status.as_bytes());
    string(out, b"stored_status", stored.as_bytes());
    field(
        out,
        b"delivery_key_live",
        boolean(delivery == key::State::Live),
    );
    string(out, b"delivery_key_state", delivery.as_bytes());
    out.extend_from_slice(b",\"delivery_key_id\":");
    super::optional(out, intent.delivery_key.as_deref());
    string(out, b"claim_topology", policy.topology.as_bytes());
    string(out, b"quorum_mode", policy.quorum.as_bytes());
    string(out, b"ingress_strategy", policy.ingress.as_bytes());
    string(out, b"lease_class", policy.lease.as_bytes());
    let threshold = if policy.topology == Topology::Quorum {
        policy.threshold.unwrap_or(2)
    } else {
        1
    };
    field(out, b"quorum_threshold", threshold.to_string().as_bytes());
    let weight_threshold = if policy.quorum == Quorum::Weighted {
        (if policy.topology == Topology::Quorum {
            policy.weight_threshold.unwrap_or(2)
        } else {
            1
        })
        .to_string()
        .into_bytes()
    } else {
        b"null".to_vec()
    };
    field(out, b"quorum_weight_threshold", &weight_threshold);
    let limit = policy
        .max_active
        .or_else(|| (policy.topology == Topology::Single).then_some(1));
    field(
        out,
        b"max_active_claims",
        &limit.map_or_else(|| b"null".to_vec(), |limit| limit.to_string().into_bytes()),
    );
    field(
        out,
        b"active_claim_count",
        active.len().to_string().as_bytes(),
    );
    let weight = active.iter().fold(0i64, |sum, claim| {
        sum.wrapping_add(policy.weight(&claim.relay))
            .wrapping_shl(1)
            >> 1
    });
    field(out, b"active_claim_weight", weight.to_string().as_bytes());
    out.extend_from_slice(b",\"relay_weights\":{");
    for (index, (relay, weight)) in policy.weights.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, relay);
        out.push(b':');
        out.extend_from_slice(weight.to_string().as_bytes());
    }
    out.push(b'}');
    field(out, b"claim_ready", boolean(policy.ready(&active)));
    out.extend_from_slice(b",\"selected_ingress_relay\":");
    super::optional(out, eligible.first().map(|claim| claim.relay.as_slice()));
    out.extend_from_slice(b",\"ingress_eligible_relays\":[");
    for (index, claim) in eligible.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, &claim.relay);
    }
    out.push(b']');
    field(out, b"claims", &claim_array(&claims));
    field(out, b"active_claims", &claim_array(&active));
    field(
        out,
        b"resolution",
        &evaluated.resolution.as_ref().map_or_else(
            || b"null".to_vec(),
            octra_node_protocol::circle_transport::Resolution::encode,
        ),
    );
    Ok(())
}
