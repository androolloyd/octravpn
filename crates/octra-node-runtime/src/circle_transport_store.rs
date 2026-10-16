// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Outbox reads and materialized key shutdown within the epoch savepoint.
use crate::{
    circle_error::{unavailable, Failure},
    state_batch::{Snapshot, StateBatch},
};
use octra_node_protocol::{
    circle_policy::{key, transport},
    circle_program::Refusal,
    circle_transport::{Claim, Intent, Packet, Reason, Resolution, Status},
    native_json::Document,
};
type Result<T> = std::result::Result<T, Failure>;
pub(crate) fn policy(state: &Snapshot, circle: &[u8]) -> Result<transport::Policy> {
    let mut values = Vec::with_capacity(transport::NAMES.len());
    for name in transport::NAMES {
        let raw = crate::circle_store::inline(
            state,
            circle,
            &[b"transport_policy:".as_slice(), name].concat(),
        )
        .map_err(unavailable)?;
        values.push((name, raw));
    }
    Ok(transport::Policy::from_stored(|name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .and_then(|(_, raw)| raw.clone())
    }))
}
pub(crate) fn status(state: &Snapshot, circle: &[u8], id: &[u8]) -> Status {
    status_opt(state, circle, id).unwrap_or(Status::Open)
}
pub(crate) fn status_opt(state: &Snapshot, circle: &[u8], id: &[u8]) -> Option<Status> {
    state
        .get(&[b"circles", circle, b"egress", b"outbox", id, b"status"])
        .and_then(Status::parse)
}
pub(crate) fn resolution(state: &Snapshot, circle: &[u8], id: &[u8]) -> Result<Option<Resolution>> {
    record(
        state.get(&[
            b"circles",
            circle,
            b"egress",
            b"outbox",
            id,
            b"resolution",
            b"meta",
        ]),
        Resolution::parse,
    )
}
pub(crate) fn packet(state: &Snapshot, circle: &[u8], id: &[u8]) -> Result<Option<Packet>> {
    record(
        state.get(&[b"circles", circle, b"ingress", b"packets", id, b"meta"]),
        Packet::parse,
    )
}
pub(crate) fn delivery_state(
    state: &Snapshot,
    circle: &[u8],
    intent: &Intent,
    epoch: i64,
) -> Result<key::State> {
    intent
        .delivery_key
        .as_deref()
        .map_or(Ok(key::State::Live), |key| {
            key_policy(state, circle, key).map(|policy| policy.state(epoch))
        })
}
pub(crate) fn deliverable(
    state: &Snapshot,
    circle: &[u8],
    intent: &Intent,
    epoch: i64,
    deadline: i64,
) -> Result<bool> {
    intent.delivery_key.as_deref().map_or(Ok(true), |key| {
        key_policy(state, circle, key).map(|policy| policy.deliverable(epoch, deadline))
    })
}
pub(crate) fn set_status(
    state: &mut StateBatch,
    circle: &[u8],
    id: &[u8],
    status: Status,
) -> Result<()> {
    state
        .set(
            &[b"circles", circle, b"egress", b"outbox", id, b"status"],
            status.as_bytes().to_vec(),
        )
        .map_err(unavailable)
}
pub(crate) fn save_intent(state: &mut StateBatch, circle: &[u8], intent: &Intent) -> Result<()> {
    state
        .set(
            &[
                b"circles", circle, b"egress", b"outbox", &intent.id, b"meta",
            ],
            intent.encode(),
        )
        .map_err(unavailable)?;
    set_status(state, circle, &intent.id, Status::Open)?;
    if let Some(key) = &intent.delivery_key {
        state
            .set(
                &[
                    b"circles",
                    circle,
                    b"egress",
                    b"by_delivery_key",
                    key,
                    b"intents",
                    &intent.id,
                ],
                b"1".to_vec(),
            )
            .map_err(unavailable)?;
    }
    Ok(())
}
pub(crate) fn save_claim(state: &mut StateBatch, circle: &[u8], claim: &Claim) -> Result<()> {
    let raw = claim.encode();
    state
        .set(
            &[
                b"circles",
                circle,
                b"egress",
                b"outbox",
                &claim.intent,
                b"claims",
                &claim.relay,
                b"meta",
            ],
            raw.clone(),
        )
        .map_err(unavailable)?;
    state
        .remove(&[
            b"circles",
            circle,
            b"egress",
            b"outbox",
            &claim.intent,
            b"claims",
            &claim.relay,
            b"resolution",
        ])
        .map_err(unavailable)?;
    state
        .set(
            &[
                b"circles",
                circle,
                b"egress",
                b"outbox",
                &claim.intent,
                b"claim",
                b"meta",
            ],
            raw,
        )
        .map_err(unavailable)
}
pub(crate) fn save_resolution(
    state: &mut StateBatch,
    circle: &[u8],
    resolution: &Resolution,
    relay: Option<&[u8]>,
) -> Result<()> {
    let mut path = vec![
        b"circles".as_slice(),
        circle,
        b"egress",
        b"outbox",
        &resolution.intent,
    ];
    if let Some(relay) = relay {
        path.extend([b"claims".as_slice(), relay]);
    }
    path.extend([b"resolution".as_slice(), b"meta"]);
    state.set(&path, resolution.encode()).map_err(unavailable)
}
pub(crate) fn save_packet(state: &mut StateBatch, circle: &[u8], packet: &Packet) -> Result<()> {
    state
        .set(
            &[
                b"circles",
                circle,
                b"ingress",
                b"packets",
                &packet.intent,
                b"meta",
            ],
            packet.encode(),
        )
        .map_err(unavailable)
}
fn record<T>(
    raw: Option<&[u8]>,
    parse: impl FnOnce(&Document) -> std::result::Result<T, Refusal>,
) -> Result<Option<T>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let doc = Document::parse(raw).map_err(unavailable)?;
    match parse(&doc) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.tag == "malformed_transaction_exception" => {
            Err(unavailable(String::from_utf8_lossy(&error.reason)))
        }
        Err(_) => Ok(None),
    }
}
pub(crate) fn intent(state: &Snapshot, circle: &[u8], intent: &[u8]) -> Result<Option<Intent>> {
    record(
        state.get(&[b"circles", circle, b"egress", b"outbox", intent, b"meta"]),
        |doc| Intent::parse(doc, None),
    )
}
pub(crate) fn claims(state: &Snapshot, circle: &[u8], intent: &[u8]) -> Result<Vec<Claim>> {
    let prefix: &[&[u8]] = &[b"circles", circle, b"egress", b"outbox", intent, b"claims"];
    let mut claims = vec![];
    for relay in state.child_names(prefix) {
        let mut path = prefix.to_vec();
        path.extend([relay, b"meta"]);
        if let Some(claim) = record(state.get(&path), Claim::parse)? {
            claims.push(claim);
        }
    }
    Ok(claims)
}
pub(crate) fn active_claims(
    state: &Snapshot,
    circle: &[u8],
    intent: &[u8],
    epoch: i64,
) -> Result<Vec<Claim>> {
    let claims = claims(state, circle, intent)?;
    let prefix: &[&[u8]] = &[b"circles", circle, b"egress", b"outbox", intent, b"claims"];
    let mut cancelled = vec![];
    for relay in state.child_names(prefix) {
        let mut path = prefix.to_vec();
        path.extend([relay, b"resolution", b"meta"]);
        if let Some(resolution) = record(state.get(&path), Resolution::parse)? {
            if let Some(actor) = resolution.actor {
                cancelled.push(actor);
            }
        }
    }
    let mut live: Vec<_> = claims
        .into_iter()
        .filter(|claim| claim.live(epoch) && !cancelled.contains(&claim.relay))
        .collect();
    live.sort_by(|left, right| {
        right
            .epoch
            .cmp(&left.epoch)
            .then(right.expiry.cmp(&left.expiry))
            .then(left.relay.cmp(&right.relay))
    });
    Ok(live)
}
pub(crate) fn key_policy(state: &Snapshot, circle: &[u8], key: &[u8]) -> Result<key::Policy> {
    let mut values = Vec::with_capacity(4);
    for name in [
        b"activate_after_epoch".as_slice(),
        b"expire_after_epoch",
        b"revoked",
        b"erased",
    ] {
        let raw = crate::circle_store::inline(
            state,
            circle,
            &[b"key_policy:".as_slice(), key, b":", name].concat(),
        )
        .map_err(unavailable)?;
        values.push((name, raw));
    }
    Ok(key::Policy::from_stored(|name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value.clone())
    }))
}
pub(crate) fn shutdown(
    state: &mut StateBatch,
    circle: &[u8],
    key: &[u8],
    epoch: i64,
    policy: key::Policy,
) -> Result<()> {
    let Some(reason) = Reason::from_key(policy.state(epoch)) else {
        return Ok(());
    };
    let snapshot = state.snapshot();
    for id in snapshot.child_names(&[
        b"circles",
        circle,
        b"egress",
        b"by_delivery_key",
        key,
        b"intents",
    ]) {
        if intent(&snapshot, circle, id)?.is_none() {
            continue;
        }
        let status = snapshot
            .get(&[b"circles", circle, b"egress", b"outbox", id, b"status"])
            .and_then(Status::parse)
            .unwrap_or(Status::Open);
        if !matches!(status, Status::Open | Status::Claimed) {
            continue;
        }
        let resolution = Resolution {
            intent: id.to_vec(),
            status: Status::Cancelled,
            reason,
            epoch,
            actor: None,
            key: Some(key.to_vec()),
        };
        for claim in active_claims(&snapshot, circle, id, epoch)? {
            state
                .set(
                    &[
                        b"circles",
                        circle,
                        b"egress",
                        b"outbox",
                        id,
                        b"claims",
                        &claim.relay,
                        b"resolution",
                        b"meta",
                    ],
                    resolution.encode(),
                )
                .map_err(unavailable)?;
        }
        state
            .set(
                &[
                    b"circles",
                    circle,
                    b"egress",
                    b"outbox",
                    id,
                    b"resolution",
                    b"meta",
                ],
                resolution.encode(),
            )
            .map_err(unavailable)?;
        state
            .set(
                &[b"circles", circle, b"egress", b"outbox", id, b"status"],
                Status::Cancelled.as_bytes().to_vec(),
            )
            .map_err(unavailable)?;
    }
    Ok(())
}
