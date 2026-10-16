// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{private::unavailable, wire::Object};
use crate::{circle_store::ResourcePolicy, circle_transport_store, state_batch::Snapshot};
use octra_node_protocol::{circle_policy::key, rpc::Fault};
pub(super) fn key_state(
    state: &Snapshot,
    circle: &[u8],
    key: Option<&[u8]>,
    epoch: i64,
) -> Result<key::State, Fault> {
    key.map_or(Ok(key::State::Live), |key| {
        circle_transport_store::key_policy(state, circle, key)
            .map(|policy| policy.state(epoch))
            .map_err(unavailable)
    })
}
pub(super) fn delivery_fields(
    out: &mut Object,
    state: &Snapshot,
    circle: &[u8],
    key: Option<&[u8]>,
    epoch: i64,
    nullable: bool,
) -> Result<(), Fault> {
    if let Some(key) = key {
        let status = key_state(state, circle, Some(key), epoch)?;
        out.string(b"delivery_key_id", key)
            .string(b"delivery_key_state", status.as_bytes())
            .boolean(b"delivery_key_live", status == key::State::Live);
    } else if nullable {
        for name in [
            b"delivery_key_id".as_slice(),
            b"delivery_key_state",
            b"delivery_key_live",
        ] {
            out.raw(name, b"null");
        }
    }
    Ok(())
}
pub(super) fn encode(
    state: &Snapshot,
    circle: &[u8],
    policy: &ResourcePolicy,
    epoch: i64,
) -> Result<Vec<u8>, Fault> {
    let mut out = Object::new();
    delivery_fields(
        &mut out,
        state,
        circle,
        policy.delivery_key.as_deref(),
        epoch,
        true,
    )?;
    out.epoch(
        b"activate_after_epoch",
        policy.visibility.activate_after_epoch,
    )
    .epoch(b"expire_after_epoch", policy.visibility.expire_after_epoch)
    .boolean(b"tombstone", policy.visibility.tombstone)
    .boolean(b"revoked", policy.visibility.revoked);
    Ok(out.finish())
}
