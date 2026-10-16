// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle RPC reads keep authorization and execution on one snapshot.
use crate::{
    circle_store::{self, Info},
    state_batch::Snapshot,
};
use octra_node_protocol::{
    circle_auth::{self, Auth, Gate},
    native_json::{Document, Value},
    rpc::{require_string, Fault},
    transaction::json_string,
};
pub mod assets;
mod objects;
mod outbox;
mod policy;
pub mod private;
pub mod program;
mod records;
pub mod view;
mod wire;
fn error(reason: impl AsRef<[u8]>) -> Fault {
    Fault::new(-32000, reason)
}
fn load(state: &Snapshot, circle: &[u8]) -> Result<Info, Fault> {
    circle_store::info(state, circle)
        .map_err(|reason| error(&reason.0))?
        .ok_or_else(|| Fault::new(112, b"not found").string_data(b"circle not found"))
}
fn optional(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => json_string(out, value),
        None => out.extend_from_slice(b"null"),
    }
}
pub fn info(
    state: &Snapshot,
    doc: &Document,
    params: &Value,
    authenticated: bool,
) -> Result<Vec<u8>, Fault> {
    let circle = require_string(doc, params, 0, "circle_id")?;
    let info = load(state, circle)?;
    if authenticated {
        Auth::parse(doc, params, [1, 2, 3])?.authorize(
            &info.privacy,
            &info.owner,
            Gate::OwnerPrivate,
            b"octra_circle_info",
            circle,
            b"",
        )?;
    } else if !circle_auth::public_info_allowed(&info.privacy) {
        return Err(error(b"authenticated circle info required"));
    }
    Ok(info_json(&info))
}
pub fn info_json(info: &Info) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (index, (key, value)) in [
        (b"circle_id".as_slice(), info.circle_id.as_slice()),
        (b"runtime", &info.runtime),
        (b"version", info.version.to_string().as_bytes()),
        (b"owner", &info.owner),
        (b"code_hash", &info.code_hash),
        (b"stable_root", &info.stable_root),
        (b"assets_root", &info.assets_root),
        (b"privacy_class", &info.privacy),
        (b"browser_mode", &info.browser),
        (b"resource_mode", &info.resource),
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        json_string(&mut out, value);
    }
    for (key, value) in [
        (b"policy_hash".as_slice(), info.policy_hash.as_deref()),
        (b"members_root", info.members_root.as_deref()),
        (b"export_policy", info.export_policy.as_deref()),
    ] {
        out.push(b',');
        json_string(&mut out, key);
        out.push(b':');
        optional(&mut out, value);
    }
    out.extend_from_slice(b",\"limits\":{");
    for (index, (key, value)) in circle_store::LIMIT_NAMES
        .iter()
        .zip(info.limits)
        .enumerate()
    {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        json_string(&mut out, value.to_string().as_bytes());
    }
    out.extend_from_slice(b"}}");
    out
}
