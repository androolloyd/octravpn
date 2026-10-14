// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Committed Circle input roots retained by native epoch advancement.
use crate::{
    execution::Error,
    state_batch::{Snapshot, StateBatch},
};
use octra_node_protocol::{
    consensus::{codec::Wire, ParentCommit, ValidatorSet},
    native_integer::parse_int64,
    oce1::{Reader, Writer},
};
pub const WINDOW: i64 = 65;
pub struct Root {
    pub chain_id: Vec<u8>,
    pub epoch: i64,
    pub state: Vec<u8>,
    pub validators: ValidatorSet,
    pub tree: Snapshot,
}
fn error(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}
fn slot(epoch: i64) -> Vec<u8> {
    epoch.wrapping_rem(WINDOW).to_string().into_bytes()
}
pub fn remember(
    state: &mut StateBatch,
    head: Option<&Snapshot>,
    epoch: i64,
    previous: &[u8],
    parent: &ParentCommit,
) -> Result<(), Error> {
    let previous = if previous.len() == 64 {
        hex::decode(previous).map_err(error)?
    } else {
        previous.to_vec()
    };
    let cert = &parent.certificate;
    if epoch <= 0
        || cert.epoch_id != epoch.wrapping_sub(1)
        || cert.header.proposed_state_root != previous
    {
        return Err(error("compute input parent differs"));
    }
    let head = head.ok_or_else(|| error("store head missing"))?;
    let captured = head
        .get(&[b"meta", b"last_epoch"])
        .and_then(parse_int64)
        .filter(|v| *v >= 0)
        .ok_or_else(|| error("store epoch missing"))?;
    if captured != cert.epoch_id {
        return Err(error("compute input head epoch differs"));
    }
    let mut projected = StateBatch::default();
    projected.begin().map_err(error)?;
    if let Some(circles) = head.subtree(&[b"circles"]) {
        projected.graft(&[b"circles"], &circles).map_err(error)?;
    }
    let tree = projected.snapshot();
    let mut writer = Writer::new();
    writer.put_bytes(&cert.chain_id).map_err(error)?;
    writer.put_u64(cert.epoch_id as u64).map_err(error)?;
    writer.put_hash32(&previous).map_err(error)?;
    writer
        .put_bytes(&parent.validator_set.encode().map_err(error)?)
        .map_err(error)?;
    writer
        .put_bytes(hex::encode(tree.root().map_err(error)?).as_bytes())
        .map_err(error)?;
    let slot = slot(cert.epoch_id);
    state
        .set(&[b"compute", b"roots", &slot, b"meta"], writer.into_bytes())
        .map_err(error)?;
    state
        .graft(&[b"compute", b"roots", &slot, b"data"], &tree)
        .map_err(error)
}
pub fn load(state: &StateBatch, epoch: i64) -> Result<Option<Root>, Error> {
    let slot = slot(epoch);
    let snapshot = state.snapshot();
    let raw = state.get(&[b"compute", b"roots", &slot, b"meta"]);
    let tree = snapshot.subtree(&[b"compute", b"roots", &slot, b"data"]);
    let raw = match (raw, tree.as_ref()) {
        (None, None) => return Ok(None),
        (Some(raw), _) => raw,
        _ => return Err(error("compute input state incomplete")),
    };
    let tree = tree.unwrap_or_else(|| StateBatch::default().snapshot());
    let mut reader = Reader::new(raw);
    let chain_id = reader.get_bytes_bounded(128).map_err(error)?.to_vec();
    let epoch = reader.get_u64().map_err(error)? as i64;
    let root = reader.get_hash32().map_err(error)?.to_vec();
    let validators =
        ValidatorSet::decode(reader.get_bytes_bounded(1_000_000).map_err(error)?).map_err(error)?;
    let hash = reader.get_bytes_bounded(128).map_err(error)?;
    reader.finish().map_err(error)?;
    if chain_id.is_empty()
        || epoch < 0
        || validators.n == 0
        || hash != hex::encode(tree.root().map_err(error)?).as_bytes()
    {
        return Err(error("compute input state corrupt"));
    }
    Ok(Some(Root {
        chain_id,
        epoch,
        state: root,
        validators,
        tree,
    }))
}
pub fn recent(state: &StateBatch, epoch: i64, root: &[u8]) -> Result<Root, Error> {
    load(state, epoch)?
        .filter(|r| r.epoch == epoch && r.state == root)
        .ok_or_else(|| error("compute input origin not retained"))
}
