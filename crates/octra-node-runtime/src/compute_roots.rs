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
#[derive(Clone, Debug)]
pub struct Root {
    pub(crate) chain_id: Vec<u8>,
    pub(crate) epoch: i64,
    pub(crate) state: Vec<u8>,
    pub(crate) validators: ValidatorSet,
    pub(crate) tree: Snapshot,
}
impl Root {
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    pub fn epoch(&self) -> i64 {
        self.epoch
    }
    pub fn state(&self) -> &[u8] {
        &self.state
    }
    pub fn validators(&self) -> &ValidatorSet {
        &self.validators
    }
    pub fn tree(&self) -> &Snapshot {
        &self.tree
    }
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
    let slot = slot(cert.epoch_id);
    save_at(
        state,
        &[b"compute", b"roots", &slot],
        &Root {
            chain_id: cert.chain_id.clone(),
            epoch: cert.epoch_id,
            state: previous,
            validators: parent.validator_set.clone(),
            tree,
        },
    )
}
pub fn load(state: &StateBatch, epoch: i64) -> Result<Option<Root>, Error> {
    let slot = slot(epoch);
    load_at(&state.snapshot(), &[b"compute", b"roots", &slot])
}
pub(crate) fn save_at(state: &mut StateBatch, path: &[&[u8]], root: &Root) -> Result<(), Error> {
    let mut writer = Writer::new();
    writer.put_bytes(&root.chain_id).map_err(error)?;
    writer.put_u64(root.epoch as u64).map_err(error)?;
    writer.put_hash32(&root.state).map_err(error)?;
    writer
        .put_bytes(&root.validators.encode().map_err(error)?)
        .map_err(error)?;
    writer
        .put_bytes(hex::encode(root.tree.root().map_err(error)?).as_bytes())
        .map_err(error)?;
    let mut field = path.to_vec();
    field.push(b"meta");
    state.set(&field, writer.into_bytes()).map_err(error)?;
    *field.last_mut().expect("root field") = b"data";
    state.graft(&field, &root.tree).map_err(error)
}
pub(crate) fn load_at(snapshot: &Snapshot, path: &[&[u8]]) -> Result<Option<Root>, Error> {
    let mut field = path.to_vec();
    field.push(b"meta");
    let raw = snapshot.get(&field);
    *field.last_mut().expect("root field") = b"data";
    let tree = snapshot.subtree(&field);
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
