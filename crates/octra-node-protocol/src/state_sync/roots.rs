// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The recent root window is linked backwards from authenticated finality.
use super::{anchor::VerifiedAnchor, require, Result};
use crate::{
    consensus::{codec::Wire, hash, qc, Finalize, ParentCommit},
    oce1::{Reader, Writer},
};
pub const WIDTH: usize = 64;
pub const MAX_FILE: usize = 32_000_000;
const MAX_ITEM: usize = 4_000_000;

pub fn encode(values: &[Finalize]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.put_list(values, |w, value| w.put_bytes(&value.encode()?))?;
    Ok(w.into_bytes())
}
pub fn decode(raw: &[u8]) -> Result<Vec<Finalize>> {
    require(
        raw.len() <= MAX_FILE,
        "ready root window exceeds byte limit",
    )?;
    let mut reader = Reader::new(raw);
    let values = reader.get_list(WIDTH, |r| Finalize::decode(r.get_bytes_bounded(MAX_ITEM)?))?;
    reader.finish()?;
    require(
        encode(&values)? == raw,
        "ready root window encoding is not exact",
    )?;
    Ok(values)
}
fn expected(parent: &ParentCommit) -> Result<qc::ExpectedParent> {
    let c = &parent.certificate;
    Ok(qc::ExpectedParent {
        chain_id: c.chain_id.clone(),
        epoch_id: c.epoch_id,
        proposal_id: c.proposal_id.clone(),
        state_root: c.header.proposed_state_root.clone(),
        validator_set_hash: hash::validator_set_hash(&parent.validator_set)?.to_vec(),
    })
}
pub fn link(current: &Finalize, prior: &Finalize) -> Result<()> {
    let parent = current
        .parent_commit
        .as_ref()
        .ok_or("ready root parent commit is missing")?;
    require(current.epoch_id > 0, "ready root epoch underflows")?;
    require(
        prior.epoch_id == current.epoch_id - 1 && prior.header.epoch_id == current.epoch_id - 1,
        "ready root epochs are not consecutive",
    )?;
    require(
        current.chain_id == prior.chain_id && current.header.chain_id == prior.header.chain_id,
        "ready root chain differs",
    )?;
    require(
        current.header.prev_state_root == prior.header.proposed_state_root,
        "ready root state link differs",
    )?;
    require(
        hash::parent_commit_hash_opt(current.parent_commit.as_ref())?.as_slice()
            == current.header.parent_commit_hash,
        "ready root parent hash differs",
    )?;
    let got = ParentCommit {
        certificate: prior.certificate(),
        validator_set: parent.validator_set.clone(),
    };
    require(
        got.encode()? == parent.encode()?,
        "ready root certificate differs",
    )?;
    qc::validate_parent(&expected(parent)?, parent).map_err(|e| format!("ready root qc {e}").into())
}
fn root(finalize: &Finalize) -> Result<(i64, Vec<u8>)> {
    require(
        (0..=(1i64 << 62) - 1).contains(&finalize.epoch_id),
        "ready root epoch exceeds platform range",
    )?;
    Ok((
        finalize.epoch_id,
        hex::encode(&finalize.header.proposed_state_root).into_bytes(),
    ))
}
/// Includes the checkpoint root, then prior roots in descending epoch order.
/// The sealed anchor is required so this cannot promote a self-signed window.
pub fn verify(anchor: &VerifiedAnchor, values: &[Finalize]) -> Result<Vec<(i64, Vec<u8>)>> {
    require(values.len() <= WIDTH, "ready root window is too wide")?;
    let mut current = &anchor.anchor().finalize;
    let mut roots = vec![root(current)?];
    for prior in values {
        link(current, prior)?;
        roots.push(root(prior)?);
        current = prior;
    }
    Ok(roots)
}
pub fn verify_snapshot(anchor: &VerifiedAnchor, raw: &[u8]) -> Result<Vec<(i64, Vec<u8>)>> {
    let values = decode(raw)?;
    let epoch = anchor.anchor().finalize.epoch_id;
    require(
        epoch >= 0 && values.len() == epoch.min(WIDTH as i64) as usize,
        "ready root window length differs",
    )?;
    verify(anchor, &values)
}
