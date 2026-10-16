// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Fee-bounded, content-checked public compute input retention. Plans use only
//! committed retained roots; publication remains owned by epoch execution.
mod capture;
use crate::{
    compute_roots::{self, Root},
    state_batch::{Snapshot, StateBatch},
};
use num_bigint::BigInt;
use octra_node_protocol::{
    consensus::hash::validator_set_hash,
    network::verify_ed25519,
    oce1::{Reader, Writer},
    resource_compute::{call::Header, request::Request, Error, Result},
};
use sha2::{Digest, Sha256};

pub struct Plan {
    id: [u8; 32],
    call: Root,
    model: Root,
    session: Vec<u8>,
    fee: BigInt,
}
impl Plan {
    pub fn fee(&self) -> &BigInt {
        &self.fee
    }
    pub fn call(&self) -> &Root {
        &self.call
    }
    pub fn model(&self) -> &Root {
        &self.model
    }
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
pub fn input_path(id: &[u8]) -> Result<[Vec<u8>; 3]> {
    if id.len() != 32 {
        return Err(refused(b"compute input id refused"));
    }
    Ok([
        b"compute".to_vec(),
        b"inputs".to_vec(),
        hex::encode(id).into_bytes(),
    ])
}
pub fn session_path(request: &Request) -> Result<[Vec<u8>; 3]> {
    let mut out = Writer::new();
    out.put_bytes(&request.chain_id)?;
    out.put_bytes(&request.caller)?;
    out.put_hash32(&request.session_id)?;
    Ok([
        b"compute".to_vec(),
        b"models".to_vec(),
        hex::encode(Sha256::digest(out.into_bytes())).into_bytes(),
    ])
}
fn recent(state: &StateBatch, epoch: i64, root: &[u8]) -> Result<Root> {
    compute_roots::load(state, epoch)
        .map_err(unavailable)?
        .filter(|found| found.epoch == epoch && found.state == root)
        .ok_or_else(|| refused(b"compute input origin not retained"))
}
fn uses(state: &Snapshot, session: &[u8], required: bool) -> Result<Vec<Vec<u8>>> {
    let Some(raw) = state.get(&[b"compute", b"models", session, b"uses"]) else {
        return if required {
            Err(unavailable("compute input references missing"))
        } else {
            Ok(vec![])
        };
    };
    let mut input = Reader::new(raw);
    let ids = input
        .get_list(64, |input| input.get_hash32().map(|id| id.to_vec()))
        .map_err(unavailable)?;
    input.finish().map_err(unavailable)?;
    Ok(ids)
}
fn write_uses(state: &mut StateBatch, session: &[u8], ids: &[Vec<u8>]) -> Result<()> {
    let mut out = Writer::new();
    out.put_list(ids, |out, id| out.put_hash32(id))
        .map_err(unavailable)?;
    state
        .set(&[b"compute", b"models", session, b"uses"], out.into_bytes())
        .map_err(unavailable)
}
// Compare the distinct native requested/offered/observed epoch fields.
#[allow(clippy::suspicious_operation_groupings)]
pub fn prepare(state: &StateBatch, max_fee: &BigInt, header: &Header) -> Result<Plan> {
    let request = header.request();
    if !(1..=64).contains(&request.sequence) {
        return Err(refused(b"compute input session length"));
    }
    let call = recent(state, request.epoch_id, &request.state_root)?;
    if call.chain_id != request.chain_id
        || validator_set_hash(&call.validators)
            .map_err(unavailable)?
            .as_slice()
            != request.validator_set_root
    {
        return Err(refused(b"compute input validators differ"));
    }
    let coordinator_valid = match call.validators.public_key(header.coordinator()) {
        Some(key) => verify_ed25519(key, &header.sign_bytes()?, header.signature()),
        None => false,
    };
    if !coordinator_valid {
        return Err(refused(b"compute input coordinator signature refused"));
    }
    let session = session_path(request)?;
    let session = session[2].clone();
    let id = request.id()?;
    let snapshot = state.snapshot();
    let ids = uses(&snapshot, &session, false)?;
    if ids.iter().any(|prior| prior.as_slice() == id) || ids.len() >= 64 {
        return Err(refused(b"compute input session capacity"));
    }
    let model = match compute_roots::load_at(&snapshot, &[b"compute", b"models", &session])
        .map_err(unavailable)?
    {
        Some(model)
            if model.chain_id == request.chain_id
                && model.epoch == request.model_epoch
                && model.state == request.model_state_root =>
        {
            model
        }
        Some(_) => return Err(refused(b"compute input session model differs")),
        None => recent(state, request.model_epoch, &request.model_state_root)?,
    };
    if model.chain_id != request.chain_id {
        return Err(refused(b"compute input model chain differs"));
    }
    let (call, model, fee) = capture::capture(call, model, request, max_fee)?;
    Ok(Plan {
        id,
        call,
        model,
        session,
        fee,
    })
}
/// The plan seals both request identity and the captured trees. The caller must
/// run this with the deposit/ledger mutation under the same transaction savepoint.
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
pub fn commit(state: &mut StateBatch, plan: Plan) -> Result<()> {
    let mut ids = uses(&state.snapshot(), &plan.session, false)?;
    if ids.iter().any(|id| id.as_slice() == plan.id) || ids.len() >= 64 {
        return Err(unavailable("compute input session capacity"));
    }
    ids.insert(0, plan.id.to_vec());
    write_uses(state, &plan.session, &ids)?;
    let path = input_path(&plan.id)?;
    let base: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
    let mut field = base.clone();
    field.push(b"session");
    state
        .set(&field, plan.session.clone())
        .map_err(unavailable)?;
    *field.last_mut().expect("input field") = b"call";
    compute_roots::save_at(state, &field, &plan.call).map_err(unavailable)?;
    *field.last_mut().expect("input field") = b"model";
    compute_roots::save_at(state, &field, &plan.model).map_err(unavailable)?;
    compute_roots::save_at(state, &[b"compute", b"models", &plan.session], &plan.model)
        .map_err(unavailable)
}
pub fn release(state: &mut StateBatch, id: &[u8]) -> Result<()> {
    let path = input_path(id)?;
    let base: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
    let mut field = base.clone();
    field.push(b"session");
    let Some(session) = state.get(&field).map(<[u8]>::to_vec) else {
        return Ok(());
    };
    if session.len() != 64 {
        return Err(unavailable("compute input session key corrupt"));
    }
    let mut ids = uses(&state.snapshot(), &session, true)?;
    if !ids.iter().any(|prior| prior == id) {
        return Err(unavailable("compute input reference missing"));
    }
    ids.retain(|prior| prior != id);
    state.remove(&base).map_err(unavailable)?;
    if ids.is_empty() {
        state
            .remove(&[b"compute", b"models", &session])
            .map_err(unavailable)
    } else {
        write_uses(state, &session, &ids)
    }
}
// Compare the distinct native requested/offered/observed epoch fields.
#[allow(clippy::suspicious_operation_groupings)]
pub fn read(state: &Snapshot, header: &Header) -> Result<(Root, Root)> {
    let request = header.request();
    let path = input_path(&request.id()?)?;
    let mut field: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
    field.push(b"call");
    let call = compute_roots::load_at(state, &field).map_err(unavailable)?;
    *field.last_mut().expect("input field") = b"model";
    let model = compute_roots::load_at(state, &field).map_err(unavailable)?;
    match (call, model) {
        (Some(call), Some(model))
            if call.chain_id == request.chain_id
                && model.chain_id == request.chain_id
                && call.epoch == request.epoch_id
                && call.state == request.state_root
                && model.epoch == request.model_epoch
                && model.state == request.model_state_root
                && validator_set_hash(&call.validators)
                    .map_err(unavailable)?
                    .as_slice()
                    == request.validator_set_root =>
        {
            Ok((call, model))
        }
        _ => Err(refused(b"compute input not pinned")),
    }
}
