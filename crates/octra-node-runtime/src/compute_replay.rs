// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted CPU provider replay over retained roots and the native WASM engine.
//! Provider observations are reconstructed from interpreter receipts.
mod observation;
mod payload;
use crate::{
    circle::CircleRuntime,
    circle_store, compute_model,
    compute_record::Session,
    compute_settle::{Inputs, Replay},
};
use octra_node_protocol::{
    circle_storage::StorageTable,
    circle_wasm::{self, codec, receipt::Receipt},
    native_json::{Document, ReadError, ReadMode, Value},
    network::domain_hash,
    oce1::Writer,
    resource_compute::{
        bill::{self, Measured},
        call::Call,
        request::Request,
        Error, Result,
    },
    transaction::decode_base64,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub struct NativeReplay<'a> {
    runtime: &'a CircleRuntime,
}
impl<'a> NativeReplay<'a> {
    pub fn new(runtime: &'a CircleRuntime) -> Self {
        Self { runtime }
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
fn read_reply(raw: &[u8]) -> Result<Document> {
    Document::parse_native(raw, ReadMode::Safe).map_err(|error| {
        let reason = error
            .exception()
            .unwrap_or_else(|| b"native JSON allocation unavailable".to_vec());
        Error::Unavailable(
            [
                b"invalid native wasm runtime response: ".as_slice(),
                &reason,
            ]
            .concat(),
        )
    })
}
fn host(error: crate::circle::Error) -> Error {
    match error {
        crate::circle::Error::Rejected(reason) => Error::Rejected(reason.into_bytes()),
        crate::circle::Error::Unavailable(reason) => Error::Unavailable(reason.into_bytes()),
    }
}
fn wasm(error: circle_wasm::Error) -> Error {
    match error {
        circle_wasm::Error::Rejected(reason) => Error::Rejected(reason),
        circle_wasm::Error::Unavailable(reason) => Error::Unavailable(reason),
    }
}
fn deadline(start: Instant) -> Result<()> {
    if start.elapsed() > Duration::from_secs(300) {
        Err(unavailable("compute replay timeout"))
    } else {
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
struct Program<'a> {
    runtime: &'a [u8],
    code_b64: &'a [u8],
    code_hash: &'a [u8],
}
fn program<'a>(
    inputs: &'a Inputs,
    epoch: i64,
    root: &[u8],
    circle: &[u8],
    expected: &[u8],
) -> Result<Program<'a>> {
    let source = inputs
        .find(epoch, Some(root))
        .ok_or_else(|| refused(b"compute input snapshot missing"))?;
    let program = circle_store::public_program(source.tree(), circle).map_err(|error| {
        if error.0
            == octra_node_protocol::native_json::Error::Allocation
                .to_string()
                .as_bytes()
        {
            unavailable(error)
        } else {
            refused(&error.0)
        }
    })?;
    let code = decode_base64(program.code_b64)
        .map_err(|_| refused(b"resource compute program base64 refused"))?;
    let expected = hex::encode(expected);
    if program.runtime != b"wasm_v1"
        || program.code_hash != expected.as_bytes()
        || hex::encode(Sha256::digest(code)) != expected
    {
        return Err(refused(b"resource compute program root differs"));
    }
    Ok(Program {
        runtime: program.runtime,
        code_b64: program.code_b64,
        code_hash: program.code_hash,
    })
}
fn params(call: &Call) -> Result<Vec<u8>> {
    request_bytes(&call.method_name, &call.params_json)
}
fn request_bytes(method: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let document = Document::parse_native(raw, ReadMode::Safe).map_err(|error| match error {
        ReadError::Json { .. } => refused(b"resource compute params JSON refused"),
        ReadError::Unavailable(error) => unavailable(error),
    })?;
    if !matches!(document.root(), Value::List(_)) {
        return Err(refused(b"resource compute params list required"));
    }
    let params = codec::request_params(&document).map_err(wasm)?;
    codec::encode_request(method, &params).map_err(wasm)
}
fn scope(request: &Request) -> Result<Vec<u8>> {
    session_scope(
        &request.circle_id,
        &request.model_root,
        &request.caller,
        &request.session_id,
    )
}
fn session_scope(circle: &[u8], model: &[u8], caller: &[u8], session: &[u8]) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.put_bytes(circle)?;
    out.put_hash32(model)?;
    out.put_bytes(caller)?;
    out.put_hash32(session)?;
    Ok(hex::encode(domain_hash(
        b"octra:resource_compute_session",
        &out.into_bytes(),
    ))
    .into_bytes())
}
// Preserve the native remainder guard and its evaluation order.
#[allow(clippy::manual_is_multiple_of)]
fn raw32_lossy(raw: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = if raw.len() % 2 == 0 {
        hex::decode(raw).map_err(|_| refused(b"int_of_string"))?
    } else {
        vec![]
    };
    bytes.resize(32, 0);
    bytes.truncate(32);
    Ok(bytes)
}
pub(crate) fn execute_single(
    runtime: &CircleRuntime,
    model: &crate::compute_provider::owner::Model,
    program: &crate::compute_provider::Program,
    request: &octra_node_protocol::resource_compute::provider::Execute,
) -> Result<crate::compute_provider::Observation> {
    let bytes = request_bytes(&request.method_name, &request.params_json)?;
    let scope = session_scope(
        &request.circle_id,
        &raw32_lossy(&request.model_root)?,
        &request.caller,
        &raw32_lossy(&request.session_id)?,
    )?;
    let payload = payload::single(request, program, model, &bytes, &scope, true)?;
    let reply = match runtime.execute(&payload) {
        Err(crate::circle::Error::Rejected(reason))
            if reason.starts_with("missing wasm module cache:") =>
        {
            let full = payload::single(request, program, model, &bytes, &scope, false)?;
            runtime.execute(&full).map_err(host)?
        }
        other => other.map_err(host)?,
    };
    let receipt =
        circle_wasm::receipt::decode(reply.as_ref(), &StorageTable::new(8)).map_err(wasm)?;
    observation::observe(&receipt).map(|(observation, _)| observation)
}
fn check_scope(call: &Call) -> Result<()> {
    if !call.request.shape()
        || call.request.input_bytes != call.params_json.len() as i64
        || call.request.input_hash
            != octra_node_protocol::resource_compute::call::input_hash(
                &call.method_name,
                &call.params_json,
            )?
    {
        return Err(refused(b"compute measurement scope differs"));
    }
    Ok(())
}
impl NativeReplay<'_> {
    fn executor(&self, expected: &[u8]) -> Result<()> {
        let reply = self
            .runtime
            .execute(br#"{"action":"compute_self_test"}"#)
            .map_err(unavailable)?;
        let doc = read_reply(reply.as_ref())?;
        let identity = octra_node_protocol::resource_compute::provider::SelfTest::from_json(&doc)
            .map_err(unavailable)?;
        if identity.executor_root != hex::encode(expected).as_bytes() {
            return Err(refused(b"compute executor root differs"));
        }
        Ok(())
    }
    fn execute(&self, payload: &[u8], count: usize) -> Result<Vec<Receipt>> {
        let reply = self.runtime.execute(payload).map_err(host)?;
        let doc = read_reply(reply.as_ref())?;
        let Value::Object(fields) = doc.root() else {
            return Err(unavailable("compute replay response differs"));
        };
        let Some(Value::List(replies)) = doc.field(doc.root(), b"replies") else {
            return Err(unavailable("compute replay response differs"));
        };
        if fields.len() != 1 || replies.len() != count {
            return Err(unavailable("compute replay response differs"));
        }
        let empty = StorageTable::new(8);
        replies
            .iter()
            .map(|id| {
                let raw = doc
                    .write(doc.get(*id).expect("JSON arena child"), false)
                    .map_err(unavailable)?;
                circle_wasm::receipt::decode(&raw, &empty).map_err(wasm)
            })
            .collect()
    }
}
impl Replay for NativeReplay<'_> {
    fn replay(&mut self, session: &Session<'_>, inputs: &Inputs) -> Result<Vec<Measured>> {
        let start = Instant::now();
        let calls = session.calls().collect::<Vec<_>>();
        let Some(first) = calls.first() else {
            return Err(refused(b"compute replay empty"));
        };
        if calls.len() > 64 {
            return Err(refused(b"compute replay step count"));
        }
        let request = &first.request;
        let mut prior: Option<Program<'_>> = None;
        for (epoch, root) in
            std::iter::once((request.model_epoch, request.model_state_root.as_slice())).chain(
                calls
                    .iter()
                    .map(|call| (call.request.epoch_id, call.request.state_root.as_slice())),
            )
        {
            deadline(start)?;
            let current = program(
                inputs,
                epoch,
                root,
                &request.circle_id,
                &request.program_root,
            )?;
            if prior.as_ref().is_some_and(|prior| *prior != current) {
                return Err(refused(b"compute replay program changed"));
            }
            prior = Some(current);
        }
        let program = prior.ok_or_else(|| refused(b"compute replay program missing"))?;
        self.executor(&request.executor_root)?;
        deadline(start)?;
        let source = inputs
            .find(request.model_epoch, Some(&request.model_state_root))
            .ok_or_else(|| refused(b"compute input snapshot missing"))?;
        let model = compute_model::load(
            source,
            &request.circle_id,
            hex::encode(&request.graph_root).as_bytes(),
            hex::encode(&request.model_root).as_bytes(),
        )?;
        deadline(start)?;
        let mut steps = Vec::new();
        let mut previous = request.epoch_id;
        for (index, call) in calls.iter().enumerate() {
            check_scope(call)?;
            if call.request.sequence != (index + 1) as i64 {
                return Err(refused(b"compute replay sequence differs"));
            }
            if call.request.caller != request.caller
                || call.request.session_id != request.session_id
                || call.request.chain_id != request.chain_id
                || call.request.epoch_id < previous
            {
                return Err(refused(b"compute replay session differs"));
            }
            let raw = params(call)?;
            steps.push(raw);
            previous = call.request.epoch_id;
        }
        let payload = payload::encode(&calls, &steps, &program, model.cache(), &scope(request)?)?;
        deadline(start)?;
        let replies = self.execute(&payload, calls.len())?;
        deadline(start)?;
        calls
            .iter()
            .zip(&replies)
            .map(|(call, receipt)| observation::measure(call, receipt))
            .collect()
    }
}
