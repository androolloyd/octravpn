// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Cancellation, Request};
use octra_node_protocol::{
    native_integer::parse_int64,
    native_json::{Document, Value},
    resource_compute::{read::Read, request::Limits},
    rpc::Fault,
    transaction::{decode_base64, is_valid_address},
};
type Result<T> = std::result::Result<T, Fault>;
type Fields<'a> = &'a [(Vec<u8>, usize)];

const SUBMIT_FIELDS: &[&[u8]] = &[
    b"unit_price",
    b"fee_cap",
    b"memory_bytes",
    b"guest_bytes",
    b"fuel_limit",
    b"valid_until",
    b"caller",
    b"caller_public_key",
    b"caller_signature",
    b"circle_id",
    b"executor_root",
    b"graph_root",
    b"max_output_bytes",
    b"method_name",
    b"model_epoch",
    b"model_root",
    b"model_state_root",
    b"params_json",
    b"program_root",
    b"sequence",
    b"session_id",
];
const READ_FIELDS: &[&[u8]] = &[
    b"chain_id",
    b"node_id",
    b"caller",
    b"caller_public_key",
    b"caller_signature",
    b"job_id",
    b"epoch_id",
    b"expires_epoch",
];
const CANCEL_FIELDS: &[&[u8]] = &[
    b"caller",
    b"caller_public_key",
    b"caller_signature",
    b"session_id",
];

fn named(reason: &[u8], name: &[u8]) -> Fault {
    Fault::invalid([b"resource compute ".as_slice(), reason, b": ", name].concat())
}
fn object_fields<'a>(
    document: &'a Document,
    expected: &[&[u8]],
    params: &'a Value,
) -> Result<Fields<'a>> {
    let value = match params {
        Value::List(values) if values.len() == 1 => document.get(values[0]),
        Value::Object(_) => Some(params),
        _ => None,
    };
    match value {
        Some(Value::Object(fields))
            if fields.len() == expected.len()
                && expected.iter().all(|name| {
                    fields
                        .iter()
                        .filter(|(key, _)| key.as_slice() == *name)
                        .count()
                        == 1
                }) =>
        {
            Ok(fields)
        }
        _ => Err(Fault::invalid(b"resource compute parameters differ")),
    }
}
fn field<'a>(document: &'a Document, fields: Fields<'_>, name: &[u8]) -> Result<&'a Value> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, id)| document.get(*id))
        .ok_or_else(|| named(b"parameter missing", name))
}
fn string<'a>(document: &'a Document, fields: Fields<'_>, name: &[u8]) -> Result<&'a [u8]> {
    match field(document, fields, name)? {
        Value::String(value) => Ok(value),
        _ => Err(named(b"string required", name)),
    }
}
fn integer(document: &Document, fields: Fields<'_>, name: &[u8]) -> Result<i64> {
    match field(document, fields, name)? {
        Value::Int(value) => Ok(value.get()),
        _ => Err(named(b"integer required", name)),
    }
}
fn int64(document: &Document, fields: Fields<'_>, name: &[u8]) -> Result<i64> {
    match field(document, fields, name)? {
        Value::Int(value) => Ok(value.get()),
        Value::String(value) => parse_int64(value).ok_or_else(|| named(b"int64 required", name)),
        _ => Err(named(b"int64 required", name)),
    }
}
fn hash(document: &Document, fields: Fields<'_>, name: &[u8]) -> Result<Vec<u8>> {
    let value = string(document, fields, name)?;
    if value.len() != 64 || !value.iter().all(u8::is_ascii_hexdigit) {
        return Err(named(b"hash refused", name));
    }
    hex::decode(value).map_err(|_| named(b"hash refused", name))
}
fn fee(document: &Document, fields: Fields<'_>, name: &[u8]) -> Result<i64> {
    let value = string(document, fields, name)?;
    if value.is_empty()
        || value.len() > 19
        || value.first() == Some(&b'0')
        || !value.iter().all(u8::is_ascii_digit)
    {
        return Err(named(b"fee refused", name));
    }
    parse_int64(value)
        .filter(|value| *value > 0)
        .ok_or_else(|| named(b"fee refused", name))
}
fn address(document: &Document, fields: Fields<'_>, name: &[u8]) -> Result<Vec<u8>> {
    let value = string(document, fields, name)?;
    if is_valid_address(value) {
        Ok(value.to_vec())
    } else {
        Err(named(b"address refused", name))
    }
}
fn base64(document: &Document, fields: Fields<'_>, name: &[u8], bytes: usize) -> Result<Vec<u8>> {
    let value = string(document, fields, name)?;
    if value.len() > bytes.div_ceil(3) * 4 {
        return Err(named(b"base64 refused", name));
    }
    decode_base64(value)
        .ok()
        .filter(|value| value.len() == bytes)
        .ok_or_else(|| named(b"base64 refused", name))
}

pub fn request_of_params(document: &Document, params: &Value) -> Result<Request> {
    let fields = object_fields(document, SUBMIT_FIELDS, params)?;
    // Field order is the native refusal priority; shape and signature admission
    // remain the service's responsibility after this pure boundary decoder.
    let unit_price = fee(document, fields, b"unit_price")?;
    let fee_cap = fee(document, fields, b"fee_cap")?;
    let memory_bytes = integer(document, fields, b"memory_bytes")?;
    let guest_bytes = integer(document, fields, b"guest_bytes")?;
    let fuel_limit = integer(document, fields, b"fuel_limit")?;
    let valid_until = int64(document, fields, b"valid_until")?;
    let model_epoch = int64(document, fields, b"model_epoch")?;
    let model_state_root = hash(document, fields, b"model_state_root")?;
    let circle_id = address(document, fields, b"circle_id")?;
    let graph_root = hash(document, fields, b"graph_root")?;
    let model_root = hash(document, fields, b"model_root")?;
    let program_root = hash(document, fields, b"program_root")?;
    let executor_root = hash(document, fields, b"executor_root")?;
    let caller = address(document, fields, b"caller")?;
    let caller_public_key = base64(document, fields, b"caller_public_key", 32)?;
    let caller_signature = base64(document, fields, b"caller_signature", 64)?;
    let session_id = hash(document, fields, b"session_id")?;
    let sequence = int64(document, fields, b"sequence")?;
    let method_name = string(document, fields, b"method_name")?.to_vec();
    let params_json = string(document, fields, b"params_json")?.to_vec();
    let max_output_bytes = integer(document, fields, b"max_output_bytes")?;
    Ok(Request {
        limits: Limits {
            unit_price: Some(unit_price),
            fee_cap: Some(fee_cap),
            memory_bytes: Some(memory_bytes),
            guest_bytes: Some(guest_bytes),
            fuel_limit: Some(fuel_limit),
        },
        valid_until: Some(valid_until),
        model_epoch,
        model_state_root,
        circle_id,
        graph_root,
        model_root,
        program_root,
        executor_root,
        caller,
        caller_public_key,
        caller_signature,
        session_id,
        sequence,
        method_name,
        params_json,
        max_output_bytes,
    })
}

pub fn read_of_params(document: &Document, params: &Value) -> Result<Read> {
    let fields = object_fields(document, READ_FIELDS, params)?;
    let chain_id = string(document, fields, b"chain_id")?.to_vec();
    let node_id = address(document, fields, b"node_id")?;
    let caller = address(document, fields, b"caller")?;
    let caller_public_key = base64(document, fields, b"caller_public_key", 32)?;
    let caller_signature = base64(document, fields, b"caller_signature", 64)?;
    let job_id = hash(document, fields, b"job_id")?;
    let epoch_id = int64(document, fields, b"epoch_id")?;
    let expires_epoch = int64(document, fields, b"expires_epoch")?;
    let read = Read {
        chain_id,
        node_id,
        caller,
        caller_public_key,
        caller_signature,
        job_id,
        epoch_id,
        expires_epoch,
    };
    if read.shape() {
        Ok(read)
    } else {
        Err(Fault::invalid(b"compute read shape refused"))
    }
}

pub fn cancellation_of_params(document: &Document, params: &Value) -> Result<Cancellation> {
    let mut extended = Vec::with_capacity(CANCEL_FIELDS.len() + 1);
    extended.push(b"valid_until".as_slice());
    extended.extend_from_slice(CANCEL_FIELDS);
    let fields = object_fields(document, &extended, params)
        .or_else(|_| object_fields(document, CANCEL_FIELDS, params))?;
    let caller = address(document, fields, b"caller")?;
    let caller_public_key = base64(document, fields, b"caller_public_key", 32)?;
    let caller_signature = base64(document, fields, b"caller_signature", 64)?;
    let session_id = hash(document, fields, b"session_id")?;
    let until = if fields.iter().any(|(name, _)| name == b"valid_until") {
        Some(int64(document, fields, b"valid_until")?)
    } else {
        None
    };
    Ok(Cancellation {
        caller,
        caller_public_key,
        caller_signature,
        session_id,
        until,
    })
}
