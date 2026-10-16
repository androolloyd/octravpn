// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Call_plan input projection and native multi-exec diagnostic order.
use super::{operational, BigInt, Document, Error, ReadMode, Signed, Value, Zero};
use octra_node_protocol::{
    native_integer::parse_integer, native_json::ReadError, transaction::is_valid_address,
};

pub(super) fn empty() -> Result<Document, Error> {
    Document::parse(b"[]").map_err(operational)
}
pub(super) fn params(
    raw: Option<&[u8]>,
    forgiving: bool,
) -> Result<std::result::Result<Document, Vec<u8>>, Error> {
    let Some(raw) = raw else {
        return Ok(Ok(empty()?));
    };
    match Document::parse_native(raw, ReadMode::Tree) {
        Ok(doc) if matches!(doc.root(), Value::List(_)) => Ok(Ok(doc)),
        Ok(_) => Ok(Ok(empty()?)),
        Err(error) => match error.exception() {
            Some(_) if forgiving => Ok(Ok(empty()?)),
            Some(exception) => Ok(Err(exception)),
            None => Err(operational(error.legacy())),
        },
    }
}
pub(super) struct Call {
    pub target: Vec<u8>,
    pub method: Vec<u8>,
    pub params: Document,
    pub amount: BigInt,
}
pub(super) fn multi(
    raw: &[u8],
    max_calls: usize,
) -> Result<std::result::Result<Vec<Call>, Vec<u8>>, Error> {
    let invalid = || b"multi_exec payload is invalid".to_vec();
    let doc = match Document::parse_native(raw, ReadMode::Tree) {
        Ok(doc) => doc,
        Err(ReadError::Json { .. }) => return Ok(Err(invalid())),
        Err(ReadError::Unavailable(error)) => return Err(operational(error)),
    };
    let calls = match doc.root() {
        Value::List(calls) => Some(calls),
        root @ Value::Object(_) => match doc.field(root, b"calls") {
            Some(Value::List(calls)) => Some(calls),
            _ => None,
        },
        _ => None,
    };
    let Some(calls) = calls else {
        return Ok(Err(b"multi_exec requires calls list".to_vec()));
    };
    if calls.is_empty() {
        return Ok(Err(b"multi_exec requires at least one call".to_vec()));
    }
    if calls.len() > max_calls {
        return Ok(Err(
            format!("multi_exec call count exceeds {max_calls}").into_bytes()
        ));
    }
    let mut out = vec![];
    for (index, id) in calls.iter().enumerate() {
        let item = doc.get(*id).expect("native JSON arena child");
        if !matches!(item, Value::Object(_)) {
            return Ok(Err(
                format!("multi_exec call {index} must be object").into_bytes()
            ));
        }
        // Amount conversion occurs before reporting missing fields or bad
        // parameter shape in native parse_call, even on malformed objects.
        let amount = match doc.field(item, b"amount") {
            Some(Value::Int(value)) => BigInt::from(value.get()),
            Some(Value::String(value) | Value::IntLiteral(value)) => match parse_integer(value) {
                Some(value) => value,
                None => return Ok(Err(invalid())),
            },
            _ => BigInt::zero(),
        };
        let string = |name: &[u8]| match doc.field(item, name) {
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            _ => None,
        };
        let Some(target) = string(b"to") else {
            return Ok(Err(
                format!("multi_exec call {index} missing to").into_bytes()
            ));
        };
        let Some(method) = string(b"method") else {
            return Ok(Err(
                format!("multi_exec call {index} missing method").into_bytes()
            ));
        };
        let params = match doc.field(item, b"params") {
            Some(value @ Value::List(_)) => {
                let raw = doc.write(value, false).map_err(operational)?;
                Document::parse(&raw).map_err(operational)?
            }
            Some(Value::Null) | None => empty()?,
            _ => {
                return Ok(Err(
                    format!("multi_exec call {index} params must be list").into_bytes()
                ))
            }
        };
        if !is_valid_address(&target) {
            return Ok(Err(format!(
                "multi_exec call {index} invalid program address"
            )
            .into_bytes()));
        }
        if amount.is_negative() {
            return Ok(Err(format!(
                "multi_exec call {index} amount must not be negative"
            )
            .into_bytes()));
        }
        out.push(Call {
            target,
            method,
            params,
            amount,
        });
    }
    Ok(Ok(out))
}
