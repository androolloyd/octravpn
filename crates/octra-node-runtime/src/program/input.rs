// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Program_input kinds, constructor/call conversion and internal value checks.
use super::{Error, Result};
use crate::octb::Value;
use num_bigint::BigInt;
use num_traits::Signed;
use octra_node_protocol::{
    native_integer::parse_integer,
    native_json::{Document, Value as Json},
    octb::{admission::Admitted, program::Kind, StorageKind},
    transaction::{decode_base64, is_valid_address, json_string},
};
use std::{collections::BTreeMap, sync::Arc};

pub fn entry_kinds(admitted: &Admitted, target: usize) -> Vec<Kind> {
    let Some(facts) = admitted.facts() else {
        return vec![];
    };
    let mut slots = if target == 0 {
        facts.root.clone()
    } else {
        facts
            .entries
            .iter()
            .find(|entry| entry.target == target as i64)
            .map_or_else(Vec::new, |entry| entry.memory.clone())
    };
    slots.sort_by_key(|(slot, _)| *slot);
    slots.into_iter().map(|(_, kind)| kind).collect()
}
fn number(value: &Json) -> Option<BigInt> {
    match value {
        Json::Int(value) => Some(BigInt::from(value.get())),
        Json::IntLiteral(raw) => parse_integer(raw),
        _ => None,
    }
}
fn parsed(kind: Kind, value: &Json) -> Option<Value> {
    let integer = |bits: u64| {
        number(value)
            .filter(|value| !value.is_negative() && value.bits() <= bits)
            .map(Arc::new)
    };
    Some(match (kind, value) {
        (Kind::Int, _) => Value::int(number(value)?),
        (Kind::Bool, Json::Bool(value)) => Value::Bool(*value),
        (Kind::String, Json::String(value)) => Value::string(value.clone()),
        (Kind::Bytes, Json::String(value)) => Value::Bytes(value.clone().into()),
        (Kind::Bytes32, Json::String(value)) => {
            let raw = if value.len() == 32 {
                Some(value.clone())
            } else if value.len() == 44 {
                decode_base64(value).ok().filter(|value| value.len() == 32)
            } else {
                None
            }?;
            Value::Bytes32(raw.into())
        }
        (Kind::U64, _) => Value::U64(integer(64)?),
        (Kind::U128, _) => Value::U128(integer(128)?),
        (Kind::U256, _) => Value::U256(integer(256)?),
        (Kind::Addr, Json::String(value)) if is_valid_address(value) => {
            Value::Address(value.clone().into())
        }
        _ => return None,
    })
}
pub fn legacy(params: &Document) -> Result<Vec<Value>> {
    let values = match params.root() {
        Json::List(values) => values.as_slice(),
        _ => &[],
    };
    values
        .iter()
        .map(|id| {
            let value = params.get(*id).expect("native JSON arena child");
            Ok(match value {
                Json::String(raw) => Value::string(raw.clone()),
                Json::Bool(value) => Value::Bool(*value),
                Json::Int(_) | Json::IntLiteral(_) => {
                    Value::int(number(value).ok_or_else(|| {
                        Error::unavailable("OCTB parameter integer conversion unavailable")
                    })?)
                }
                _ => Value::string(vec![]),
            })
        })
        .collect()
}
pub fn parse(admitted: &Admitted, target: usize, params: &Document) -> Result<Vec<Value>> {
    if admitted.facts().is_none() {
        return legacy(params);
    }
    let values = match params.root() {
        Json::List(values) => values.as_slice(),
        _ => &[],
    };
    let kinds = entry_kinds(admitted, target);
    if kinds.len() != values.len() {
        return Err(Error::rejected("program parameter count mismatch"));
    }
    kinds
        .into_iter()
        .zip(values)
        .enumerate()
        .map(|(index, (kind, id))| {
            parsed(kind, params.get(*id).expect("native JSON arena child")).ok_or_else(|| {
                Error::rejected(
                    if matches!(kind, Kind::Cipher | Kind::PubKey | Kind::Unknown) {
                        format!("unsupported program parameter kind: {}", kind.name())
                    } else {
                        format!("invalid program parameter at index {index}")
                    },
                )
            })
        })
        .collect()
}
pub fn validate(admitted: &Admitted, target: usize, values: &[Value]) -> Result<()> {
    if admitted.facts().is_none() {
        return Ok(());
    }
    let kinds = entry_kinds(admitted, target);
    if kinds.len() != values.len() {
        return Err(Error::rejected("program parameter count mismatch"));
    }
    for (index, (kind, value)) in kinds.into_iter().zip(values).enumerate() {
        let actual = match value {
            Value::Int(_) => Some(Kind::Int),
            Value::Bool(_) => Some(Kind::Bool),
            Value::String(_) => Some(Kind::String),
            Value::Bytes(_) => Some(Kind::Bytes),
            Value::Bytes32(_) => Some(Kind::Bytes32),
            Value::U64(_) => Some(Kind::U64),
            Value::U128(_) => Some(Kind::U128),
            Value::U256(_) => Some(Kind::U256),
            Value::Address(_) => Some(Kind::Addr),
            Value::Cipher(_) => Some(Kind::Cipher),
            Value::PublicKey(_) => Some(Kind::PubKey),
            Value::Capability(_) => None,
        };
        if actual != Some(kind) {
            return Err(Error::rejected(format!(
                "invalid program parameter at index {index}"
            )));
        }
    }
    Ok(())
}
pub fn storage_kinds(admitted: &Admitted) -> BTreeMap<Vec<u8>, StorageKind> {
    admitted
        .facts()
        .into_iter()
        .flat_map(|facts| &facts.storage)
        .filter_map(|(key, kind)| {
            Some((
                key.clone(),
                match kind {
                    Kind::Int => StorageKind::Int,
                    Kind::Bool => StorageKind::Bool,
                    Kind::String => StorageKind::String,
                    Kind::Bytes => StorageKind::Bytes,
                    Kind::Bytes32 => StorageKind::Bytes32,
                    Kind::U64 => StorageKind::U64,
                    Kind::U128 => StorageKind::U128,
                    Kind::U256 => StorageKind::U256,
                    Kind::Addr => StorageKind::Addr,
                    _ => return None,
                },
            ))
        })
        .collect()
}
/// Receipt_view.nested_call_arg_json; the pre-activation projection preserves
/// booleans and unsigned values as strings rather than typed JSON arguments.
pub fn nested(values: &[Value], typed: bool) -> Result<Document> {
    let mut raw = vec![b'['];
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            raw.push(b',');
        }
        match value {
            Value::Int(value) => raw.extend_from_slice(value.to_string().as_bytes()),
            Value::Bool(value) if typed => {
                raw.extend_from_slice(if *value { b"true" } else { b"false" });
            }
            Value::U64(value) | Value::U128(value) | Value::U256(value) if typed => {
                raw.extend_from_slice(value.to_string().as_bytes());
            }
            Value::Capability(_) | Value::Cipher(_) | Value::PublicKey(_) if typed => {
                raw.extend_from_slice(b"null");
            }
            value => json_string(&mut raw, &value.text()),
        }
    }
    raw.push(b']');
    Document::parse(&raw).map_err(Error::unavailable)
}
