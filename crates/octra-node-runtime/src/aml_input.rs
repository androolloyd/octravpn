// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Aml_input conversion. Text and address values retain arbitrary
//! input bytes; canonical integer parsing is stricter than legacy Zarith input.
mod structured;
use crate::octb::Value;
use num_bigint::{BigInt, Sign};
use octra_node_protocol::{
    aml::ast::{Ast, Function, Type, Visibility},
    native_integer::parse_integer,
};
use std::sync::Arc;
pub use structured::{core, core_eval, core_octb, core_source, core_value, vm, CoreValue};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MethodAbsent(Vec<u8>),
    MethodPrivate(Vec<u8>),
    Arity(usize, usize),
    Value(usize, Vec<u8>),
    Type(usize, Vec<u8>),
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::MethodAbsent(name) => [b"method is absent method = ".as_slice(), name].concat(),
            Self::MethodPrivate(name) => {
                [b"method is not public method = ".as_slice(), name].concat()
            }
            Self::Arity(expected, actual) => {
                format!("argument count differs expected = {expected} actual = {actual}")
                    .into_bytes()
            }
            Self::Value(index, typ) => [
                format!("argument value is invalid index = {index} type = ").as_bytes(),
                typ,
            ]
            .concat(),
            Self::Type(index, typ) => [
                format!("argument type is unavailable index = {index} type = ").as_bytes(),
                typ,
            ]
            .concat(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}

pub fn integer(raw: &[u8]) -> Option<BigInt> {
    let value = parse_integer(raw)?;
    (value.to_string().as_bytes() == raw).then_some(value)
}
fn natural(raw: &[u8], bits: u64) -> Option<Arc<BigInt>> {
    let value = integer(raw)?;
    (value.sign() != Sign::Minus && value.bits() <= bits).then(|| Arc::new(value))
}
fn hex(raw: &[u8]) -> Option<Arc<[u8]>> {
    let body = raw.strip_prefix(b"0x")?;
    if body.len() % 2 != 0 {
        return None;
    }
    Some(hex::decode(body).ok()?.into())
}
fn tagged_parts(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = raw.iter().position(|byte| *byte == b':')?;
    Some((&raw[..at], &raw[at + 1..]))
}
fn tag_known(tag: &[u8]) -> bool {
    matches!(
        tag,
        b"int" | b"bool" | b"text" | b"bytes" | b"bytes32" | b"u64" | b"u128" | b"u256" | b"addr"
    )
}
pub fn tagged(raw: &[u8]) -> Option<Value> {
    let (tag, body) = tagged_parts(raw)?;
    Some(match tag {
        b"int" => Value::Int(Arc::new(integer(body)?)),
        b"bool" => match body {
            b"true" => Value::Bool(true),
            b"false" => Value::Bool(false),
            _ => return None,
        },
        b"text" => Value::String(Arc::from(body)),
        b"bytes" | b"bytes32" => {
            let value = hex(&[b"0x".as_slice(), body].concat())?;
            if tag == b"bytes32" {
                if value.len() != 32 {
                    return None;
                }
                Value::Bytes32(value)
            } else {
                Value::Bytes(value)
            }
        }
        b"u64" => Value::U64(natural(body, 64)?),
        b"u128" => Value::U128(natural(body, 128)?),
        b"u256" => Value::U256(natural(body, 256)?),
        b"addr" => Value::Address(Arc::from(body)),
        _ => return None,
    })
}
pub fn detached(raw: &[u8]) -> Option<Value> {
    if let Some(value) = tagged(raw) {
        return Some(value);
    }
    if tagged_parts(raw).is_some_and(|(tag, _)| tag_known(tag)) {
        return None;
    }
    if let Some(value) = integer(raw) {
        return Some(Value::Int(Arc::new(value)));
    }
    match raw {
        b"true" => Some(Value::Bool(true)),
        b"false" => Some(Value::Bool(false)),
        _ => hex(raw).map(Value::Bytes),
    }
}
pub fn method<'a>(ast: &'a Ast, name: &[u8]) -> Result<&'a Function, Error> {
    let function = ast
        .contract
        .functions
        .iter()
        .find(|function| function.name == name)
        .ok_or_else(|| Error::MethodAbsent(name.to_vec()))?;
    if function.visibility != Visibility::Public {
        return Err(Error::MethodPrivate(name.to_vec()));
    }
    Ok(function)
}
pub fn scalar(index: usize, typ: &Type, raw: &[u8]) -> Result<Value, Error> {
    let invalid = || Error::Value(index, typ.name().to_vec());
    Ok(match typ {
        Type::Int | Type::Enum(_) => Value::Int(Arc::new(integer(raw).ok_or_else(invalid)?)),
        Type::Bool => match raw {
            b"true" => Value::Bool(true),
            b"false" => Value::Bool(false),
            _ => return Err(invalid()),
        },
        Type::String => Value::String(Arc::from(raw)),
        Type::Address => Value::Address(Arc::from(raw)),
        Type::Bytes => Value::Bytes(hex(raw).ok_or_else(invalid)?),
        Type::Bytes32 => {
            let value = hex(raw)
                .filter(|value| value.len() == 32)
                .ok_or_else(invalid)?;
            Value::Bytes32(value)
        }
        Type::U64 => Value::U64(natural(raw, 64).ok_or_else(invalid)?),
        Type::U128 => Value::U128(natural(raw, 128).ok_or_else(invalid)?),
        Type::U256 => Value::U256(natural(raw, 256).ok_or_else(invalid)?),
        _ => return Err(Error::Type(index, typ.name().to_vec())),
    })
}
pub fn parse(ast: &Ast, name: &[u8], values: &[Vec<u8>]) -> Result<Vec<Value>, Error> {
    let function = method(ast, name)?;
    if function.params.len() != values.len() {
        return Err(Error::Arity(function.params.len(), values.len()));
    }
    function
        .params
        .iter()
        .zip(values)
        .enumerate()
        .map(|(index, (param, raw))| scalar(index, ast.nodes.typ(param.typ), raw))
        .collect()
}
