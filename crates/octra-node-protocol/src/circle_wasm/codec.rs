// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCWR1/OCWS1 wire values preserve native byte strings and integer spellings.
use super::{reject, Error};
use crate::{
    native_integer::parse_integer,
    native_json::{Document, Value},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scalar {
    Null,
    Bool(bool),
    Integer(Vec<u8>),
    String(Vec<u8>),
}
pub fn request_params(document: &Document) -> Result<Vec<Scalar>, Error> {
    let Value::List(items) = document.root() else {
        return Err(reject("wasm params must be a list"));
    };
    items
        .iter()
        .map(|id| match document.get(*id).expect("native arena child") {
            Value::Null => Ok(Scalar::Null),
            Value::Bool(value) => Ok(Scalar::Bool(*value)),
            Value::String(value) => Ok(Scalar::String(value.clone())),
            Value::Int(value) => Ok(Scalar::Integer(value.get().to_string().into_bytes())),
            Value::IntLiteral(value) if parse_integer(value).is_some() => {
                Ok(Scalar::Integer(value.clone()))
            }
            Value::IntLiteral(_) => Err(reject("invalid wasm integer literal")),
            _ => Err(reject(
                "wasm_v1 only supports null, bool, int, and string params",
            )),
        })
        .collect()
}
pub fn encode_request(method: &[u8], params: &[Scalar]) -> Result<Vec<u8>, Error> {
    for param in params {
        if matches!(param,Scalar::Integer(value)if parse_integer(value).is_none()) {
            return Err(reject("invalid wasm integer literal"));
        }
    }
    let mut output = b"OCWR1".to_vec();
    // The native codec truncates length prefixes but still appends all bytes.
    // Admission limits belong to the host; changing this would change framing.
    output.extend_from_slice(&(method.len() as u16).to_be_bytes());
    output.extend_from_slice(method);
    output.extend_from_slice(&(params.len() as u16).to_be_bytes());
    for param in params {
        let (tag, bytes) = match param {
            Scalar::Null => (0, &[][..]),
            Scalar::Bool(false) => (1, &[][..]),
            Scalar::Bool(true) => (2, &[][..]),
            Scalar::Integer(bytes) => (3, bytes.as_slice()),
            Scalar::String(bytes) => (4, bytes.as_slice()),
        };
        output.push(tag);
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(bytes);
    }
    Ok(output)
}
pub fn decode_response(raw: &[u8]) -> Result<Scalar, Error> {
    if raw.len() < 10 {
        return Err(reject("wasm response too short"));
    }
    if &raw[..5] != b"OCWS1" {
        return Err(reject("invalid wasm response magic"));
    }
    let size = u32::from_be_bytes(raw[6..10].try_into().expect("response header")) as usize;
    if size != raw.len() - 10 {
        return Err(reject("invalid wasm response framing"));
    }
    Ok(match raw[5] {
        0 => Scalar::Null,
        1 => Scalar::Bool(false),
        2 => Scalar::Bool(true),
        3 => Scalar::Integer(raw[10..].to_vec()),
        4 => Scalar::String(raw[10..].to_vec()),
        _ => return Err(reject("unsupported wasm response tag")),
    })
}
