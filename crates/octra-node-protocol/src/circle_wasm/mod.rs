// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Circle host framing and effect decoding. Decoding does not authorize
//! an effect or apply it to canonical state; the execution host owns that step.
pub mod codec;
pub mod public_read;
pub mod receipt;
pub mod transcript;

use crate::native_json::{Document, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rejected(Vec<u8>),
    Unavailable(Vec<u8>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Rejected(bytes) | Self::Unavailable(bytes)) = self;
        write!(f, "{}", String::from_utf8_lossy(bytes))
    }
}
impl std::error::Error for Error {}
fn reject(message: impl Into<Vec<u8>>) -> Error {
    Error::Rejected(message.into())
}
fn field<'a>(doc: &'a Document, value: &'a Value, name: &str) -> Option<&'a Value> {
    doc.field(value, name.as_bytes())
}
fn string(value: Option<&Value>) -> Option<&[u8]> {
    match value {
        Some(Value::String(v)) => Some(v),
        _ => None,
    }
}
fn int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Int(v)) => Some(v.get()),
        _ => None,
    }
}
fn boolean(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(v)) => Some(*v),
        _ => None,
    }
}
fn parse(raw: &[u8]) -> Result<Document, Error> {
    Document::parse(raw).map_err(|e| {
        Error::Unavailable(format!("invalid native wasm runtime response: {e}").into_bytes())
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Execution {
    Standard,
    Compute,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    pub name: Vec<u8>,
    pub view: bool,
    pub execution: Execution,
}
pub fn methods(raw: &[u8]) -> Result<Vec<Method>, Error> {
    let doc = parse(raw)?;
    let root = doc.root();
    if !matches!(root, Value::Object(_)) {
        return Err(reject("invalid wasm descriptor"));
    }
    let mut exports = Vec::new();
    if let Some(Value::List(items)) = field(&doc, root, "exports") {
        for item in items {
            let value = doc.get(*item).expect("native arena child");
            let name = string(field(&doc, value, "name"));
            let kind = string(field(&doc, value, "kind"));
            let (Some(name), Some(kind)) = (name, kind) else {
                return Err(reject("invalid wasm export descriptor"));
            };
            if kind == b"function" {
                exports.push(name);
            }
        }
    }
    let entries = match field(&doc, root, "manifest") {
        None | Some(Value::Null) => None,
        Some(value @ Value::Object(_)) => match field(&doc, value, "methods") {
            None => None,
            Some(Value::List(items)) if items.is_empty() => None,
            Some(Value::List(items)) => Some(items),
            _ => return Err(reject("invalid wasm methods manifest")),
        },
        _ => return Err(reject("invalid wasm manifest")),
    };
    if let Some(entries) = entries {
        entries
            .iter()
            .map(|id| {
                let value = doc.get(*id).expect("native arena child");
                let (Some(name), Some(view)) = (
                    string(field(&doc, value, "name")),
                    boolean(field(&doc, value, "view")),
                ) else {
                    return Err(reject("invalid wasm method descriptor"));
                };
                let execution = match field(&doc, value, "execution") {
                    None => Execution::Standard,
                    Some(Value::String(v)) if v == b"standard" => Execution::Standard,
                    Some(Value::String(v)) if v == b"compute" && view => Execution::Compute,
                    Some(Value::String(v)) if v == b"compute" => {
                        return Err(reject("compute method must be view-only"))
                    }
                    Some(Value::String(_)) => return Err(reject("invalid wasm method execution")),
                    _ => return Err(reject("invalid wasm method execution encoding")),
                };
                Ok(Method {
                    name: name.to_vec(),
                    view,
                    execution,
                })
            })
            .collect()
    } else {
        Ok([
            (b"octra_query".as_slice(), true),
            (b"octra_update", false),
            (b"octra_http_request", true),
        ]
        .into_iter()
        .filter(|(name, _)| exports.contains(name))
        .map(|(name, view)| Method {
            name: name.to_vec(),
            view,
            execution: Execution::Standard,
        })
        .collect())
    }
}
pub fn method_execution(methods: &[Method], name: &[u8]) -> Execution {
    methods
        .iter()
        .find(|m| m.name == name)
        .map_or(Execution::Standard, |m| m.execution)
}
