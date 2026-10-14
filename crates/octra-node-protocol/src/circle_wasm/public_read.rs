// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Manifest declarations for snapshot-bound public Circle reads.
use super::{field, parse, reject, string, Error};
use crate::{
    circles,
    native_integer::parse_int63,
    native_json::{Document, Value},
    transaction::is_valid_address,
};
use std::collections::BTreeSet;

pub const MAX_READS: usize = 16;
pub const MAX_ASSETS: usize = 4;
pub const MAX_RANGE: usize = 65_536;
pub const MAX_TOTAL: usize = 262_144;
pub const MAX_SOURCE: usize = 1_048_576;
pub const BASE_EFFORT: i64 = 2_000;
pub const BYTE_EFFORT: i64 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    pub method: Vec<u8>,
    pub circle: Vec<u8>,
    pub path: String,
    pub path_key: String,
    pub offset: i64,
    pub max_bytes: i64,
}
fn integer(doc: &Document, v: &Value, name: &str) -> Result<i64, Error> {
    let parsed = match field(doc, v, name) {
        Some(Value::Int(n)) => Some(n.get()),
        Some(Value::IntLiteral(raw) | Value::String(raw)) => parse_int63(raw),
        _ => None,
    };
    parsed.ok_or_else(|| reject(format!("invalid wasm public read field: {name}")))
}
fn declaration(doc: &Document, v: &Value, method: &[u8]) -> Result<Declaration, Error> {
    let (Some(circle), Some(raw_path), Some(_), Some(_)) = (
        string(field(doc, v, "circle_id")),
        string(field(doc, v, "path")),
        field(doc, v, "offset"),
        field(doc, v, "max_bytes"),
    ) else {
        return Err(reject("invalid wasm public read declaration"));
    };
    let path = circles::normalize_path(raw_path).map_err(|e| Error::Rejected(e.0))?;
    let offset = integer(doc, v, "offset")?;
    let max_bytes = integer(doc, v, "max_bytes")?;
    if path.as_bytes() != raw_path
        || !is_valid_address(circle)
        || offset < 0
        || max_bytes <= 0
        || max_bytes > MAX_RANGE as i64
    {
        return Err(reject("invalid wasm public read declaration"));
    }
    Ok(Declaration {
        method: method.to_vec(),
        circle: circle.to_vec(),
        path_key: circles::path_key(path.as_bytes()),
        path,
        offset,
        max_bytes,
    })
}
/// Takes the native engine descriptor, including its optional manifest.
pub fn declarations(raw: &[u8]) -> Result<Vec<Declaration>, Error> {
    let doc = parse(raw)?;
    let methods = match field(&doc, doc.root(), "manifest") {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(v @ Value::Object(_)) => match field(&doc, v, "methods") {
            None => return Ok(vec![]),
            Some(Value::List(items)) => items,
            _ => return Err(reject("invalid wasm methods manifest")),
        },
        _ => return Err(reject("invalid wasm manifest")),
    };
    let mut out = Vec::new();
    let mut names = Vec::new();
    for id in methods {
        let v = doc.get(*id).expect("arena child");
        let Some(name) = string(field(&doc, v, "name")) else {
            return Err(reject("invalid wasm method manifest"));
        };
        names.push(name);
        let entries = match field(&doc, v, "public_reads") {
            None => continue,
            Some(Value::List(items)) => items,
            _ => return Err(reject("invalid wasm method manifest")),
        };
        if entries.len() > MAX_READS {
            return Err(reject("wasm public read count exceeds limit"));
        }
        let batch = entries
            .iter()
            .map(|id| declaration(&doc, doc.get(*id).expect("arena child"), name))
            .collect::<Result<Vec<_>, _>>()?;
        if batch.iter().map(|d| d.max_bytes).sum::<i64>() > MAX_TOTAL as i64
            || unique_assets(&batch) > MAX_ASSETS
        {
            return Err(reject("wasm public read set exceeds limit"));
        }
        out.extend(batch);
    }
    if names.iter().any(|name| name.is_empty()) {
        return Err(reject("invalid wasm method manifest"));
    }
    if names.iter().collect::<BTreeSet<_>>().len() != names.len() {
        return Err(reject("duplicate wasm method manifest"));
    }
    let keys: BTreeSet<_> = out
        .iter()
        .map(|d| {
            [
                d.method.as_slice(),
                b"\0",
                &d.circle,
                b"\0",
                d.path.as_bytes(),
                b"\0",
                d.offset.to_string().as_bytes(),
                b"\0",
                d.max_bytes.to_string().as_bytes(),
            ]
            .concat()
        })
        .collect();
    if keys.len() != out.len() {
        return Err(reject("duplicate wasm public read declaration"));
    }
    Ok(out)
}
pub fn unique_assets(declarations: &[Declaration]) -> usize {
    declarations
        .iter()
        .map(|d| [d.circle.as_slice(), b"\0", d.path.as_bytes()].concat())
        .collect::<BTreeSet<_>>()
        .len()
}
