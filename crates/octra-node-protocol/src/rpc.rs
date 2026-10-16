// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Rpc request framing and Rpc_response_limit, without method authority.
use crate::{
    native_json::{self, Document, ReadError, ReadMode, Value},
    transaction::json_string,
};
use std::sync::Arc;
pub const MAX_BODY: usize = 100_000_000;
pub const MAX_SINGLE: usize = 8 * 1024 * 1024;
pub const MAX_BATCH: usize = 16 * 1024 * 1024;
pub const MAX_ITEMS: usize = 100;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: i64,
    pub message: Vec<u8>,
    /// Already encoded native JSON; constructors quote string data explicitly.
    pub data: Option<Vec<u8>>,
    response_limit: bool,
}
impl Fault {
    pub fn new(code: i64, message: impl AsRef<[u8]>) -> Self {
        Self {
            code,
            message: message.as_ref().to_vec(),
            data: None,
            response_limit: false,
        }
    }
    /// Internal early refusal after a bounded projector proves the successful
    /// response cannot fit. Rendering retains the native refusal ID policy.
    pub fn response_limit() -> Self {
        let mut error = Self::new(-32013, b"RPC response exceeds byte limit");
        error.response_limit = true;
        error
    }
    pub fn string_data(mut self, data: impl AsRef<[u8]>) -> Self {
        let mut raw = vec![];
        json_string(&mut raw, data.as_ref());
        self.data = Some(raw);
        self
    }
    pub fn invalid(reason: impl AsRef<[u8]>) -> Self {
        Self::new(-32602, b"invalid params").string_data(reason)
    }
    pub fn missing(method: &[u8]) -> Self {
        Self::new(-32601, [b"method not found: ".as_slice(), method].concat())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("{{\"code\":{},\"message\":", self.code).into_bytes();
        json_string(&mut out, &self.message);
        if let Some(data) = &self.data {
            out.extend_from_slice(b",\"data\":");
            out.extend_from_slice(data);
        }
        out.push(b'}');
        out
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    pub method: Vec<u8>,
    params: Option<usize>,
    id: Option<usize>,
}
impl Request {
    pub fn params<'a>(&self, doc: &'a Document) -> Option<&'a Value> {
        self.params.and_then(|id| doc.get(id))
    }
}
pub type Checked = std::result::Result<Request, Fault>;
pub fn param_id(params: &Value, index: usize) -> Option<usize> {
    let Value::List(items) = params else {
        return None;
    };
    items.get(index).copied()
}
pub fn param<'a>(doc: &'a Document, params: &Value, index: usize) -> Option<&'a Value> {
    param_id(params, index).and_then(|id| doc.get(id))
}
pub fn param_int(doc: &Document, params: &Value, index: usize) -> Option<i64> {
    match param(doc, params, index) {
        Some(Value::Int(value)) => Some(value.get()),
        _ => None,
    }
}
pub fn require_int(
    doc: &Document,
    params: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<i64, Fault> {
    param_int(doc, params, index)
        .ok_or_else(|| Fault::invalid(format!("missing required param: {name} (index {index})")))
}
pub fn require_string<'a>(
    doc: &'a Document,
    params: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<&'a [u8], Fault> {
    match param(doc, params, index) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(Fault::invalid(format!(
            "missing required param: {name} (index {index})"
        ))),
    }
}
pub fn require_address<'a>(
    doc: &'a Document,
    params: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<&'a [u8], Fault> {
    let value = require_string(doc, params, index, name)?;
    if crate::transaction::is_valid_address(value) {
        Ok(value)
    } else {
        Err(Fault::new(109, b"invalid address")
            .string_data(format!("invalid address format for {name}")))
    }
}
pub fn require_hash<'a>(
    doc: &'a Document,
    params: &Value,
    index: usize,
    name: &str,
) -> std::result::Result<&'a [u8], Fault> {
    let value = require_string(doc, params, index, name)?;
    if value.len() == 64
        && value
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        Ok(value)
    } else {
        Err(Fault::invalid(format!("invalid hash format for {name}")))
    }
}
#[derive(Clone, Debug)]
pub struct Parsed {
    pub document: Arc<Document>,
    pub requests: Vec<Checked>,
    pub batch: bool,
}
#[derive(Clone, Debug)]
pub enum Error {
    Rpc(Fault),
    Unavailable(native_json::Error),
}
fn field(root: &Value, name: &[u8]) -> Option<usize> {
    let Value::Object(fields) = root else {
        return None;
    };
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, id)| *id)
}
fn valid_params(doc: &Document, value: &Value) -> std::result::Result<bool, native_json::Error> {
    enum Frame<'a> {
        Value(&'a Value, usize),
        List(std::slice::Iter<'a, usize>, usize),
        Object(std::slice::Iter<'a, (Vec<u8>, usize)>, usize),
    }
    let mut pending = vec![Frame::Value(value, 0)];
    while let Some(next) = pending.pop() {
        let item = match next {
            Frame::List(mut values, depth) => match values.next() {
                None => continue,
                Some(id) => {
                    pending.push(Frame::List(values, depth));
                    Some((*id, depth))
                }
            },
            Frame::Object(mut fields, depth) => match fields.next() {
                None => continue,
                Some((_, id)) => {
                    pending.push(Frame::Object(fields, depth));
                    Some((*id, depth))
                }
            },
            Frame::Value(value, depth) => {
                if depth > 8 {
                    return Ok(false);
                }
                match value {
                    Value::String(raw) if raw.len() > MAX_BODY => return Ok(false),
                    Value::List(values) => pending.push(Frame::List(values.iter(), depth + 1)),
                    Value::Object(fields) => pending.push(Frame::Object(fields.iter(), depth + 1)),
                    _ => (),
                }
                None
            }
        };
        if let Some((id, depth)) = item {
            pending.push(Frame::Value(
                doc.get(id).ok_or(native_json::Error::Syntax(id))?,
                depth,
            ));
        }
    }
    Ok(true)
}
fn request(doc: &Document, root: &Value) -> std::result::Result<Checked, native_json::Error> {
    if !matches!(root, Value::Object(_)) {
        return Ok(Err(Fault::new(-32600, b"invalid request")));
    }
    if !matches!(doc.field(root, b"jsonrpc"), Some(Value::String(value)) if value == b"2.0") {
        return Ok(Err(Fault::new(-32600, b"invalid request")));
    }
    let method = match doc.field(root, b"method") {
        Some(Value::String(value)) => value.as_slice(),
        _ => b"",
    };
    if method.is_empty()
        || method.len() > 64
        || !method
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Ok(Err(Fault::invalid(b"invalid method name")));
    }
    let params = field(root, b"params");
    if let Some(id) = params {
        if !valid_params(doc, doc.get(id).ok_or(native_json::Error::Syntax(id))?)? {
            return Ok(Err(Fault::invalid(b"params too deep or too large")));
        }
    }
    Ok(Ok(Request {
        method: method.to_vec(),
        params,
        id: field(root, b"id"),
    }))
}
fn admissions(doc: &Document, request: &Request) -> usize {
    match request.method.as_slice() {
        b"octra_submit" | b"octra_privateTransfer" => 1,
        b"octra_submitBatch" => match request.params(doc) {
            Some(Value::List(values)) => match values.first().and_then(|id| doc.get(*id)) {
                Some(Value::List(values)) => values.len(),
                _ => 0,
            },
            _ => 0,
        },
        _ => 0,
    }
}
pub fn parse(raw: &[u8]) -> std::result::Result<Parsed, Error> {
    if raw.len() > MAX_BODY {
        return Err(Error::Rpc(Fault::new(-32700, b"parse error")));
    }
    let document = Document::parse_native(raw, ReadMode::Safe).map_err(|error| match error {
        ReadError::Json { .. } => Error::Rpc(Fault::new(-32700, b"parse error")),
        ReadError::Unavailable(error) => Error::Unavailable(error),
    })?;
    let (requests, batch) = match document.root() {
        Value::List(items) => {
            if items.len() > MAX_ITEMS {
                return Err(Error::Rpc(Fault::invalid(format!(
                    "batch size {} exceeds limit {MAX_ITEMS}",
                    items.len()
                ))));
            }
            let mut requests = vec![];
            for id in items {
                requests.push(
                    request(
                        &document,
                        document
                            .get(*id)
                            .ok_or(Error::Unavailable(native_json::Error::Syntax(*id)))?,
                    )
                    .map_err(Error::Unavailable)?,
                );
            }
            (requests, true)
        }
        value => (
            vec![Ok(request(&document, value)
                .map_err(Error::Unavailable)?
                .map_err(Error::Rpc)?)],
            false,
        ),
    };
    let count: usize = requests
        .iter()
        .filter_map(|value| value.as_ref().ok())
        .map(|request| admissions(&document, request))
        .sum();
    if count > 100 {
        return Err(Error::Rpc(Fault::invalid(format!(
            "admission attempts = {count} limit = 100"
        ))));
    }
    Ok(Parsed {
        document: Arc::new(document),
        requests,
        batch,
    })
}
/// Render after measuring the ID; an oversized ID is never serialized merely
/// to reject the response. Limits and refusal ID handling match the native host.
pub fn response(
    doc: Option<&Document>,
    request: Option<&Request>,
    result: std::result::Result<&[u8], &Fault>,
    limit: usize,
) -> std::result::Result<Vec<u8>, native_json::Error> {
    let forced_refusal = matches!(result, Err(error) if error.response_limit);
    let id = request
        .and_then(|request| request.id)
        .and_then(|id| doc.and_then(|doc| doc.get(id)));
    let id_size = match (doc, id) {
        (Some(doc), Some(id)) => doc.measure(id, limit)?,
        _ => Some(4),
    };
    let fault;
    let (mut prefix, payload) = match result {
        Ok(raw) => (b"{\"jsonrpc\":\"2.0\",\"result\":".as_slice(), raw),
        Err(error) => {
            fault = error.encode();
            (
                b"{\"jsonrpc\":\"2.0\",\"error\":".as_slice(),
                fault.as_slice(),
            )
        }
    };
    let suffix = b",\"id\":";
    let total = id_size.filter(|_| !forced_refusal).and_then(|size| {
        size.checked_add(prefix.len())?
            .checked_add(payload.len())?
            .checked_add(suffix.len() + 1)
    });
    let refused;
    let payload = if total.is_some_and(|size| size <= limit) {
        payload
    } else {
        prefix = b"{\"jsonrpc\":\"2.0\",\"error\":";
        refused = Fault::new(-32013, b"RPC response exceeds byte limit").encode();
        refused.as_slice()
    };
    let id_cap = if total.is_some_and(|size| size <= limit) {
        limit
    } else {
        256
    };
    let encoded_id = match (doc, id) {
        (Some(doc), Some(id)) if doc.measure(id, id_cap)?.is_some() => doc.write(id, false)?,
        _ => b"null".to_vec(),
    };
    let mut out = prefix.to_vec();
    out.extend_from_slice(payload);
    out.extend_from_slice(suffix);
    out.extend_from_slice(&encoded_id);
    out.push(b'}');
    Ok(out)
}
