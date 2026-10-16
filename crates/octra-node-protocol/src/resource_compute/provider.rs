// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native provider JSON boundaries. Admission limits belong to these decoders;
//! successful decoding does not authenticate a compute job or its origins.
mod config;
mod encode;
use super::{request::MAX_MEMORY, Error, Result};
use crate::{
    native_integer::parse_int64,
    native_json::{Document, ReadError, ReadMode, Value},
    transaction::{decode_base64, is_valid_address},
};
pub use config::{Config, Limits};
use std::collections::BTreeSet;
pub const MAX_HTTP_BODY: usize = 4 * 1024 * 1024;
pub const MAX_PROGRAM: usize = 1024 * 1024;
pub const MAX_PARAMS: usize = 1024 * 1024;
pub const MAX_STORAGE_ENTRIES: usize = 2048;
pub const MAX_STORAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STORAGE_KEY: usize = 256;
pub const MAX_STORAGE_VALUE: usize = 1024 * 1024;
pub const MAX_OUTPUT: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepare {
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execute {
    pub memory_bytes: i64,
    pub guest_bytes: i64,
    pub fuel_limit: i64,
    pub request_id: Vec<u8>,
    pub session_id: Vec<u8>,
    pub epoch_id: i64,
    pub state_root: Vec<u8>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub caller: Vec<u8>,
    pub method_name: Vec<u8>,
    pub params_json: Vec<u8>,
    pub program_b64: Vec<u8>,
    pub program_runtime: Vec<u8>,
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
    pub max_output_bytes: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTest {
    pub executor_root: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub profile: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub cache_key: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub entries: i64,
    pub bytes: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Executed {
    pub output_json: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub trace_root: Vec<u8>,
    pub steps: i64,
    pub operations: i64,
    pub effort_used: i64,
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn named(reason: &[u8], name: &[u8]) -> Error {
    refused(
        &[
            b"resource compute provider ".as_slice(),
            reason,
            b": ",
            name,
        ]
        .concat(),
    )
}
fn ascii(raw: &[u8], max: usize) -> bool {
    !raw.is_empty() && raw.len() <= max && raw.is_ascii()
}
fn hash(name: &[u8], raw: &[u8]) -> Result<()> {
    if raw.len() == 64
        && raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        Ok(())
    } else {
        Err(named(b"hash refused", name))
    }
}
fn address(name: &[u8], raw: &[u8]) -> Result<()> {
    if is_valid_address(raw) {
        Ok(())
    } else {
        Err(named(b"address refused", name))
    }
}
struct Fields<'a> {
    doc: &'a Document,
    value: &'a Value,
}
impl<'a> Fields<'a> {
    fn at(doc: &'a Document, value: &'a Value, names: &[&[u8]], reason: &[u8]) -> Result<Self> {
        let Value::Object(fields) = value else {
            return Err(refused(reason));
        };
        let mut keys = fields
            .iter()
            .map(|(name, _)| name.as_slice())
            .collect::<Vec<_>>();
        let mut names = names.to_vec();
        keys.sort();
        names.sort();
        if keys != names {
            return Err(refused(reason));
        }
        Ok(Self { doc, value })
    }
    fn new(doc: &'a Document, names: &[&[u8]]) -> Result<Self> {
        Self::at(
            doc,
            doc.root(),
            names,
            b"resource compute provider fields differ",
        )
    }
    fn field(&self, name: &[u8]) -> Result<&'a Value> {
        self.doc
            .field(self.value, name)
            .ok_or_else(|| named(b"field missing", name))
    }
    fn text(&self, name: &[u8]) -> Result<Vec<u8>> {
        match self.field(name)? {
            Value::String(value) => Ok(value.clone()),
            _ => Err(named(b"string required", name)),
        }
    }
    fn int(&self, name: &[u8]) -> Result<i64> {
        match self.field(name)? {
            Value::Int(value) => Ok(value.get()),
            _ => Err(named(b"integer required", name)),
        }
    }
    fn int64(&self, name: &[u8]) -> Result<i64> {
        match self.field(name)? {
            Value::String(raw) => parse_int64(raw).ok_or_else(|| named(b"int64 required", name)),
            _ => Err(named(b"int64 required", name)),
        }
    }
}
impl Prepare {
    pub fn from_json(doc: &Document) -> Result<Self> {
        let fields = Fields::new(
            doc,
            &[
                b"circle_id",
                b"executor_root",
                b"graph_root",
                b"model_epoch",
                b"model_root",
                b"model_state_root",
                b"program_root",
            ],
        )?;
        let model_epoch = fields.int64(b"model_epoch")?;
        let model_state_root = fields.text(b"model_state_root")?;
        let circle_id = fields.text(b"circle_id")?;
        let graph_root = fields.text(b"graph_root")?;
        let model_root = fields.text(b"model_root")?;
        let program_root = fields.text(b"program_root")?;
        let executor_root = fields.text(b"executor_root")?;
        hash(b"model_state_root", &model_state_root)?;
        address(b"circle_id", &circle_id)?;
        hash(b"graph_root", &graph_root)?;
        hash(b"model_root", &model_root)?;
        hash(b"program_root", &program_root)?;
        hash(b"executor_root", &executor_root)?;
        if model_epoch < 0 {
            return Err(refused(b"resource compute provider model epoch refused"));
        }
        Ok(Self {
            model_epoch,
            model_state_root,
            circle_id,
            graph_root,
            model_root,
            program_root,
            executor_root,
        })
    }
}
fn storage_entry(fields: &Fields<'_>, value: &Value) -> Result<(Vec<u8>, Vec<u8>)> {
    let fields = Fields::at(
        fields.doc,
        value,
        &[b"key", b"value_b64"],
        b"resource compute provider storage entry differs",
    )?;
    let key = fields.text(b"key")?;
    let encoded = fields.text(b"value_b64")?;
    if !ascii(&key, MAX_STORAGE_KEY) {
        return Err(refused(b"resource compute provider storage key refused"));
    }
    let value = decode_base64(&encoded)
        .map_err(|_| refused(b"resource compute provider storage base64 refused"))?;
    if value.len() > MAX_STORAGE_VALUE {
        return Err(refused(
            b"resource compute provider storage value exceeds limit",
        ));
    }
    Ok((key, value))
}
fn storage(fields: &Fields<'_>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let Value::List(values) = fields.field(b"storage")? else {
        return Err(refused(b"resource compute provider storage list required"));
    };
    if values.len() > MAX_STORAGE_ENTRIES {
        return Err(refused(
            b"resource compute provider storage entries exceed limit",
        ));
    }
    let mut bytes = 0_usize;
    let mut keys = BTreeSet::new();
    let mut entries = Vec::new();
    for id in values {
        let (key, value) = storage_entry(fields, fields.doc.get(*id).expect("JSON arena child"))?;
        bytes += key.len() + value.len();
        if bytes > MAX_STORAGE_BYTES {
            return Err(refused(b"resource compute provider storage exceeds limit"));
        }
        if !keys.insert(key.clone()) {
            return Err(refused(b"resource compute provider storage key duplicated"));
        }
        entries.push((key, value));
    }
    Ok(entries)
}
fn valid_json(raw: &[u8], list: bool) -> Result<bool> {
    match Document::parse_native(raw, ReadMode::Safe) {
        Ok(doc) => Ok(!list || matches!(doc.root(), Value::List(_))),
        Err(ReadError::Json { .. }) => Ok(false),
        Err(ReadError::Unavailable(error)) => {
            Err(Error::Unavailable(error.to_string().into_bytes()))
        }
    }
}
impl Execute {
    pub fn from_json(doc: &Document) -> Result<Self> {
        let fields = Fields::new(
            doc,
            &[
                b"memory_bytes",
                b"guest_bytes",
                b"fuel_limit",
                b"caller",
                b"circle_id",
                b"epoch_id",
                b"executor_root",
                b"graph_root",
                b"max_output_bytes",
                b"method_name",
                b"model_epoch",
                b"model_root",
                b"model_state_root",
                b"params_json",
                b"program_b64",
                b"program_root",
                b"program_runtime",
                b"request_id",
                b"session_id",
                b"state_root",
                b"storage",
            ],
        )?;
        let memory_bytes = fields.int(b"memory_bytes")?;
        let guest_bytes = fields.int(b"guest_bytes")?;
        let fuel_limit = fields.int(b"fuel_limit")?;
        let request_id = fields.text(b"request_id")?;
        let session_id = fields.text(b"session_id")?;
        let epoch_id = fields.int64(b"epoch_id")?;
        let state_root = fields.text(b"state_root")?;
        let model_epoch = fields.int64(b"model_epoch")?;
        let model_state_root = fields.text(b"model_state_root")?;
        let circle_id = fields.text(b"circle_id")?;
        let graph_root = fields.text(b"graph_root")?;
        let model_root = fields.text(b"model_root")?;
        let program_root = fields.text(b"program_root")?;
        let executor_root = fields.text(b"executor_root")?;
        let caller = fields.text(b"caller")?;
        let method_name = fields.text(b"method_name")?;
        let params_json = fields.text(b"params_json")?;
        let program_b64 = fields.text(b"program_b64")?;
        let program_runtime = fields.text(b"program_runtime")?;
        let storage = storage(&fields)?;
        let max_output_bytes = fields.int(b"max_output_bytes")?;
        for (name, value) in [
            (b"request_id".as_slice(), &request_id),
            (b"session_id", &session_id),
            (b"state_root", &state_root),
            (b"model_state_root", &model_state_root),
        ] {
            hash(name, value)?;
        }
        address(b"circle_id", &circle_id)?;
        for (name, value) in [
            (b"graph_root".as_slice(), &graph_root),
            (b"model_root", &model_root),
            (b"program_root", &program_root),
            (b"executor_root", &executor_root),
        ] {
            hash(name, value)?;
        }
        address(b"caller", &caller)?;
        if memory_bytes <= 0 || memory_bytes > MAX_MEMORY {
            return Err(refused(b"resource compute provider memory refused"));
        }
        if !(65_536..=67_108_864).contains(&guest_bytes) || guest_bytes % 65_536 != 0 {
            return Err(refused(b"resource compute provider pages refused"));
        }
        if !(1..=2_000_000_000).contains(&fuel_limit) {
            return Err(refused(b"resource compute provider fuel refused"));
        }
        if epoch_id < 0 || model_epoch < 0 {
            return Err(refused(b"resource compute provider epoch refused"));
        }
        if !ascii(&method_name, 64) {
            return Err(refused(b"resource compute provider method refused"));
        }
        if params_json.len() > MAX_PARAMS || !valid_json(&params_json, true)? {
            return Err(refused(b"resource compute provider params refused"));
        }
        if !decode_base64(&program_b64)
            .is_ok_and(|code| !code.is_empty() && code.len() <= MAX_PROGRAM)
        {
            return Err(refused(b"resource compute provider program refused"));
        }
        if program_runtime != b"wasm_v1" {
            return Err(refused(b"resource compute provider runtime refused"));
        }
        if max_output_bytes <= 0 || max_output_bytes > MAX_OUTPUT as i64 {
            return Err(refused(b"resource compute provider output limit refused"));
        }
        Ok(Self {
            memory_bytes,
            guest_bytes,
            fuel_limit,
            request_id,
            session_id,
            epoch_id,
            state_root,
            model_epoch,
            model_state_root,
            circle_id,
            graph_root,
            model_root,
            program_root,
            executor_root,
            caller,
            method_name,
            params_json,
            program_b64,
            program_runtime,
            storage,
            max_output_bytes,
        })
    }
}
impl SelfTest {
    pub fn from_json(doc: &Document) -> Result<Self> {
        let fields = Fields::new(doc, &[b"evidence_root", b"executor_root", b"profile"])?;
        let evidence_root = fields.text(b"evidence_root")?;
        let executor_root = fields.text(b"executor_root")?;
        let profile = fields.text(b"profile")?;
        hash(b"evidence_root", &evidence_root)?;
        hash(b"executor_root", &executor_root)?;
        if !ascii(&profile, 32) {
            return Err(refused(b"resource compute provider profile refused"));
        }
        Ok(Self {
            executor_root,
            evidence_root,
            profile,
        })
    }
}
impl Prepared {
    pub fn from_json(doc: &Document) -> Result<Self> {
        let fields = Fields::new(
            doc,
            &[
                b"bytes",
                b"cache_key",
                b"entries",
                b"executor_root",
                b"graph_root",
                b"model_root",
                b"program_root",
            ],
        )?;
        let bytes = fields.int64(b"bytes")?;
        let cache_key = fields.text(b"cache_key")?;
        let entries = fields.int(b"entries")?;
        let executor_root = fields.text(b"executor_root")?;
        let graph_root = fields.text(b"graph_root")?;
        let model_root = fields.text(b"model_root")?;
        let program_root = fields.text(b"program_root")?;
        for (name, value) in [
            (b"cache_key".as_slice(), &cache_key),
            (b"executor_root", &executor_root),
            (b"graph_root", &graph_root),
            (b"model_root", &model_root),
            (b"program_root", &program_root),
        ] {
            hash(name, value)?;
        }
        if entries <= 0 || bytes <= 0 {
            return Err(refused(
                b"resource compute provider cache dimensions refused",
            ));
        }
        Ok(Self {
            cache_key,
            graph_root,
            model_root,
            program_root,
            executor_root,
            entries,
            bytes,
        })
    }
}
impl Executed {
    pub fn from_json(doc: &Document) -> Result<Self> {
        let fields = Fields::new(
            doc,
            &[
                b"effort_used",
                b"operations",
                b"output_hash",
                b"output_json",
                b"steps",
                b"trace_root",
            ],
        )?;
        let effort_used = fields.int(b"effort_used")?;
        let operations = fields.int64(b"operations")?;
        let output_hash = fields.text(b"output_hash")?;
        let output_json = fields.text(b"output_json")?;
        let steps = fields.int64(b"steps")?;
        let trace_root = fields.text(b"trace_root")?;
        hash(b"output_hash", &output_hash)?;
        hash(b"trace_root", &trace_root)?;
        if effort_used < 0 || steps < 0 || operations < 0 {
            return Err(refused(b"resource compute provider counters refused"));
        }
        if output_json.len() > MAX_OUTPUT {
            return Err(refused(b"resource compute provider output exceeds limit"));
        }
        if !valid_json(&output_json, false)? {
            return Err(refused(b"resource compute provider output JSON refused"));
        }
        Ok(Self {
            output_json,
            output_hash,
            trace_root,
            steps,
            operations,
            effort_used,
        })
    }
}
