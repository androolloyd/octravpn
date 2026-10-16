// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native public tensor graph admission and deterministic model cache plans.
//! A validated graph describes content; it does not authenticate a state root.
mod parse;
mod view;
use super::{Error, Result};
use crate::native_json::{self, Document, ReadError, ReadMode, Value};
use sha2::{Digest, Sha256};
pub use view::{cache_key, CacheEntry, CachePlan, CacheSource};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_graph_bytes: usize,
    pub max_shards: usize,
    pub max_segments: usize,
    pub max_chunks: usize,
    pub max_tensors: usize,
    pub max_segment_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_shard_bytes: usize,
    pub max_model_bytes: i64,
    pub max_cache_entries: usize,
    pub max_cache_bytes: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_graph_bytes: 2 * 1024 * 1024,
            max_shards: 64,
            max_segments: 1024,
            max_chunks: 2048,
            max_tensors: 1024,
            max_segment_bytes: 4 * 1024 * 1024,
            max_chunk_bytes: 8 * 1024 * 1024,
            max_shard_bytes: 32 * 1024 * 1024,
            max_model_bytes: 536_870_912,
            max_cache_entries: 1024,
            max_cache_bytes: 536_870_912,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub index: usize,
    pub offset: usize,
    pub bytes: usize,
    pub path: Vec<u8>,
    pub sha256: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub index: usize,
    pub bytes: usize,
    pub sha256: Vec<u8>,
    pub source: Vec<u8>,
    pub stream_offset: i64,
    pub tensor: Vec<u8>,
    pub tensor_chunk: usize,
    pub shard: usize,
    pub shard_offset: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard {
    pub index: usize,
    pub circle_id: Vec<u8>,
    pub bytes: usize,
    pub sha256: Vec<u8>,
    pub stream_offset: i64,
    pub chunk_indices: Vec<usize>,
    pub segments: Vec<Segment>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tensor {
    pub name: Vec<u8>,
    pub source_name: Vec<u8>,
    pub scale_bits: i64,
    pub shape: Vec<usize>,
    pub chunks: Vec<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub id: Vec<u8>,
    pub root_domain: Vec<u8>,
    pub root: Vec<u8>,
    pub raw_bytes: i64,
    pub chunks: usize,
    pub tensors: Vec<Tensor>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    format: Vec<u8>,
    root_circle_id: Vec<u8>,
    graph_root: Vec<u8>,
    layout_root: Vec<u8>,
    model: Model,
    chunks: Vec<Chunk>,
    shards: Vec<Shard>,
}
impl Graph {
    pub fn format(&self) -> &[u8] {
        &self.format
    }
    pub fn root_circle_id(&self) -> &[u8] {
        &self.root_circle_id
    }
    pub fn graph_root(&self) -> &[u8] {
        &self.graph_root
    }
    pub fn layout_root(&self) -> &[u8] {
        &self.layout_root
    }
    pub fn model(&self) -> &Model {
        &self.model
    }
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }
    pub fn shards(&self) -> &[Shard] {
        &self.shards
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn unavailable(error: native_json::Error) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
pub fn stable_json(raw: &[u8]) -> Result<Vec<u8>> {
    let doc = read(raw)?;
    doc.write(doc.root(), true).map_err(unavailable)
}
fn read(raw: &[u8]) -> Result<Document> {
    Document::parse_native(raw, ReadMode::Plain).map_err(|error| match error {
        ReadError::Json { .. } => refused(b"resource graph JSON refused"),
        ReadError::Unavailable(error) => unavailable(error),
    })
}
fn ascii_fits(raw: &[u8], maximum: usize) -> bool {
    !raw.is_empty() && raw.len() <= maximum && raw.is_ascii()
}
fn lower_hex(raw: &[u8]) -> bool {
    raw.len() == 64
        && raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn digest(raw: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(raw)).into_bytes()
}
fn digest_json(domain: &[u8], stable: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(stable);
    hex::encode(hash.finalize()).into_bytes()
}
fn domains(format: &[u8]) -> Result<[&'static [u8]; 3]> {
    match format {
        b"octra-smollm-resource-graph" => Ok([
            b"octra:smollm360_resource_layout",
            b"octra:smollm360_resource_graph",
            b"octra:smollm360_resource_shard",
        ]),
        b"octra-resource-tensor-graph-v1" => Ok([
            b"octra:resource_tensor_layout:v1",
            b"octra:resource_tensor_graph:v1",
            b"octra:resource_tensor_shard:v1",
        ]),
        _ => Err(refused(b"resource graph format refused")),
    }
}
fn string(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::transaction::json_string(&mut out, raw);
    out
}
fn number(value: impl std::fmt::Display) -> Vec<u8> {
    value.to_string().into_bytes()
}
fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut out = vec![b'['];
    for (index, raw) in values.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&raw);
    }
    out.push(b']');
    out
}
// All supplied values are already encoded by Json_tree.write or these helpers.
fn object(mut fields: Vec<(&[u8], Vec<u8>)>) -> Vec<u8> {
    fields.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = vec![b'{'];
    for (index, (key, raw)) in fields.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&string(key));
        out.push(b':');
        out.extend_from_slice(&raw);
    }
    out.push(b'}');
    out
}
