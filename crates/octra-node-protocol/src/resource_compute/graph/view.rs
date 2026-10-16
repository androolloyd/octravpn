use super::{
    array, digest, digest_json, domains, lower_hex, number, object, refused, string, Chunk, Error,
    Graph, Limits, Model, Result, Segment, Shard,
};
use std::collections::BTreeSet;

pub(super) fn model_root(model: &Model, chunks: &[Chunk]) -> Vec<u8> {
    let mut out = model.root_domain.clone();
    for tensor in &model.tensors {
        out.extend_from_slice(&(tensor.name.len() as u16).to_be_bytes());
        out.extend_from_slice(&tensor.name);
        out.extend_from_slice(&tensor.scale_bits.to_be_bytes());
        out.extend_from_slice(&(tensor.chunks.len() as u16).to_be_bytes());
        for (index, id) in tensor.chunks.iter().enumerate() {
            let chunk = &chunks[*id];
            out.extend_from_slice(&(index as u16).to_be_bytes());
            out.extend_from_slice(&(chunk.bytes as u32).to_be_bytes());
            // Native model roots contain the lowercase hexadecimal digest text.
            out.extend_from_slice(&chunk.sha256);
        }
    }
    digest(&out)
}
fn segment_json(segment: &Segment) -> Vec<u8> {
    object(vec![
        (b"bytes", number(segment.bytes)),
        (b"index", number(segment.index)),
        (b"offset", number(segment.offset)),
        (b"path", string(&segment.path)),
        (b"sha256", string(&segment.sha256)),
    ])
}
fn chunk_json(chunk: &Chunk) -> Vec<u8> {
    object(vec![
        (b"bytes", number(chunk.bytes)),
        (b"index", number(chunk.index)),
        (b"sha256", string(&chunk.sha256)),
        (b"shard", number(chunk.shard)),
        (b"shard_offset", number(chunk.shard_offset)),
        (b"source", string(&chunk.source)),
        (b"stream_offset", number(chunk.stream_offset)),
        (b"tensor", string(&chunk.tensor)),
        (b"tensor_chunk", number(chunk.tensor_chunk)),
    ])
}
pub(super) fn shard_json(shard: &Shard, include_circle: bool) -> Vec<u8> {
    let mut fields: Vec<(&[u8], Vec<u8>)> = vec![
        (b"bytes", number(shard.bytes)),
        (
            b"chunk_indices",
            array(shard.chunk_indices.iter().map(number)),
        ),
        (b"index", number(shard.index)),
        (b"segments", array(shard.segments.iter().map(segment_json))),
        (b"sha256", string(&shard.sha256)),
        (b"stream_offset", number(shard.stream_offset)),
    ];
    if include_circle {
        fields.push((b"circle_id", string(&shard.circle_id)));
    }
    object(fields)
}
impl Graph {
    /// Index into this admitted graph, so malformed external shard indices can
    /// never reach model chunk indexing or construct a forged manifest.
    pub fn shard_manifest(&self, index: usize) -> Result<Vec<u8>> {
        let shard = self
            .shards
            .get(index)
            .ok_or_else(|| refused(b"resource shard index refused"))?;
        let [_, _, domain] = domains(&self.format)?;
        let mut fields: Vec<(&[u8], Vec<u8>)> = vec![
            (b"bytes", number(shard.bytes)),
            (
                b"chunks",
                array(
                    shard
                        .chunk_indices
                        .iter()
                        .map(|id| chunk_json(&self.chunks[*id])),
                ),
            ),
            (b"circle_id", string(&shard.circle_id)),
            (b"graph_root", string(&self.graph_root)),
            (b"index", number(shard.index)),
            (b"layout_root", string(&self.layout_root)),
            (b"model_root", string(&self.model.root)),
            (b"segments", array(shard.segments.iter().map(segment_json))),
            (b"sha256", string(&shard.sha256)),
        ];
        let root = digest_json(domain, &object(fields.clone()));
        fields.push((b"shard_root", string(&root)));
        Ok(object(fields))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheSource {
    Inline(Vec<u8>),
    ModelChunk(Chunk),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntry {
    pub key: Vec<u8>,
    pub bytes: usize,
    pub sha256: Vec<u8>,
    pub source: CacheSource,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePlan {
    pub key: Vec<u8>,
    pub root: Vec<u8>,
    pub bytes: i64,
    pub entries: Vec<CacheEntry>,
}
pub fn cache_key(circle_id: &[u8], graph_root: &[u8]) -> Vec<u8> {
    digest(
        &[
            b"octra:resource_compute_model_cache:v2".as_slice(),
            circle_id,
            graph_root,
        ]
        .join(&0),
    )
}
impl Graph {
    pub fn cache_plan(&self, limits: &Limits, state_root: &[u8]) -> Result<CachePlan> {
        if !lower_hex(state_root) {
            return Err(refused(b"resource compute state root refused"));
        }
        let mut entries = Vec::new();
        for tensor in &self.model.tensors {
            for (prefix, value) in [
                (b"meta:scale:".as_slice(), number(tensor.scale_bits)),
                (b"meta:chunks:".as_slice(), number(tensor.chunks.len())),
            ] {
                entries.push(CacheEntry {
                    key: [prefix, &tensor.name].concat(),
                    bytes: value.len(),
                    sha256: digest(&value),
                    source: CacheSource::Inline(value),
                });
            }
        }
        for chunk in &self.chunks {
            entries.push(CacheEntry {
                key: [
                    b"w:".as_slice(),
                    &chunk.tensor,
                    b":",
                    &number(chunk.tensor_chunk),
                ]
                .concat(),
                bytes: chunk.bytes,
                sha256: chunk.sha256.clone(),
                source: CacheSource::ModelChunk(chunk.clone()),
            });
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let bytes = entries
            .iter()
            .fold(0_i64, |sum, e| sum.wrapping_add(e.bytes as i64));
        if entries.len() > limits.max_cache_entries {
            return Err(refused(b"resource compute cache entry limit exceeded"));
        }
        if bytes > limits.max_cache_bytes {
            return Err(refused(b"resource compute cache byte limit exceeded"));
        }
        let mut keys = BTreeSet::new();
        if !entries.iter().all(|e| keys.insert(e.key.as_slice())) {
            return Err(refused(b"resource compute cache keys repeat"));
        }
        let mut out = b"octra:compute_storage_cache:v1\0".to_vec();
        for entry in &entries {
            out.extend_from_slice(&(entry.key.len() as u32).to_be_bytes());
            out.extend_from_slice(&entry.key);
            out.extend_from_slice(&(entry.bytes as i64).to_be_bytes());
            // Admitted chunk hashes and locally computed inline hashes are hex64.
            let raw = hex::decode(&entry.sha256)
                .map_err(|error| Error::Unavailable(error.to_string().into_bytes()))?;
            out.extend_from_slice(&raw);
        }
        Ok(CachePlan {
            key: cache_key(&self.root_circle_id, &self.graph_root),
            root: digest(&out),
            bytes,
            entries,
        })
    }
}
