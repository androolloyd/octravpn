// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Content-checked model loading into the adopted native compute cache. A lease
//! owns the loaded cache for replay; the cache never authorizes ledger effects.
use crate::{circle_store, compute_roots::Root, state_batch::Snapshot};
use octra_circle_wasm_host::rust_api::{
    compute_storage_status, ComputeStorageBuilder, ComputeStorageLease, ComputeStorageStatus,
};
use octra_node_protocol::{
    circles, native_json,
    resource_compute::{
        bill,
        graph::{self, CachePlan, CacheSource, Graph, Limits, Shard},
        Error, Result,
    },
    transaction::decode_base64,
};
use sha2::{Digest, Sha256};

pub struct Loaded {
    graph: Graph,
    cache: CachePlan,
    _lease: ComputeStorageLease,
}
#[derive(Clone, Copy)]
pub(crate) struct Source<'a> {
    pub epoch: i64,
    pub state: &'a [u8],
    pub tree: &'a Snapshot,
}
fn active(cancel: &impl Fn() -> Option<Vec<u8>>) -> Result<()> {
    if let Some(reason) = cancel() {
        Err(Error::Unavailable(reason))
    } else {
        Ok(())
    }
}
impl Loaded {
    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn cache(&self) -> &CachePlan {
        &self.cache
    }
}
fn refused(reason: &[u8]) -> Error {
    Error::rejected(reason)
}
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
fn stored(error: circles::Error) -> Error {
    if error.0 == native_json::Error::Allocation.to_string().as_bytes() {
        unavailable(error)
    } else {
        refused(&error.0)
    }
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(unavailable)
}
pub fn limits(memory_bytes: i64) -> Limits {
    let bytes = 536_870_912.min(memory_bytes / 2);
    Limits {
        max_model_bytes: bytes,
        max_cache_bytes: bytes,
        ..Limits::default()
    }
}
pub(crate) fn asset(
    source: &Snapshot,
    circle: &[u8],
    path: &[u8],
    max_bytes: usize,
    content_type: &[u8],
) -> Result<Vec<u8>> {
    let asset = circle_store::public_asset(source, circle, path, max_bytes).map_err(stored)?;
    let size = asset.meta.size_bytes as usize;
    if asset.body_b64.len() > size.div_ceil(3) * 4 {
        return Err(refused(b"circle asset encoded size exceeds limit"));
    }
    let body =
        decode_base64(asset.body_b64).map_err(|_| refused(b"circle asset base64 refused"))?;
    if body.len() != size {
        return Err(refused(b"circle asset size differs"));
    }
    if asset.meta.content_type != content_type {
        return Err(refused(b"circle asset content type differs"));
    }
    if asset.meta.encoding != b"identity" {
        return Err(refused(b"circle asset encoding differs"));
    }
    if asset.browser_mode != b"gateway_allowed" {
        return Err(refused(b"circle asset browser mode differs"));
    }
    if asset.resource_mode != b"public_resources" {
        return Err(refused(b"circle asset resource mode differs"));
    }
    if asset.meta.blob_hash != hex::encode(Sha256::digest(&body)).as_bytes() {
        return Err(refused(b"circle asset body hash differs"));
    }
    Ok(body)
}
fn put(writer: Option<&ComputeStorageBuilder>, key: &[u8], value: &[u8]) -> Result<()> {
    if let Some(writer) = writer {
        writer.put(text(key)?, value).map_err(unavailable)?;
    }
    Ok(())
}
fn push_shard(
    source: &Snapshot,
    graph: &Graph,
    shard: &Shard,
    max_bytes: usize,
    writer: Option<&ComputeStorageBuilder>,
    cancel: &impl Fn() -> Option<Vec<u8>>,
) -> Result<()> {
    active(cancel)?;
    let raw = asset(
        source,
        &shard.circle_id,
        b"/model/shard.json",
        max_bytes,
        b"application/json; charset=utf-8",
    )?;
    let actual = graph::stable_json(&raw).map_err(|error| {
        if error.is_operational() {
            error
        } else {
            refused(b"resource shard manifest JSON refused")
        }
    })?;
    if actual != graph.shard_manifest(shard.index)? {
        return Err(refused(b"resource shard manifest differs"));
    }
    let mut body = Vec::new();
    let mut offset = 0_usize;
    let mut segments = shard.segments.iter();
    let mut hash = Sha256::new();
    let mut fetched = 0_usize;
    for index in &shard.chunk_indices {
        active(cancel)?;
        let chunk = &graph.chunks()[*index];
        let mut value = Vec::new();
        value.try_reserve_exact(chunk.bytes).map_err(unavailable)?;
        while value.len() < chunk.bytes {
            if offset < body.len() {
                let count = (chunk.bytes - value.len()).min(body.len() - offset);
                value.extend_from_slice(&body[offset..offset + count]);
                offset += count;
            } else {
                active(cancel)?;
                let segment = segments
                    .next()
                    .ok_or_else(|| refused(b"resource shard differs"))?;
                body = asset(
                    source,
                    &shard.circle_id,
                    &segment.path,
                    segment.bytes,
                    b"application/octet-stream",
                )?;
                if body.len() != segment.bytes
                    || hex::encode(Sha256::digest(&body)).as_bytes() != segment.sha256
                {
                    return Err(refused(b"resource segment differs"));
                }
                hash.update(&body);
                fetched += body.len();
                offset = 0;
            }
        }
        if hex::encode(Sha256::digest(&value)).as_bytes() != chunk.sha256 {
            return Err(refused(b"resource chunk differs"));
        }
        let key = [
            b"w:".as_slice(),
            &chunk.tensor,
            b":",
            chunk.tensor_chunk.to_string().as_bytes(),
        ]
        .concat();
        put(writer, &key, &value)?;
    }
    if segments.next().is_some()
        || offset != body.len()
        || fetched != shard.bytes
        || hex::encode(hash.finalize()).as_bytes() != shard.sha256
    {
        return Err(refused(b"resource shard differs"));
    }
    Ok(())
}
pub fn load(source: &Root, circle: &[u8], graph_root: &[u8], model_root: &[u8]) -> Result<Loaded> {
    load_at(
        Source {
            epoch: source.epoch(),
            state: source.state(),
            tree: source.tree(),
        },
        circle,
        graph_root,
        model_root,
        &limits(bill::MODEL_LIMIT),
        &|| None,
    )
}
pub(crate) fn load_at(
    source: Source<'_>,
    circle: &[u8],
    graph_root: &[u8],
    model_root: &[u8],
    limits: &Limits,
    cancel: &impl Fn() -> Option<Vec<u8>>,
) -> Result<Loaded> {
    active(cancel)?;
    if source.epoch < 0 {
        return Err(refused(b"resource compute snapshot epoch refused"));
    }
    let raw = asset(
        source.tree,
        circle,
        b"/model/resource-graph.json",
        limits.max_graph_bytes,
        b"application/json; charset=utf-8",
    )?;
    let graph = Graph::parse(limits, circle, &raw)?;
    if graph.graph_root() != graph_root {
        return Err(refused(b"resource compute graph root differs"));
    }
    if graph.model().root != model_root {
        return Err(refused(b"resource compute model root differs"));
    }
    let cache = graph.cache_plan(limits, hex::encode(source.state).as_bytes())?;
    let key = text(&cache.key)?;
    let root = text(&cache.root)?;
    let writer = match compute_storage_status(key).map_err(unavailable)? {
        ComputeStorageStatus::Missing => {
            Some(ComputeStorageBuilder::begin(key).map_err(unavailable)?)
        }
        ComputeStorageStatus::Ready {
            root: ready,
            entries,
            bytes,
        } => {
            if ready.as_bytes() != cache.root
                || entries != cache.entries.len()
                || bytes as i64 != cache.bytes
            {
                return Err(refused(b"resource compute cache identity differs"));
            }
            None
        }
    };
    if writer.is_some() {
        for entry in &cache.entries {
            active(cancel)?;
            if let CacheSource::Inline(value) = &entry.source {
                put(writer.as_ref(), &entry.key, value)?;
            }
        }
    }
    for shard in graph.shards() {
        push_shard(
            source.tree,
            &graph,
            shard,
            limits.max_graph_bytes,
            writer.as_ref(),
            cancel,
        )?;
    }
    if let Some(writer) = writer {
        active(cancel)?;
        writer
            .seal(root, cache.entries.len(), cache.bytes as usize)
            .map_err(unavailable)?;
        writer.close();
    }
    let lease = ComputeStorageLease::hold(key, root, cache.entries.len(), cache.bytes as usize)
        .map_err(unavailable)?;
    Ok(Loaded {
        graph,
        cache,
        _lease: lease,
    })
}
