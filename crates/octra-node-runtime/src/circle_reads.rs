// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Snapshot-bound public reads with the native visibility, range and effort rules.
use crate::{circle_store, state_batch::Snapshot};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_wasm::public_read::{self as rules, Declaration},
    circles::{self, AssetMeta, AssetPolicy, Error, LocatorMode, MetadataMode, ResourceMode},
    transaction::{decode_base64, json_string},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRead {
    pub root: String,
    pub circle: Vec<u8>,
    pub path: String,
    pub offset: i64,
    pub max_bytes: i64,
    pub metadata: Vec<u8>,
    pub body: Vec<u8>,
}
impl PublicRead {
    pub fn native_json(&self) -> Vec<u8> {
        let mut out = b"{\"snapshot_root\":".to_vec();
        json_string(&mut out, self.root.as_bytes());
        for (key, bytes) in [
            (b"circle_id".as_slice(), self.circle.as_slice()),
            (b"canonical_path", self.path.as_bytes()),
        ] {
            out.push(b',');
            json_string(&mut out, key);
            out.push(b':');
            json_string(&mut out, bytes);
        }
        out.extend_from_slice(
            format!(
                ",\"offset\":{},\"max_bytes\":{},\"metadata_json\":",
                self.offset, self.max_bytes
            )
            .as_bytes(),
        );
        json_string(&mut out, &self.metadata);
        out.extend_from_slice(b",\"body_b64\":");
        json_string(&mut out, STANDARD.encode(&self.body).as_bytes());
        out.push(b'}');
        out
    }
    /// Native engine inputs require valid UTF-8 for these string fields.
    pub fn engine_json(&self) -> Result<Value, Error> {
        serde_json::from_slice(&self.native_json())
            .map_err(|_| Error(b"public read contains non-UTF-8 engine input".to_vec()))
    }
}

pub fn policy(state: &Snapshot, circle: &[u8], key: &[u8]) -> Result<AssetPolicy, Error> {
    let read = |suffix: &[u8]| -> Result<Option<Vec<u8>>, Error> {
        for prefix in [b"slot_policy:".as_slice(), b"mailbox:"] {
            let name = [prefix, key, b":", suffix].concat();
            if let Some(value) = circle_store::inline(state, circle, &name)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    };
    Ok(AssetPolicy {
        activate_after_epoch: read(b"activate_after_epoch")?
            .as_deref()
            .and_then(circles::policy_integer),
        expire_after_epoch: read(b"expire_after_epoch")?
            .as_deref()
            .and_then(circles::policy_integer),
        tombstone: read(b"tombstone")?
            .as_deref()
            .is_some_and(circles::policy_bool),
        revoked: read(b"revoked")?
            .as_deref()
            .is_some_and(circles::policy_bool),
    })
}
fn metadata(
    root: &str,
    info: &circle_store::Info,
    meta: &AssetMeta,
    offset: i64,
    returned: usize,
) -> Vec<u8> {
    let version = info.version.to_string();
    let size = meta.size_bytes.to_string();
    let mut out = vec![b'{'];
    for (i, (name, value)) in [
        (b"version".as_slice(), b"circle_public_read_v1".as_slice()),
        (b"snapshot_root", root.as_bytes()),
        (b"circle_id", &info.circle_id),
        (b"circle_version", version.as_bytes()),
        (b"assets_root", &info.assets_root),
        (b"canonical_path", &meta.canonical_path),
        (b"content_type", &meta.content_type),
        (b"encoding", &meta.encoding),
        (b"size_bytes", size.as_bytes()),
        (b"blob_hash", &meta.blob_hash),
    ]
    .into_iter()
    .enumerate()
    {
        if i != 0 {
            out.push(b',');
        }
        json_string(&mut out, name);
        out.push(b':');
        json_string(&mut out, value);
    }
    out.extend_from_slice(
        format!(",\"offset\":{offset},\"returned_bytes\":{returned}}}").as_bytes(),
    );
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub reads: Vec<PublicRead>,
    pub effort: i64,
}

/// `budget` is the remaining view effort. On failure accepted charges are still
/// counted in `spent`, matching the native host's receipt accounting.
pub fn load(
    state: &Snapshot,
    epoch: i64,
    declarations: &[Declaration],
    budget: Option<i64>,
    spent: &mut i64,
) -> Result<Bundle, Error> {
    load_at(state, epoch, declarations, budget, spent, None)
}

/// Captured RPC reads bind to the folded root. Update execution without a
/// captured RPC snapshot retains the native current-batch ledger-root binding.
pub(crate) fn load_at(
    state: &Snapshot,
    epoch: i64,
    declarations: &[Declaration],
    budget: Option<i64>,
    spent: &mut i64,
    snapshot_root: Option<&[u8]>,
) -> Result<Bundle, Error> {
    *spent = 0;
    if declarations.is_empty() {
        return Ok(Bundle {
            reads: vec![],
            effort: 0,
        });
    }
    let mut charge = |cost: i64| {
        if let Some(limit) = budget {
            if cost < 0 || cost > limit - *spent {
                return false;
            }
            *spent += cost;
        }
        true
    };
    let fail = |reason: &str| Error(reason.as_bytes().to_vec());
    if !charge(rules::BASE_EFFORT) {
        return Err(fail("wasm public read effort exceeds limit"));
    }
    let batch_root;
    let root = if let Some(root) = snapshot_root {
        root
    } else {
        batch_root = hex::encode(
            state
                .root()
                .map_err(|_| fail("wasm public read snapshot root is unavailable"))?,
        );
        batch_root.as_bytes()
    };
    let root = circles::domain_hash(b"circle_public_read_snapshot_v1", &[root]);
    if declarations.len() > rules::MAX_READS
        || rules::unique_assets(declarations) > rules::MAX_ASSETS
    {
        return Err(fail("wasm public read set exceeds limit"));
    }
    let mut reads = Vec::new();
    let mut total = 0;
    for declaration in declarations {
        let info = circle_store::info(state, &declaration.circle)?
            .ok_or_else(|| fail("wasm public read circle not found"))?;
        if info.privacy != b"public" || info.resource != b"public_resources" {
            return Err(fail("wasm public read requires a public circle"));
        }
        let get = |field: &[u8]| {
            state.get(&[
                b"circles",
                &declaration.circle,
                b"assets",
                b"by_hash",
                declaration.path_key.as_bytes(),
                field,
            ])
        };
        let meta = match get(b"meta").map(AssetMeta::parse) {
            Some(Ok(meta)) => Some(meta),
            Some(Err(e))
                if e.0 == b"circle asset metadata JSON refused"
                    || e.0 == b"circle asset metadata integer refused" =>
            {
                return Err(e)
            }
            _ => None,
        };
        let meta = meta.ok_or_else(|| fail("wasm public read asset not found"))?;
        if meta.body_mode != ResourceMode::Public
            || meta.locator_mode != LocatorMode::Path
            || meta.metadata_mode != MetadataMode::Reveal
            || meta.key_id.is_some()
            || meta.canonical_path != declaration.path.as_bytes()
        {
            return Err(fail("wasm public read asset is not public"));
        }
        let size_ok = meta.size_bytes >= 0 && meta.size_bytes <= rules::MAX_SOURCE as i64;
        if budget.is_some() && (!size_ok || !charge(meta.size_bytes * rules::BYTE_EFFORT)) {
            return Err(fail("wasm public read effort exceeds limit"));
        }
        if !policy(state, &declaration.circle, declaration.path_key.as_bytes())?
            .visible_at(epoch, &meta)
        {
            return Err(fail("wasm public read asset is not visible"));
        }
        let encoded = get(b"body_b64").ok_or_else(|| fail("wasm public read body not found"))?;
        if budget.is_some() && encoded.len() > (meta.size_bytes as usize).div_ceil(3) * 4 {
            return Err(fail("wasm public read body size invalid"));
        }
        let raw = decode_base64(encoded).map_err(|_| fail("invalid wasm public read body"))?;
        if raw.len() > rules::MAX_SOURCE
            || meta.size_bytes != raw.len() as i64
            || meta.blob_hash != hex::encode(Sha256::digest(&raw)).as_bytes()
        {
            return Err(fail("wasm public read body binding mismatch"));
        }
        let offset = usize::try_from(declaration.offset)
            .map_err(|_| fail("invalid wasm public read body"))?;
        if offset > raw.len() {
            return Err(fail("wasm public read offset exceeds body"));
        }
        let len = usize::try_from(declaration.max_bytes)
            .map_err(|_| fail("invalid wasm public read body"))?
            .min(raw.len() - offset);
        let body = raw[offset..offset + len].to_vec();
        total += len;
        if total > rules::MAX_TOTAL {
            return Err(fail("wasm public read bytes exceed limit"));
        }
        reads.push(PublicRead {
            root: root.clone(),
            circle: declaration.circle.clone(),
            path: declaration.path.clone(),
            offset: declaration.offset,
            max_bytes: declaration.max_bytes,
            metadata: metadata(&root, &info, &meta, declaration.offset, len),
            body,
        });
    }
    Ok(Bundle {
        reads,
        effort: budget.map_or(
            rules::BASE_EFFORT + total as i64 * rules::BYTE_EFFORT,
            |_| *spent,
        ),
    })
}

pub fn engine_reads(bundle: &Bundle) -> Result<Value, Error> {
    Ok(json!(bundle
        .reads
        .iter()
        .map(PublicRead::engine_json)
        .collect::<Result<Vec<_>, _>>()?))
}
