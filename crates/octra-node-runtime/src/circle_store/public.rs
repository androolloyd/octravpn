// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native minimal snapshot accessors, without full Circle descriptor admission.
use super::{circles, Error, Snapshot, StableEntry, StableValue};

/// Native bounded committed-storage loader. Rows remain in stored-hash order,
/// including duplicate raw keys; malformed rows are refused rather than skipped.
// Preserve the ordered native tuple/borrowed-field projection API.
#[allow(clippy::type_complexity)]
pub fn storage_at(
    state: &Snapshot,
    circle: &[u8],
    max_entries: usize,
    max_bytes: usize,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let path = [b"circles".as_slice(), circle, b"stable", b"by_hash"];
    if state.child_count(&path) > max_entries {
        return Err(Error(b"circle storage entries exceed limit".to_vec()));
    }
    let envelope = StableEntry {
        key: vec![],
        hash: vec![b'0'; 64],
        value: StableValue::Inline(vec![]),
    }
    .encode()
    .len();
    let mut room = max_bytes;
    let mut pairs = Vec::new();
    for name in state.child_names(&path).take(max_entries) {
        let raw = state
            .get(&[b"circles", circle, b"stable", b"by_hash", name])
            .ok_or_else(|| Error(b"circle stable entry missing".to_vec()))?;
        let raw_max = room
            .checked_mul(6)
            .and_then(|v| v.checked_add(envelope))
            .ok_or_else(|| Error(b"circle storage bytes exceed limit".to_vec()))?;
        if raw.len() > raw_max {
            return Err(Error(b"circle storage bytes exceed limit".to_vec()));
        }
        let entry =
            StableEntry::parse(raw).map_err(|_| Error(b"circle stable entry refused".to_vec()))?;
        let StableValue::Inline(value) = entry.value else {
            return Err(Error(
                b"circle stable storage contains non-inline values".to_vec(),
            ));
        };
        if entry.key.len() > room || value.len() > room - entry.key.len() {
            return Err(Error(b"circle storage bytes exceed limit".to_vec()));
        }
        let used = entry.key.len() + value.len();
        if raw.len() > 6 * used + envelope {
            return Err(Error(b"circle stable entry size refused".to_vec()));
        }
        // Canonical memory contents have no untrusted Irmin pack-length field;
        // retained object framing is checked by the canonical snapshot reader.
        room -= used;
        pairs.push((entry.key, value));
    }
    Ok(pairs)
}

pub struct PublicProgram<'a> {
    pub runtime: &'a [u8],
    pub code_hash: &'a [u8],
    pub privacy_class: &'a [u8],
    pub resource_mode: &'a [u8],
    pub code_b64: &'a [u8],
}
pub fn public_program<'a>(state: &'a Snapshot, circle: &[u8]) -> Result<PublicProgram<'a>, Error> {
    let at = |suffix: &[&[u8]]| {
        let mut path = vec![b"circles".as_slice(), circle];
        path.extend_from_slice(suffix);
        state.get(&path)
    };
    let (Some(runtime), Some(code_hash), Some(privacy_class), Some(resource_mode), Some(code_b64)) = (
        at(&[b"runtime"]),
        at(&[b"code_hash"]),
        at(&[b"privacy", b"class"]),
        at(&[b"resources", b"mode"]),
        at(&[b"program", b"code_b64"]),
    ) else {
        return Err(Error(b"circle program snapshot missing".to_vec()));
    };
    Ok(PublicProgram {
        runtime,
        code_hash,
        privacy_class,
        resource_mode,
        code_b64,
    })
}
pub struct PublicAsset<'a> {
    pub canonical_path: Vec<u8>,
    pub path_key: Vec<u8>,
    pub browser_mode: &'a [u8],
    pub resource_mode: &'a [u8],
    pub meta: circles::AssetMeta,
    pub body_b64: &'a [u8],
}
/// Unlike asset_meta(), this accessor returns malformed stored metadata as an
/// ordinary Result refusal, matching Store_irmin.get_circle_public_asset_at.
pub fn public_asset<'a>(
    state: &'a Snapshot,
    circle: &[u8],
    raw_path: &[u8],
    max_bytes: usize,
) -> Result<PublicAsset<'a>, Error> {
    let path = circles::normalize_path(raw_path)?.into_bytes();
    let key = circles::path_key(&path).into_bytes();
    let (Some(browser_mode), Some(resource_mode), Some(raw)) = (
        state.get(&[b"circles", circle, b"browser", b"mode"]),
        state.get(&[b"circles", circle, b"resources", b"mode"]),
        state.get(&[b"circles", circle, b"assets", b"by_hash", &key, b"meta"]),
    ) else {
        return Err(Error(b"circle asset missing".to_vec()));
    };
    let meta = circles::AssetMeta::parse(raw)?;
    if meta.size_bytes < 0 || meta.size_bytes as u64 > max_bytes as u64 {
        return Err(Error(b"circle asset size exceeds limit".to_vec()));
    }
    if meta.path_key != key || meta.canonical_path != path {
        return Err(Error(b"circle asset metadata differs".to_vec()));
    }
    let body_b64 = state
        .get(&[b"circles", circle, b"assets", b"by_hash", &key, b"body_b64"])
        .ok_or_else(|| Error(b"circle asset missing".to_vec()))?;
    Ok(PublicAsset {
        canonical_path: path,
        path_key: key,
        browser_mode,
        resource_mode,
        meta,
        body_b64,
    })
}
