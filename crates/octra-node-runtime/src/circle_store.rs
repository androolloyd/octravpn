// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle records read from one immutable state tree.
use crate::state_batch::{Snapshot, StateBatch};
use num_bigint::BigInt;
use octra_node_protocol::{
    circle_storage::StorageTable,
    circle_wasm::receipt::Storage,
    circles::{self, Error},
    native_integer::parse_int64,
    native_json::{Document, Value},
    transaction::json_string,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub circle_id: Vec<u8>,
    pub runtime: Vec<u8>,
    pub version: i64,
    pub owner: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub stable_root: Vec<u8>,
    pub assets_root: Vec<u8>,
    pub privacy: Vec<u8>,
    pub browser: Vec<u8>,
    pub resource: Vec<u8>,
    pub policy_hash: Option<Vec<u8>>,
    pub members_root: Option<Vec<u8>>,
    pub export_policy: Option<Vec<u8>>,
    pub limits: [i64; 4],
}
pub const LIMIT_NAMES: [&[u8]; 4] = [
    b"max_stable_bytes",
    b"max_assets_bytes",
    b"max_inline_value",
    b"max_wasm_bytes",
];

/// Missing fields or unknown enums mean no Circle, as in Store_irmin.
/// Corrupt integer encodings are an operational error, not a default value.
pub fn info(state: &Snapshot, circle: &[u8]) -> Result<Option<Info>, Error> {
    let get = |suffix: &[&[u8]]| {
        let mut path = vec![b"circles".as_slice(), circle];
        path.extend_from_slice(suffix);
        state.get(&path)
    };
    let fields: [&[&[u8]]; 13] = [
        &[b"runtime"],
        &[b"version"],
        &[b"owner"],
        &[b"code_hash"],
        &[b"stable_root"],
        &[b"assets_root"],
        &[b"privacy", b"class"],
        &[b"browser", b"mode"],
        &[b"resources", b"mode"],
        &[b"limits", LIMIT_NAMES[0]],
        &[b"limits", LIMIT_NAMES[1]],
        &[b"limits", LIMIT_NAMES[2]],
        &[b"limits", LIMIT_NAMES[3]],
    ];
    let Some(v) = fields.iter().map(|p| get(p)).collect::<Option<Vec<_>>>() else {
        return Ok(None);
    };
    if !matches!(v[0], b"octb" | b"wasm_v1")
        || !matches!(v[6], b"public" | b"scoped" | b"sealed" | b"circle")
        || !matches!(v[7], b"gateway_allowed" | b"native_sealed")
        || !matches!(v[8], b"public_resources" | b"sealed_read")
    {
        return Ok(None);
    }
    let number =
        |i: usize| parse_int64(v[i]).ok_or_else(|| Error(b"circle info integer refused".to_vec()));
    Ok(Some(Info {
        circle_id: circle.to_vec(),
        runtime: v[0].to_vec(),
        version: number(1)?,
        owner: v[2].to_vec(),
        code_hash: v[3].to_vec(),
        stable_root: v[4].to_vec(),
        assets_root: v[5].to_vec(),
        privacy: v[6].to_vec(),
        browser: v[7].to_vec(),
        resource: v[8].to_vec(),
        policy_hash: get(&[b"privacy", b"policy_hash"]).map(<[u8]>::to_vec),
        members_root: get(&[b"privacy", b"members_root"]).map(<[u8]>::to_vec),
        export_policy: get(&[b"privacy", b"export_policy"]).map(<[u8]>::to_vec),
        limits: [number(9)?, number(10)?, number(11)?, number(12)?],
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StableValue {
    Inline(Vec<u8>),
    Blob { hash: Vec<u8>, size: i64 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableEntry {
    pub key: Vec<u8>,
    pub hash: Vec<u8>,
    pub value: StableValue,
}

impl StableEntry {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(raw)
            .map_err(|_| Error(b"circle stable entry JSON refused".to_vec()))?;
        let root = doc.root();
        if !matches!(root, Value::Object(_)) {
            return Err(Error(b"stable entry must be a json object".to_vec()));
        }
        let string = |object, name: &[u8]| match doc.field(object, name) {
            Some(Value::String(v)) => Some(v.clone()),
            _ => None,
        };
        let key = string(root, b"raw_key")
            .ok_or_else(|| Error(b"missing stable entry field: raw_key".to_vec()))?;
        let hash = string(root, b"key_hash")
            .ok_or_else(|| Error(b"missing stable entry field: key_hash".to_vec()))?;
        let value = doc
            .field(root, b"value")
            .ok_or_else(|| Error(b"missing stable value object".to_vec()))?;
        if !matches!(value, Value::Object(_)) {
            return Err(Error(b"stable value must be a json object".to_vec()));
        }
        let value = match string(value, b"value_kind").as_deref() {
            Some(b"inline") => StableValue::Inline(
                string(value, b"value_inline")
                    .ok_or_else(|| Error(b"missing stable inline value".to_vec()))?,
            ),
            Some(b"blob_ref") => {
                let (Some(hash), Some(size)) = (
                    string(value, b"value_blob_hash"),
                    string(value, b"value_size"),
                ) else {
                    return Err(Error(b"missing stable blob ref fields".to_vec()));
                };
                StableValue::Blob {
                    hash,
                    size: parse_int64(&size)
                        .ok_or_else(|| Error(b"circle stable entry integer refused".to_vec()))?,
                }
            }
            Some(other) => return Err(Error([b"unknown stable value kind: ", other].concat())),
            None => return Err(Error(b"missing stable value kind".to_vec())),
        };
        Ok(Self { key, hash, value })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"{\"raw_key\":".to_vec();
        json_string(&mut out, &self.key);
        out.extend_from_slice(b",\"key_hash\":");
        json_string(&mut out, &self.hash);
        match &self.value {
            StableValue::Inline(value) => {
                out.extend_from_slice(b",\"value\":{\"value_kind\":\"inline\",\"value_inline\":");
                json_string(&mut out, value);
            }
            StableValue::Blob { hash, size } => {
                out.extend_from_slice(
                    b",\"value\":{\"value_kind\":\"blob_ref\",\"value_blob_hash\":",
                );
                json_string(&mut out, hash);
                out.extend_from_slice(b",\"value_size\":");
                json_string(&mut out, size.to_string().as_bytes());
            }
        }
        out.extend_from_slice(b"}}");
        out
    }
}

/// The uncharged native view loader skips rejected entries and refuses any
/// valid blob reference. Duplicate raw keys follow sorted stored-hash order.
pub fn storage(state: &Snapshot, circle: &[u8]) -> Result<Storage, Error> {
    Ok(load_storage(state, circle, None)?.values().clone())
}

/// Native execution loader. Charged reads reject malformed entry shapes, while
/// historical uncharged reads skip them. Operational decode failures propagate.
pub fn load_storage(
    state: &Snapshot,
    circle: &[u8],
    mut charge: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<StorageTable, Error> {
    let priced = charge.is_some();
    let mut out = StorageTable::new(if priced { 0 } else { 100 });
    let read_error = || Error(b"circle storage read effort exceeds limit".to_vec());
    if let Some(charge) = charge.as_mut() {
        let path = [b"circles".as_slice(), circle, b"stable", b"by_hash"];
        if state.contains_tree(&path) {
            let count = state.child_count(&path);
            if !charge(count.checked_mul(16).ok_or_else(read_error)?) {
                return Err(read_error());
            }
        }
    }
    let mut inline_only = true;
    let path = [b"circles".as_slice(), circle, b"stable", b"by_hash"];
    // Irmin's charged fold invokes contents on a contents-valued root too;
    // the legacy Tree.list path sees no children there.
    let root = if priced { state.get(&path) } else { None };
    for raw in root
        .into_iter()
        .chain(state.entries(&path).map(|(_, raw)| raw))
    {
        if let Some(charge) = charge.as_mut() {
            if !charge(raw.len().div_ceil(16)) {
                return Err(read_error());
            }
        }
        let entry = match StableEntry::parse(raw) {
            Ok(entry) => entry,
            Err(e)
                if priced
                    || e.0 == b"circle stable entry integer refused"
                    || e.0 == b"circle stable entry JSON refused" =>
            {
                return Err(e)
            }
            Err(_) => continue,
        };
        match entry.value {
            StableValue::Inline(value) => {
                out.replace(entry.key, value);
            }
            StableValue::Blob { .. } => {
                inline_only = false;
                if priced {
                    break;
                }
            }
        }
    }
    if inline_only {
        Ok(out)
    } else {
        Err(Error(
            b"circle stable storage contains non-inline values".to_vec(),
        ))
    }
}

pub fn validate_storage_limits(
    storage: &StorageTable,
    max_stable: i64,
    max_inline: i64,
) -> Result<i64, Error> {
    let mut total = 0i64;
    for (key, value) in storage.values() {
        total = total
            .wrapping_add(key.len() as i64)
            .wrapping_add(value.len() as i64);
    }
    for key in storage.keys() {
        let size = storage.values()[key].len() as i64;
        if size > max_inline {
            return Err(Error(
                [
                    b"circle stable value exceeds max_inline_value key=".as_slice(),
                    key,
                    format!(" bytes={size} limit={max_inline}").as_bytes(),
                ]
                .concat(),
            ));
        }
    }
    if total > max_stable {
        return Err(Error(
            format!(
                "circle stable storage exceeds max_stable_bytes bytes={total} limit={max_stable}"
            )
            .into_bytes(),
        ));
    }
    Ok(total)
}

/// Replace stable entries within the caller's speculative epoch batch. Does not
/// authorize VM effects or publish a canonical commit. Refusal leaves it intact.
pub fn save_storage(
    state: &mut StateBatch,
    circle: &[u8],
    storage: &StorageTable,
    max_stable: i64,
    max_inline: i64,
) -> Result<Vec<u8>, Error> {
    validate_storage_limits(storage, max_stable, max_inline)?;
    let savepoint = state
        .save()
        .map_err(|e| Error(e.to_string().into_bytes()))?;
    let result = (|| {
        state
            .remove(&[b"circles", circle, b"stable", b"by_hash"])
            .map_err(|e| Error(e.to_string().into_bytes()))?;
        for (key, value) in storage.values() {
            let hash = circles::stable_key(key).into_bytes();
            let entry = StableEntry {
                key: key.clone(),
                hash: hash.clone(),
                value: StableValue::Inline(value.clone()),
            };
            state
                .set(
                    &[b"circles", circle, b"stable", b"by_hash", &hash],
                    entry.encode(),
                )
                .map_err(|e| Error(e.to_string().into_bytes()))?;
        }
        let root = state
            .snapshot()
            .hash_at(&[b"circles", circle, b"stable"])
            .map_err(|_| Error(b"Irmin inode depth exhausted".to_vec()))?
            .map_or_else(|| "0".repeat(64), hex::encode)
            .into_bytes();
        state
            .set(&[b"circles", circle, b"stable_root"], root.clone())
            .map_err(|e| Error(e.to_string().into_bytes()))?;
        Ok(root)
    })();
    if result.is_err() {
        state
            .restore(savepoint)
            .map_err(|e| Error(e.to_string().into_bytes()))?;
    }
    result
}

pub fn storage_effort(storage: &StorageTable) -> BigInt {
    let count = storage.values().len();
    let levels = usize::BITS - count.leading_zeros();
    let bytes: BigInt = storage
        .values()
        .iter()
        .map(|(key, value)| BigInt::from(key.len()) * (1 + levels) + BigInt::from(value.len()))
        .sum();
    (bytes + 15) / 16 + BigInt::from(count) * (16 + levels)
}
pub fn write_effort(storage: &StorageTable) -> BigInt {
    let overhead = StableEntry {
        key: vec![],
        hash: circles::stable_key(b"").into_bytes(),
        value: StableValue::Inline(vec![]),
    }
    .encode()
    .len();
    let escaped = |bytes: &[u8]| -> BigInt {
        bytes
            .iter()
            .map(|b| {
                BigInt::from(match b {
                    b'"' | b'\\' | 8 | 12 | b'\n' | b'\r' | b'\t' => 1,
                    0..=31 | 127 => 5,
                    _ => 0,
                })
            })
            .sum()
    };
    let extra: BigInt = storage
        .values()
        .iter()
        .map(|(key, value)| BigInt::from(overhead) + escaped(key) + escaped(value))
        .sum();
    storage_effort(storage) + (extra + 15) / 16
}

pub fn inline(state: &Snapshot, circle: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let hash = circles::stable_key(key);
    let Some(raw) = state.get(&[b"circles", circle, b"stable", b"by_hash", hash.as_bytes()]) else {
        return Ok(None);
    };
    let entry = match StableEntry::parse(raw) {
        Ok(entry) => entry,
        Err(e)
            if e.0 == b"circle stable entry integer refused"
                || e.0 == b"circle stable entry JSON refused" =>
        {
            return Err(e)
        }
        Err(_) => return Ok(None),
    };
    Ok(match entry.value {
        StableValue::Inline(v) if entry.key == key => Some(v),
        _ => None,
    })
}
