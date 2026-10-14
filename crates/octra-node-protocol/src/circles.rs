// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle asset paths and byte-preserving metadata.
use crate::{
    native_integer::parse_int64,
    native_json::{Document, Value},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub Vec<u8>);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
impl std::error::Error for Error {}

pub fn normalize_path(raw: &[u8]) -> Result<String, Error> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        if raw[at] == b'%' {
            if raw.len() - at < 3 {
                return Err(Error("truncated percent escape".into()));
            }
            let nibble = |b| {
                char::from(b)
                    .to_digit(16)
                    .ok_or_else(|| Error([b"invalid hex nibble: ".as_slice(), &[b]].concat()))
            };
            decoded.push((nibble(raw[at + 1])? * 16 + nibble(raw[at + 2])?) as u8);
            at += 3;
        } else {
            decoded.push(raw[at]);
            at += 1;
        }
    }
    let decoded =
        std::str::from_utf8(&decoded).map_err(|_| Error("path is not valid utf-8".into()))?;
    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => (),
            ".." => return Err(Error("path traversal is not allowed".into())),
            _ => segments.push(segment),
        }
    }
    let path = format!("/{}", segments.join("/"));
    if path.len() > 1024 {
        return Err(Error("path exceeds max length".into()));
    }
    Ok(path)
}
pub fn domain_hash(tag: &[u8], parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update([0]);
    for part in parts {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hex::encode(hash.finalize())
}
pub fn path_key(path: &[u8]) -> String {
    domain_hash(b"octra:asset_path:v1", &[path])
}
pub fn resource_key(circle: &[u8], path: &[u8]) -> String {
    domain_hash(b"octra:circle_resource_key:v1", &[circle, path])
}
pub fn stable_key(key: &[u8]) -> String {
    domain_hash(b"octra:stable_key:v1", &[key])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceMode {
    Public,
    Sealed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorMode {
    Path,
    Slot,
    State,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataMode {
    Reveal,
    Opaque,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetMeta {
    pub path_key: Vec<u8>,
    pub canonical_path: Vec<u8>,
    pub content_type: Vec<u8>,
    pub encoding: Vec<u8>,
    pub size_bytes: i64,
    pub blob_hash: Vec<u8>,
    pub body_mode: ResourceMode,
    pub plaintext_hash: Option<Vec<u8>>,
    pub key_id: Option<Vec<u8>>,
    pub padding_class: Option<Vec<u8>>,
    pub resource_key: Vec<u8>,
    pub locator_mode: LocatorMode,
    pub slot_ref: Option<Vec<u8>>,
    pub activate_after_epoch: Option<i64>,
    pub expire_after_epoch: Option<i64>,
    pub metadata_mode: MetadataMode,
}

#[derive(Clone, Debug, Default)]
pub struct AssetPolicy {
    pub activate_after_epoch: Option<i64>,
    pub expire_after_epoch: Option<i64>,
    pub tombstone: bool,
    pub revoked: bool,
}
fn trim(raw: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
    let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &raw[start..end]
}
pub fn policy_integer(raw: &[u8]) -> Option<i64> {
    parse_int64(trim(raw))
}
pub fn policy_bool(raw: &[u8]) -> bool {
    let raw = trim(raw);
    raw == b"1" || raw.eq_ignore_ascii_case(b"true") || raw.eq_ignore_ascii_case(b"yes")
}
impl AssetPolicy {
    pub fn visible_at(&self, epoch: i64, meta: &AssetMeta) -> bool {
        self.activate_after_epoch
            .or(meta.activate_after_epoch)
            .map_or(true, |n| epoch >= n)
            && self
                .expire_after_epoch
                .or(meta.expire_after_epoch)
                .map_or(true, |n| epoch < n)
            && !self.tombstone
            && !self.revoked
    }
}
fn text<'a>(doc: &'a Document, name: &str) -> Result<&'a [u8], Error> {
    match doc.field(doc.root(), name.as_bytes()) {
        Some(Value::String(raw)) => Ok(raw),
        _ => Err(Error(
            format!("missing asset meta field: {name}").into_bytes(),
        )),
    }
}
fn optional<'a>(doc: &'a Document, name: &str) -> Result<Option<&'a [u8]>, Error> {
    match doc.field(doc.root(), name.as_bytes()) {
        Some(Value::String(raw)) => Ok(Some(raw)),
        None | Some(Value::Null) => Ok(None),
        _ => Err(Error(
            format!("invalid asset meta field: {name}").into_bytes(),
        )),
    }
}
fn unknown(kind: &str, value: &[u8]) -> Error {
    Error([format!("unknown {kind}: ").as_bytes(), value].concat())
}

fn integer(raw: &[u8]) -> Result<i64, Error> {
    parse_int64(raw).ok_or_else(|| Error("circle asset metadata integer refused".into()))
}
impl AssetMeta {
    pub fn to_json_bytes(&self) -> Vec<u8> {
        use crate::transaction::{json_optional, json_string};
        let size = self.size_bytes.to_string();
        let activate = self.activate_after_epoch.map(|n| n.to_string());
        let expire = self.expire_after_epoch.map(|n| n.to_string());
        let body = match self.body_mode {
            ResourceMode::Public => b"public_resources".as_slice(),
            ResourceMode::Sealed => b"sealed_read",
        };
        let locator = match self.locator_mode {
            LocatorMode::Path => b"path".as_slice(),
            LocatorMode::Slot => b"opaque_slot",
            LocatorMode::State => b"private_state",
        };
        let metadata = match self.metadata_mode {
            MetadataMode::Reveal => b"reveal".as_slice(),
            MetadataMode::Opaque => b"opaque",
        };
        let fields = [
            ("path_key", Some(self.path_key.as_slice())),
            ("canonical_path", Some(self.canonical_path.as_slice())),
            ("content_type", Some(self.content_type.as_slice())),
            ("encoding", Some(self.encoding.as_slice())),
            ("size_bytes", Some(size.as_bytes())),
            ("blob_hash", Some(self.blob_hash.as_slice())),
            ("body_mode", Some(body)),
            ("plaintext_hash", self.plaintext_hash.as_deref()),
            ("key_id", self.key_id.as_deref()),
            ("padding_class", self.padding_class.as_deref()),
            ("resource_key", Some(self.resource_key.as_slice())),
            ("locator_mode", Some(locator)),
            ("slot_ref", self.slot_ref.as_deref()),
            (
                "activate_after_epoch",
                activate.as_deref().map(str::as_bytes),
            ),
            ("expire_after_epoch", expire.as_deref().map(str::as_bytes)),
            ("metadata_mode", Some(metadata)),
        ];
        let mut out = vec![b'{'];
        for (index, (name, value)) in fields.into_iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            json_string(&mut out, name.as_bytes());
            out.push(b':');
            json_optional(&mut out, value);
        }
        out.push(b'}');
        out
    }
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(raw).map_err(|e| {
            Error(match e {
                crate::native_json::Error::Allocation => e.to_string().into_bytes(),
                crate::native_json::Error::Syntax(_) => "circle asset metadata JSON refused".into(),
            })
        })?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(Error("asset meta must be a json object".into()));
        }
        // OCaml evaluates the tuple from the right. Int64.of_string exceptions
        // occur before the leftmost missing-field Result is selected.
        for name in ["expire_after_epoch", "activate_after_epoch"] {
            if let Some(Value::String(raw)) = doc.field(doc.root(), name.as_bytes()) {
                integer(raw)?;
            }
        }
        let path_key = text(&doc, "path_key")?;
        let canonical_path = text(&doc, "canonical_path")?;
        let content_type = text(&doc, "content_type")?;
        let encoding = text(&doc, "encoding")?;
        let size = text(&doc, "size_bytes")?;
        let blob_hash = text(&doc, "blob_hash")?;
        let body = text(&doc, "body_mode")?;
        let plaintext_hash = optional(&doc, "plaintext_hash")?;
        let key_id = optional(&doc, "key_id")?;
        let padding_class = optional(&doc, "padding_class")?;
        let resource_key = text(&doc, "resource_key")?;
        let locator = optional(&doc, "locator_mode")?;
        let slot_ref = optional(&doc, "slot_ref")?;
        let activate = optional(&doc, "activate_after_epoch")?;
        let expire = optional(&doc, "expire_after_epoch")?;
        let metadata = optional(&doc, "metadata_mode")?;
        let body_mode = match body {
            b"public_resources" => ResourceMode::Public,
            b"sealed_read" => ResourceMode::Sealed,
            v => return Err(unknown("resource mode", v)),
        };
        let locator_mode = match locator.unwrap_or(b"path") {
            b"path" => LocatorMode::Path,
            b"opaque_slot" => LocatorMode::Slot,
            b"private_state" => LocatorMode::State,
            v => return Err(unknown("locator mode", v)),
        };
        let metadata_mode = match metadata.unwrap_or(b"reveal") {
            b"reveal" => MetadataMode::Reveal,
            b"opaque" => MetadataMode::Opaque,
            v => return Err(unknown("metadata mode", v)),
        };
        Ok(Self {
            path_key: path_key.to_vec(),
            canonical_path: canonical_path.to_vec(),
            content_type: content_type.to_vec(),
            encoding: encoding.to_vec(),
            size_bytes: integer(size)?,
            blob_hash: blob_hash.to_vec(),
            body_mode,
            plaintext_hash: plaintext_hash.map(<[u8]>::to_vec),
            key_id: key_id.map(<[u8]>::to_vec),
            padding_class: padding_class.map(<[u8]>::to_vec),
            resource_key: resource_key.to_vec(),
            locator_mode,
            slot_ref: slot_ref.map(<[u8]>::to_vec),
            activate_after_epoch: activate.map(integer).transpose()?,
            expire_after_epoch: expire.map(integer).transpose()?,
            metadata_mode,
        })
    }
}
