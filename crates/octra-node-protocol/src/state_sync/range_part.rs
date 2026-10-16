// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Range_part transport. Multipart hashes pin bytes, not finality.
use super::{fields, lower_hex, require, Error, Result};
use crate::{
    light_rpc::json,
    native_json::{Document, Value},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub const VERSION: &[u8] = b"octra-range-part-v1";
pub const BODY_MAX: usize = 4_500_000;
pub const RAW_MAX: usize = 3_000_000;
pub const FULL_MAX: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Encoded {
    raw: Vec<u8>,
    digest: Option<Vec<u8>>,
}
impl Encoded {
    pub fn encode(raw: Vec<u8>) -> Result<Self> {
        require(raw.len() <= FULL_MAX, "range response exceeds full limit")?;
        let digest = (raw.len() > BODY_MAX).then(|| hex::encode(Sha256::digest(&raw)).into_bytes());
        Ok(Self { raw, digest })
    }
    pub fn digest(&self) -> Option<&[u8]> {
        self.digest.as_deref()
    }
    pub fn render(&self, index: Option<i64>) -> Result<Vec<u8>> {
        let Some(digest) = &self.digest else {
            require(index.is_none(), "range response has no parts")?;
            return Ok(self.raw.clone());
        };
        let count = self.raw.len().div_ceil(RAW_MAX);
        let index = index.unwrap_or(0);
        require(
            index >= 0 && (index as u64) < count as u64,
            "range part index is invalid",
        )?;
        let start = index as usize * RAW_MAX;
        let data = &self.raw[start..self.raw.len().min(start + RAW_MAX)];
        Ok(json::object(&[
            ("version", json::string(VERSION)),
            ("status", json::string(b"part")),
            ("sha256", json::string(digest)),
            ("index", json::number(index)),
            ("count", json::number(count)),
            ("data", json::string(STANDARD.encode(data))),
        ]))
    }
}

#[derive(Clone, Debug)]
pub struct Part {
    pub sha256: Vec<u8>,
    pub index: i64,
    pub count: i64,
    pub data: Vec<u8>,
}
pub enum View {
    Full(Document),
    Part(Part),
}
pub fn view(raw: &[u8]) -> Result<View> {
    require(raw.len() <= FULL_MAX, "range response exceeds full limit")?;
    let doc = Document::parse(raw).map_err(|e| Error::from(e.to_string()))?;
    if !matches!(doc.field(doc.root(),b"status"),Some(Value::String(s)) if s==b"part") {
        return Ok(View::Full(doc));
    }
    fields(
        doc.root(),
        &[
            b"version", b"status", b"sha256", b"index", b"count", b"data",
        ],
        "range part",
    )
    .map_err(|_| Error::from("range part fields are invalid"))?;
    let parse = || -> Result<Part> {
        let (version, sha256, index, count, encoded) = match (
            doc.field(doc.root(), b"version"),
            doc.field(doc.root(), b"sha256"),
            doc.field(doc.root(), b"index"),
            doc.field(doc.root(), b"count"),
            doc.field(doc.root(), b"data"),
        ) {
            (
                Some(Value::String(version)),
                Some(Value::String(hash)),
                Some(Value::Int(index)),
                Some(Value::Int(count)),
                Some(Value::String(data)),
            ) => (version, hash, index.get(), count.get(), data),
            _ => return Err("range part values are invalid".into()),
        };
        require(
            version == VERSION && lower_hex(sha256, 64) && count > 1 && index >= 0 && index < count,
            "range part values are invalid",
        )?;
        let data = crate::native_base64::decode(encoded)
            .map_err(|_| Error::from("range part data is not base64"))?;
        require(
            STANDARD.encode(&data).as_bytes() == encoded.as_slice(),
            "range part data is not exact",
        )?;
        require(data.len() <= RAW_MAX, "range part size is invalid")?;
        Ok(Part {
            sha256: sha256.clone(),
            index,
            count,
            data,
        })
    };
    parse().map(View::Part)
}
pub fn join(parts: &[Part]) -> Result<Vec<u8>> {
    let first = parts
        .first()
        .ok_or_else(|| Error::from("range parts are empty"))?;
    require(
        parts.len() as u64 == first.count as u64,
        "range part count does not match",
    )?;
    let mut raw = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        require(
            part.index == i as i64 && part.count == first.count && part.sha256 == first.sha256,
            "range part sequence does not match",
        )?;
        require(
            !part.data.is_empty()
                && part.data.len() <= RAW_MAX
                && (i + 1 == parts.len() || part.data.len() == RAW_MAX)
                && raw.len().saturating_add(part.data.len()) <= FULL_MAX,
            "range part size is invalid",
        )?;
        raw.extend_from_slice(&part.data);
    }
    require(
        raw.len() > BODY_MAX,
        "range parts encode an inline response",
    )?;
    require(
        hex::encode(Sha256::digest(&raw)).as_bytes() == first.sha256,
        "range part hash does not match",
    )?;
    match view(&raw) {
        Ok(View::Full(_)) => Ok(raw),
        Ok(View::Part(_)) => Err("range parts contain a nested part".into()),
        Err(_) => Err("range parts do not contain JSON".into()),
    }
}
