// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native default flat/full64 encoding, with explicit local output limits.
use super::{error, Limits, Result};
use crate::state_batch::Snapshot;
use std::{collections::BTreeSet, io::Write};

#[derive(Debug, serde::Serialize)]
pub struct Written {
    pub root: String,
    pub records: u64,
    pub bytes: u64,
    pub pvac_hashes: Vec<String>,
}
struct Sink<W> {
    output: W,
    bytes: u64,
    limits: Limits,
}
impl<W: Write> Sink<W> {
    fn put(&mut self, raw: &[u8]) -> Result<()> {
        let bytes = self
            .bytes
            .checked_add(raw.len() as u64)
            .filter(|size| *size <= self.limits.bytes)
            .ok_or_else(|| error("image exceeds local byte limit"))?;
        self.output.write_all(raw).map_err(error)?;
        self.bytes = bytes;
        Ok(())
    }
    fn string(&mut self, raw: &[u8]) -> Result<()> {
        if raw.len() as u64 > self.limits.string_bytes || raw.len() as u64 > i64::MAX as u64 {
            return Err(error("string exceeds local allocation limit"));
        }
        self.put(&(raw.len() as u64).to_le_bytes())?;
        self.put(raw)
    }
}

/// Streams native `octra-ledger-image-3` bytes from one immutable tree. The
/// caller owns atomic output publication and fsync; a partial sink is unusable.
pub fn write(state: &Snapshot, output: impl Write, limits: Limits) -> Result<Written> {
    if state.get(&[]).is_some() {
        return Err(error("root must be a directory"));
    }
    let root = hex::encode(state.root().map_err(error)?);
    let mut sink = Sink {
        output,
        bytes: 0,
        limits,
    };
    sink.put(b"octra-ledger-image-3\n")?;
    let mut records = 0u64;
    let mut pvac = BTreeSet::new();
    for (path, value) in state.walk() {
        if !(1..=1024).contains(&path.len()) {
            return Err(error("path width exceeds limit"));
        }
        records = records
            .checked_add(1)
            .filter(|count| *count <= limits.records && i64::try_from(*count).is_ok())
            .ok_or_else(|| error("record count exceeds local limit"))?;
        if path.len() == 2 && path[0] == b"pvac_hashes" {
            if let Some(hash) = value.filter(|hash| *hash != b"none") {
                if hash.len() != 64
                    || !hash
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
                {
                    return Err(error("PVAC hash is invalid"));
                }
                pvac.insert(String::from_utf8(hash.to_vec()).map_err(error)?);
            }
        }
        sink.put(&(path.len() as u32).to_le_bytes())?;
        sink.put(&[if value.is_some() { 2 } else { 1 }])?;
        for part in path {
            sink.string(part)?;
        }
        if let Some(value) = value {
            sink.string(value)?;
        }
    }
    sink.put(&0u32.to_le_bytes())?;
    sink.output.flush().map_err(error)?;
    Ok(Written {
        root,
        records,
        bytes: sink.bytes,
        pvac_hashes: pvac.into_iter().collect(),
    })
}
