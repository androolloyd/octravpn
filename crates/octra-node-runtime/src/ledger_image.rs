// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Streaming native ledger images, including backward subtree references.
//! Restoring bytes establishes a ledger commitment, not finality authority.
use crate::state_batch::{Snapshot, StateBatch};
use std::{collections::BTreeMap, io::Read};
mod writer;
pub use writer::{write, Written};

#[derive(Debug, thiserror::Error)]
#[error("ledger image: {0}")]
pub struct Error(String);
type Result<T> = std::result::Result<T, Error>;
fn error(value: impl std::fmt::Display) -> Error {
    Error(value.to_string())
}

/// Local resource policy, independent of protocol validity. An operator may
/// raise these bounds when importing a larger authenticated checkpoint.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub bytes: u64,
    pub records: u64,
    pub string_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 8 * 1024 * 1024 * 1024,
            records: 16_777_216,
            string_bytes: 256 * 1024 * 1024,
        }
    }
}
pub struct Restored {
    pub state: Snapshot,
    pub records: u64,
    pub bytes: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Prior,
    Path64,
    Full64,
    Refs,
}
type Key = Vec<Vec<u8>>;
struct Reader<R> {
    source: R,
    remaining: u64,
    string_limit: u64,
}
impl<R: Read> Reader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() as u64 > self.remaining {
            return Err(error("unexpected end of file"));
        }
        self.source.read_exact(bytes).map_err(error)?;
        self.remaining -= bytes.len() as u64;
        Ok(())
    }
    fn u8(&mut self) -> Result<u8> {
        let mut b = [0];
        self.read(&mut b)?;
        Ok(b[0])
    }
    fn u32(&mut self) -> Result<u32> {
        let mut b = [0; 4];
        self.read(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> Result<u64> {
        let mut b = [0; 8];
        self.read(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn string(&mut self, length: u64, maximum: u64, name: &str) -> Result<Vec<u8>> {
        if length > maximum || length > i64::MAX as u64 {
            return Err(error(format!("{name} exceeds limit")));
        }
        if length > self.remaining {
            return Err(error(format!("{name} exceeds remaining file bytes")));
        }
        if length > self.string_limit {
            return Err(error(format!("{name} exceeds local allocation limit")));
        }
        let length = usize::try_from(length).map_err(error)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(error)?;
        bytes.resize(length, 0);
        self.read(&mut bytes)?;
        Ok(bytes)
    }
    fn hash(&mut self) -> Result<String> {
        let length = self.u64()?;
        let bytes = self.string(length, 256, "subtree hash")?;
        if bytes.len() != 128
            || !bytes
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(error("subtree hash is invalid"));
        }
        String::from_utf8(bytes).map_err(error)
    }
    fn header(&mut self) -> Result<Format> {
        let mut header = Vec::new();
        while header.len() < b"octra-ledger-image-refs\n".len() {
            let byte = self.u8()?;
            header.push(byte);
            if byte == b'\n' {
                return match header.as_slice() {
                    b"octra-ledger-image\n" => Ok(Format::Prior),
                    b"octra-ledger-image-2\n" => Ok(Format::Path64),
                    b"octra-ledger-image-3\n" => Ok(Format::Full64),
                    b"octra-ledger-image-refs\n" => Ok(Format::Refs),
                    _ => Err(error("header is invalid")),
                };
            }
        }
        Err(error("header is invalid"))
    }
    fn path(&mut self, count: u32, format: Format) -> Result<Key> {
        if !(1..=1024).contains(&count) {
            return Err(error("path width exceeds limit"));
        }
        let mut path = Vec::with_capacity(count as usize);
        for index in 0..count {
            let (length, maximum) = if format == Format::Prior {
                (u64::from(self.u32()?), 4096)
            } else {
                (self.u64()?, i64::MAX as u64)
            };
            path.push(self.string(
                length,
                maximum,
                &format!("path part = {index} bytes = {length}"),
            )?);
        }
        Ok(path)
    }
}
fn refs(path: &Key) -> Vec<&[u8]> {
    path.iter().map(Vec::as_slice).collect()
}
fn check_parent(path: &Key, opened: &[(Key, u64)]) -> Result<()> {
    let expected = opened
        .last()
        .map(|(key, _)| key.as_slice())
        .unwrap_or_default();
    if &path[..path.len() - 1] != expected {
        return Err(error("subtree order is invalid"));
    }
    Ok(())
}
fn subtree(state: &StateBatch, path: &Key) -> Result<Snapshot> {
    state
        .snapshot()
        .subtree(&refs(path))
        .ok_or_else(|| error("subtree is missing"))
}

/// The caller must supply the authenticated checkpoint's ledger root. Reads
/// exactly `size` bytes and rejects trailing data, unfinished nodes and forward
/// references. No filesystem or canonical state is modified on failure.
// Preserve the native bounds expression and intermediate arithmetic.
#[allow(clippy::manual_div_ceil)]
pub fn restore(
    source: impl Read,
    size: u64,
    expected_root: &str,
    limits: Limits,
) -> Result<Restored> {
    if size > limits.bytes {
        return Err(error("image exceeds local byte limit"));
    }
    let mut reader = Reader {
        source,
        remaining: size,
        string_limit: limits.string_bytes,
    };
    let format = reader.header()?;
    let mut state = StateBatch::default();
    state.begin().map_err(error)?;
    let mut opened = Vec::<(Key, u64)>::new();
    let mut seen = BTreeMap::<u64, (u8, String, Key)>::new();
    let mut prior: Option<Key> = None;
    let mut records = 0u64;
    loop {
        let count = reader.u32()?;
        if count == 0 {
            break;
        }
        if records >= limits.records {
            return Err(error("record count exceeds local limit"));
        }
        if matches!(format, Format::Prior | Format::Path64) && records >= 16_777_216 {
            return Err(error("record count exceeds limit"));
        }
        let kind = reader.u8()?;
        if kind == 0 || kind > if format == Format::Refs { 5 } else { 2 } {
            return Err(error("record kind is invalid"));
        }
        let path = reader.path(count, format)?;
        if kind != 5 {
            if prior.as_ref().is_some_and(|previous| previous >= &path) {
                return Err(error("paths are not strictly ordered"));
            }
            prior = Some(path.clone());
        }
        records = records
            .checked_add(1)
            .ok_or_else(|| error("record counter overflow"))?;
        if format == Format::Refs && kind != 5 {
            check_parent(&path, &opened)?;
        }
        match kind {
            1 => {
                if format == Format::Refs {
                    opened.push((path.clone(), records));
                }
                state
                    .graft(&refs(&path), &StateBatch::default().snapshot())
                    .map_err(error)?;
            }
            2 => {
                let (length, maximum) = if matches!(format, Format::Prior | Format::Path64) {
                    (u64::from(reader.u32()?), ((33_554_432 + 2) / 3) * 4)
                } else {
                    (reader.u64()?, i64::MAX as u64)
                };
                let value = reader.string(length, maximum, "value")?;
                let hash = (format == Format::Refs)
                    .then(|| hex::encode(octra_node_protocol::irmin::contents_hash(&value)));
                state.set(&refs(&path), value).map_err(error)?;
                if let Some(hash) = hash {
                    seen.insert(records, (2, hash, path));
                }
            }
            3 | 4 => {
                let id = reader.u64()?;
                if id == 0 || id >= records || id > i64::MAX as u64 {
                    return Err(error("reference is not backward"));
                }
                let hash = reader.hash()?;
                let (actual_kind, actual_hash, source) = seen
                    .get(&id)
                    .ok_or_else(|| error("reference target is not finished"))?;
                if *actual_kind != kind - 2 {
                    return Err(error("reference kind mismatch"));
                }
                if *actual_hash != hash {
                    return Err(error("reference hash mismatch"));
                }
                let child = subtree(&state, source)?;
                state.graft(&refs(&path), &child).map_err(error)?;
                seen.insert(records, (kind - 2, hash, path));
            }
            5 => {
                let hash = reader.hash()?;
                let (current, id) = opened
                    .last()
                    .ok_or_else(|| error("subtree finish order is invalid"))?;
                if current != &path {
                    return Err(error("subtree finish order is invalid"));
                }
                let actual = hex::encode(subtree(&state, &path)?.root().map_err(error)?);
                if actual != hash {
                    return Err(error("subtree hash mismatch"));
                }
                seen.insert(*id, (1, hash, path));
                opened.pop();
            }
            _ => unreachable!(),
        }
    }
    let mut extra = [0];
    if reader.remaining != 0 || reader.source.read(&mut extra).map_err(error)? != 0 {
        return Err(error("has trailing bytes"));
    }
    if !opened.is_empty() {
        return Err(error("subtree is unfinished"));
    }
    let counter = state
        .get(&[b"index", b"stealth_counter"])
        .map(|value| {
            octra_node_protocol::native_integer::parse_int64(value)
                .ok_or_else(|| error("corrupt stealth counter"))
        })
        .transpose()?
        .unwrap_or(0);
    state.set_stealth_counter(counter);
    let snapshot = state.snapshot();
    if hex::encode(snapshot.root().map_err(error)?) != expected_root {
        return Err(error("root differs from checkpoint"));
    }
    Ok(Restored {
        state: snapshot,
        records,
        bytes: size,
    })
}
