// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Durable native validator-relief decisions. The caller authenticates a mark
//! with `relief::Plan` before keeping it and again when restoring it.
use super::{
    codec::Wire,
    journal_io as io,
    relief::{self, Mark},
    Bytes, Error, RoundSync,
};
use crate::{
    native_base64, native_integer,
    native_json::{Document, Value},
    transaction::json_string,
};
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub const MAX_WIRE_BYTES: u64 = 262_144;
pub const MAX_MARKS: usize = 64;

pub enum ReliefLog {
    Memory(BTreeMap<i64, Mark>),
    Disk(PathBuf),
}
impl ReliefLog {
    pub fn memory() -> Self {
        Self::Memory(BTreeMap::new())
    }
    pub fn disk(data_dir: impl AsRef<Path>) -> Self {
        Self::Disk(data_dir.as_ref().join("relief_log"))
    }
    pub fn keep(&mut self, mark: Mark) -> Result<Mark, Error> {
        match self {
            Self::Memory(marks) => {
                if let Some(saved) = marks.get(&mark.height) {
                    return same(saved.clone(), &mark);
                }
                if marks.len() >= MAX_MARKS {
                    return Err("relief log record limit exceeded".into());
                }
                marks.insert(mark.height, mark.clone());
                Ok(mark)
            }
            Self::Disk(root) => {
                io::directory(root, "relief log")?;
                let record = root.join(name(mark.height));
                match fs::symlink_metadata(&record) {
                    Ok(_) => return same(read(&record)?, &mark),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(io::io_error(e)),
                }
                let staged = stage(&record, &encode(&mark)?)?;
                let linked = match fs::hard_link(&staged, &record) {
                    Ok(()) => Ok(mark),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        read(&record).and_then(|saved| same(saved, &mark))
                    }
                    Err(e) => Err(io::io_error(e)),
                };
                // Always clean up and fsync, even when a competing writer won.
                let removed = match fs::remove_file(staged) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(io::io_error(e)),
                };
                let synced = io::sync_directory(root);
                let saved = linked?;
                removed?;
                synced?;
                Ok(saved)
            }
        }
    }
    pub fn latest(&self, through_height: i64) -> Result<Option<Mark>, Error> {
        let marks = match self {
            Self::Memory(marks) => {
                return Ok(marks
                    .range(..=through_height)
                    .next_back()
                    .map(|(_, m)| m.clone()))
            }
            Self::Disk(root) => disk_marks(root)?,
        };
        Ok(marks
            .into_iter()
            .filter(|m| m.height <= through_height)
            .max_by_key(|m| m.height))
    }
    pub fn prune(&mut self, through_epoch: i64) -> Result<(), Error> {
        let expired = |m: &Mark| through_epoch >= m.activate_epoch.wrapping_sub(1);
        match self {
            Self::Memory(marks) => marks.retain(|_, mark| !expired(mark)),
            Self::Disk(root) => {
                let mut removed = false;
                for mark in disk_marks(root)? {
                    if expired(&mark) {
                        fs::remove_file(root.join(name(mark.height))).map_err(io::io_error)?;
                        removed = true;
                    }
                }
                if removed {
                    io::sync_directory(root)?;
                }
            }
        }
        Ok(())
    }
}
fn same(saved: Mark, proposed: &Mark) -> Result<Mark, Error> {
    if relief::same_plan(&saved, proposed) {
        Ok(saved)
    } else {
        Err("relief log plan conflicts".into())
    }
}
pub fn name(height: i64) -> String {
    format!("{height:020}.mark")
}
pub fn height_of_name(value: &[u8]) -> Option<i64> {
    let height = native_integer::parse_int64(value.strip_suffix(b".mark")?)?;
    (name(height).as_bytes() == value).then_some(height)
}
pub fn encode(mark: &Mark) -> Result<Bytes, Error> {
    let mut out = b"{\"standard\":\"octra-consensus-relief\",\"height\":".to_vec();
    json_string(&mut out, mark.height.to_string().as_bytes());
    out.extend_from_slice(format!(",\"round\":{},\"activate_epoch\":", mark.round).as_bytes());
    json_string(&mut out, mark.activate_epoch.to_string().as_bytes());
    for (key, value) in [
        (
            b"source_hash".as_slice(),
            hex::encode(&mark.source_hash).into_bytes(),
        ),
        (b"target_hash", hex::encode(&mark.target_hash).into_bytes()),
        (b"fingerprint", mark.fingerprint.clone()),
    ] {
        out.push(b',');
        json_string(&mut out, key);
        out.push(b':');
        json_string(&mut out, &value);
    }
    out.extend_from_slice(b",\"proof\":[");
    for (i, sync) in mark.proof.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_string(&mut out, STANDARD.encode(sync.encode()?).as_bytes());
    }
    out.extend_from_slice(b"]}");
    Ok(out)
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a [u8], Error> {
    if let Value::String(v) = value {
        Ok(v)
    } else {
        Err(format!("relief log field must be text: {name}").into())
    }
}
fn raw(hash: &[u8]) -> Result<Bytes, Error> {
    if hash.len() != 64 {
        return Err("relief log hash length is invalid".into());
    }
    hash.chunks_exact(2)
        .map(|pair| {
            let token = [b'0', b'x', pair[0], pair[1]];
            native_integer::parse_int63(&token)
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| Error::from("relief log hash encoding is invalid"))
        })
        .collect()
}
pub fn decode(wire: &[u8]) -> Result<Mark, Error> {
    let doc = Document::parse(wire).map_err(|e| Error::from(e.to_string()))?;
    if !matches!(doc.root(), Value::Object(_)) {
        return Err("relief log record must be an object".into());
    }
    let field = |key: &str| {
        doc.field(doc.root(), key.as_bytes())
            .ok_or_else(|| Error::from(format!("relief log field is missing: {key}")))
    };
    let integer = |key: &str| {
        native_integer::parse_int64(text(field(key)?, key)?)
            .ok_or_else(|| Error::from(format!("relief log integer is invalid: {key}")))
    };
    if text(field("standard")?, "standard")? != b"octra-consensus-relief" {
        return Err("relief log standard is invalid".into());
    }
    let height = integer("height")?;
    let round = if let Value::Int(v) = field("round")? {
        v.get()
    } else {
        return Err("relief log field must be integer: round".into());
    };
    let activate_epoch = integer("activate_epoch")?;
    let source_hash = raw(text(field("source_hash")?, "source_hash")?)?;
    let target_hash = raw(text(field("target_hash")?, "target_hash")?)?;
    let fingerprint = text(field("fingerprint")?, "fingerprint")?.to_vec();
    let Value::List(values) = field("proof")? else {
        return Err("relief log proof must be a list".into());
    };
    let mut proof = Vec::with_capacity(values.len());
    for index in values {
        let value = text(doc.get(*index).expect("JSON child"), "proof")?;
        let raw = native_base64::decode(value)
            .map_err(|e| Error::from(format!("Invalid_argument(\"{e}\")")))?;
        let sync = RoundSync::decode(&raw).map_err(|e| io::failure(&e))?;
        if sync.encode()? != raw {
            return Err("relief log proof wire is not exact".into());
        }
        proof.push(sync);
    }
    let mark = Mark {
        height,
        round,
        activate_epoch,
        source_hash,
        target_hash,
        fingerprint,
        proof,
    };
    if encode(&mark)? != wire {
        return Err("relief log wire is not exact".into());
    }
    Ok(mark)
}
fn read(path: &Path) -> Result<Mark, Error> {
    decode(&io::regular(path, MAX_WIRE_BYTES, "relief log record")?)
}
fn disk_marks(root: &Path) -> Result<Vec<Mark>, Error> {
    match fs::symlink_metadata(root) {
        Ok(m) if m.is_dir() => (),
        Ok(_) => return Err("relief log path is not a directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(io::io_error(e)),
    }
    let mut records = vec![];
    for entry in fs::read_dir(root).map_err(io::io_error)? {
        let entry = entry.map_err(io::io_error)?;
        if let Some(height) = height_of_name(entry.file_name().as_encoded_bytes()) {
            records.push((entry.path(), height));
        }
    }
    if records.len() > MAX_MARKS {
        return Err("relief log record limit exceeded".into());
    }
    records
        .into_iter()
        .map(|(path, height)| {
            let mark = read(&path)?;
            if mark.height == height {
                Ok(mark)
            } else {
                Err("relief log name differs from record".into())
            }
        })
        .collect()
}
fn stage(record: &Path, wire: &[u8]) -> Result<PathBuf, Error> {
    for attempt in 0..MAX_MARKS {
        let mut name = record.as_os_str().to_owned();
        name.push(format!(".staged.{}.{attempt}", std::process::id()));
        let staged = PathBuf::from(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&staged) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(wire).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(staged);
                    return Err(io::io_error(error));
                }
                return Ok(staged);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(io::io_error(e)),
        }
    }
    Err("relief log stage limit exceeded".into())
}
