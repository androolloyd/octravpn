// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Durable authenticated round-sync witnesses with native retention and recovery rules.
use super::{
    codec::Wire, engine::MAX_SYNC_AHEAD, hash, journal_io as io, Bytes, Error, RoundStep, RoundSync,
};
use crate::native_integer;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
pub const MAX_RECORDS: usize = 3 * (MAX_SYNC_AHEAD as usize + 1);
pub const MAX_BEFORE_TRIM: usize = MAX_RECORDS + 3;
pub enum SyncLog {
    Memory(BTreeMap<Bytes, RoundSync>),
    Disk(PathBuf),
}
impl SyncLog {
    pub fn memory() -> Self {
        Self::Memory(BTreeMap::new())
    }
    pub fn disk(data_dir: impl AsRef<Path>) -> Self {
        Self::Disk(data_dir.as_ref().join("round_sync_log"))
    }
    pub fn keep(&mut self, sync: RoundSync, public: &[u8]) -> Result<RoundSync, Error> {
        if !valid(&sync) || !hash::verify_round_sync(public, &sync)? {
            return Err("round sync log record is invalid".into());
        }
        match self {
            Self::Memory(records) => {
                let id = key(&sync);
                if let Some(prior) = records.get(&id) {
                    if same(prior, &sync) && hash::verify_round_sync(public, prior)? {
                        return Ok(prior.clone());
                    }
                    return Err("round sync log record conflicts".into());
                }
                records.insert(id.clone(), sync.clone());
                let floor = (sync.round - MAX_SYNC_AHEAD).max(0);
                records.retain(|_, s| s.epoch_id != sync.epoch_id || s.round >= floor);
                if records
                    .values()
                    .filter(|s| s.epoch_id == sync.epoch_id)
                    .count()
                    > MAX_RECORDS
                {
                    records.remove(&id);
                    return Err("round sync log record limit exceeded".into());
                }
                Ok(sync)
            }
            Self::Disk(root) => {
                io::directory(root, "round sync log")?;
                let path = root.join(format!("{:020}", sync.epoch_id));
                io::directory(&path, "round sync log")?;
                let record = path.join(name(&sync));
                let wire = sync.encode()?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options.mode(0o600);
                let (stored, wrote) = match options.open(&record) {
                    Ok(mut f) => {
                        f.write_all(&wire)
                            .and_then(|()| f.sync_all())
                            .map_err(io::io_error)?;
                        (sync.clone(), true)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let prior = read(&record)?;
                        if !same(&prior, &sync) || !hash::verify_round_sync(public, &prior)? {
                            return Err("round sync log record conflicts".into());
                        }
                        (prior, false)
                    }
                    Err(e) => return Err(io::io_error(e)),
                };
                if wrote {
                    io::sync_directory(&path)?;
                    trim(&path, sync.epoch_id, sync.round)?;
                }
                Ok(stored)
            }
        }
    }
    pub fn load(
        &self,
        chain: &[u8],
        validator: &[u8],
        epoch: i64,
        public: &[u8],
    ) -> Result<Vec<RoundSync>, Error> {
        let mut out = Vec::new();
        match self {
            Self::Memory(records) => {
                for s in records.values().filter(|s| s.epoch_id == epoch) {
                    check(chain, validator, epoch, public, s)?;
                    out.push(s.clone());
                }
            }
            Self::Disk(root) => {
                if !existing_directory(root)? {
                    return Ok(out);
                }
                let path = root.join(format!("{epoch:020}"));
                if !existing_directory(&path)? {
                    return Ok(out);
                }
                let entries = io::names(&path, ".sync")?;
                if entries.len() > MAX_RECORDS {
                    return Err("round sync log record limit exceeded".into());
                }
                for path in entries {
                    let s = read(&path)?;
                    if path
                        .file_name()
                        .expect("record basename")
                        .as_encoded_bytes()
                        != name(&s).as_bytes()
                    {
                        return Err("round sync log name does not match".into());
                    }
                    check(chain, validator, epoch, public, &s)?;
                    out.push(s);
                }
            }
        }
        out.sort_by_key(|s| (s.round, s.step as u8));
        Ok(out)
    }
    pub fn prune(&mut self, through_epoch: i64) -> Result<(), Error> {
        match self {
            Self::Memory(records) => {
                records.retain(|_, s| s.epoch_id > through_epoch);
                Ok(())
            }
            Self::Disk(root) => {
                if !existing_directory(root)? {
                    return Ok(());
                }
                let mut removed = false;
                for entry in fs::read_dir(&root).map_err(io::io_error)? {
                    let path = entry.map_err(io::io_error)?.path();
                    if epoch_of_name(path.file_name().expect("journal entry").as_encoded_bytes())
                        .is_some_and(|e| e <= through_epoch)
                    {
                        remove(&path)?;
                        removed = true;
                    }
                }
                if removed {
                    io::sync_directory(root)?;
                }
                Ok(())
            }
        }
    }
}
pub fn key(sync: &RoundSync) -> Bytes {
    let mut key = b"octra:round_sync_log\0".to_vec();
    for s in [&sync.chain_id, &sync.validator] {
        key.extend_from_slice(s);
        key.push(0);
    }
    key.extend_from_slice(
        format!("{}\0{}\0{}", sync.epoch_id, sync.round, step(sync.step)).as_bytes(),
    );
    key
}
pub fn name(sync: &RoundSync) -> String {
    format!(
        "{:020}_{:08}_{}_{}.sync",
        sync.epoch_id,
        sync.round,
        step(sync.step),
        hex::encode(Sha256::digest(key(sync)))
    )
}
pub fn same(left: &RoundSync, right: &RoundSync) -> bool {
    left.chain_id == right.chain_id
        && left.epoch_id == right.epoch_id
        && left.round == right.round
        && left.step == right.step
        && left.request == right.request
        && left.validator == right.validator
}
pub fn valid(sync: &RoundSync) -> bool {
    !sync.request
        && sync.epoch_id >= 0
        && (0..=1_000_000).contains(&sync.round)
        && sync.signature.len() == 64
}
pub fn epoch_of_name(name: &[u8]) -> Option<i64> {
    let epoch = native_integer::parse_int64(name)?;
    (name == format!("{epoch:020}").as_bytes()).then_some(epoch)
}
pub fn check(
    chain: &[u8],
    validator: &[u8],
    epoch: i64,
    public: &[u8],
    sync: &RoundSync,
) -> Result<(), Error> {
    let err = if !valid(sync) {
        Some("round sync log record is invalid")
    } else if sync.chain_id != chain {
        Some("round sync log chain does not match")
    } else if sync.validator != validator {
        Some("round sync log validator does not match")
    } else if sync.epoch_id != epoch {
        Some("round sync log epoch does not match")
    } else if !hash::verify_round_sync(public, sync)? {
        Some("round sync log signature is invalid")
    } else {
        None
    };
    if let Some(e) = err {
        Err(e.into())
    } else {
        Ok(())
    }
}
fn step(step: RoundStep) -> &'static str {
    match step {
        RoundStep::Propose => "propose",
        RoundStep::Prevote => "prevote",
        RoundStep::Precommit => "precommit",
    }
}
fn existing_directory(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Ok(true),
        Ok(_) => Err("round sync log path is not a directory".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io::io_error(e)),
    }
}
fn read(path: &Path) -> Result<RoundSync, Error> {
    let wire = io::regular(path, 512, "round sync log record")?;
    let sync = RoundSync::decode(&wire).map_err(|e| io::failure(&e))?;
    if sync.encode()? != wire {
        return Err("round sync log wire is not exact".into());
    }
    Ok(sync)
}
fn trim(path: &Path, epoch: i64, round: i64) -> Result<(), Error> {
    let floor = (round - MAX_SYNC_AHEAD).max(0);
    let entries = io::names(path, ".sync")?;
    if entries.len() > MAX_BEFORE_TRIM {
        return Err("round sync log record limit exceeded".into());
    }
    let mut removed = false;
    for path in entries {
        let sync = read(&path)?;
        if sync.epoch_id != epoch {
            return Err("round sync log epoch does not match".into());
        }
        if sync.round < floor {
            fs::remove_file(path).map_err(io::io_error)?;
            removed = true;
        }
    }
    if removed {
        io::sync_directory(path)?;
    }
    Ok(())
}
fn remove(path: &Path) -> Result<(), Error> {
    let m = fs::symlink_metadata(path).map_err(io::io_error)?;
    if m.is_file() {
        fs::remove_file(path).map_err(io::io_error)
    } else if m.is_dir() {
        for entry in fs::read_dir(path).map_err(io::io_error)? {
            remove(&entry.map_err(io::io_error)?.path())?;
        }
        fs::remove_dir(path).map_err(io::io_error)
    } else {
        Err(io::failure(&Error::from(
            "round sync log entry is not removable",
        )))
    }
}
