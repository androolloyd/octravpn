// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native durable anti-equivocation journal, floors, round marks and recovery scans.
use super::{codec::Wire, journal_io as io, Bytes, Error, Vote, VoteType};
use crate::native_integer;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
pub const MAX_WIRE_BYTES: u64 = 512;
pub const MAX_EPOCH_FILES: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub epoch_id: i64,
    pub round: i64,
}
pub enum VoteLog {
    Memory(BTreeMap<Bytes, Vote>),
    Disk(PathBuf),
}
impl VoteLog {
    pub fn memory() -> Self {
        Self::Memory(BTreeMap::new())
    }
    pub fn disk(data_dir: impl AsRef<Path>) -> Self {
        Self::Disk(data_dir.as_ref().join("vote_log"))
    }
    pub fn floor(&self) -> Result<Option<i64>, Error> {
        match self {
            Self::Memory(_) => Ok(Some(i64::MIN)),
            Self::Disk(path) => {
                if !path.exists() {
                    return Ok(None);
                }
                io::directory(path, "vote log")?;
                let file = path.join("floor");
                if !file.exists() {
                    return Ok(None);
                }
                decode_floor(&io::regular(&file, 32, "vote log floor")?).map(Some)
            }
        }
    }
    pub fn round_mark(&self) -> Result<Option<Position>, Error> {
        match self {
            Self::Memory(_) => Ok(None),
            Self::Disk(path) => {
                if !path.exists() {
                    return Ok(None);
                }
                io::directory(path, "vote log")?;
                let file = path.join("round_mark");
                if !file.exists() {
                    return Ok(None);
                }
                decode_round_mark(&io::regular(&file, 64, "vote log round mark")?).map(Some)
            }
        }
    }
    pub fn set_floor(&mut self, through_epoch: i64) -> Result<(), Error> {
        if matches!(self, Self::Memory(_)) {
            return Ok(());
        }
        match self.floor()? {
            Some(prior) if prior > through_epoch => {
                return Err("vote log floor exceeds finalized epoch".into())
            }
            Some(prior) if prior == through_epoch => return Ok(()),
            _ => {}
        }
        let Self::Disk(path) = self else {
            unreachable!()
        };
        io::directory(path, "vote log")?;
        io::publish(
            path,
            &path.join("floor"),
            format!("{through_epoch}\n").as_bytes(),
            false,
        )?;
        Ok(())
    }
    pub fn set_round_mark(&mut self, epoch: i64, round: i64) -> Result<(), Error> {
        if !valid_round_mark(epoch, round) {
            return Err("vote log round mark is invalid".into());
        }
        if let Self::Disk(path) = self {
            io::directory(path, "vote log")?;
        } else {
            return Ok(());
        }
        match self.round_mark()? {
            Some(prior) if prior.epoch_id > epoch => {
                return Err("vote log round mark exceeds current epoch".into())
            }
            Some(prior) if prior.epoch_id == epoch && prior.round > round => {
                return Err("vote log round mark exceeds current round".into())
            }
            Some(prior) if prior.epoch_id == epoch && prior.round == round => return Ok(()),
            _ => {}
        }
        let Self::Disk(path) = self else {
            unreachable!()
        };
        io::publish(
            path,
            &path.join("round_mark"),
            &round_mark_wire(epoch, round),
            false,
        )?;
        Ok(())
    }
    pub fn check(&self, vote: &Vote) -> Result<(), Error> {
        match self {
            Self::Memory(records) => match records.get(&key(vote)) {
                Some(stored) if !same_statement(stored, vote) => {
                    Err("local vote conflicts with stored vote".into())
                }
                _ => Ok(()),
            },
            Self::Disk(path) => {
                io::directory(path, "vote log")?;
                let record = path.join(name(vote));
                if record.exists() {
                    check_existing(&record, vote)?;
                }
                Ok(())
            }
        }
    }
    pub fn keep(&mut self, vote: Vote) -> Result<Vote, Error> {
        match self {
            Self::Memory(records) => match records.get(&key(&vote)) {
                Some(prior) if same_statement(prior, &vote) => Ok(prior.clone()),
                Some(_) => Err("local vote conflicts with stored vote".into()),
                None => {
                    records.insert(key(&vote), vote.clone());
                    Ok(vote)
                }
            },
            Self::Disk(path) => {
                io::directory(path, "vote log")?;
                let record = path.join(name(&vote));
                if record.exists() {
                    return check_existing(&record, &vote);
                }
                if io::publish(path, &record, &vote.encode()?, true)? {
                    Ok(vote)
                } else {
                    check_existing(&record, &vote)
                }
            }
        }
    }
    pub fn find_statement(&self, expected: &Vote) -> Result<Option<Vote>, Error> {
        let found = match self {
            Self::Memory(records) => records.get(&key(expected)).cloned(),
            Self::Disk(path) => {
                if !path.exists() {
                    return Ok(None);
                }
                io::directory(path, "vote log")?;
                let record = path.join(name(expected));
                if record.exists() {
                    Some(read(&record)?)
                } else {
                    None
                }
            }
        };
        Ok(found.filter(|v| same_statement(v, expected)))
    }
    pub fn max_round(
        &self,
        chain: &[u8],
        validator: &[u8],
        epoch: i64,
    ) -> Result<Option<i64>, Error> {
        match self {
            Self::Memory(records) => Ok(records
                .values()
                .filter(|v| belongs(v, chain, validator, epoch))
                .map(|v| v.round)
                .max()),
            Self::Disk(path) => {
                if !path.exists() {
                    return Ok(None);
                }
                io::directory(path, "vote log")?;
                io::sync_directory(path)?;
                let prefix = format!("{epoch:020}_");
                let records: Vec<_> = io::names(path, ".vote")?
                    .into_iter()
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|v| v.as_encoded_bytes().starts_with(prefix.as_bytes()))
                    })
                    .collect();
                let mut entries = Vec::new();
                for p in records {
                    let position =
                        record_position(p.file_name().expect("record basename").as_encoded_bytes())
                            .filter(|p| p.epoch_id == epoch)
                            .ok_or_else(|| Error::from("vote log record name is invalid"))?;
                    entries.push((p, position));
                }
                if entries.len() > MAX_EPOCH_FILES {
                    return Err("vote log epoch record limit exceeded".into());
                }
                let mut rounds = Vec::new();
                for (path, position) in entries {
                    match read(&path) {
                        Ok(vote) if vote.epoch_id == epoch => {
                            if belongs(&vote, chain, validator, epoch) {
                                rounds.push(vote.round);
                            }
                        }
                        Ok(_) => return Err("vote log epoch does not match file".into()),
                        Err(_) => rounds.push(position.round),
                    }
                }
                if let Some(mark) = self.round_mark()? {
                    if mark.epoch_id == epoch {
                        rounds.push(mark.round);
                    }
                }
                Ok(rounds.into_iter().max())
            }
        }
    }
    pub fn prune(&mut self, through_epoch: i64) -> Result<(), Error> {
        match self {
            Self::Memory(records) => {
                records.retain(|_, v| v.epoch_id > through_epoch);
                Ok(())
            }
            Self::Disk(path) => {
                if !path.exists() {
                    return Ok(());
                }
                io::directory(path, "vote log")?;
                let mark_path = path.join("round_mark");
                let mark = if mark_path.exists() {
                    Some(decode_round_mark(&io::regular(
                        &mark_path,
                        64,
                        "vote log round mark",
                    )?)?)
                } else {
                    None
                };
                let mut removed = false;
                for p in io::names(path, ".vote")? {
                    let epoch = read(&p).map(|v| v.epoch_id).ok().or_else(|| {
                        record_position(p.file_name()?.as_encoded_bytes()).map(|p| p.epoch_id)
                    });
                    if epoch.is_some_and(|e| e <= through_epoch) {
                        fs::remove_file(p).map_err(io::io_error)?;
                        removed = true;
                    }
                }
                if mark.is_some_and(|m| m.epoch_id <= through_epoch) {
                    fs::remove_file(mark_path).map_err(io::io_error)?;
                    removed = true;
                }
                if removed {
                    io::sync_directory(path)?;
                }
                Ok(())
            }
        }
    }
}
pub fn key(v: &Vote) -> Bytes {
    let mut key = b"octra:local_vote:v1\0".to_vec();
    for value in [&v.chain_id, &v.validator] {
        key.extend_from_slice(value);
        key.push(0);
    }
    key.extend_from_slice(
        format!(
            "{}\0{}\0{}",
            v.epoch_id,
            v.round,
            if v.vote_type == VoteType::Prevote {
                "prevote"
            } else {
                "precommit"
            }
        )
        .as_bytes(),
    );
    key
}
pub fn same_statement(left: &Vote, right: &Vote) -> bool {
    left.chain_id == right.chain_id
        && left.epoch_id == right.epoch_id
        && left.round == right.round
        && left.vote_type == right.vote_type
        && left.proposal_id == right.proposal_id
        && left.validator == right.validator
}
pub fn name(v: &Vote) -> String {
    format!(
        "{:020}_{:08}_{}.vote",
        v.epoch_id,
        v.round,
        hex::encode(Sha256::digest(key(v)))
    )
}
pub fn record_position(entry: &[u8]) -> Option<Position> {
    let body = entry.strip_suffix(b".vote")?;
    let parts: Vec<_> = body.split(|b| *b == b'_').collect();
    if parts.len() != 3 {
        return None;
    }
    let epoch = native_integer::parse_int64(parts[0])?;
    let round = native_integer::parse_int63(parts[1])?;
    if valid_round_mark(epoch, round)
        && parts[0] == format!("{epoch:020}").as_bytes()
        && parts[1] == format!("{round:08}").as_bytes()
        && parts[2].len() == 64
        && parts[2]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        Some(Position {
            epoch_id: epoch,
            round,
        })
    } else {
        None
    }
}
pub fn valid_round_mark(epoch: i64, round: i64) -> bool {
    (0..i64::MAX).contains(&epoch) && (0..=1_000_000).contains(&round)
}
pub fn round_mark_wire(epoch: i64, round: i64) -> Bytes {
    format!("{epoch} {round}\n").into_bytes()
}
pub fn decode_floor(raw: &[u8]) -> Result<i64, Error> {
    let body = raw
        .strip_suffix(b"\n")
        .ok_or_else(|| Error::from("vote log floor is invalid"))?;
    let n = native_integer::parse_int64(body)
        .ok_or_else(|| io::failure(&Error::from("Int64.of_string")))?;
    if raw == format!("{n}\n").as_bytes() {
        Ok(n)
    } else {
        Err("vote log floor is invalid".into())
    }
}
pub fn decode_round_mark(raw: &[u8]) -> Result<Position, Error> {
    let body = raw
        .strip_suffix(b"\n")
        .ok_or_else(|| Error::from("vote log round mark is invalid"))?;
    let parts: Vec<_> = body.split(|b| *b == b' ').collect();
    if parts.len() != 2 {
        return Err("vote log round mark is invalid".into());
    }
    let epoch = native_integer::parse_int64(parts[0])
        .ok_or_else(|| io::failure(&Error::from("Int64.of_string")))?;
    let round = native_integer::parse_int63(parts[1])
        .ok_or_else(|| io::failure(&Error::from("int_of_string")))?;
    if valid_round_mark(epoch, round) && raw == round_mark_wire(epoch, round) {
        Ok(Position {
            epoch_id: epoch,
            round,
        })
    } else {
        Err("vote log round mark is invalid".into())
    }
}
pub fn vote_of_wire(wire: &[u8]) -> Result<Vote, Error> {
    let vote = Vote::decode(wire).map_err(|e| io::failure(&e))?;
    if vote.encode()?.as_slice() == wire {
        Ok(vote)
    } else {
        Err("vote log wire is not exact".into())
    }
}
fn read(path: &Path) -> Result<Vote, Error> {
    vote_of_wire(&io::regular(path, MAX_WIRE_BYTES, "vote log record")?)
}
fn check_existing(path: &Path, expected: &Vote) -> Result<Vote, Error> {
    let stored = read(path)?;
    if same_statement(&stored, expected) {
        Ok(stored)
    } else {
        Err("local vote conflicts with stored vote".into())
    }
}
fn belongs(vote: &Vote, chain: &[u8], validator: &[u8], epoch: i64) -> bool {
    vote.chain_id == chain && vote.validator == validator && vote.epoch_id == epoch
}
