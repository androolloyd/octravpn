// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native durable compute record formats and transaction lifecycle.
mod cancellation;
pub mod codec;
mod jobs;
mod notices;
mod prune;
mod sessions;
mod transitions;
pub use codec::{JobRow, JobState, Notice, Relay, Row, Saved, Scope, Work};
pub const WORK_LIMIT: usize = 64 * 1024 * 1024;
pub const MAX_REPLY_BYTES: usize = 263_168;
pub const MAX_CONTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_JOB_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_NOTICES: usize = 256;
pub const CALLER_NOTICES: usize = 32;
pub const NOTICE_ROUNDS: i64 = 64;
pub const MAX_NOTICE_BYTES: usize = 1024;
pub const MAX_CANCEL_ACKS: usize = 256;
pub const SEND_LIMIT: i64 = 160;
pub const FORWARD_LIMIT: i64 = SEND_LIMIT / 2;
pub const TRANSIT_LIMIT: i64 = 32;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub Vec<u8>);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
const SESSIONS: usize = 0;
const CALLERS: usize = 1;
const JOBS: usize = 2;
const IDENTITY: usize = 3;
impl From<octra_lmdb::Error> for Error {
    fn from(error: octra_lmdb::Error) -> Self {
        match error {
            octra_lmdb::Error::Policy(reason) if !reason.starts_with("Invalid_argument(") => {
                invalid(reason.as_bytes())
            }
            other => Self(other.to_string().into_bytes()),
        }
    }
}
pub struct History {
    store: std::sync::Mutex<Option<std::sync::Arc<octra_lmdb::Store>>>,
    max_sessions: u64,
    caller_limit: i64,
    page: usize,
}
impl History {
    pub fn open(
        data_dir: &std::path::Path,
        chain: &[u8],
        node: &[u8],
        max_sessions: usize,
        caller_limit: usize,
    ) -> Result<Self> {
        if !(1..=262_144).contains(&max_sessions)
            || !(1..=4096).contains(&caller_limit)
            || chain.is_empty()
            || chain.len() > 256
            || node.is_empty()
            || node.len() > 128
        {
            return Err(invalid(b"compute history configuration"));
        }
        let store = octra_lmdb::Store::open(
            &data_dir.join("compute_history"),
            ["sessions", "callers", "jobs", "identity"],
            WORK_LIMIT,
            |page| map_limit(page).map_err(|error| error.to_string()),
        )?;
        store.write(|txn| -> Result<()> {
            match (txn.get(IDENTITY, b"chain")?, txn.get(IDENTITY, b"node")?) {
                (None, None)
                    if txn.count(SESSIONS)? == 0
                        && txn.count(CALLERS)? == 0
                        && txn.count(JOBS)? == 0 =>
                {
                    txn.put(IDENTITY, b"chain", chain)?;
                    txn.put(IDENTITY, b"node", node)?;
                    Ok(())
                }
                (Some(saved_chain), Some(saved_node))
                    if saved_chain == chain && saved_node == node =>
                {
                    Ok(())
                }
                _ => Err(invalid(b"compute history identity mismatch")),
            }
        })?;
        let page = store.page_size();
        Ok(Self {
            store: std::sync::Mutex::new(Some(std::sync::Arc::new(store))),
            max_sessions: max_sessions as u64,
            caller_limit: caller_limit as i64,
            page,
        })
    }
    pub fn close(&self) -> Result<()> {
        let store = self.lock()?.take();
        drop(store);
        Ok(())
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Option<std::sync::Arc<octra_lmdb::Store>>>> {
        self.store
            .lock()
            .map_err(|_| Error(b"Failure(\"compute history poisoned\")".to_vec()))
    }
    fn write<T>(&self, change: impl FnOnce(&mut octra_lmdb::Write<'_>) -> Result<T>) -> Result<T> {
        self.write_closed(b"compute history closed", change)
    }
    fn write_closed<T>(
        &self,
        closed: &[u8],
        change: impl FnOnce(&mut octra_lmdb::Write<'_>) -> Result<T>,
    ) -> Result<T> {
        let store = self
            .lock()?
            .as_ref()
            .cloned()
            .ok_or_else(|| invalid(closed))?;
        store.write(change)
    }
    fn read<T>(
        &self,
        closed: &[u8],
        read: impl FnOnce(octra_lmdb::Read<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let store = self
            .lock()?
            .as_ref()
            .cloned()
            .ok_or_else(|| invalid(closed))?;
        store.read(read)
    }
    fn check_work(txn: &octra_lmdb::Write<'_>) -> Result<()> {
        if txn.live_bytes()? > WORK_LIMIT as u64 {
            Err(invalid(b"compute history work space full"))
        } else {
            Ok(())
        }
    }
    fn closed(&self) -> Result<bool> {
        Ok(self.lock()?.is_none())
    }
}
fn required(value: Option<Vec<u8>>) -> Result<Vec<u8>> {
    value.ok_or_else(|| Error(b"Not_found".to_vec()))
}
fn invalid(reason: &[u8]) -> Error {
    Error(octra_node_protocol::native_exception::string_argument(
        b"Invalid_argument",
        reason,
    ))
}
fn allocation() -> Error {
    Error(b"Out_of_memory".to_vec())
}
pub fn map_limit(page: usize) -> Result<usize> {
    if !(512..=65536).contains(&page) || !page.is_power_of_two() {
        return Err(invalid(b"compute page size"));
    }
    let frame = 1 + 8 + 128 + 32 + 128 + 16 + 64;
    let pages = 2 + (MAX_NOTICE_BYTES + frame).div_ceil(page);
    let slots = MAX_NOTICES * (MAX_CANCEL_ACKS + 3);
    let bytes = 2 * ((pages * slots + 8) * page + WORK_LIMIT);
    if bytes as u64 > (1_u64 << 62) - 1 {
        Err(invalid(b"compute map address space"))
    } else {
        Ok(bytes)
    }
}
