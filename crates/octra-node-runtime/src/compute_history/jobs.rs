// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Durable job identity, reference migration and result storage.
use super::{
    codec::{
        expiry_key, held_key, integer, job_key, job_refs, notice_key, read_integer, scope_key,
        session_key, split_job, JobRow, JobState, Row, Work,
    },
    invalid, History, Result, CALLERS, IDENTITY, JOBS, MAX_JOB_BYTES, SESSIONS,
};

pub(super) fn count(txn: &octra_lmdb::Write<'_>, map: usize, key: &[u8]) -> Result<i64> {
    Ok(txn
        .get(map, key)?
        .as_deref()
        .map(read_integer)
        .transpose()?
        .unwrap_or(0))
}
impl History {
    fn add_ref(
        &self,
        txn: &mut octra_lmdb::Write<'_>,
        caller: &[u8],
        session: &[u8],
    ) -> Result<()> {
        let key = job_refs(caller, session)?;
        let value = count(txn, JOBS, &key)?;
        if value >= self.max_sessions as i64 {
            return Err(invalid(b"compute job reference capacity"));
        }
        txn.put(JOBS, &key, &integer(value + 1))?;
        Ok(())
    }
    pub(super) fn index_refs(&self, txn: &mut octra_lmdb::Write<'_>) -> Result<()> {
        match txn.get(IDENTITY, b"job_refs")?.as_deref() {
            Some(b"ready") => return Ok(()),
            Some(_) => return Err(invalid(b"compute job reference index")),
            None => {}
        }
        for tag in [2_u8, 3] {
            for (index, (key, raw)) in txn
                .prefix(JOBS, &[tag], self.max_sessions as usize)?
                .into_iter()
                .enumerate()
            {
                if index >= self.max_sessions as usize {
                    return Err(invalid(b"compute job index capacity"));
                }
                let (caller, _) = split_job(&key)?;
                let session = if tag == 3 {
                    JobRow::decode(&raw)?.session
                } else if raw.len() > 32 {
                    raw[..32].to_vec()
                } else {
                    return Err(invalid(b"compute saved job size"));
                };
                self.add_ref(txn, caller, &session)?;
            }
        }
        txn.put(IDENTITY, b"job_refs", b"ready")?;
        Ok(())
    }
    fn count_job(
        &self,
        txn: &mut octra_lmdb::Write<'_>,
        caller: &[u8],
        session: &[u8],
    ) -> Result<()> {
        self.index_refs(txn)?;
        let key = [b"\x01".as_slice(), caller].concat();
        let total = count(txn, JOBS, b"\x00")?;
        let own = count(txn, JOBS, &key)?;
        if total >= self.max_sessions as i64 || own >= self.caller_limit {
            return Err(invalid(b"compute job capacity"));
        }
        txn.put(JOBS, b"\x00", &integer(total + 1))?;
        txn.put(JOBS, &key, &integer(own + 1))?;
        self.add_ref(txn, caller, session)
    }
    pub(super) fn check_job(txn: &octra_lmdb::Write<'_>, before: Option<u64>) -> Result<()> {
        match before {
            None => Self::check_work(txn),
            Some(bytes) if txn.live_bytes()? > bytes => {
                Err(invalid(b"compute reserved job grew storage"))
            }
            Some(_) => Ok(()),
        }
    }
    pub fn known_job(&self, caller: &[u8], session: &[u8]) -> Result<bool> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        let key = job_key(caller, session)?;
        self.write(|txn| {
            self.index_refs(txn)?;
            if count(txn, JOBS, &job_refs(caller, session)?)? > 0 {
                return Ok(true);
            }
            let Some(row) = txn.get(SESSIONS, &key)? else {
                return Ok(false);
            };
            match Row::decode(&row)? {
                Row::Reserved { .. } | Row::Finished { .. } => Ok(true),
                _ => Ok(txn.get(JOBS, &notice_key(caller, session))?.is_some()
                    || txn.get(JOBS, &scope_key(caller, session))?.is_some()),
            }
        })
    }
    pub fn plan_job(
        &self,
        caller: &[u8],
        session: &[u8],
        id: &[u8],
        body: &[u8],
        expires: Option<i64>,
    ) -> Result<bool> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        if session.len() != 32 || body.is_empty() || body.len() > MAX_JOB_BYTES {
            return Err(invalid(b"compute job body shape"));
        }
        let key = job_key(caller, id)?;
        let session_key = session_key(caller, session);
        self.write(|txn| {
            let row = txn.get(SESSIONS, &session_key)?;
            if row.as_deref() == Some(b"\x01") {
                return Ok(false);
            }
            if let Some(row) = &row {
                Row::decode(row)?;
            }
            if txn
                .get(JOBS, &[b"\x02".as_slice(), &key].concat())?
                .is_some()
            {
                return Ok(false);
            }
            let pending = [b"\x03".as_slice(), &key].concat();
            if let Some(raw) = txn.get(JOBS, &pending)? {
                let saved = JobRow::decode(&raw)?;
                return Ok(saved.session == session
                    && saved.value == JobState::Pending(Work::Planned(body.to_vec())));
            }
            if row.is_none() {
                let own = count(txn, CALLERS, caller)?;
                if own >= self.caller_limit || txn.count(SESSIONS)? >= self.max_sessions {
                    return Err(invalid(b"compute history session capacity"));
                }
                txn.put(CALLERS, caller, &integer(own + 1))?;
                txn.put(SESSIONS, &session_key, b"")?;
            }
            self.count_job(txn, caller, session)?;
            if let Some(until) = expires {
                if until < 0 {
                    return Err(invalid(b"compute job expiry"));
                }
                let key = expiry_key(caller, session);
                let previous = count(txn, JOBS, &key)?;
                txn.put(JOBS, &key, &integer(previous.max(until)))?;
                let key = held_key(caller, session);
                if txn.get(JOBS, &key)?.is_none() {
                    txn.put(JOBS, &key, &integer(0))?;
                }
            }
            let row = JobRow {
                session: session.to_vec(),
                value: JobState::Pending(Work::Planned(body.to_vec())),
                room: None,
            };
            txn.put(JOBS, &pending, &row.encode()?)?;
            Self::check_work(txn)?;
            Ok(true)
        })
    }
    pub fn work(&self, caller: &[u8], id: &[u8]) -> Result<Option<Work>> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        let key = [b"\x03".as_slice(), &job_key(caller, id)?].concat();
        self.read(b"compute history closed", |txn| {
            let Some(raw) = txn.get(JOBS, &key)? else {
                return Ok(None);
            };
            match JobRow::decode(&raw)?.value {
                JobState::Pending(work) => Ok(Some(work)),
                JobState::Stored(_) => Ok(None),
            }
        })
    }
    pub fn save_job(&self, caller: &[u8], session: &[u8], id: &[u8], body: &[u8]) -> Result<bool> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        if session.len() != 32 || body.is_empty() || body.len() > MAX_JOB_BYTES {
            return Err(invalid(b"compute job body shape"));
        }
        let key = job_key(caller, id)?;
        let saved_key = [b"\x02".as_slice(), &key].concat();
        let pending = [b"\x03".as_slice(), &key].concat();
        let value = [session, body].concat();
        self.write(|txn| {
            match txn.get(SESSIONS, &session_key(caller, session))?.as_deref() {
                None | Some(b"\x01") => return Ok(false),
                Some(raw) => {
                    Row::decode(raw)?;
                }
            }
            match (txn.get(JOBS, &saved_key)?, txn.get(JOBS, &pending)?) {
                (Some(_), Some(_)) => Err(invalid(b"compute job has duplicate rows")),
                (Some(prior), None) => Ok(prior == value),
                (None, Some(raw)) => {
                    let saved = JobRow::decode(&raw)?;
                    if saved.session != session {
                        return Ok(false);
                    }
                    match (saved.value, saved.room) {
                        (JobState::Stored(prior), Some(_)) => Ok(prior == body),
                        (JobState::Pending(Work::Issued(_)), Some(size)) => {
                            let pages = txn.live_bytes()?;
                            let needed = 41 + body.len();
                            if needed > size {
                                return Err(invalid(b"compute job exceeds reserved space"));
                            }
                            let room = (41 + self.page).max(needed);
                            if room < size {
                                txn.remove(JOBS, &pending)?;
                            }
                            let row = JobRow {
                                session: saved.session,
                                value: JobState::Stored(body.to_vec()),
                                room: Some(room),
                            };
                            txn.put(JOBS, &pending, &row.encode()?)?;
                            Self::check_job(txn, Some(pages))?;
                            Ok(true)
                        }
                        (JobState::Pending(Work::Issued(_)), None) => {
                            txn.remove(JOBS, &pending)?;
                            txn.put(JOBS, &saved_key, &value)?;
                            Self::check_work(txn)?;
                            Ok(true)
                        }
                        _ => Ok(false),
                    }
                }
                (None, None) => {
                    self.count_job(txn, caller, session)?;
                    txn.put(JOBS, &saved_key, &value)?;
                    Self::check_work(txn)?;
                    Ok(true)
                }
            }
        })
    }
    pub fn load_job(&self, caller: &[u8], id: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        let key = job_key(caller, id)?;
        self.read(b"compute history closed", |txn| {
            match (
                txn.get(JOBS, &[b"\x02".as_slice(), &key].concat())?,
                txn.get(JOBS, &[b"\x03".as_slice(), &key].concat())?,
            ) {
                (Some(_), Some(_)) => Err(invalid(b"compute job has duplicate rows")),
                (Some(raw), None) if raw.len() > 32 && raw.len() <= 32 + MAX_JOB_BYTES => {
                    Ok(Some(raw[32..].to_vec()))
                }
                (None, Some(raw)) => match JobRow::decode(&raw)?.value {
                    JobState::Stored(body) => Ok(Some(body)),
                    JobState::Pending(_) => Ok(None),
                },
                (None, None) => Ok(None),
                _ => Err(invalid(b"compute job row shape")),
            }
        })
    }
}
