// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Paid work transitions, storage reservations and durable fetch replay limits.
use super::{
    codec::{
        held_key, integer, job_key, read_integer, scope_key, session_key, JobRow, JobState, Row,
        Scope, Work,
    },
    invalid, required, Error, History, Result, IDENTITY, JOBS, MAX_JOB_BYTES, SESSIONS,
};
impl History {
    pub fn claim_fetch(
        &self,
        caller: &[u8],
        session: &[u8],
        id: &[u8],
        limit: usize,
    ) -> Result<Option<usize>> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        if session.len() != 32 || !(1..=256).contains(&limit) {
            return Err(invalid(b"compute fetch limit shape"));
        }
        let key = job_key(caller, id)?;
        let round_key = [b"\x04".as_slice(), &key].concat();
        self.write(|txn| {
            let (Some(row), Some(work)) = (
                txn.get(SESSIONS, &session_key(caller, session))?,
                txn.get(JOBS, &[b"\x03".as_slice(), &key].concat())?,
            ) else {
                return Ok(None);
            };
            if row == b"\x01" {
                return Ok(None);
            }
            Row::decode(&row)?;
            let saved = JobRow::decode(&work)?;
            if !matches!(saved.value, JobState::Pending(Work::Issued(_)))
                || saved.session != session
            {
                return Ok(None);
            }
            let pages = saved.room.map(|_| txn.live_bytes()).transpose()?;
            let previous = txn.get(JOBS, &round_key)?;
            let used = previous
                .as_deref()
                .map(read_integer)
                .transpose()?
                .unwrap_or(0);
            if saved.room.is_some() && previous.is_none() {
                return Err(invalid(b"compute reserved fetch counter absent"));
            }
            if used > limit as i64 {
                return Err(invalid(b"compute fetch counter exceeds limit"));
            }
            if used == limit as i64 {
                return Ok(None);
            }
            txn.put(JOBS, &round_key, &integer(used + 1))?;
            Self::check_job(txn, pages)?;
            Ok(Some(used as usize))
        })
    }
    fn move_job(
        &self,
        caller: &[u8],
        session: &[u8],
        id: &[u8],
        before: &Work,
        after: &Work,
        scope: Option<&Scope>,
        room: Option<usize>,
        check: impl FnOnce(&mut octra_lmdb::Write<'_>) -> Result<()>,
    ) -> Result<bool> {
        if self.closed()? {
            return Err(invalid(b"compute history closed"));
        }
        let valid = |body: &[u8]| !body.is_empty() && body.len() <= MAX_JOB_BYTES;
        let issued = match after {
            Work::Issued(body) | Work::Funding(body) => body.as_slice(),
            Work::Planned(_) => b"",
        };
        if session.len() != 32
            || !valid(before.body())
            || !valid(issued)
            || room.is_some_and(|bytes| !(1..=MAX_JOB_BYTES).contains(&bytes))
        {
            return Err(invalid(b"compute work transition shape"));
        }
        let key = [b"\x03".as_slice(), &job_key(caller, id)?].concat();
        self.write(|txn| {
            let (Some(row), Some(previous)) = (
                txn.get(SESSIONS, &session_key(caller, session))?,
                txn.get(JOBS, &key)?,
            ) else {
                return Ok(false);
            };
            if row == b"\x01" {
                return Ok(false);
            }
            Row::decode(&row)?;
            check(txn)?;
            let saved = JobRow::decode(&previous)?;
            if saved.session != session {
                return Ok(false);
            }
            if saved.value == JobState::Pending(after.clone()) {
                if room.is_some_and(|bytes| saved.room != Some(41 + bytes.max(self.page))) {
                    return Err(invalid(b"compute work allocation changed"));
                }
                let pages = saved.room.map(|_| txn.live_bytes()).transpose()?;
                if let Some(scope) = scope {
                    super::sessions::put_scope(txn, caller, session, scope)?;
                }
                Self::check_job(txn, pages)?;
                return Ok(true);
            }
            if saved.value != JobState::Pending(before.clone()) {
                return Ok(false);
            }
            let pages = saved.room.map(|_| txn.live_bytes()).transpose()?;
            let capacity = match (saved.room, room, before) {
                (Some(size), None, _) => Some(size),
                (None, Some(bytes), Work::Planned(_)) => Some(41 + bytes.max(self.page)),
                (None, None, _) => None,
                _ => return Err(invalid(b"compute work allocation changed")),
            };
            if let Some(scope) = scope {
                super::sessions::put_scope(txn, caller, session, scope)?;
            }
            let held = held_key(caller, session);
            if matches!(after, Work::Issued(_)) && txn.get(JOBS, &held)?.is_some() {
                txn.put(JOBS, &held, &integer(1))?;
            }
            let row = JobRow {
                session: saved.session,
                value: JobState::Pending(after.clone()),
                room: capacity,
            };
            txn.put(JOBS, &key, &row.encode()?)?;
            if saved.room.is_none() && capacity.is_some() {
                let counter = [b"\x04".as_slice(), &job_key(caller, id)?].concat();
                if txn.get(JOBS, &counter)?.is_some() {
                    return Err(invalid(b"compute fetch counter already exists"));
                }
                txn.put(JOBS, &counter, &integer(0))?;
            }
            Self::check_job(txn, pages)?;
            Ok(true)
        })
    }
    pub fn advance_job(
        &self,
        caller: &[u8],
        session: &[u8],
        id: &[u8],
        before: &Work,
        after: &Work,
        scope: Option<&Scope>,
        room: Option<usize>,
    ) -> Result<bool> {
        if matches!(before, Work::Funding(_)) || matches!(after, Work::Funding(_)) {
            return Err(Error(b"compute funding proof required".to_vec()));
        }
        self.move_job(caller, session, id, before, after, scope, room, |_| Ok(()))
    }
    pub fn wait_job(
        &self,
        caller: &[u8],
        session: &[u8],
        id: &[u8],
        before: &[u8],
        body: &[u8],
        scope: &Scope,
        room: usize,
    ) -> Result<bool> {
        self.move_job(
            caller,
            session,
            id,
            &Work::Planned(before.to_vec()),
            &Work::Funding(body.to_vec()),
            Some(scope),
            Some(room),
            |txn| {
                let saved = JobRow::decode(&required(
                    txn.get(JOBS, &[b"\x03".as_slice(), &job_key(caller, id)?].concat())?,
                )?)?;
                if matches!(saved.value, JobState::Pending(Work::Funding(_))) {
                    let current =
                        Scope::decode(&required(txn.get(JOBS, &scope_key(caller, session))?)?)?;
                    if &current != scope {
                        return Err(invalid(b"compute funding scope changed"));
                    }
                }
                Ok(())
            },
        )
    }
    pub fn fund_job(
        &self,
        epoch: i64,
        state_root: &[u8],
        id: &[u8],
        body: &[u8],
        funds: &crate::compute_deposits::Funded,
    ) -> Result<bool> {
        if epoch != funds.epoch() || state_root != funds.state_root() {
            return Err(Error(b"compute funding observation changed".to_vec()));
        }
        let expected = funds
            .header()
            .id()
            .map_err(|error| Error(error.as_bytes().to_vec()))?;
        if id != expected.as_slice() {
            return Err(Error(b"compute funding job differs".to_vec()));
        }
        let request = funds.header().request();
        let caller = &request.caller;
        let session = &request.session_id;
        self.move_job(
            caller,
            session,
            id,
            &Work::Funding(body.to_vec()),
            &Work::Issued(body.to_vec()),
            None,
            None,
            |txn| {
                if required(txn.get(IDENTITY, b"chain")?)? != request.chain_id {
                    return Err(invalid(b"compute funding chain differs"));
                }
                let scope = Scope::decode(&required(txn.get(JOBS, &scope_key(caller, session))?)?)?;
                if scope.sequence != request.sequence
                    || scope.request != funds.deposit().request_id()
                {
                    return Err(invalid(b"compute funding request differs"));
                }
                Ok(())
            },
        )
    }
}
