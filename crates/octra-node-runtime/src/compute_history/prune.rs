// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Incremental expiry retains issued work, paid cancellations and job references.
use super::{
    codec::{
        expiry_key, held_key, integer, job_key, job_refs, read_integer, scope_key, scope_prefix,
        split_job, JobRow, JobState, Row, Work,
    },
    invalid, required, Error, History, Result, CALLERS, IDENTITY, JOBS, SESSIONS,
};
fn decrease(txn: &mut octra_lmdb::Write<'_>, map: usize, key: &[u8]) -> Result<bool> {
    let count = read_integer(&required(txn.get(map, key)?)?)?;
    if count < 1 {
        return Err(invalid(b"compute history counter empty"));
    }
    if count == 1 {
        txn.remove(map, key)?;
    } else {
        txn.put(map, key, &integer(count - 1))?;
    }
    Ok(count == 1)
}
fn remove_archive(txn: &mut octra_lmdb::Write<'_>, caller: &[u8], session: &[u8]) -> Result<()> {
    let mut keys = Vec::new();
    let _: Option<()> = txn
        .view()
        .find(JOBS, &scope_prefix(caller, session), |key, _| {
            keys.push(key.to_vec());
            Ok::<Option<()>, Error>(None)
        })?;
    for key in keys {
        txn.remove(JOBS, &key)?;
    }
    Ok(())
}
// Preserve the ordered native tuple/borrowed-field projection API.
#[allow(clippy::type_complexity)]
fn batch(
    txn: &octra_lmdb::Write<'_>,
    cursor: &[u8],
    tag: u8,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>)> {
    let start = txn.get(IDENTITY, cursor)?.unwrap_or_else(|| vec![tag]);
    let mut rows = txn.view().batch(JOBS, &start, &[tag], 32)?;
    let next = rows
        .get(32)
        .map_or_else(|| vec![tag], |(key, _)| key.clone());
    rows.truncate(32);
    Ok((rows, next))
}
impl History {
    pub fn prune_jobs(
        &self,
        mut expired: impl FnMut(&[u8], &[u8], &[u8], &[u8]) -> bool,
    ) -> Result<usize> {
        self.try_prune_jobs(move |caller, session, id, body| Ok(expired(caller, session, id, body)))
    }
    pub fn try_prune_jobs(
        &self,
        mut expired: impl FnMut(&[u8], &[u8], &[u8], &[u8]) -> Result<bool>,
    ) -> Result<usize> {
        self.write(|txn| {
            self.index_refs(txn)?;
            let (rows, next) = batch(txn, b"job_cursor", 3)?;
            let mut removed = 0;
            for (key, raw) in rows {
                let row = JobRow::decode(&raw)?;
                let (caller, id) = split_job(&key)?;
                let discard = match &row.value {
                    JobState::Pending(Work::Planned(body) | Work::Funding(body)) => {
                        expired(caller, &row.session, id, body)?
                    }
                    JobState::Pending(Work::Issued(_)) | JobState::Stored(_) => false,
                };
                if !discard {
                    continue;
                }
                txn.remove(JOBS, &key)?;
                txn.remove(JOBS, &[b"\x04".as_slice(), &job_key(caller, id)?].concat())?;
                decrease(txn, JOBS, b"\x00")?;
                decrease(txn, JOBS, &[b"\x01".as_slice(), caller].concat())?;
                if decrease(txn, JOBS, &job_refs(caller, &row.session)?)? {
                    let session = job_key(caller, &row.session)?;
                    if Row::decode(&required(txn.get(SESSIONS, &session)?)?)? == Row::Ready {
                        txn.remove(SESSIONS, &session)?;
                        decrease(txn, CALLERS, caller)?;
                        for key in [
                            scope_key(caller, &row.session),
                            held_key(caller, &row.session),
                            expiry_key(caller, &row.session),
                        ] {
                            txn.remove(JOBS, &key)?;
                        }
                        remove_archive(txn, caller, &row.session)?;
                    }
                }
                removed += 1;
            }
            txn.put(IDENTITY, b"job_cursor", &next)?;
            Ok(removed)
        })
    }
    pub fn prune_cancels(&self, epoch: i64) -> Result<usize> {
        if epoch < 0 {
            return Err(invalid(b"compute cancel expiry read"));
        }
        self.write_closed(b"compute cancel expiry read", |txn| {
            super::notices::live_notices(txn, epoch)?;
            self.index_refs(txn)?;
            let (rows, next) = batch(txn, b"cancel_cursor", 12)?;
            let mut removed = 0;
            for (key, raw) in rows {
                let (caller, session) = split_job(&key)?;
                if read_integer(&raw)? >= epoch
                    || txn.get(JOBS, &job_refs(caller, session)?)?.is_some()
                {
                    continue;
                }
                if super::jobs::count(txn, JOBS, &held_key(caller, session))? != 0 {
                    return Err(invalid(b"compute paid cancellation expiry"));
                }
                let row = job_key(caller, session)?;
                if required(txn.get(SESSIONS, &row)?)? != b"\x01" {
                    return Err(invalid(b"compute cancel expiry row differs"));
                }
                txn.remove(SESSIONS, &row)?;
                let own = read_integer(&required(txn.get(CALLERS, caller)?)?)?;
                if own < 1 {
                    return Err(invalid(b"compute caller count empty"));
                }
                if own == 1 {
                    txn.remove(CALLERS, caller)?;
                } else {
                    txn.put(CALLERS, caller, &integer(own - 1))?;
                }
                for key in [
                    key.clone(),
                    held_key(caller, session),
                    expiry_key(caller, session),
                    scope_key(caller, session),
                ] {
                    txn.remove(JOBS, &key)?;
                }
                remove_archive(txn, caller, session)?;
                removed += 1;
            }
            txn.put(IDENTITY, b"cancel_cursor", &next)?;
            Ok(removed)
        })
    }
}
