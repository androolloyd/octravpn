// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    codec::{ack_prefix, integer, notice_key, read_integer, scoped_key, Notice, Relay, Row},
    invalid, required, Error, History, Result, CALLER_NOTICES, IDENTITY, JOBS, MAX_CANCEL_ACKS,
    MAX_NOTICES, MAX_NOTICE_BYTES, NOTICE_ROUNDS, SESSIONS, TRANSIT_LIMIT,
};
pub(super) fn notice_rows(txn: &octra_lmdb::Write<'_>) -> Result<Vec<(Vec<u8>, Notice)>> {
    let mut rows = Vec::new();
    for (index, (key, raw)) in txn
        .prefix(JOBS, b"\x05", MAX_NOTICES)?
        .into_iter()
        .enumerate()
    {
        if index >= MAX_NOTICES {
            return Err(invalid(b"compute cancel capacity differs"));
        }
        let notice = Notice::decode(&key, &raw)?;
        let row = required(txn.get(SESSIONS, &key[1..])?)?;
        if Row::decode(&row)? != Row::Cancelled {
            return Err(invalid(b"compute cancel session differs"));
        }
        rows.push((key, notice));
    }
    Ok(rows)
}
fn ack_rows(
    txn: &octra_lmdb::Write<'_>,
    caller: &[u8],
    session: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let prefix = ack_prefix(caller, session);
    let rows = txn.prefix(JOBS, &prefix, MAX_CANCEL_ACKS)?;
    for (index, (key, body)) in rows.iter().enumerate() {
        let size = key.len() - prefix.len();
        if index >= MAX_CANCEL_ACKS
            || !(1..=128).contains(&size)
            || body.is_empty()
            || body.len() > MAX_NOTICE_BYTES
        {
            return Err(invalid(b"compute cancel ack row shape"));
        }
    }
    Ok(rows)
}
pub(super) fn live_notices(
    txn: &mut octra_lmdb::Write<'_>,
    epoch: i64,
) -> Result<Vec<(Vec<u8>, Notice)>> {
    let rows = notice_rows(txn)?;
    let mut live = Vec::new();
    for (key, row) in rows {
        if row.expires >= epoch {
            live.push((key, row));
        } else {
            for (key, _) in ack_rows(txn, &row.caller, &row.session)? {
                txn.remove(JOBS, &key)?;
            }
            txn.remove(JOBS, &key)?;
        }
    }
    Ok(live)
}
fn identity(caller: &[u8], session: &[u8]) -> bool {
    !caller.is_empty() && caller.len() <= 128 && session.len() == 32
}
impl History {
    pub fn queue_cancel(
        &self,
        epoch: i64,
        expires: i64,
        caller: &[u8],
        session: &[u8],
        body: &[u8],
        until: Option<i64>,
    ) -> Result<bool> {
        if epoch < 0
            || expires < epoch
            || body.is_empty()
            || body.len() > MAX_NOTICE_BYTES
            || until.is_some_and(|until| until != expires)
        {
            return Err(Error(b"compute cancel message shape".to_vec()));
        }
        self.cancel_edit(caller, session, until, |txn| {
            let rows = live_notices(txn, epoch)?;
            let key = notice_key(caller, session);
            match rows.iter().find(|(saved, _)| *saved == key) {
                Some((_, row)) if row.body == body => Ok(()),
                Some(_) => Err(invalid(b"compute cancel message differs")),
                None => {
                    if rows.len() >= MAX_NOTICES
                        || rows.iter().filter(|(_, row)| row.caller == caller).count()
                            >= CALLER_NOTICES
                    {
                        return Err(invalid(b"compute cancel queue full"));
                    }
                    let notice = Notice {
                        caller: caller.to_vec(),
                        session: session.to_vec(),
                        expires,
                        round: 0,
                        body: body.to_vec(),
                    };
                    txn.put(JOBS, &key, &notice.encode())?;
                    Ok(())
                }
            }
        })
    }
    pub fn pending_notices(&self, epoch: i64) -> Result<Vec<Notice>> {
        if epoch < 0 {
            return Err(invalid(b"compute cancel read refused"));
        }
        self.write_closed(b"compute cancel read refused", |txn| {
            Ok(live_notices(txn, epoch)?
                .into_iter()
                .map(|(_, row)| row)
                .collect())
        })
    }
    pub fn claim_notice(
        &self,
        epoch: i64,
        target: Option<(&[u8], &[u8])>,
        now: Option<i64>,
        rounds: bool,
    ) -> Result<Option<Notice>> {
        if epoch < 0 {
            return Err(invalid(b"compute cancel claim refused"));
        }
        self.write_closed(b"compute cancel claim refused", |txn| {
            let rows = live_notices(txn, epoch)?;
            let allowed = if let Some(time) = now {
                if !(0..=i64::MAX - 3000).contains(&time) {
                    return Err(invalid(b"compute cancel time"));
                }
                let next = txn
                    .get(IDENTITY, b"cancel_next")?
                    .as_deref()
                    .map(read_integer)
                    .transpose()?
                    .unwrap_or(0);
                time >= next
            } else {
                true
            };
            let mut selected: Option<(Vec<u8>, Notice)> = None;
            for (key, row) in rows {
                if !allowed
                    || row.round >= if rounds { NOTICE_ROUNDS } else { 1 }
                    || target.is_some_and(|(caller, session)| {
                        row.caller != caller || row.session != session
                    })
                {
                    continue;
                }
                if selected
                    .as_ref()
                    .is_some_and(|(_, previous)| previous.round <= row.round)
                {
                    continue;
                }
                selected = Some((key, row));
            }
            let Some((key, mut row)) = selected else {
                return Ok(None);
            };
            row.round += 1;
            txn.put(JOBS, &key, &row.encode())?;
            if let Some(time) = now {
                txn.put(IDENTITY, b"cancel_next", &integer(time + 3000))?;
            }
            Ok(Some(row))
        })
    }
    pub fn confirm_cancel(
        &self,
        epoch: i64,
        expires: i64,
        round: i64,
        caller: &[u8],
        session: &[u8],
        cancel: &[u8],
        node: &[u8],
        body: &[u8],
    ) -> Result<bool> {
        if epoch < 0
            || !identity(caller, session)
            || node.is_empty()
            || node.len() > 128
            || body.is_empty()
            || body.len() > MAX_NOTICE_BYTES
        {
            return Err(invalid(b"compute cancel ack shape"));
        }
        self.write_closed(b"compute cancel ack shape", |txn| {
            let notices = live_notices(txn, epoch)?;
            let key = notice_key(caller, session);
            let Some((_, notice)) = notices.iter().find(|(saved, _)| *saved == key) else {
                return Ok(false);
            };
            if notice.body != cancel
                || notice.expires != expires
                || round < 2
                || round > notice.round
            {
                return Ok(false);
            }
            let rows = ack_rows(txn, caller, session)?;
            let key = [ack_prefix(caller, session).as_slice(), node].concat();
            if rows.iter().any(|(saved, _)| *saved == key) {
                return Ok(false);
            }
            if rows.len() >= MAX_CANCEL_ACKS {
                return Err(invalid(b"compute cancel ack capacity"));
            }
            txn.put(JOBS, &key, body)?;
            Ok(true)
        })
    }
    pub fn cancel_acks(
        &self,
        epoch: i64,
        caller: &[u8],
        session: &[u8],
    ) -> Result<Option<(Notice, Vec<Vec<u8>>)>> {
        if epoch < 0 || !identity(caller, session) {
            return Err(invalid(b"compute cancel ack read shape"));
        }
        self.write_closed(b"compute cancel ack read shape", |txn| {
            let rows = live_notices(txn, epoch)?;
            let key = notice_key(caller, session);
            match rows.into_iter().find(|(saved, _)| *saved == key) {
                None => Ok(None),
                Some((_, row)) => Ok(Some((
                    row,
                    ack_rows(txn, caller, session)?
                        .into_iter()
                        .map(|(_, body)| body)
                        .collect(),
                ))),
            }
        })
    }
    pub fn relay_cancel(
        &self,
        epoch: i64,
        expires: i64,
        round: i64,
        origin: &[u8],
        id: &[u8],
        caller: &[u8],
        session: &[u8],
        until: Option<i64>,
        close: bool,
        now: Option<i64>,
        transit: bool,
    ) -> Result<bool> {
        if self.closed()?
            || epoch < 0
            || expires < epoch
            || expires - epoch > 64
            || !(1..=NOTICE_ROUNDS).contains(&round)
            || origin.is_empty()
            || origin.len() > 128
            || id.len() != 32
            || until.is_some_and(|until| until != expires)
        {
            return Err(Error(b"compute cancel relay request".to_vec()));
        }
        let commit = |txn: &mut octra_lmdb::Write<'_>| -> Result<()> {
            let mut rows = Vec::new();
            for (index, (key, raw)) in txn
                .prefix(JOBS, b"\x06", MAX_NOTICES)?
                .into_iter()
                .enumerate()
            {
                if index >= MAX_NOTICES {
                    return Err(invalid(b"compute cancel relay capacity differs"));
                }
                rows.push((key.clone(), Relay::decode(&key, &raw)?));
            }
            let mut live = Vec::new();
            for (key, row) in rows {
                if row.expires >= epoch {
                    live.push((key, row));
                } else {
                    txn.remove(JOBS, &key)?;
                }
            }
            let key = scoped_key(6, origin, id);
            match live.iter().find(|(saved, _)| *saved == key) {
                Some((_, row)) if row.expires != expires => {
                    return Err(invalid(b"compute cancel relay expiry differs"))
                }
                Some((_, row)) if row.round >= round => {
                    return Err(invalid(b"compute cancel relay repeated"))
                }
                None if live.len() >= MAX_NOTICES
                    || live.iter().filter(|(_, row)| row.origin == origin).count()
                        >= CALLER_NOTICES =>
                {
                    return Err(invalid(b"compute cancel relay full"))
                }
                Some(_) | None => {}
            }
            if let Some(now) = now {
                let (key, limit) = if transit {
                    (b"cancel_transit".as_slice(), TRANSIT_LIMIT)
                } else {
                    (b"cancel_relay".as_slice(), CALLER_NOTICES as i64)
                };
                if !Self::take_output(txn, key, limit, now)? {
                    return Err(invalid(b"compute cancel relay quota"));
                }
            }
            txn.put(
                JOBS,
                &key,
                &Relay {
                    origin: origin.to_vec(),
                    expires,
                    round,
                }
                .encode(),
            )?;
            Ok(())
        };
        if close {
            self.cancel_edit(caller, session, until, commit)
        } else {
            self.write(|txn| {
                commit(txn)?;
                Self::check_work(txn)?;
                Ok(true)
            })
        }
    }
}
