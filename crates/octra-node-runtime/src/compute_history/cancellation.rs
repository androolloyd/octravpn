// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    codec::{expiry_key, held_key, integer, read_integer, until_key, Row},
    invalid,
    sessions::Mode,
    History, Result, CALLER_NOTICES, FORWARD_LIMIT, IDENTITY, JOBS, SEND_LIMIT, TRANSIT_LIMIT,
};
use std::cell::Cell;

impl History {
    pub(super) fn cancel_edit(
        &self,
        caller: &[u8],
        session: &[u8],
        expires: Option<i64>,
        commit: impl FnOnce(&mut octra_lmdb::Write<'_>) -> Result<()>,
    ) -> Result<bool> {
        let permanent = Cell::new(false);
        let closed = Cell::new(false);
        self.edit(
            Mode::Control,
            caller,
            session,
            |previous| {
                closed.set(matches!(previous, Some(Row::Cancelled)));
                permanent.set(matches!(
                    previous,
                    Some(Row::Reserved { .. } | Row::Finished { .. })
                ));
                Ok((Some(Row::Cancelled), true))
            },
            |txn| {
                let key = until_key(caller, session);
                if let Some(until) = expires {
                    if until < 0 {
                        return Err(invalid(b"compute cancel expiry"));
                    }
                    let held = txn
                        .get(JOBS, &held_key(caller, session))?
                        .as_deref()
                        .map(read_integer)
                        .transpose()?
                        .is_some_and(|v| v != 0);
                    let previous = txn.get(JOBS, &key)?;
                    if !(permanent.get() || closed.get() && previous.is_none() || held) {
                        if txn
                            .get(JOBS, &expiry_key(caller, session))?
                            .as_deref()
                            .map(read_integer)
                            .transpose()?
                            .is_some_and(|v| v != until)
                        {
                            return Err(invalid(b"compute cancel deadline differs"));
                        }
                        match previous {
                            Some(raw) if read_integer(&raw)? != until => {
                                return Err(invalid(b"compute cancel deadline changed"))
                            }
                            Some(_) => {}
                            None => txn.put(JOBS, &key, &integer(until))?,
                        }
                    }
                } else {
                    txn.remove(JOBS, &key)?;
                }
                commit(txn)
            },
        )
    }
    pub fn cancel(&self, caller: &[u8], session: &[u8], expires: Option<i64>) -> Result<bool> {
        self.cancel_edit(caller, session, expires, |_| Ok(()))
    }
    pub fn cancel_deadline(&self, caller: &[u8], session: &[u8]) -> Result<Option<i64>> {
        self.read(b"compute history closed", |txn| {
            if txn
                .get(JOBS, &held_key(caller, session))?
                .as_deref()
                .map(read_integer)
                .transpose()?
                .is_some_and(|v| v > 0)
            {
                return Ok(None);
            }
            txn.get(JOBS, &expiry_key(caller, session))?
                .as_deref()
                .map(read_integer)
                .transpose()
        })
    }
    pub(super) fn take_output(
        txn: &mut octra_lmdb::Write<'_>,
        key: &[u8],
        limit: i64,
        now: i64,
    ) -> Result<bool> {
        if !(0..=i64::MAX - 60_000).contains(&now) {
            return Err(invalid(b"compute relay time"));
        }
        let current = window(txn, key, b"compute relay counter")?;
        let (next, count) = if now >= current.0 {
            (now + 60_000, 0)
        } else {
            current
        };
        if count >= limit {
            return Ok(false);
        }
        txn.put(
            IDENTITY,
            key,
            &[integer(next).as_slice(), &integer(count + 1)].concat(),
        )?;
        Ok(true)
    }
    fn claim_output(&self, key: &[u8], limit: i64, now: i64) -> Result<bool> {
        self.write(|txn| Self::take_output(txn, key, limit, now))
    }
    pub fn claim_relay(&self, now: i64) -> Result<bool> {
        self.claim_output(b"cancel_relay", CALLER_NOTICES as i64, now)
    }
    pub fn claim_transit(&self, now: i64) -> Result<bool> {
        self.claim_output(b"cancel_transit", TRANSIT_LIMIT, now)
    }
    pub fn claim_send(&self, local: bool, now: i64) -> Result<bool> {
        self.write(|txn| {
            if !(0..=i64::MAX - 60_000).contains(&now) {
                return Err(invalid(b"compute send time"));
            }
            let current = window(txn, b"compute_send", b"compute send counter")?;
            let (next, count) = if now >= current.0 {
                (now + 60_000, 0)
            } else {
                current
            };
            let (until, forwarded) = window(txn, b"compute_forward", b"compute send counter")?;
            let forwarded = if until == next { forwarded } else { 0 };
            if count >= SEND_LIMIT || !local && forwarded >= FORWARD_LIMIT {
                return Ok(false);
            }
            txn.put(
                IDENTITY,
                b"compute_send",
                &[integer(next).as_slice(), &integer(count + 1)].concat(),
            )?;
            txn.put(
                IDENTITY,
                b"compute_forward",
                &[
                    integer(next).as_slice(),
                    &integer(if local { forwarded } else { forwarded + 1 }),
                ]
                .concat(),
            )?;
            Ok(true)
        })
    }
}
fn window(txn: &octra_lmdb::Write<'_>, key: &[u8], label: &[u8]) -> Result<(i64, i64)> {
    let Some(raw) = txn.get(IDENTITY, key)? else {
        return Ok((0, 0));
    };
    if raw.len() != 16 {
        return Err(invalid(label));
    }
    Ok((read_integer(&raw[..8])?, read_integer(&raw[8..])?))
}
