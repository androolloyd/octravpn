// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    codec::{integer, read_integer, scope_key, scope_prefix, session_key, Row, Saved, Scope},
    invalid, Error, History, Result, CALLERS, JOBS, MAX_CONTEXT_BYTES, MAX_REPLY_BYTES, SESSIONS,
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Work,
    Control,
    Complete,
}
fn identity(caller: &[u8], session: &[u8]) -> bool {
    !caller.is_empty() && caller.len() <= 128 && session.len() == 32
}
pub(super) fn archive(
    txn: &mut octra_lmdb::Write<'_>,
    caller: &[u8],
    session: &[u8],
    raw: &[u8],
) -> Result<()> {
    let scope = Scope::decode(raw)?;
    let key = [
        scope_prefix(caller, session).as_slice(),
        &integer(scope.sequence),
    ]
    .concat();
    match txn.get(JOBS, &key)? {
        Some(previous) if previous != raw => Err(invalid(b"compute scope archive changed")),
        Some(_) => Ok(()),
        None => {
            txn.put(JOBS, &key, raw)?;
            Ok(())
        }
    }
}
pub(super) fn put_scope(
    txn: &mut octra_lmdb::Write<'_>,
    caller: &[u8],
    session: &[u8],
    value: &Scope,
) -> Result<()> {
    let key = scope_key(caller, session);
    let raw = value.encode()?;
    if let Some(previous) = txn.get(JOBS, &key)? {
        let scope = Scope::decode(&previous)?;
        if scope.sequence > value.sequence || scope.sequence == value.sequence && previous != raw {
            return Err(invalid(b"compute scope changed"));
        }
        archive(txn, caller, session, &previous)?;
    }
    archive(txn, caller, session, &raw)?;
    txn.put(JOBS, &key, &raw)?;
    Ok(())
}
impl History {
    pub(super) fn edit<T>(
        &self,
        mode: Mode,
        caller: &[u8],
        session: &[u8],
        change: impl FnOnce(Option<&Row>) -> Result<(Option<Row>, T)>,
        commit: impl FnOnce(&mut octra_lmdb::Write<'_>) -> Result<()>,
    ) -> Result<T> {
        self.write(|txn| {
            if !identity(caller, session) {
                return Err(invalid(b"compute history request shape"));
            }
            let key = session_key(caller, session);
            let previous = txn
                .get(SESSIONS, &key)?
                .as_deref()
                .map(Row::decode)
                .transpose()?;
            let (updated, accepted) = change(previous.as_ref())?;
            if let Some(row) = updated {
                let held = match (&previous, &row, mode) {
                    (
                        Some(Row::Reserved {
                            room: Some(size), ..
                        }),
                        Row::Finished { .. },
                        Mode::Complete,
                    ) => Some(*size),
                    _ => None,
                };
                let before = held.map(|_| txn.live_bytes()).transpose()?;
                if previous.is_none() {
                    let count = txn
                        .get(CALLERS, caller)?
                        .as_deref()
                        .map(read_integer)
                        .transpose()?
                        .unwrap_or(0);
                    if count >= self.caller_limit || txn.count(SESSIONS)? >= self.max_sessions {
                        return Err(invalid(b"compute history session capacity"));
                    }
                    txn.put(CALLERS, caller, &integer(count + 1))?;
                }
                let raw = match (held, &row) {
                    (
                        Some(size),
                        Row::Finished {
                            sequence,
                            request,
                            saved,
                        },
                    ) => Row::complete_bytes(*sequence, request, saved, size, self.page)?,
                    _ => row.encode()?,
                };
                if held.is_some_and(|size| raw.len() < size) {
                    txn.remove(SESSIONS, &key)?;
                }
                txn.put(SESSIONS, &key, &raw)?;
                commit(txn)?;
                match before {
                    Some(before) if txn.live_bytes()? > before => {
                        return Err(invalid(b"compute reserved reply grew storage"))
                    }
                    None if !(mode == Mode::Control && previous.is_some()) => {
                        Self::check_work(txn)?;
                    }
                    Some(_) | None => {}
                }
            }
            Ok(accepted)
        })
    }
    pub fn ensure(&self, caller: &[u8], session: &[u8]) -> Result<bool> {
        self.edit(
            Mode::Work,
            caller,
            session,
            |previous| {
                Ok(match previous {
                    Some(Row::Cancelled) => (None, false),
                    Some(_) => (None, true),
                    None => (Some(Row::Ready), true),
                })
            },
            |_| Ok(()),
        )
    }
    pub fn cancelled(&self, caller: &[u8], session: &[u8]) -> Result<bool> {
        self.edit(
            Mode::Work,
            caller,
            session,
            |previous| Ok((None, matches!(previous, Some(Row::Cancelled)))),
            |_| Ok(()),
        )
    }
    pub fn reserve(
        &self,
        caller: &[u8],
        session: &[u8],
        sequence: i64,
        request: &[u8],
        scope: Option<&[u8]>,
        room: Option<usize>,
    ) -> Result<bool> {
        let room = room.unwrap_or(MAX_REPLY_BYTES + MAX_CONTEXT_BYTES);
        if sequence < 0
            || request.len() != 32
            || !(1..=MAX_REPLY_BYTES + MAX_CONTEXT_BYTES).contains(&room)
            || scope.is_some_and(|body| body.is_empty() || body.len() > MAX_CONTEXT_BYTES)
        {
            return Err(Error(b"compute history request shape".to_vec()));
        }
        self.edit(Mode::Work,caller,session,|previous| {
            let accepted=!matches!(previous,Some(Row::Cancelled)) && !matches!(previous,
                Some(Row::Reserved {sequence:saved,..}|Row::Finished {sequence:saved,..}) if sequence<=*saved);
            Ok((accepted.then(||Row::Reserved {sequence,request:request.to_vec(),room:Some(57+room.max(self.page))}),accepted))
        },|txn| {
            if let Some(body)=scope {put_scope(txn,caller,session,&Scope {sequence,request:request.to_vec(),body:body.to_vec()})}
            else {
                let key=scope_key(caller,session);
                if let Some(previous)=txn.get(JOBS,&key)? {archive(txn,caller,session,&previous)?;txn.remove(JOBS,&key)?;}
                Ok(())
            }
        })
    }
    pub fn scope(&self, caller: &[u8], session: &[u8]) -> Result<Option<Scope>> {
        if !identity(caller, session) {
            return Err(invalid(b"compute scope read shape"));
        }
        self.read(b"compute scope read shape", |txn| {
            txn.get(JOBS, &scope_key(caller, session))?
                .as_deref()
                .map(Scope::decode)
                .transpose()
        })
    }
    pub fn find_scope(
        &self,
        caller: &[u8],
        session: &[u8],
        mut accept: impl FnMut(&Scope) -> bool,
    ) -> Result<Option<Scope>> {
        if !identity(caller, session) {
            return Err(invalid(b"compute scope read shape"));
        }
        self.read(b"compute scope read shape", |txn| {
            let latest = txn
                .get(JOBS, &scope_key(caller, session))?
                .as_deref()
                .map(Scope::decode)
                .transpose()?;
            if latest.as_ref().is_some_and(&mut accept) {
                return Ok(latest);
            }
            let prefix = scope_prefix(caller, session);
            txn.find(JOBS, &prefix, |key, raw| {
                if key.len() != prefix.len() + 8 {
                    return Err(invalid(b"compute scope archive key"));
                }
                let scope = Scope::decode(raw)?;
                if key[prefix.len()..] != integer(scope.sequence) {
                    return Err(invalid(b"compute scope archive sequence"));
                }
                Ok(accept(&scope).then_some(scope))
            })
        })
    }
    pub fn finish(
        &self,
        caller: &[u8],
        session: &[u8],
        sequence: i64,
        request: &[u8],
        reply: &[u8],
        context: Option<&[u8]>,
    ) -> Result<bool> {
        if sequence < 0
            || request.len() != 32
            || reply.is_empty()
            || reply.len() > MAX_REPLY_BYTES
            || context.is_some_and(|body| body.is_empty() || body.len() > MAX_CONTEXT_BYTES)
        {
            return Err(Error(b"compute history reply shape".to_vec()));
        }
        let saved = Saved {
            reply: reply.to_vec(),
            context: context.map(<[u8]>::to_vec),
        };
        self.edit(
            Mode::Complete,
            caller,
            session,
            |previous| {
                Ok(match previous {
                    Some(Row::Reserved {
                        sequence: prior,
                        request: id,
                        ..
                    }) if *prior == sequence && id == request => (
                        Some(Row::Finished {
                            sequence,
                            request: request.to_vec(),
                            saved,
                        }),
                        true,
                    ),
                    Some(Row::Finished {
                        sequence: prior,
                        request: id,
                        saved: old,
                    }) => (None, *prior == sequence && id == request && *old == saved),
                    _ => (None, false),
                })
            },
            |_| Ok(()),
        )
    }
    pub fn saved(
        &self,
        caller: &[u8],
        session: &[u8],
        sequence: i64,
        request: &[u8],
    ) -> Result<Option<Saved>> {
        if sequence < 0 || request.len() != 32 {
            return Err(Error(b"compute history request shape".to_vec()));
        }
        self.edit(
            Mode::Work,
            caller,
            session,
            |previous| {
                Ok((
                    None,
                    match previous {
                        Some(Row::Finished {
                            sequence: prior,
                            request: id,
                            saved,
                        }) if *prior == sequence && id == request => Some(saved.clone()),
                        _ => None,
                    },
                ))
            },
            |_| Ok(()),
        )
    }
    pub fn reply(
        &self,
        caller: &[u8],
        session: &[u8],
        sequence: i64,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .saved(caller, session, sequence, request)?
            .map(|saved| saved.reply))
    }
}
