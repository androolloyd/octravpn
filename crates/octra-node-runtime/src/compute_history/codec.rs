// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native LMDB byte keys and row encodings, including reserved-space padding.
//! These decoders refuse corrupt records; absence is handled by the store.
use super::{
    allocation, invalid, Result, MAX_CONTEXT_BYTES, MAX_JOB_BYTES, MAX_NOTICE_BYTES,
    MAX_REPLY_BYTES, NOTICE_ROUNDS,
};

pub fn integer(value: i64) -> [u8; 8] {
    value.to_be_bytes()
}
pub fn read_integer(raw: &[u8]) -> Result<i64> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| invalid(b"compute history integer length"))?;
    let value = i64::from_be_bytes(bytes);
    if value < 0 {
        Err(invalid(b"compute history negative integer"))
    } else {
        Ok(value)
    }
}
fn number(raw: &[u8], offset: usize) -> Result<i64> {
    read_integer(
        raw.get(offset..offset + 8)
            .ok_or_else(|| invalid(b"String.sub / Bytes.sub"))?,
    )
}
fn zeros(raw: &[u8], start: usize) -> bool {
    raw.get(start..)
        .is_some_and(|raw| raw.iter().all(|byte| *byte == 0))
}
pub fn padded(size: usize, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > size {
        return Err(invalid(b"compute reply exceeds reserved space"));
    }
    let mut out = Vec::new();
    out.try_reserve_exact(size).map_err(|_| allocation())?;
    out.extend_from_slice(body);
    out.resize(size, 0);
    Ok(out)
}
pub fn session_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    [integer(caller.len() as i64).as_slice(), caller, session].concat()
}
pub fn scoped_key(tag: u8, caller: &[u8], session: &[u8]) -> Vec<u8> {
    [&[tag], session_key(caller, session).as_slice()].concat()
}
pub fn scope_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(8, caller, session)
}
pub fn scope_prefix(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(9, caller, session)
}
pub fn held_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(11, caller, session)
}
pub fn until_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(12, caller, session)
}
pub fn expiry_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(13, caller, session)
}
pub fn notice_key(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(5, caller, session)
}
pub fn ack_prefix(caller: &[u8], session: &[u8]) -> Vec<u8> {
    scoped_key(7, caller, session)
}
pub fn job_key(caller: &[u8], id: &[u8]) -> Result<Vec<u8>> {
    if caller.is_empty() || caller.len() > 128 || id.len() != 32 {
        return Err(invalid(b"compute job identity shape"));
    }
    Ok(session_key(caller, id))
}
pub fn job_refs(caller: &[u8], session: &[u8]) -> Result<Vec<u8>> {
    Ok([b"\x0a".as_slice(), &job_key(caller, session)?].concat())
}
pub fn split_job(key: &[u8]) -> Result<(&[u8], &[u8])> {
    if key.len() < 42 {
        return Err(invalid(b"compute job key size"));
    }
    let size = number(key, 1)?;
    if !(1..=128).contains(&size) || size as usize != key.len() - 41 {
        return Err(invalid(b"compute job key caller"));
    }
    let end = 9 + size as usize;
    Ok((&key[9..end], &key[end..]))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub reply: Vec<u8>,
    pub context: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub sequence: i64,
    pub request: Vec<u8>,
    pub body: Vec<u8>,
}
impl Scope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.sequence < 0
            || self.request.len() != 32
            || self.body.is_empty()
            || self.body.len() > MAX_CONTEXT_BYTES
        {
            return Err(invalid(b"compute scope shape"));
        }
        Ok([integer(self.sequence).as_slice(), &self.request, &self.body].concat())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() <= 40 || raw.len() > 40 + MAX_CONTEXT_BYTES {
            return Err(invalid(b"compute scope length"));
        }
        Ok(Self {
            sequence: number(raw, 0)?,
            request: raw[8..40].to_vec(),
            body: raw[40..].to_vec(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Row {
    Ready,
    Cancelled,
    Reserved {
        sequence: i64,
        request: Vec<u8>,
        room: Option<usize>,
    },
    Finished {
        sequence: i64,
        request: Vec<u8>,
        saved: Saved,
    },
}
impl Row {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let len = raw.len();
        if raw.is_empty() {
            return Ok(Self::Ready);
        }
        if raw == b"\x01" {
            return Ok(Self::Cancelled);
        }
        if len == 40 {
            return Ok(Self::Reserved {
                sequence: number(raw, 0)?,
                request: raw[8..].to_vec(),
                room: None,
            });
        }
        if len > 41 && len <= 41 + MAX_REPLY_BYTES && raw[0] == 2 {
            return Ok(Self::Finished {
                sequence: number(raw, 1)?,
                request: raw[9..41].to_vec(),
                saved: Saved {
                    reply: raw[41..].to_vec(),
                    context: None,
                },
            });
        }
        if len > 49 && raw[0] == 3 {
            let size = number(raw, 41)?;
            if size < 1 || size > MAX_REPLY_BYTES as i64 {
                return Err(invalid(b"compute history reply length"));
            }
            let rest = len as i64 - 49 - size;
            if rest < 1 || rest > MAX_CONTEXT_BYTES as i64 {
                return Err(invalid(b"compute history context length"));
            }
            let end = 49 + size as usize;
            return Ok(Self::Finished {
                sequence: number(raw, 1)?,
                request: raw[9..41].to_vec(),
                saved: Saved {
                    reply: raw[49..end].to_vec(),
                    context: Some(raw[end..].to_vec()),
                },
            });
        }
        if len > 57
            && len <= 57 + MAX_REPLY_BYTES + MAX_CONTEXT_BYTES
            && raw[0] == 4
            && zeros(raw, 41)
        {
            return Ok(Self::Reserved {
                sequence: number(raw, 1)?,
                request: raw[9..41].to_vec(),
                room: Some(len),
            });
        }
        if len > 57 && len <= 57 + MAX_REPLY_BYTES + MAX_CONTEXT_BYTES && raw[0] == 5 {
            let size = number(raw, 41)?;
            let context = number(raw, 49)?;
            if size < 1
                || size > MAX_REPLY_BYTES as i64
                || context > MAX_CONTEXT_BYTES as i64
                || size + context > (len - 57) as i64
            {
                return Err(invalid(b"compute reserved reply length"));
            }
            let end = 57 + size as usize;
            let last = end + context as usize;
            if !zeros(raw, last) {
                return Err(invalid(b"compute reserved reply padding"));
            }
            return Ok(Self::Finished {
                sequence: number(raw, 1)?,
                request: raw[9..41].to_vec(),
                saved: Saved {
                    reply: raw[57..end].to_vec(),
                    context: (context != 0).then(|| raw[end..last].to_vec()),
                },
            });
        }
        Err(invalid(b"compute history row length"))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Ready => Ok(vec![]),
            Self::Cancelled => Ok(vec![1]),
            Self::Reserved {
                sequence,
                request,
                room: None,
            } => Ok([integer(*sequence).as_slice(), request].concat()),
            Self::Reserved {
                sequence,
                request,
                room: Some(size),
            } => padded(
                *size,
                &[b"\x04".as_slice(), &integer(*sequence), request].concat(),
            ),
            Self::Finished {
                sequence,
                request,
                saved:
                    Saved {
                        reply,
                        context: None,
                    },
            } => Ok([b"\x02".as_slice(), &integer(*sequence), request, reply].concat()),
            Self::Finished {
                sequence,
                request,
                saved:
                    Saved {
                        reply,
                        context: Some(context),
                    },
            } => Ok([
                b"\x03".as_slice(),
                &integer(*sequence),
                request,
                &integer(reply.len() as i64),
                reply,
                context,
            ]
            .concat()),
        }
    }
    pub fn complete_bytes(
        sequence: i64,
        request: &[u8],
        saved: &Saved,
        held: usize,
        page: usize,
    ) -> Result<Vec<u8>> {
        let context = saved.context.as_deref().unwrap_or_default();
        let body = [
            b"\x05".as_slice(),
            &integer(sequence),
            request,
            &integer(saved.reply.len() as i64),
            &integer(context.len() as i64),
            &saved.reply,
            context,
        ]
        .concat();
        if body.len() > held {
            return Err(invalid(b"compute reply exceeds reserved space"));
        }
        padded((57 + page).max(body.len()), &body)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Work {
    Planned(Vec<u8>),
    Funding(Vec<u8>),
    Issued(Vec<u8>),
}
impl Work {
    pub fn body(&self) -> &[u8] {
        match self {
            Self::Planned(body) | Self::Funding(body) | Self::Issued(body) => body,
        }
    }
    fn tag(&self) -> u8 {
        match self {
            Self::Planned(_) => 0,
            Self::Funding(_) => 4,
            Self::Issued(_) => 1,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        [&[self.tag()], self.body()].concat()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Pending(Work),
    Stored(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRow {
    pub session: Vec<u8>,
    pub value: JobState,
    pub room: Option<usize>,
}
impl JobRow {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let len = raw.len();
        if !(34..=41 + MAX_JOB_BYTES).contains(&len) {
            return Err(invalid(b"compute work row shape"));
        }
        let session = raw[..32].to_vec();
        let tag = raw[32];
        if matches!(tag, 0 | 1 | 4) && len <= 33 + MAX_JOB_BYTES {
            let body = raw[33..].to_vec();
            let work = match tag {
                0 => Work::Planned(body),
                4 => Work::Funding(body),
                _ => Work::Issued(body),
            };
            return Ok(Self {
                session,
                value: JobState::Pending(work),
                room: None,
            });
        }
        if matches!(tag, 2 | 3 | 5) && len > 41 {
            let size = number(raw, 33)?;
            if size < 1 || size > MAX_JOB_BYTES as i64 || size > (len - 41) as i64 {
                return Err(invalid(b"compute work payload size"));
            }
            let end = 41 + size as usize;
            if !zeros(raw, end) {
                return Err(invalid(b"compute work padding"));
            }
            let body = raw[41..end].to_vec();
            let value = match tag {
                2 => JobState::Pending(Work::Issued(body)),
                5 => JobState::Pending(Work::Funding(body)),
                _ => JobState::Stored(body),
            };
            return Ok(Self {
                session,
                value,
                room: Some(len),
            });
        }
        Err(invalid(b"compute work stage"))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        match (&self.room, &self.value) {
            (None, JobState::Pending(work)) => {
                Ok([self.session.as_slice(), &work.encode()].concat())
            }
            (
                Some(size),
                JobState::Pending(Work::Issued(body) | Work::Funding(body))
                | JobState::Stored(body),
            ) => {
                let tag = match &self.value {
                    JobState::Stored(_) => 3,
                    JobState::Pending(Work::Funding(_)) => 5,
                    JobState::Pending(_) => 2,
                };
                let bytes = [
                    self.session.as_slice(),
                    &[tag],
                    &integer(body.len() as i64),
                    body,
                ]
                .concat();
                if bytes.len() > *size {
                    return Err(invalid(b"compute job exceeds reserved space"));
                }
                padded(*size, &bytes)
            }
            _ => Err(invalid(b"compute work allocation stage")),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub caller: Vec<u8>,
    pub session: Vec<u8>,
    pub expires: i64,
    pub round: i64,
    pub body: Vec<u8>,
}
impl Notice {
    pub fn encode(&self) -> Vec<u8> {
        [
            integer(self.expires).as_slice(),
            &integer(self.round),
            &self.body,
        ]
        .concat()
    }
    pub fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.len() < 42 || key[0] != 5 || value.len() < 17 || value.len() > 16 + MAX_NOTICE_BYTES
        {
            return Err(invalid(b"compute cancel row shape"));
        }
        let size = number(key, 1)?;
        if !(1..=128).contains(&size) || size as usize != key.len() - 41 {
            return Err(invalid(b"compute cancel caller shape"));
        }
        let round = number(value, 8)?;
        if round > NOTICE_ROUNDS {
            return Err(invalid(b"compute cancel round"));
        }
        let end = 9 + size as usize;
        Ok(Self {
            caller: key[9..end].to_vec(),
            session: key[end..].to_vec(),
            expires: number(value, 0)?,
            round,
            body: value[16..].to_vec(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    pub origin: Vec<u8>,
    pub expires: i64,
    pub round: i64,
}
impl Relay {
    pub fn decode(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.len() < 42 || value.len() != 16 {
            return Err(invalid(b"compute cancel relay shape"));
        }
        let size = number(key, 1)?;
        if !(1..=128).contains(&size) || size as usize != key.len() - 41 {
            return Err(invalid(b"compute cancel relay origin"));
        }
        let expires = number(value, 0)?;
        let round = number(value, 8)?;
        if !(1..=NOTICE_ROUNDS).contains(&round) {
            return Err(invalid(b"compute cancel relay round"));
        }
        Ok(Self {
            origin: key[9..9 + size as usize].to_vec(),
            expires,
            round,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        [integer(self.expires).as_slice(), &integer(self.round)].concat()
    }
}
