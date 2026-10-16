// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native compute message tags, including historical call limit extensions.
//! Like upstream, raw decoding does not shape-check offers, calls or outputs.
mod body;
use super::{
    call::{Call, MAX_METHOD, MAX_OUTPUT, MAX_PARAMS},
    capability::{Accelerator, Capability},
    certificate::Vote,
    message::{CancelAck, CancelRound, Cancellation, Fetch, Offer, Output},
    request::{Limits, Request},
    selection::{Commitment, Reveal},
    Error, Result,
};
use crate::{
    consensus::codec::Wire,
    oce1::{Reader, Writer},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Offer(Offer),
    Capability(Capability),
    Commitment(Commitment),
    Reveal(Reveal),
    Call(Call),
    Result(Output),
    Cancel(Cancellation),
    CancelRound(CancelRound),
    CancelAck(CancelAck),
    Fetch(Fetch),
    Answer(Fetch, Output),
}
fn string(input: &mut Reader<'_>, max: usize) -> Result<Vec<u8>> {
    Ok(input.get_bytes_bounded(max)?.to_vec())
}
fn int64(input: &mut Reader<'_>) -> Result<i64> {
    Ok(input.get_u64()? as i64)
}
fn int32(input: &mut Reader<'_>) -> Result<i64> {
    Ok(i64::from(input.get_u32()? as i32))
}
fn check(valid: bool, reason: &[u8]) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(Error::rejected(reason))
    }
}
fn call_level(call: &Call) -> u8 {
    let limits = call.request.limits;
    if limits.unit_price.is_some() {
        5
    } else if limits.memory_bytes.is_some() {
        4
    } else if limits.guest_bytes.is_some() {
        3
    } else if limits.fuel_limit.is_some() {
        2
    } else {
        u8::from(call.valid_until.is_some())
    }
}
fn put_call(out: &mut Writer, call: &Call) -> Result<()> {
    if let Some(value) = call.valid_until {
        out.put_u64(value as u64)?;
    }
    let limits = call.request.limits;
    for value in [limits.fuel_limit, limits.guest_bytes, limits.memory_bytes]
        .into_iter()
        .flatten()
    {
        out.put_u32(value as u32)?;
    }
    for value in [limits.unit_price, limits.fee_cap].into_iter().flatten() {
        out.put_u64(value as u64)?;
    }
    call.request.put_base(out)?;
    out.put_bytes(&call.method_name)?;
    out.put_bytes(&call.params_json)?;
    out.put_hash32(&call.caller_public_key)?;
    out.put_sig64(&call.caller_signature)?;
    out.put_bytes(&call.coordinator)?;
    out.put_sig64(&call.signature)?;
    Ok(())
}
fn get_call(input: &mut Reader<'_>, level: u8) -> Result<Call> {
    let valid_until = if level >= 1 {
        Some(int64(input)?)
    } else {
        None
    };
    let fuel_limit = if level >= 2 {
        Some(int32(input)?)
    } else {
        None
    };
    let guest_bytes = if level >= 3 {
        Some(int32(input)?)
    } else {
        None
    };
    let memory_bytes = if level >= 4 {
        Some(i64::from(input.get_u32()?))
    } else {
        None
    };
    let unit_price = if level >= 5 {
        Some(int64(input)?)
    } else {
        None
    };
    let fee_cap = if level >= 5 {
        Some(int64(input)?)
    } else {
        None
    };
    let request = Request::get_base(
        input,
        Limits {
            unit_price,
            fee_cap,
            memory_bytes,
            guest_bytes,
            fuel_limit,
        },
    )?;
    Ok(Call {
        request,
        valid_until,
        method_name: string(input, MAX_METHOD)?,
        params_json: string(input, MAX_PARAMS)?,
        caller_public_key: input.get_hash32()?.to_vec(),
        caller_signature: input.get_sig64()?.to_vec(),
        coordinator: string(input, 128)?,
        signature: input.get_sig64()?.to_vec(),
    })
}
fn put_output(out: &mut Writer, value: &Output) -> Result<()> {
    value.vote.put(out)?;
    out.put_bytes(&value.output_json)?;
    Ok(())
}
fn get_output(input: &mut Reader<'_>) -> Result<Output> {
    Ok(Output {
        vote: Vote::get(input)?,
        output_json: string(input, MAX_OUTPUT)?,
    })
}
fn put_fetch(out: &mut Writer, value: &Fetch) -> Result<()> {
    check(value.shape()?, b"compute fetch shape")?;
    put_call(out, &value.call)?;
    out.put_bytes(&value.target)?;
    out.put_u64(value.epoch_id as u64)?;
    out.put_u64(value.expires_epoch as u64)?;
    out.put_u8(value.round as u8)?;
    out.put_sig64(&value.signature)?;
    Ok(())
}
fn get_fetch(input: &mut Reader<'_>, level: u8) -> Result<Fetch> {
    let value = Fetch {
        call: get_call(input, level)?,
        target: string(input, 128)?,
        epoch_id: int64(input)?,
        expires_epoch: int64(input)?,
        round: i64::from(input.get_u8()?),
        signature: input.get_sig64()?.to_vec(),
    };
    check(value.shape()?, b"compute fetch shape")?;
    Ok(value)
}
fn put_cancel(out: &mut Writer, value: &Cancellation) -> Result<()> {
    check(value.shape(), b"resource compute cancellation")?;
    out.put_bytes(&value.chain_id)?;
    out.put_bytes(&value.caller)?;
    out.put_hash32(&value.caller_public_key)?;
    out.put_hash32(&value.session_id)?;
    out.put_sig64(&value.caller_signature)?;
    if let Some(until) = value.until {
        out.put_u64(until as u64)?;
    }
    Ok(())
}
fn get_cancel(input: &mut Reader<'_>, timed: bool) -> Result<Cancellation> {
    Ok(Cancellation {
        chain_id: string(input, 128)?,
        caller: string(input, 128)?,
        caller_public_key: input.get_hash32()?.to_vec(),
        session_id: input.get_hash32()?.to_vec(),
        caller_signature: input.get_sig64()?.to_vec(),
        until: if timed { Some(int64(input)?) } else { None },
    })
}
fn put_round(out: &mut Writer, value: &CancelRound) -> Result<()> {
    check(value.shape(), b"compute cancel round shape")?;
    put_cancel(out, &value.cancel)?;
    out.put_bytes(&value.origin)?;
    out.put_u64(value.epoch as u64)?;
    out.put_u64(value.expires as u64)?;
    out.put_u8(value.round as u8)?;
    out.put_sig64(&value.signature)?;
    Ok(())
}
fn get_round(input: &mut Reader<'_>, timed: bool) -> Result<CancelRound> {
    let value = CancelRound {
        cancel: get_cancel(input, timed)?,
        origin: string(input, 128)?,
        epoch: int64(input)?,
        expires: int64(input)?,
        round: i64::from(input.get_u8()?),
        signature: input.get_sig64()?.to_vec(),
    };
    check(value.shape(), b"compute cancel round shape")?;
    Ok(value)
}
impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Writer::new();
        match self {
            Self::Offer(value) => {
                out.put_u8(1)?;
                value.put(&mut out)?;
            }
            Self::Capability(value) => {
                out.put_u8(2)?;
                value.put(&mut out)?;
            }
            Self::Commitment(value) => {
                out.put_u8(3)?;
                value.put(&mut out)?;
            }
            Self::Reveal(value) => {
                out.put_u8(4)?;
                value.put(&mut out)?;
            }
            Self::Call(value) => {
                out.put_u8([5, 10, 13, 16, 19, 22][call_level(value) as usize])?;
                put_call(&mut out, value)?;
            }
            Self::Result(value) => {
                out.put_u8(6)?;
                put_output(&mut out, value)?;
            }
            Self::Cancel(value) => {
                out.put_u8(if value.until.is_some() { 27 } else { 7 })?;
                put_cancel(&mut out, value)?;
            }
            Self::CancelRound(value) => {
                out.put_u8(if value.cancel.until.is_some() { 28 } else { 25 })?;
                put_round(&mut out, value)?;
            }
            Self::CancelAck(value) => {
                check(value.shape(), b"compute cancel ack shape")?;
                out.put_u8(if value.delivery.cancel.until.is_some() {
                    29
                } else {
                    26
                })?;
                put_round(&mut out, &value.delivery)?;
                out.put_hash32(&value.origin_key)?;
                out.put_bytes(&value.node_id)?;
                out.put_hash32(&value.node_key)?;
                out.put_u64(value.epoch as u64)?;
                out.put_sig64(&value.signature)?;
            }
            Self::Fetch(value) => {
                out.put_u8([8, 11, 14, 17, 20, 23][call_level(&value.call) as usize])?;
                put_fetch(&mut out, value)?;
            }
            Self::Answer(fetch, value) => {
                out.put_u8([9, 12, 15, 18, 21, 24][call_level(&fetch.call) as usize])?;
                put_fetch(&mut out, fetch)?;
                put_output(&mut out, value)?;
            }
        }
        Ok(out.into_bytes())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut input = Reader::new(raw);
        let tag = input.get_u8()?;
        let value = match tag {
            1 => Self::Offer(Offer::get(&mut input)?),
            2 => Self::Capability(Capability::get(&mut input)?),
            3 => Self::Commitment(Commitment::get(&mut input)?),
            4 => Self::Reveal(Reveal::get(&mut input)?),
            5 | 10 | 13 | 16 | 19 | 22 => Self::Call(get_call(
                &mut input,
                if tag == 5 { 0 } else { (tag - 7) / 3 },
            )?),
            6 => Self::Result(get_output(&mut input)?),
            7 | 27 => Self::Cancel(get_cancel(&mut input, tag == 27)?),
            25 | 28 => Self::CancelRound(get_round(&mut input, tag == 28)?),
            26 | 29 => {
                let delivery = get_round(&mut input, tag == 29)?;
                let value = CancelAck {
                    delivery,
                    origin_key: input.get_hash32()?.to_vec(),
                    node_id: string(&mut input, 128)?,
                    node_key: input.get_hash32()?.to_vec(),
                    epoch: int64(&mut input)?,
                    signature: input.get_sig64()?.to_vec(),
                };
                check(value.shape(), b"compute cancel ack shape")?;
                Self::CancelAck(value)
            }
            8 | 11 | 14 | 17 | 20 | 23 => Self::Fetch(get_fetch(
                &mut input,
                if tag == 8 { 0 } else { (tag - 8) / 3 },
            )?),
            9 | 12 | 15 | 18 | 21 | 24 => {
                let fetch = get_fetch(&mut input, (tag - 9) / 3)?;
                Self::Answer(fetch, get_output(&mut input)?)
            }
            _ => return Err(Error::rejected(b"bad resource compute message tag")),
        };
        input.finish()?;
        Ok(value)
    }
}
