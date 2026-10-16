// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native retained compute job and read-context framing. Decoding a record binds
//! its optional validator extension to the request; it does not verify selection,
//! finalized origins, funding, result agreement or program/model replay.
use super::{
    call::Call,
    capability::Capability,
    certificate::Vote,
    message::{self, CancelAck, Offer, Output},
    selection::{Commitment, Reveal},
    wire::Message,
    Error, Result,
};
use crate::{
    consensus::{codec::Wire, hash::validator_set_hash, ValidatorSet},
    oce1::{Reader, Writer},
};
use std::collections::BTreeSet;
pub const MAX_JOB_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REPLY_BYTES: usize = 263_168;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub offer: Offer,
    pub capabilities: Vec<Capability>,
    pub commitments: Vec<Commitment>,
    pub reveals: Vec<Reveal>,
    pub call: Call,
    pub results: Vec<Output>,
    pub validators: Option<ValidatorSet>,
}
fn require(valid: bool, reason: &[u8]) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(Error::rejected(reason))
    }
}
fn check_set(call: &Call, validators: &ValidatorSet) -> Result<()> {
    require(
        validator_set_hash(validators)?.as_slice() == call.request.validator_set_root,
        b"compute record validator root differs",
    )
}
fn put(out: &mut Writer, message: &Message) -> Result<()> {
    out.put_bytes(&message.encode()?)?;
    Ok(())
}
fn get(input: &mut Reader<'_>) -> Result<Message> {
    Message::decode(input.get_bytes_bounded(MAX_REPLY_BYTES)?)
}
fn put_list<T>(
    out: &mut Writer,
    values: &[T],
    limit: usize,
    message: impl Fn(&T) -> Message,
) -> Result<()> {
    require(values.len() <= limit, b"compute record count")?;
    out.put_u16(values.len() as u16)?;
    for value in values {
        put(out, &message(value))?;
    }
    Ok(())
}
fn get_list<T>(
    input: &mut Reader<'_>,
    limit: usize,
    convert: impl Fn(Message) -> Result<T>,
) -> Result<Vec<T>> {
    let count = usize::from(input.get_u16()?);
    require(count <= limit, b"compute record count")?;
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(convert(get(input)?)?);
    }
    Ok(values)
}
macro_rules! variant {
    ($value:expr,$variant:ident,$reason:literal) => {
        match $value {
            Message::$variant(value) => Ok(value),
            _ => Err(Error::rejected($reason)),
        }
    };
}
impl Record {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Writer::new();
        put(&mut out, &Message::Offer(self.offer.clone()))?;
        put_list(&mut out, &self.capabilities, message::MAX_RECORDS, |v| {
            Message::Capability(v.clone())
        })?;
        put_list(&mut out, &self.commitments, message::MAX_RECORDS, |v| {
            Message::Commitment(v.clone())
        })?;
        put_list(&mut out, &self.reveals, message::MAX_RECORDS, |v| {
            Message::Reveal(v.clone())
        })?;
        put(&mut out, &Message::Call(self.call.clone()))?;
        put_list(&mut out, &self.results, message::MAX_MEMBERS, |v| {
            Message::Result(v.clone())
        })?;
        if let Some(validators) = &self.validators {
            check_set(&self.call, validators)?;
            out.put_bytes(b"validators")?;
            out.put_bytes(&validators.encode()?)?;
        }
        let raw = out.into_bytes();
        require(raw.len() <= MAX_JOB_BYTES, b"compute record size")?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= MAX_JOB_BYTES, b"compute record size")?;
        let mut input = Reader::new(raw);
        let offer = variant!(get(&mut input)?, Offer, b"compute record offer")?;
        let capabilities = get_list(&mut input, message::MAX_RECORDS, |v| {
            variant!(v, Capability, b"compute record capability")
        })?;
        let commitments = get_list(&mut input, message::MAX_RECORDS, |v| {
            variant!(v, Commitment, b"compute record commitment")
        })?;
        let reveals = get_list(&mut input, message::MAX_RECORDS, |v| {
            variant!(v, Reveal, b"compute record reveal")
        })?;
        let call = variant!(get(&mut input)?, Call, b"compute record call")?;
        let results = get_list(&mut input, message::MAX_MEMBERS, |v| {
            variant!(v, Result, b"compute record result")
        })?;
        let validators = if input.remaining() == 0 {
            None
        } else {
            require(
                input.get_bytes_bounded(10)? == b"validators",
                b"compute record extension",
            )?;
            let validators = ValidatorSet::decode(input.get_bytes_bounded(MAX_JOB_BYTES)?)?;
            check_set(&call, &validators)?;
            Some(validators)
        };
        input.finish()?;
        Ok(Self {
            offer,
            capabilities,
            commitments,
            reveals,
            call,
            results,
            validators,
        })
    }
    pub fn job_space(&self, members: &[Vec<u8>]) -> Result<usize> {
        require(
            self.call.shape()?
                && self.results.is_empty()
                && !members.is_empty()
                && members.len() <= message::MAX_MEMBERS
                && members.iter().collect::<BTreeSet<_>>().len() == members.len(),
            b"compute job allocation shape",
        )?;
        let mut size = self.encode()?.len();
        for node in members {
            let frame = result_frame(&self.call, node)?;
            let mut out = Writer::new();
            out.put_bytes(&frame)?;
            size += out.into_bytes().len() + self.call.request.max_output_bytes as usize;
        }
        require(size <= MAX_JOB_BYTES, b"compute job exceeds history limit")?;
        Ok(size)
    }
}
pub fn encode_read(call: &Call, validators: &ValidatorSet) -> Result<Vec<u8>> {
    check_set(call, validators)?;
    let mut out = Writer::new();
    out.put_hash32(&call.sign_bytes()?)?;
    out.put_sig64(&call.signature)?;
    out.put_bytes(&validators.encode()?)?;
    let raw = out.into_bytes();
    require(raw.len() <= MAX_CONTEXT_BYTES, b"compute read context size")?;
    Ok(raw)
}
pub fn decode_read(call: &Call, raw: &[u8]) -> Result<ValidatorSet> {
    require(raw.len() <= MAX_CONTEXT_BYTES, b"compute read context size")?;
    let mut input = Reader::new(raw);
    let digest = input.get_hash32()?;
    let signature = input.get_sig64()?;
    require(
        digest == call.sign_bytes()? && signature.as_slice() == call.signature,
        b"compute read call differs",
    )?;
    let validators = ValidatorSet::decode(input.get_bytes_bounded(MAX_CONTEXT_BYTES)?)?;
    check_set(call, &validators)?;
    input.finish()?;
    Ok(validators)
}
pub fn encode_scope(call: &Call, validators: &ValidatorSet) -> Result<Vec<u8>> {
    let mut out = Writer::new();
    out.put_bytes(&Message::Call(call.clone()).encode()?)?;
    out.put_bytes(&encode_read(call, validators)?)?;
    let raw = out.into_bytes();
    require(raw.len() <= MAX_CONTEXT_BYTES, b"compute scope size")?;
    Ok(raw)
}
pub fn decode_scope(raw: &[u8]) -> Result<(Call, ValidatorSet)> {
    require(raw.len() <= MAX_CONTEXT_BYTES, b"compute scope size")?;
    let mut input = Reader::new(raw);
    let call = variant!(
        Message::decode(input.get_bytes_bounded(MAX_CONTEXT_BYTES)?)?,
        Call,
        b"compute scope call"
    )?;
    let validators = decode_read(&call, input.get_bytes_bounded(MAX_CONTEXT_BYTES)?)?;
    input.finish()?;
    Ok((call, validators))
}
fn result_frame(call: &Call, node: &[u8]) -> Result<Vec<u8>> {
    Message::Result(Output {
        vote: Vote {
            request_id: call.request.id()?.to_vec(),
            node_id: node.to_vec(),
            output_hash: vec![0; 32],
            trace_root: vec![0; 32],
            output_bytes: 0,
            steps: 0,
            operations: 0,
            signature: vec![0; 64],
        },
        output_json: vec![],
    })
    .encode()
}
pub fn reply_space(call: &Call, validators: &ValidatorSet, node: &[u8]) -> Result<usize> {
    require(call.shape()?, b"compute reply request shape")?;
    let size = result_frame(call, node)?.len() + call.request.max_output_bytes as usize;
    require(
        size <= MAX_REPLY_BYTES,
        b"compute reply exceeds history limit",
    )?;
    Ok(size + encode_read(call, validators)?.len())
}
pub fn select(votes: &[Vote], results: &[Output]) -> Result<Vec<Output>> {
    votes
        .iter()
        .map(|vote| {
            results
                .iter()
                .find(|result| result.vote == *vote)
                .cloned()
                .ok_or_else(|| Error::rejected(b"compute record vote absent"))
        })
        .collect()
}
pub fn select_cancels(
    call: &Call,
    validators: &ValidatorSet,
    members: &[Vec<u8>],
    acks: &[CancelAck],
) -> Result<Vec<CancelAck>> {
    check_set(call, validators)?;
    let mut selected = acks
        .iter()
        .filter(|ack| {
            let cancel = &ack.delivery.cancel;
            members.contains(&ack.node_id)
                && cancel.chain_id == call.request.chain_id
                && cancel.caller == call.request.caller
                && cancel.session_id == call.request.session_id
                && cancel.caller_public_key == call.caller_public_key
                && cancel
                    .until
                    .is_none_or(|until| call.valid_until == Some(until))
                && ack.delivery.origin == call.coordinator
                && validators.public_key(&ack.node_id) == Some(ack.node_key.as_slice())
                && validators.public_key(&call.coordinator) == Some(ack.origin_key.as_slice())
        })
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    Ok(selected)
}
