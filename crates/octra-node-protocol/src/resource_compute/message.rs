// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native compute control messages and signing scopes. Transport decoding does
//! not establish validator membership, caller authority or finalized origins.
use super::{
    call::{self, Call},
    certificate::Vote,
    hash, nonempty, Error, Result,
};
pub const MAX_MEMBERS: usize = 5;
pub const MAX_RECORDS: usize = 256;
pub const REVEAL_DELAY: i64 = 1;
pub const OFFER_TTL: i64 = 16;
pub const CAPACITY_TTL: i64 = 16;
pub const CANCEL_ROUNDS: i64 = 64;
pub const CANCEL_SPAN: i64 = 64;
pub const FETCH_ROUNDS: i64 = 8;
pub const FETCH_SPAN: i64 = 4;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub chain_id: Vec<u8>,
    pub offered_epoch: i64,
    pub expires_epoch: i64,
    pub coordinator: Vec<u8>,
    pub validator_set_root: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub min_memory_bytes: i64,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub signature: Vec<u8>,
}
impl Offer {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && self.offered_epoch >= 0
            && self.expires_epoch >= self.offered_epoch
            && nonempty(&self.coordinator, 128)
            && self.validator_set_root.len() == 32
            && nonempty(&self.circle_id, 128)
            && self.model_epoch >= 0
            && [
                &self.model_state_root,
                &self.graph_root,
                &self.model_root,
                &self.program_root,
                &self.executor_root,
            ]
            .iter()
            .all(|v| v.len() == 32)
            && self.min_memory_bytes > 0
            && (1..=1_048_576).contains(&self.request_bytes)
            && (1..=1_048_576).contains(&self.response_bytes)
            && self.signature.len() == 64
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"resource compute offer"));
        }
        hash(b"octra:resource_compute_offer", |out| {
            out.put_bytes(&self.chain_id)?;
            out.put_u64(self.offered_epoch as u64)?;
            out.put_u64(self.expires_epoch as u64)?;
            out.put_bytes(&self.coordinator)?;
            out.put_hash32(&self.validator_set_root)?;
            out.put_bytes(&self.circle_id)?;
            out.put_u64(self.model_epoch as u64)?;
            out.put_hash32(&self.model_state_root)?;
            out.put_hash32(&self.graph_root)?;
            out.put_hash32(&self.model_root)?;
            out.put_hash32(&self.program_root)?;
            out.put_hash32(&self.executor_root)?;
            out.put_u64(self.min_memory_bytes as u64)?;
            out.put_u32(self.request_bytes as u32)?;
            out.put_u32(self.response_bytes as u32)
        })
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        let signed = self.sign_bytes()?;
        hash(b"octra:resource_compute_offer_id", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.signature)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cancellation {
    pub chain_id: Vec<u8>,
    pub caller: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub caller_signature: Vec<u8>,
    pub until: Option<i64>,
}
impl Cancellation {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && nonempty(&self.caller, 128)
            && self.caller_public_key.len() == 32
            && self.session_id.len() == 32
            && self.caller_signature.len() == 64
            && self.until.is_none_or(|v| v >= 0)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"resource compute cancellation"));
        }
        let domain: &[u8] = if self.until.is_some() {
            b"octra:compute_cancel_until"
        } else {
            b"octra:resource_compute_cancel"
        };
        hash(domain, |out| {
            out.put_bytes(&self.chain_id)?;
            out.put_bytes(&self.caller)?;
            out.put_hash32(&self.caller_public_key)?;
            out.put_hash32(&self.session_id)?;
            if let Some(until) = self.until {
                out.put_u64(until as u64)?;
            }
            Ok(())
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelRound {
    pub cancel: Cancellation,
    pub origin: Vec<u8>,
    pub epoch: i64,
    pub expires: i64,
    pub round: i64,
    pub signature: Vec<u8>,
}
impl CancelRound {
    pub fn shape(&self) -> bool {
        self.cancel.shape()
            && nonempty(&self.origin, 128)
            && self.epoch >= 0
            && self.expires >= self.epoch
            && self.expires.wrapping_sub(self.epoch) <= CANCEL_SPAN
            && (1..=CANCEL_ROUNDS).contains(&self.round)
            && self.signature.len() == 64
            && self.cancel.until.is_none_or(|v| v == self.expires)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute cancel round shape"));
        }
        let signed = self.cancel.sign_bytes()?;
        hash(b"octra:compute_cancel_round", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.cancel.caller_signature)?;
            out.put_bytes(&self.origin)?;
            out.put_u64(self.epoch as u64)?;
            out.put_u64(self.expires as u64)?;
            out.put_u8(self.round as u8)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelAck {
    pub delivery: CancelRound,
    pub origin_key: Vec<u8>,
    pub node_id: Vec<u8>,
    pub node_key: Vec<u8>,
    pub epoch: i64,
    pub signature: Vec<u8>,
}
impl CancelAck {
    pub fn shape(&self) -> bool {
        self.delivery.shape()
            && nonempty(&self.node_id, 128)
            && self.origin_key.len() == 32
            && self.node_key.len() == 32
            && self.epoch >= self.delivery.epoch
            && self.epoch <= self.delivery.expires
            && self.signature.len() == 64
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute cancel ack shape"));
        }
        let signed = self.delivery.sign_bytes()?;
        hash(b"octra:compute_cancel_ack", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.delivery.signature)?;
            out.put_hash32(&self.origin_key)?;
            out.put_bytes(&self.node_id)?;
            out.put_hash32(&self.node_key)?;
            out.put_u64(self.epoch as u64)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetch {
    pub call: Call,
    pub target: Vec<u8>,
    pub epoch_id: i64,
    pub expires_epoch: i64,
    pub round: i64,
    pub signature: Vec<u8>,
}
impl Fetch {
    pub fn shape(&self) -> Result<bool> {
        Ok(self.call.shape()?
            && self.call.request.shape()
            && nonempty(&self.target, 128)
            && self.epoch_id >= self.call.request.epoch_id
            && self.expires_epoch >= self.epoch_id
            && self.expires_epoch <= self.call.request.expires_epoch
            && self.expires_epoch.wrapping_sub(self.epoch_id) <= FETCH_SPAN
            && (0..FETCH_ROUNDS).contains(&self.round)
            && self.signature.len() == 64)
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape()? {
            return Err(Error::rejected(b"compute fetch shape"));
        }
        let signed = self.call.sign_bytes()?;
        hash(b"octra:compute_fetch", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.call.signature)?;
            out.put_bytes(&self.target)?;
            out.put_u64(self.epoch_id as u64)?;
            out.put_u64(self.expires_epoch as u64)?;
            out.put_u8(self.round as u8)
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub vote: Vote,
    pub output_json: Vec<u8>,
}
impl Output {
    pub fn shape(&self) -> Result<bool> {
        Ok(self.output_json.len() <= call::MAX_OUTPUT
            && self.vote.output_hash == call::output_hash(&self.output_json)?)
    }
}
