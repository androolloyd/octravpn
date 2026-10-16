// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{hash, nonempty, Error, Result};
use crate::oce1::{self, Reader, Writer};
use num_bigint::BigInt;
pub const MAX_MEMORY: i64 = 2_147_483_648;
pub const MAX_REQUEST: i64 = 1_048_576;
pub const MAX_RESPONSE: i64 = 1_048_576;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub unit_price: Option<i64>,
    pub fee_cap: Option<i64>,
    pub memory_bytes: Option<i64>,
    pub guest_bytes: Option<i64>,
    pub fuel_limit: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub limits: Limits,
    pub chain_id: Vec<u8>,
    pub epoch_id: i64,
    pub expires_epoch: i64,
    pub validator_set_root: Vec<u8>,
    pub selection_root: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub state_root: Vec<u8>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub caller: Vec<u8>,
    pub session_id: Vec<u8>,
    pub sequence: i64,
    pub input_hash: Vec<u8>,
    pub input_bytes: i64,
    pub max_output_bytes: i64,
}
pub fn fee_valid(fuel: Option<i64>, price: Option<i64>, cap: Option<i64>) -> bool {
    match (price, cap) {
        (None, None) => true,
        (Some(price), Some(cap)) if price > 0 && cap > 0 => fuel.is_some_and(|fuel| {
            fuel > 0 && BigInt::from(price) * BigInt::from(fuel) <= BigInt::from(cap)
        }),
        _ => false,
    }
}
impl Request {
    pub fn shape(&self) -> bool {
        let limits = self.limits;
        fee_valid(limits.fuel_limit, limits.unit_price, limits.fee_cap)
            && (limits.unit_price.is_none() || limits.memory_bytes.is_some())
            && limits.memory_bytes.is_none_or(|bytes| {
                limits.guest_bytes.is_some() && bytes > 0 && bytes <= MAX_MEMORY
            })
            && limits.guest_bytes.is_none_or(|bytes| {
                limits.fuel_limit.is_some()
                    && (65_536..=67_108_864).contains(&bytes)
                    && bytes % 65_536 == 0
            })
            && limits
                .fuel_limit
                .is_none_or(|fuel| (1..=2_000_000_000).contains(&fuel))
            && nonempty(&self.chain_id, 128)
            && self.epoch_id >= 0
            && self.expires_epoch >= self.epoch_id
            && self.validator_set_root.len() == 32
            && self.selection_root.len() == 32
            && nonempty(&self.circle_id, 128)
            && self.state_root.len() == 32
            && self.model_epoch >= 0
            && self.model_state_root.len() == 32
            && self.graph_root.len() == 32
            && self.model_root.len() == 32
            && self.program_root.len() == 32
            && self.executor_root.len() == 32
            && nonempty(&self.caller, 128)
            && self.session_id.len() == 32
            && self.sequence >= 0
            && self.input_hash.len() == 32
            && (1..=MAX_REQUEST).contains(&self.input_bytes)
            && (1..=MAX_RESPONSE).contains(&self.max_output_bytes)
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"resource compute request"));
        }
        let mut digest = hash(b"octra:resource_compute_request", |out| self.put_base(out))?;
        for (domain, value) in [
            (
                b"octra:compute_request_fuel".as_slice(),
                self.limits.fuel_limit,
            ),
            (b"octra:compute_request_guest", self.limits.guest_bytes),
            (b"octra:compute_request_memory", self.limits.memory_bytes),
        ] {
            if let Some(value) = value {
                digest = hash(domain, |out| {
                    out.put_hash32(&digest)?;
                    out.put_u32(value as u32)
                })?;
            }
        }
        if let (Some(price), Some(cap)) = (self.limits.unit_price, self.limits.fee_cap) {
            digest = hash(b"octra:compute_request_fee", |out| {
                out.put_hash32(&digest)?;
                out.put_u64(price as u64)?;
                out.put_u64(cap as u64)
            })?;
        }
        Ok(digest)
    }
    pub(crate) fn put_base(&self, out: &mut Writer) -> std::result::Result<(), oce1::Error> {
        out.put_bytes(&self.chain_id)?;
        out.put_u64(self.epoch_id as u64)?;
        out.put_u64(self.expires_epoch as u64)?;
        out.put_hash32(&self.validator_set_root)?;
        out.put_hash32(&self.selection_root)?;
        out.put_bytes(&self.circle_id)?;
        out.put_hash32(&self.state_root)?;
        out.put_u64(self.model_epoch as u64)?;
        for root in [
            &self.model_state_root,
            &self.graph_root,
            &self.model_root,
            &self.program_root,
            &self.executor_root,
        ] {
            out.put_hash32(root)?;
        }
        out.put_bytes(&self.caller)?;
        out.put_hash32(&self.session_id)?;
        out.put_u64(self.sequence as u64)?;
        out.put_hash32(&self.input_hash)?;
        out.put_u32(self.input_bytes as u32)?;
        out.put_u32(self.max_output_bytes as u32)
    }
    pub(crate) fn get_base(
        input: &mut Reader<'_>,
        limits: Limits,
    ) -> std::result::Result<Self, oce1::Error> {
        let chain_id = input.get_bytes_bounded(128)?.to_vec();
        let epoch_id = input.get_u64()? as i64;
        let expires_epoch = input.get_u64()? as i64;
        let validator_set_root = input.get_hash32()?.to_vec();
        let selection_root = input.get_hash32()?.to_vec();
        let circle_id = input.get_bytes_bounded(128)?.to_vec();
        let state_root = input.get_hash32()?.to_vec();
        let model_epoch = input.get_u64()? as i64;
        let model_state_root = input.get_hash32()?.to_vec();
        let graph_root = input.get_hash32()?.to_vec();
        let model_root = input.get_hash32()?.to_vec();
        let program_root = input.get_hash32()?.to_vec();
        let executor_root = input.get_hash32()?.to_vec();
        let caller = input.get_bytes_bounded(128)?.to_vec();
        let session_id = input.get_hash32()?.to_vec();
        let sequence = input.get_u64()? as i64;
        let input_hash = input.get_hash32()?.to_vec();
        let input_bytes = i64::from(input.get_u32()? as i32);
        let max_output_bytes = i64::from(input.get_u32()? as i32);
        Ok(Self {
            limits,
            chain_id,
            epoch_id,
            expires_epoch,
            validator_set_root,
            selection_root,
            circle_id,
            state_root,
            model_epoch,
            model_state_root,
            graph_root,
            model_root,
            program_root,
            executor_root,
            caller,
            session_id,
            sequence,
            input_hash,
            input_bytes,
            max_output_bytes,
        })
    }
}
