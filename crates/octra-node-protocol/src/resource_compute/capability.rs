// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native provider capacity evidence. Advertised resources are not proof that
//! execution completed or that a provider belongs to an anchored validator set.
use super::{hash, nonempty, protected, Error, Result};
pub const MAX_LANES: i64 = 8;
pub const MAX_MEMORY: i64 = 1_099_511_627_776;
pub const MAX_REQUEST: i64 = 1_048_576;
pub const MAX_RESPONSE: i64 = 1_048_576;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accelerator {
    Cpu,
    Cuda,
    Metal,
    Rocm,
}
impl Accelerator {
    pub fn code(self) -> u8 {
        match self {
            Self::Cpu => 0,
            Self::Cuda => 1,
            Self::Metal => 2,
            Self::Rocm => 3,
        }
    }
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Cpu => b"cpu",
            Self::Cuda => b"cuda",
            Self::Metal => b"metal",
            Self::Rocm => b"rocm",
        }
    }
    pub fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Cpu),
            1 => Ok(Self::Cuda),
            2 => Ok(Self::Metal),
            3 => Ok(Self::Rocm),
            _ => Err(Error::rejected(b"resource compute accelerator")),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub chain_id: Vec<u8>,
    pub observed_epoch: i64,
    pub valid_until: i64,
    pub validator_set_root: Vec<u8>,
    pub node_id: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub model_epoch: i64,
    pub model_state_root: Vec<u8>,
    pub graph_root: Vec<u8>,
    pub model_root: Vec<u8>,
    pub program_root: Vec<u8>,
    pub executor_root: Vec<u8>,
    pub evidence_root: Vec<u8>,
    pub accelerator: Accelerator,
    pub lanes: i64,
    pub memory_bytes: i64,
    pub max_request_bytes: i64,
    pub max_response_bytes: i64,
    pub signature: Vec<u8>,
}
impl Capability {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && self.observed_epoch >= 0
            && self.valid_until >= self.observed_epoch
            && self.validator_set_root.len() == 32
            && nonempty(&self.node_id, 128)
            && nonempty(&self.circle_id, 128)
            && self.model_epoch >= 0
            && [
                &self.model_state_root,
                &self.graph_root,
                &self.model_root,
                &self.program_root,
                &self.executor_root,
                &self.evidence_root,
            ]
            .iter()
            .all(|v| v.len() == 32)
            && (1..=MAX_LANES).contains(&self.lanes)
            && (1..=MAX_MEMORY).contains(&self.memory_bytes)
            && (1..=MAX_REQUEST).contains(&self.max_request_bytes)
            && (1..=MAX_RESPONSE).contains(&self.max_response_bytes)
            && self.signature.len() == 64
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"resource compute capability"));
        }
        hash(b"octra:resource_compute_capability", |out| {
            out.put_bytes(&self.chain_id)?;
            out.put_u64(self.observed_epoch as u64)?;
            out.put_u64(self.valid_until as u64)?;
            out.put_hash32(&self.validator_set_root)?;
            out.put_bytes(&self.node_id)?;
            out.put_bytes(&self.circle_id)?;
            out.put_u64(self.model_epoch as u64)?;
            out.put_hash32(&self.model_state_root)?;
            out.put_hash32(&self.graph_root)?;
            out.put_hash32(&self.model_root)?;
            out.put_hash32(&self.program_root)?;
            out.put_hash32(&self.executor_root)?;
            out.put_hash32(&self.evidence_root)?;
            out.put_u8(self.accelerator.code())?;
            out.put_u16(self.lanes as u16)?;
            out.put_u64(self.memory_bytes as u64)?;
            out.put_u32(self.max_request_bytes as u32)?;
            out.put_u32(self.max_response_bytes as u32)
        })
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        let signed = self.sign_bytes()?;
        hash(b"octra:resource_compute_capability_id", |out| {
            out.put_hash32(&signed)?;
            out.put_sig64(&self.signature)
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Malformed,
    ChainMismatch,
    EpochMismatch,
    NotValidator,
    Signature,
    Evidence,
}
pub fn validate<'a>(
    chain: &[u8],
    current_epoch: i64,
    max_ttl: i64,
    capability: &'a Capability,
    mut is_validator: impl FnMut(&[u8]) -> bool,
    mut verify_signature: impl FnMut(&Capability) -> bool,
    mut verify_evidence: impl FnMut(&Capability) -> bool,
) -> std::result::Result<&'a Capability, Reject> {
    if !capability.shape() {
        Err(Reject::Malformed)
    } else if capability.chain_id != chain {
        Err(Reject::ChainMismatch)
    } else if max_ttl <= 0
        || current_epoch < capability.observed_epoch
        || current_epoch > capability.valid_until
        || capability
            .valid_until
            .wrapping_sub(capability.observed_epoch)
            > max_ttl
    {
        Err(Reject::EpochMismatch)
    } else if !protected(|| is_validator(&capability.node_id)) {
        Err(Reject::NotValidator)
    } else if !protected(|| verify_signature(capability)) {
        Err(Reject::Signature)
    } else if !protected(|| verify_evidence(capability)) {
        Err(Reject::Evidence)
    } else {
        Ok(capability)
    }
}
