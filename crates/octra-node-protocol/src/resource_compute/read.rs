// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Caller authorization for a node-local compute job read. A signed read binds
//! the chain, serving node, job and inclusive epoch window independently of the
//! original execution request. Parsing alone does not authorize a read.
use super::{hash, nonempty, Error, Result};
use crate::{
    network::{public_key_safe, verify_ed25519},
    transaction::{address_from_public_key, is_valid_address},
};
use base64::{engine::general_purpose::STANDARD, Engine};

pub const MAX_EPOCHS: i64 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub chain_id: Vec<u8>,
    pub node_id: Vec<u8>,
    pub caller: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub job_id: Vec<u8>,
    pub epoch_id: i64,
    pub expires_epoch: i64,
    pub caller_signature: Vec<u8>,
}
impl Read {
    pub fn shape(&self) -> bool {
        nonempty(&self.chain_id, 128)
            && is_valid_address(&self.node_id)
            && is_valid_address(&self.caller)
            && self.caller_public_key.len() == 32
            && self.job_id.len() == 32
            && self.caller_signature.len() == 64
            && self.epoch_id >= 0
            && self.expires_epoch >= self.epoch_id
            && self.expires_epoch - self.epoch_id <= MAX_EPOCHS
    }

    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute read shape"));
        }
        hash(b"octra:compute_read", |out| {
            out.put_bytes(&self.chain_id)?;
            out.put_bytes(&self.node_id)?;
            out.put_bytes(&self.caller)?;
            out.put_hash32(&self.caller_public_key)?;
            out.put_hash32(&self.job_id)?;
            out.put_u64(self.epoch_id as u64)?;
            out.put_u64(self.expires_epoch as u64)
        })
    }

    /// The serving service supplies its own chain, identity and current epoch;
    /// none of these values may be taken from untrusted RPC parameters.
    pub fn verify(&self, chain: &[u8], node: &[u8], epoch: i64) -> bool {
        self.shape()
            && self.chain_id == chain
            && self.node_id == node
            && self.epoch_id <= epoch
            && epoch <= self.expires_epoch
            && self.caller
                == address_from_public_key(STANDARD.encode(&self.caller_public_key).as_bytes())
            && public_key_safe(&self.caller_public_key)
            && self.sign_bytes().is_ok_and(|message| {
                verify_ed25519(&self.caller_public_key, &message, &self.caller_signature)
            })
    }
}
