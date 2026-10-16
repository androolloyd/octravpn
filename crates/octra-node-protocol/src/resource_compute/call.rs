// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shape-checked compute headers. Sealing a header does not authenticate its
//! coordinator, authorize funding or attest the selected execution result.
use super::{
    hash, nonempty,
    request::{fee_valid, Limits, Request, MAX_MEMORY},
    Error, Result,
};
use crate::{
    network::domain_hash,
    oce1::{Reader, Writer},
};
pub const MAX_METHOD: usize = 64;
pub const MAX_PARAMS: usize = 65_536;
pub const MAX_OUTPUT: usize = 262_144;
pub const CALL_TTL: i64 = 64;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    request: Request,
    valid_until: Option<i64>,
    caller_public_key: Vec<u8>,
    caller_signature: Vec<u8>,
    coordinator: Vec<u8>,
    signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub request: Request,
    pub valid_until: Option<i64>,
    pub method_name: Vec<u8>,
    pub params_json: Vec<u8>,
    pub caller_public_key: Vec<u8>,
    pub caller_signature: Vec<u8>,
    pub coordinator: Vec<u8>,
    pub signature: Vec<u8>,
}
fn terms_shape(
    request: &Request,
    until: Option<i64>,
    public: &[u8],
    caller_signature: &[u8],
    coordinator: &[u8],
    signature: &[u8],
) -> bool {
    let limits = request.limits;
    fee_valid(limits.fuel_limit, limits.unit_price, limits.fee_cap)
        && (limits.unit_price.is_none() || limits.memory_bytes.is_some())
        && limits
            .memory_bytes
            .is_none_or(|bytes| limits.guest_bytes.is_some() && bytes > 0 && bytes <= MAX_MEMORY)
        && until.is_none_or(|epoch| epoch >= 0 && request.expires_epoch <= epoch)
        && limits
            .fuel_limit
            .is_none_or(|fuel| until.is_some() && (1..=2_000_000_000).contains(&fuel))
        && limits.guest_bytes.is_none_or(|bytes| {
            limits.fuel_limit.is_some()
                && until.is_some()
                && (65_536..=67_108_864).contains(&bytes)
                && bytes % 65_536 == 0
        })
        && public.len() == 32
        && caller_signature.len() == 64
        && nonempty(coordinator, 128)
        && signature.len() == 64
}
pub fn input_hash(method: &[u8], params: &[u8]) -> Result<[u8; 32]> {
    if !nonempty(method, MAX_METHOD) || params.len() > MAX_PARAMS {
        return Err(Error::rejected(b"resource compute input"));
    }
    hash(b"octra:resource_compute_input", |out| {
        out.put_bytes(method)?;
        out.put_bytes(params)
    })
}
pub fn output_hash(output: &[u8]) -> Result<[u8; 32]> {
    if output.len() > MAX_OUTPUT {
        return Err(Error::rejected(b"resource compute output"));
    }
    Ok(domain_hash(b"octra:resource_compute_output", output))
}
impl Call {
    fn fields(&self) -> Header {
        Header {
            request: self.request.clone(),
            valid_until: self.valid_until,
            caller_public_key: self.caller_public_key.clone(),
            caller_signature: self.caller_signature.clone(),
            coordinator: self.coordinator.clone(),
            signature: self.signature.clone(),
        }
    }
    pub fn shape(&self) -> Result<bool> {
        if !nonempty(&self.method_name, MAX_METHOD)
            || !terms_shape(
                &self.request,
                self.valid_until,
                &self.caller_public_key,
                &self.caller_signature,
                &self.coordinator,
                &self.signature,
            )
            || self.params_json.len() > MAX_PARAMS
        {
            return Ok(false);
        }
        Ok(self.request.input_hash == input_hash(&self.method_name, &self.params_json)?)
    }
    pub fn header(&self) -> Result<Header> {
        if self.shape()? && self.request.shape() {
            Ok(self.fields())
        } else {
            Err(Error::rejected(b"compute header shape"))
        }
    }
    pub fn intent_sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape()? {
            return Err(Error::rejected(b"resource compute call"));
        }
        self.fields().intent_digest()
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape()? {
            return Err(Error::rejected(b"resource compute call"));
        }
        self.fields().call_digest()
    }
    pub fn intent_id(&self) -> Result<[u8; 32]> {
        signed_id(&self.intent_sign_bytes()?, &self.caller_signature)
    }
}
fn signed_id(digest: &[u8], signature: &[u8]) -> Result<[u8; 32]> {
    hash(b"octra:resource_compute_intent_id", |out| {
        out.put_hash32(digest)?;
        out.put_sig64(signature)
    })
}
impl Header {
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn valid_until(&self) -> Option<i64> {
        self.valid_until
    }
    pub fn caller_public_key(&self) -> &[u8] {
        &self.caller_public_key
    }
    pub fn caller_signature(&self) -> &[u8] {
        &self.caller_signature
    }
    pub fn coordinator(&self) -> &[u8] {
        &self.coordinator
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn shape(&self) -> bool {
        terms_shape(
            &self.request,
            self.valid_until,
            &self.caller_public_key,
            &self.caller_signature,
            &self.coordinator,
            &self.signature,
        ) && self.request.shape()
    }
    fn intent_digest(&self) -> Result<[u8; 32]> {
        let request = &self.request;
        let mut digest = hash(b"octra:resource_compute_intent", |out| {
            out.put_bytes(&request.chain_id)?;
            out.put_bytes(&request.circle_id)?;
            out.put_u64(request.model_epoch as u64)?;
            for root in [
                &request.model_state_root,
                &request.graph_root,
                &request.model_root,
                &request.program_root,
                &request.executor_root,
            ] {
                out.put_hash32(root)?;
            }
            out.put_bytes(&request.caller)?;
            out.put_hash32(&self.caller_public_key)?;
            out.put_hash32(&request.session_id)?;
            out.put_u64(request.sequence as u64)?;
            out.put_hash32(&request.input_hash)?;
            out.put_u32(request.input_bytes as u32)?;
            out.put_u32(request.max_output_bytes as u32)
        })?;
        if let Some(epoch) = self.valid_until {
            digest = hash(b"octra:compute_intent_expiry", |out| {
                out.put_hash32(&digest)?;
                out.put_u64(epoch as u64)
            })?;
        }
        for (domain, value) in [
            (
                b"octra:compute_intent_fuel".as_slice(),
                request.limits.fuel_limit,
            ),
            (b"octra:compute_intent_guest", request.limits.guest_bytes),
            (b"octra:compute_intent_memory", request.limits.memory_bytes),
        ] {
            if let Some(value) = value {
                digest = hash(domain, |out| {
                    out.put_hash32(&digest)?;
                    out.put_u32(value as u32)
                })?;
            }
        }
        if let (Some(price), Some(cap)) = (request.limits.unit_price, request.limits.fee_cap) {
            digest = hash(b"octra:compute_intent_fee", |out| {
                out.put_hash32(&digest)?;
                out.put_u64(price as u64)?;
                out.put_u64(cap as u64)
            })?;
        }
        Ok(digest)
    }
    fn call_digest(&self) -> Result<[u8; 32]> {
        let request = self.request.id()?;
        let intent = self.intent_digest()?;
        hash(b"octra:resource_compute_call", |out| {
            out.put_hash32(&request)?;
            out.put_bytes(&self.coordinator)?;
            out.put_hash32(&intent)?;
            out.put_sig64(&self.caller_signature)
        })
    }
    pub fn intent(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute header shape"));
        }
        self.intent_digest()
    }
    pub fn sign_bytes(&self) -> Result<[u8; 32]> {
        if !self.shape() {
            return Err(Error::rejected(b"compute header shape"));
        }
        self.call_digest()
    }
    pub fn id(&self) -> Result<[u8; 32]> {
        signed_id(&self.intent()?, &self.caller_signature)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !self.shape() {
            return Err(Error::rejected(b"compute header shape"));
        }
        let mut out = Writer::new();
        out.put_bytes(b"compute_header")?;
        out.put_option(self.valid_until.as_ref(), |out, value| {
            out.put_u64(*value as u64)
        })?;
        for value in [
            self.request.limits.fuel_limit,
            self.request.limits.guest_bytes,
            self.request.limits.memory_bytes,
        ] {
            out.put_option(value.as_ref(), |out, value| out.put_u32(*value as u32))?;
        }
        for value in [self.request.limits.unit_price, self.request.limits.fee_cap] {
            out.put_option(value.as_ref(), |out, value| out.put_u64(*value as u64))?;
        }
        self.request.put_base(&mut out)?;
        out.put_hash32(&self.caller_public_key)?;
        out.put_sig64(&self.caller_signature)?;
        out.put_bytes(&self.coordinator)?;
        out.put_sig64(&self.signature)?;
        Ok(out.into_bytes())
    }
    fn get(input: &mut Reader<'_>) -> std::result::Result<Self, crate::oce1::Error> {
        if input.get_bytes_bounded(14)? != b"compute_header" {
            return Err("compute header format".into());
        }
        let valid_until = input.get_option(|input| Ok(input.get_u64()? as i64))?;
        let fuel_limit = input.get_option(|input| Ok(i64::from(input.get_u32()? as i32)))?;
        let guest_bytes = input.get_option(|input| Ok(i64::from(input.get_u32()? as i32)))?;
        // The native memory decoder deliberately interprets this u32 unsigned.
        let memory_bytes = input.get_option(|input| Ok(i64::from(input.get_u32()?)))?;
        let unit_price = input.get_option(|input| Ok(input.get_u64()? as i64))?;
        let fee_cap = input.get_option(|input| Ok(input.get_u64()? as i64))?;
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
        let caller_public_key = input.get_hash32()?.to_vec();
        let caller_signature = input.get_sig64()?.to_vec();
        let coordinator = input.get_bytes_bounded(128)?.to_vec();
        let signature = input.get_sig64()?.to_vec();
        Ok(Self {
            request,
            valid_until,
            caller_public_key,
            caller_signature,
            coordinator,
            signature,
        })
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 2048 {
            return Err(Error::rejected(b"compute header size"));
        }
        super::frame(raw, b"compute header encoding", |input| {
            let value = Self::get(input)?;
            Ok(if value.shape() {
                Ok(value)
            } else {
                Err(Error::rejected(b"compute header shape"))
            })
        })
    }
}
