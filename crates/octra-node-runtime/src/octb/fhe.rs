// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Budget, Exec, Host, Instruction as I, Machine, Trap, Unavailable, Value};
use crate::crypto_worker::{self, Cipher, Key, Operation, Request, Response};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_traits::ToPrimitive;
use octra_hfhe::{proof::generators, scalar::Scalar};
use octra_node_protocol::{
    native_base64,
    octb::fhe_work::{self, Memory, Operation as WorkOperation, Shape},
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
#[derive(Clone, Copy, Debug)]
pub enum Capability {
    LoadKey,
    Encrypt,
    Decrypt,
    Arithmetic,
    VerifyZero,
    VerifyRange,
    VerifyBound,
    Commit,
    Pedersen,
    CipherSerde,
    KeySerde,
}
#[derive(Clone)]
pub enum KeySource {
    Bytes(Arc<[u8]>),
    /// Already serialized image supplied by the trusted host.
    Value(Arc<Key>),
}
#[derive(Clone, Copy)]
pub enum ProofKind {
    Zero,
    Range,
    Bound,
}
pub struct Proof<'a> {
    pub kind: ProofKind,
    pub public: &'a Key,
    pub cipher: &'a Cipher,
    pub raw: &'a [u8],
    pub commitment: Option<[u8; 32]>,
    pub math: bool,
    /// Native asynchronous suspension releases the verifier lane before work.
    pub asynchronous: bool,
}
pub(super) struct State {
    pub memory: Option<Memory>,
}
impl State {
    pub(super) fn new(memory: Option<Memory>) -> Self {
        Self { memory }
    }
}
fn worker(error: crypto_worker::Error) -> Trap {
    match error {
        crypto_worker::Error::Invalid => Trap::Refused,
        crypto_worker::Error::Unavailable(reason) => Unavailable(reason).into(),
    }
}
fn calculate(
    key: &Key,
    cipher: &Cipher,
    other: Option<&Cipher>,
    operation: Operation,
) -> Exec<Response> {
    crypto_worker::call(Request::Calculate {
        key: key.clone(),
        cipher: cipher.clone(),
        other: other.cloned(),
        operation,
    })
    .map_err(worker)
}
fn calculated_cipher(
    key: &Key,
    cipher: &Cipher,
    other: Option<&Cipher>,
    operation: Operation,
) -> Exec<Arc<Cipher>> {
    match calculate(key, cipher, other, operation)? {
        Response::Cipher(value) => Ok(Arc::new(value)),
        _ => Err(Unavailable("crypto response kind differs".into()).into()),
    }
}
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
fn native(error: octra_hfhe::Error) -> Trap {
    if error.is_operational() {
        Unavailable(error.to_string()).into()
    } else {
        Trap::Refused
    }
}
fn decode(raw: &[u8]) -> Vec<u8> {
    native_base64::decode(raw).unwrap_or_else(|_| raw.to_vec())
}
fn bytes32(raw: &[u8]) -> Option<[u8; 32]> {
    if raw.len() == 32 {
        return raw.try_into().ok();
    }
    if raw.len() != 44 {
        return None;
    }
    native_base64::decode(raw).ok()?.try_into().ok()
}
fn shape(cipher: &Cipher) -> Exec<Shape> {
    let shape = cipher.shape().map_err(native)?;
    Ok(Shape {
        slots: shape.slots as u64,
        layers: shape.layers as u64,
        edges: shape.edges as u64,
    })
}
static VERIFIER: Mutex<()> = Mutex::new(());
// Preserve the native owned-input and typed diagnostic interface.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn verify(proof: Proof<'_>) -> Result<bool, Unavailable> {
    let kind = match proof.kind {
        ProofKind::Zero => 0,
        ProofKind::Range => 1,
        ProofKind::Bound => 2,
    };
    match crypto_worker::call(Request::Verify {
        key: proof.public.clone(),
        cipher: proof.cipher.clone(),
        proof: proof.raw.to_vec(),
        kind,
        commitment: proof.commitment,
        math: proof.math,
        asynchronous: proof.asynchronous,
    }) {
        Ok(Response::Verified(valid)) => Ok(valid),
        Err(crypto_worker::Error::Invalid) => Ok(false),
        Err(crypto_worker::Error::Unavailable(reason)) => Err(Unavailable(reason)),
        _ => Err(Unavailable("crypto verifier response differs".into())),
    }
}

impl Machine {
    fn reserve_fhe(&self, amount: Option<u64>) -> Exec {
        let amount = amount.ok_or(Trap::Refused)?;
        if self.fhe.memory.as_ref().is_none_or(|m| m.reserve(amount)) {
            Ok(())
        } else {
            Err(Trap::Refused)
        }
    }
    fn public(&self, register: u8) -> Exec<Arc<Key>> {
        match self.get(register)? {
            Value::PublicKey(v) => Ok(v.clone()),
            _ => Err(Trap::Refused),
        }
    }
    fn cipher(&self, register: u8) -> Exec<Arc<Cipher>> {
        match self.get(register)? {
            Value::Cipher(v) => Ok(v.clone()),
            _ => Err(Trap::Refused),
        }
    }
    fn raw(&self, register: u8) -> Exec<Vec<u8>> {
        self.get(register)?
            .bytes()
            .map(<[u8]>::to_vec)
            .ok_or(Trap::Refused)
    }
    fn key_cost(&mut self, public: &Arc<Key>) -> Exec {
        if self.options.proof_exec || self.options.is_view {
            let raw = public.bytes();
            let image = public.image_size().map_err(native)?;
            let volume = image.checked_add(raw.len() as u64).ok_or(Trap::Refused)?;
            self.charge(fhe_work::key_effort(volume, true).ok_or(Trap::Refused)?)?;
        }
        Ok(())
    }
    pub(super) fn prepare_fhe(&mut self, op: &I) -> Exec {
        if !self.options.is_view && !self.options.fhe_work {
            return Ok(());
        }
        let operands = match op {
            I::FheAdd(_, _, a, b) | I::FheSub(_, _, a, b) => {
                Some((WorkOperation::Join, *a, *b, None))
            }
            I::FheMul(_, key, a, b) => Some((WorkOperation::Product, *a, *b, Some(*key))),
            I::FheScale(_, _, a, _)
            | I::FheDivConst(_, _, a, _)
            | I::FheAddConst(_, _, a, _)
            | I::FheSubConst(_, _, a, _)
            | I::FheSer(_, a)
            | I::FheCommit(_, _, a) => Some((WorkOperation::Copy, *a, *a, None)),
            I::FheVerifyZero(_, key, a, _)
            | I::FheVerifyRange(_, key, a, _)
            | I::FheVerifyBound(_, key, a, _, _) => Some((WorkOperation::Copy, *a, *a, Some(*key))),
            _ => None,
        };
        let Some((kind, a, b, key)) = operands else {
            return Ok(());
        };
        let (product_words, samples) = if let Some(key) = key {
            let public = self.public(key)?;
            let p = public.params();
            let samples = fhe_work::sampling(
                p.m_bits.into(),
                p.n_bits.into(),
                p.x_col_weight.into(),
                p.error_weight.into(),
                p.basis.into(),
            )
            .ok_or(Trap::Refused)?;
            self.reserve_fhe(fhe_work::key_value(public.image_size().map_err(native)?))?;
            (public.bit_words().map_err(native)?, samples)
        } else {
            (0, 0)
        };
        let a = self.cipher(a)?;
        let b = self.cipher(b)?;
        let plan = fhe_work::plan(
            kind,
            super::meter::fixed(op),
            shape(&a)?,
            shape(&b)?,
            a.bit_words().map_err(native)?,
            b.bit_words().map_err(native)?,
            product_words,
            samples,
        )
        .ok_or(Trap::Refused)?;
        self.charge(plan.effort)?;
        self.reserve_fhe(Some(plan.memory))
    }
    fn refuse_reason(&mut self, reason: Vec<u8>, budget: &mut Option<&mut Budget>) -> Exec {
        let _ = self.emit(b"Require".to_vec(), vec![Value::string(reason)], budget);
        Err(Trap::Refused)
    }
    fn key_charge(&mut self, source: &KeySource) -> Exec {
        let active = self.options.is_view || self.options.proof_exec;
        if !active && !self.options.fhe_work {
            return Ok(());
        }
        let cost = match source {
            KeySource::Bytes(raw) => fhe_work::key_read_effort(raw, active),
            KeySource::Value(key) => {
                fhe_work::key_effort(key.image_size().map_err(native)?, active)
            }
        }
        .ok_or(Trap::Refused)?;
        self.charge(cost)
    }
    fn proof(
        &mut self,
        dest: u8,
        key: u8,
        cipher: u8,
        input: u8,
        commit: Option<u8>,
        kind: ProofKind,
        host: &mut impl Host,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        let enabled = self.options.proof_exec && self.options.fhe_work && self.options.math;
        if !self.options.is_view && !enabled {
            return Err(Trap::Refused);
        }
        let key = self.public(key)?;
        let cipher = self.cipher(cipher)?;
        let input = self.raw(input)?;
        let commitment = commit.map(|r| self.raw(r)).transpose()?;
        let shape = cipher.shape().map_err(native)?;
        if shape.slots != 1
            || shape.constants != 1
            || !(1..=8).contains(&shape.layers)
            || shape.edges > 512
            || !(1..=2).contains(&shape.base_layers)
        {
            return Err(Trap::Refused);
        }
        if decode(&input).len() > 49_152 {
            return self.set(dest, Value::Bool(false));
        }
        let Ok(lane) = VERIFIER.try_lock() else {
            return self.finish_proof(
                dest,
                Err(Unavailable("fhe verifier unavailable".into())),
                budget,
            );
        };
        let commitment = commitment.as_ref().map(|v| bytes32(v));
        if commit.is_some() && commitment.flatten().is_none() {
            return self.set(dest, Value::Bool(false));
        }
        let prefix = if matches!(kind, ProofKind::Range) {
            b"rp_v1|".as_slice()
        } else {
            b"zkzp_v2|"
        };
        let raw = if let Some(encoded) = input.strip_prefix(prefix).filter(|s| !s.is_empty()) {
            match native_base64::decode(encoded) {
                Ok(v) => v,
                Err(_) => return self.set(dest, Value::Bool(false)),
            }
        } else {
            decode(&input)
        };
        // Native pack_proof raises Suspend under async_exec. Its protected
        // parser lane unwinds before Fhe_task actually queues/runs the proof.
        // Synchronous execution retains the lane through the immediate try.
        let _lane = if self.options.async_exec {
            drop(lane);
            None
        } else {
            Some(lane)
        };
        let result = host.fhe_verify(Proof {
            kind,
            public: &key,
            cipher: &cipher,
            raw: &raw,
            commitment: commitment.flatten(),
            math: self.options.math,
            asynchronous: self.options.async_exec,
        });
        self.finish_proof(dest, result, budget)
    }
    fn finish_proof(
        &mut self,
        dest: u8,
        result: Result<bool, Unavailable>,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        let enabled = self.options.proof_exec && self.options.fhe_work && self.options.math;
        match result {
            Ok(valid) => self.set(dest, Value::Bool(valid)),
            Err(e) if enabled && !self.options.is_view => {
                if self.options.async_exec {
                    self.reverted = true;
                    self.closes.clear();
                }
                Err(e.into())
            }
            Err(_) => {
                let _ = self.emit(
                    b"Require".to_vec(),
                    vec![Value::string(b"fhe verifier unavailable".to_vec())],
                    budget,
                );
                Err(if self.options.async_exec {
                    Trap::HostRefused
                } else {
                    Trap::Refused
                })
            }
        }
    }
    // Positional operand names match the native instruction layout.
    #[allow(clippy::many_single_char_names)]
    pub(super) fn execute_fhe(
        &mut self,
        op: &I,
        host: &mut impl Host,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        let capability = match op {
            I::FheLoadPk(..) => Capability::LoadKey,
            I::FheVerifyZero(..) => Capability::VerifyZero,
            I::FheVerifyRange(..) => Capability::VerifyRange,
            I::FheVerifyBound(..) => Capability::VerifyBound,
            I::FheCommit(..) => Capability::Commit,
            I::FhePedersen(..)
            | I::FhePedersenAdd(..)
            | I::FhePedersenSub(..)
            | I::FhePedersenIdentity(..) => Capability::Pedersen,
            I::FheSer(..) | I::FheDeser(..) => Capability::CipherSerde,
            I::FheSerPk(..) | I::FheDeserPk(..) => Capability::KeySerde,
            _ => Capability::Arithmetic,
        };
        if matches!(
            op,
            I::FhePedersenAdd(..) | I::FhePedersenSub(..) | I::FhePedersenIdentity(..)
        ) && !self.options.point_ops
        {
            return Err(Trap::Refused);
        }
        if !host.fhe_capability(capability)? {
            return if matches!(op, I::FheLoadPk(..)) {
                self.refuse_reason(b"fhe_load_pk not allowed".to_vec(), budget)
            } else {
                Err(Trap::Refused)
            };
        }
        let (dest, value) = match *op {
            I::FheLoadPk(dest, source) => {
                let address = self.text(source)?;
                let reason = [b"fhe pubkey not available: ".as_slice(), &address].concat();
                let Some(source) = host.fhe_key(&address)? else {
                    return self.refuse_reason(reason, budget);
                };
                self.key_charge(&source)?;
                let key = match source {
                    KeySource::Value(key) => {
                        self.reserve_fhe(fhe_work::key_value(key.image_size().map_err(native)?))?;
                        key
                    }
                    KeySource::Bytes(raw) => {
                        if self.fhe.memory.is_some() {
                            self.reserve_fhe(fhe_work::key_decode(&raw))?;
                        }
                        let shape = raw.len() <= 5_000_000
                            && (raw.len() >= 6
                                && &raw[..4] == b"PVAC"
                                && (1..=5).contains(&raw[4])
                                && raw[5] == 1
                                || raw.len() >= 5 && raw[0] == 0xec);
                        if !shape {
                            return self.refuse_reason(reason, budget);
                        }
                        match Key::read(&raw, true) {
                            Ok(v) => Arc::new(v),
                            Err(crypto_worker::Error::Unavailable(reason)) => {
                                return Err(Unavailable(reason).into())
                            }
                            Err(crypto_worker::Error::Invalid) => {
                                return self.refuse_reason(reason, budget)
                            }
                        }
                    }
                };
                (dest, Value::PublicKey(key))
            }
            I::FheAdd(dest, key, a, b)
            | I::FheSub(dest, key, a, b)
            | I::FheMul(dest, key, a, b) => {
                let key = self.public(key)?;
                let a = self.cipher(a)?;
                let b = self.cipher(b)?;
                if matches!(op, I::FheMul(..)) && a.slots() != b.slots() {
                    return Err(Trap::Refused);
                }
                self.key_cost(&key)?;
                let operation = match op {
                    I::FheAdd(..) => Operation::Add,
                    I::FheSub(..) => Operation::Sub,
                    _ => {
                        let mut hash = Sha256::new();
                        let pc = self.pc.to_string();
                        let destination = dest.to_string();
                        for (index, part) in [
                            b"aml.fhe_mul".as_slice(),
                            &self.context.tx_hash,
                            &self.context.address,
                            pc.as_bytes(),
                            destination.as_bytes(),
                        ]
                        .iter()
                        .enumerate()
                        {
                            if index > 0 {
                                hash.update([0]);
                            }
                            hash.update(part);
                        }
                        Operation::Mul {
                            seed: hash.finalize().into(),
                            math: self.options.math,
                            draws: if self.options.is_view || self.options.fhe_work {
                                32
                            } else {
                                0
                            },
                        }
                    }
                };
                let cipher = calculated_cipher(&key, &a, Some(&b), operation)?;
                (dest, Value::Cipher(cipher))
            }
            I::FheScale(dest, key, c, amount)
            | I::FheAddConst(dest, key, c, amount)
            | I::FheSubConst(dest, key, c, amount)
            | I::FheDivConst(dest, key, c, amount) => {
                let key = self.public(key)?;
                let cipher = self.cipher(c)?;
                let number = self.get(amount)?.number();
                if matches!(op, I::FheDivConst(..)) && number.to_i64().is_none_or(|v| v <= 0) {
                    return self
                        .refuse_reason(b"fhe_div_const divisor out of range".to_vec(), budget);
                }
                let amount = number.to_i64().ok_or(Trap::Exception)?;
                self.key_cost(&key)?;
                let operation = match op {
                    I::FheScale(..) => Operation::Scale {
                        math: self.options.math,
                        amount,
                    },
                    I::FheAddConst(..) => Operation::AddInt {
                        math: self.options.math,
                        amount,
                    },
                    I::FheSubConst(..) => Operation::SubInt {
                        math: self.options.math,
                        amount,
                    },
                    _ => Operation::Divide(amount),
                };
                (
                    dest,
                    Value::Cipher(calculated_cipher(&key, &cipher, None, operation)?),
                )
            }

            I::FheVerifyZero(d, k, c, p) => {
                return self.proof(d, k, c, p, None, ProofKind::Zero, host, budget)
            }
            I::FheVerifyRange(d, k, c, p) => {
                return self.proof(d, k, c, p, None, ProofKind::Range, host, budget)
            }
            I::FheVerifyBound(d, k, c, p, a) => {
                return self.proof(d, k, c, p, Some(a), ProofKind::Bound, host, budget)
            }
            I::FheCommit(dest, key, c) => {
                let key = self.public(key)?;
                let cipher = self.cipher(c)?;
                self.key_cost(&key)?;
                let Response::Digest(digest) = calculate(&key, &cipher, None, Operation::Commit)?
                else {
                    return Err(Unavailable("crypto commitment response differs".into()).into());
                };
                (dest, Value::string(STANDARD.encode(digest).into_bytes()))
            }

            I::FhePedersen(dest, amount, blind) => {
                let blind = self.raw(blind)?;
                let amount = self
                    .get(amount)?
                    .number()
                    .to_i64()
                    .filter(|n| *n >= 0)
                    .ok_or(Trap::Refused)?;
                let blind: [u8; 32] = blind.try_into().map_err(|_| Trap::Refused)?;
                (
                    dest,
                    Value::string(
                        STANDARD
                            .encode(generators::pedersen_commit(
                                &Scalar::from_u64(amount as u64),
                                &Scalar::from_bytes_raw(&blind),
                            ))
                            .into_bytes(),
                    ),
                )
            }
            I::FhePedersenAdd(dest, a, b) | I::FhePedersenSub(dest, a, b) => {
                let a = bytes32(&self.raw(a)?).ok_or(Trap::Refused)?;
                let b = bytes32(&self.raw(b)?).ok_or(Trap::Refused)?;
                let result = if matches!(op, I::FhePedersenAdd(..)) {
                    generators::point_add(&a, &b)
                } else {
                    generators::point_sub(&a, &b)
                }
                .map_err(native)?;
                (dest, Value::string(STANDARD.encode(result).into_bytes()))
            }
            I::FhePedersenIdentity(dest) => (
                dest,
                Value::string(STANDARD.encode(generators::identity()).into_bytes()),
            ),
            I::FheSer(dest, c) => {
                let cipher = self.cipher(c)?;
                let raw = cipher.bytes().clone();
                (dest, Value::string(STANDARD.encode(raw).into_bytes()))
            }
            I::FheDeser(dest, source) => {
                let raw = self.raw(source)?;
                self.charge(fhe_work::decode_effort(raw.len()).ok_or(Trap::Refused)?)?;
                let raw = decode(&raw);
                if raw.len() > 1_048_576 {
                    return Err(Trap::Refused);
                }
                self.reserve_fhe(fhe_work::cipher_decode(raw.len()))?;
                let cipher = Cipher::read(
                    &raw,
                    self.options.point_ops,
                    self.options.is_view || self.options.point_ops || self.options.fhe_work,
                )
                .map_err(worker)?;
                (dest, Value::Cipher(Arc::new(cipher)))
            }
            I::FheSerPk(dest, p) => {
                let key = self.public(p)?;
                let active = self.options.is_view || self.options.proof_exec;
                if active || self.options.fhe_work {
                    self.charge(
                        fhe_work::key_effort(key.image_size().map_err(native)?, active)
                            .ok_or(Trap::Refused)?,
                    )?;
                }
                self.reserve_fhe(fhe_work::key_value(key.image_size().map_err(native)?))?;
                let raw = key.bytes().clone();
                (dest, Value::string(STANDARD.encode(raw).into_bytes()))
            }
            I::FheDeserPk(dest, source) => {
                let raw = self.raw(source)?;
                self.charge(fhe_work::decode_effort(raw.len()).ok_or(Trap::Refused)?)?;
                let raw = decode(&raw);
                if raw.len() > 18_000_000 {
                    return Err(Trap::Refused);
                }
                self.charge(fhe_work::key_output_effort(&raw).ok_or(Trap::Refused)?)?;
                if self.fhe.memory.is_some() {
                    self.reserve_fhe(fhe_work::key_decode(&raw))?;
                }
                (
                    dest,
                    Value::PublicKey(Arc::new(Key::read(&raw, false).map_err(worker)?)),
                )
            }
            _ => unreachable!("FHE opcode family was selected"),
        };
        // Native Fhe_image serialization has already completed in the owned
        // process before any result is installed into the register file.
        self.set(dest, value)
    }
}

#[cfg(test)]
mod tests;
