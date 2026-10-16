// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Budget, Exec, Host, Instruction as I, Machine, Trap, Unavailable, Value};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_traits::ToPrimitive;
use octra_hfhe::{
    cipher::Cipher,
    field::Fp,
    keys::PublicKey,
    proof::{
        generators,
        zero::{self, BoundProfile, ZeroProof},
    },
    scalar::{Scalar, ScalarRule},
};
use octra_node_protocol::{
    native_base64,
    octb::fhe_work::{self, Memory, Operation, Shape},
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
    Value(Arc<PublicKey>),
}
#[derive(Clone, Copy)]
pub enum ProofKind {
    Zero,
    Range,
    Bound,
}
pub struct Proof<'a> {
    pub kind: ProofKind,
    pub public: &'a PublicKey,
    pub cipher: &'a Cipher,
    pub raw: &'a [u8],
    pub commitment: Option<[u8; 32]>,
    pub math: bool,
}
pub(super) struct State {
    pub memory: Option<Memory>,
    keys: Vec<(Arc<PublicKey>, Arc<[u8]>)>,
    ciphers: Vec<(Arc<Cipher>, Arc<[u8]>)>,
}
impl State {
    pub(super) fn new(memory: Option<Memory>) -> Self {
        Self {
            memory,
            keys: vec![],
            ciphers: vec![],
        }
    }
    fn key(&mut self, key: &Arc<PublicKey>) -> Exec<Arc<[u8]>> {
        if let Some((_, raw)) = self.keys.iter().find(|(saved, _)| Arc::ptr_eq(saved, key)) {
            return Ok(raw.clone());
        }
        let raw = key.to_bytes().map_err(native)?;
        if self.keys.len() >= 4 {
            self.keys.clear();
        }
        let raw: Arc<[u8]> = raw.into();
        self.keys.push((key.clone(), raw.clone()));
        Ok(raw)
    }
    fn cipher(&mut self, cipher: &Arc<Cipher>) -> Exec<Arc<[u8]>> {
        if let Some((_, raw)) = self
            .ciphers
            .iter()
            .find(|(saved, _)| Arc::ptr_eq(saved, cipher))
        {
            return Ok(raw.clone());
        }
        let raw = cipher.to_bytes().map_err(native)?;
        if self.ciphers.len() >= 32 {
            self.ciphers.clear();
        }
        let raw: Arc<[u8]> = raw.into();
        self.ciphers.push((cipher.clone(), raw.clone()));
        Ok(raw)
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
    if !proof.public.supports_alias_rejection() {
        return Ok(false);
    }
    let strict = !matches!(proof.kind, ProofKind::Zero);
    let cipher = proof
        .cipher
        .to_bytes()
        .and_then(|raw| Cipher::from_bytes_with_policy(&raw, strict, true));
    let cipher = match cipher {
        Ok(v) => v,
        Err(e) if e.is_operational() => return Err(Unavailable(e.to_string())),
        Err(_) => return Ok(false),
    };
    let parsed = match proof.kind {
        ProofKind::Range => ZeroProof::from_bound_range_bytes(proof.raw),
        _ => ZeroProof::from_raw_bytes(proof.raw),
    };
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) if e.is_operational() => return Err(Unavailable(e.to_string())),
        Err(_) => return Ok(false),
    };
    let math = if proof.math {
        ScalarRule::Wide
    } else {
        ScalarRule::Prior
    };
    let result = match proof.kind {
        ProofKind::Zero => zero::verify_zero(proof.public, &cipher, &parsed, math),
        ProofKind::Range => zero::verify_embedded_range(proof.public, &cipher, &parsed, true, math),
        ProofKind::Bound => match proof.commitment {
            Some(commitment) => zero::verify_bound(
                proof.public,
                &cipher,
                &parsed,
                &commitment,
                BoundProfile::Standard,
                true,
                math,
            ),
            None => return Ok(false),
        },
    };
    match result {
        Ok(v) => Ok(v),
        Err(e) if e.is_operational() => Err(Unavailable(e.to_string())),
        Err(_) => Ok(false),
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
    fn public(&self, register: u8) -> Exec<Arc<PublicKey>> {
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
    fn key_cost(&mut self, public: &Arc<PublicKey>) -> Exec {
        if self.options.proof_exec || self.options.is_view {
            let raw = self.fhe.key(public)?;
            let image = public.image_size().map_err(native)?;
            let volume = image.checked_add(raw.len() as u64).ok_or(Trap::Refused)?;
            self.charge(fhe_work::key_effort(volume, true).ok_or(Trap::Refused)?)?;
        }
        Ok(())
    }
    fn serialize_result(&mut self, value: Value) -> Exec<Value> {
        // Every native Fhe_task arithmetic result becomes a serialized image
        // before entering a register. Preserve serialization failure timing.
        match &value {
            Value::Cipher(v) => {
                self.fhe.cipher(v)?;
            }
            Value::PublicKey(v) => {
                self.fhe.key(v)?;
            }
            _ => (),
        }
        Ok(value)
    }
    pub(super) fn prepare_fhe(&mut self, op: &I) -> Exec {
        if !self.options.is_view && !self.options.fhe_work {
            return Ok(());
        }
        let operands = match op {
            I::FheAdd(_, _, a, b) | I::FheSub(_, _, a, b) => Some((Operation::Join, *a, *b, None)),
            I::FheMul(_, key, a, b) => Some((Operation::Product, *a, *b, Some(*key))),
            I::FheScale(_, _, a, _)
            | I::FheDivConst(_, _, a, _)
            | I::FheAddConst(_, _, a, _)
            | I::FheSubConst(_, _, a, _)
            | I::FheSer(_, a)
            | I::FheCommit(_, _, a) => Some((Operation::Copy, *a, *a, None)),
            I::FheVerifyZero(_, key, a, _)
            | I::FheVerifyRange(_, key, a, _)
            | I::FheVerifyBound(_, key, a, _, _) => Some((Operation::Copy, *a, *a, Some(*key))),
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
        let Ok(_lane) = VERIFIER.try_lock() else {
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
        let result = host.fhe_verify(Proof {
            kind,
            public: &key,
            cipher: &cipher,
            raw: &raw,
            commitment: commitment.flatten(),
            math: self.options.math,
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
                        match PublicKey::from_bytes(&raw) {
                            Ok(v) => Arc::new(v),
                            Err(e) if e.is_operational() => return Err(native(e)),
                            Err(_) => return self.refuse_reason(reason, budget),
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
                let cipher = match op {
                    I::FheAdd(..) => a.add(&key, &b),
                    I::FheSub(..) => a.subtract(&key, &b),
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
                        a.multiply_seeded(
                            &key,
                            &b,
                            &hash.finalize().into(),
                            8,
                            self.options.math,
                            if self.options.is_view || self.options.fhe_work {
                                32
                            } else {
                                0
                            },
                        )
                    }
                }
                .map_err(native)?;
                (dest, Value::Cipher(Arc::new(cipher)))
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
                let result = match op {
                    I::FheScale(..) => {
                        if self.options.math {
                            cipher.mul_constant_i64(amount)
                        } else {
                            cipher.mul_constant_u64(amount as u64)
                        }
                    }
                    I::FheAddConst(..) => cipher
                        .add_constant(
                            if self.options.math && amount < 0 {
                                Fp::from_words(amount.wrapping_sub(1) as u64, i64::MAX as u64)
                            } else {
                                Fp::from_words(amount as u64, 0)
                            },
                            self.options.math,
                        )
                        .map_err(native)?,
                    I::FheSubConst(..) => if self.options.math && amount < 0 {
                        cipher.add_constant(Fp::from_words(amount.wrapping_neg() as u64, 0), true)
                    } else {
                        cipher
                            .subtract_constant(Fp::from_words(amount as u64, 0), self.options.math)
                    }
                    .map_err(native)?,
                    _ => cipher
                        .divide_constant(Fp::from_words(amount as u64, 0))
                        .map_err(native)?,
                };
                (dest, Value::Cipher(Arc::new(result)))
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
                (
                    dest,
                    Value::string(STANDARD.encode(cipher.commitment(&key)).into_bytes()),
                )
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
                let raw = self.fhe.cipher(&cipher)?;
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
                let cipher = Cipher::from_bytes_with_policy(
                    &raw,
                    self.options.point_ops,
                    self.options.is_view || self.options.point_ops || self.options.fhe_work,
                )
                .map_err(native)?;
                (dest, Value::Cipher(Arc::new(cipher)))
            }
            I::FheSerPk(dest, p) => {
                let key = self.public(p)?;
                self.key_charge(&KeySource::Value(key.clone()))?;
                self.reserve_fhe(fhe_work::key_value(key.image_size().map_err(native)?))?;
                let raw = self.fhe.key(&key)?;
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
                    Value::PublicKey(Arc::new(PublicKey::from_bytes(&raw).map_err(native)?)),
                )
            }
            _ => unreachable!("FHE opcode family was selected"),
        };
        let value = self.serialize_result(value)?;
        self.set(dest, value)
    }
}
