// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCTB execution state. Callers admit code before running it and own the outer
//! transaction savepoint. A VM refusal retains local diagnostic state; unavailable
//! execution must abort and restore the enclosing attempt, never become a verdict.
mod data;
mod meter;
mod proof;
mod spawn;
mod value;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use octra_node_protocol::{
    circle_storage::StorageTable,
    octb::{
        work::{self, Budget, IntegerOp, Request},
        Instruction, StorageKind,
    },
    transaction::is_valid_address,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub use value::{Capability, Value};

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct Unavailable(pub String);
#[derive(Debug)]
enum Trap {
    Refused,
    HostRefused,
    Exception,
    Unavailable(Unavailable),
}
type Exec<T = ()> = Result<T, Trap>;
impl From<Unavailable> for Trap {
    fn from(e: Unavailable) -> Self {
        Self::Unavailable(e)
    }
}
#[derive(Clone, Debug)]
pub struct Context {
    pub caller: Vec<u8>,
    pub origin: Vec<u8>,
    pub address: Vec<u8>,
    pub value: BigInt,
    pub epoch: i64,
    pub epoch_time_ms: i64,
    pub tree_hash: Vec<u8>,
    pub node_id: Vec<u8>,
    pub tx_hash: Vec<u8>,
    pub depth: i64,
}
impl Default for Context {
    fn default() -> Self {
        Self {
            caller: vec![],
            origin: vec![],
            address: vec![],
            value: BigInt::zero(),
            epoch: 0,
            epoch_time_ms: 0,
            tree_hash: vec![b'0'; 64],
            node_id: b"node_001".to_vec(),
            tx_hash: vec![b'0'; 64],
            depth: 0,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Options {
    pub limit: i64,
    pub strict: bool,
    pub typed_bytes: bool,
    pub integer_work: bool,
    pub fhe_work: bool,
    pub proof_exec: bool,
    pub math: bool,
    pub point_ops: bool,
    pub is_view: bool,
    /// Native suspended-host completion semantics (used by Circle execution).
    pub async_exec: bool,
    pub storage_kinds: BTreeMap<Vec<u8>, StorageKind>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            limit: 1_000_000,
            strict: false,
            typed_bytes: false,
            integer_work: false,
            fhe_work: false,
            proof_exec: false,
            math: false,
            point_ops: false,
            is_view: false,
            async_exec: false,
            storage_kinds: BTreeMap::new(),
        }
    }
}
/// The host supplies authenticated state. Missing state is an operational error.
pub trait Host {
    fn groth16(&mut self, _key: &[u8], _proof: &[u8], _inputs: &[u8]) -> Result<bool, Unavailable> {
        Err(Unavailable("OCTB proof host is unavailable".into()))
    }
    fn spawn(
        &mut self,
        _request: SpawnRequest<'_>,
        _budget: Option<&mut Budget>,
    ) -> Result<Option<Spawned>, Unavailable> {
        Err(Unavailable("OCTB deployment host is unavailable".into()))
    }
    fn call(
        &mut self,
        _request: CallRequest<'_>,
        _storage: &mut StorageTable,
        _budget: Option<&mut Budget>,
    ) -> Result<Option<Subcall>, Unavailable> {
        Err(Unavailable("OCTB cross-call host is unavailable".into()))
    }
    fn running(&self) -> bool {
        true
    }
    fn balance(&mut self, _address: &[u8]) -> Result<BigInt, Unavailable> {
        Err(Unavailable("OCTB balance host is unavailable".into()))
    }
    fn transfer(
        &mut self,
        _from: &[u8],
        _to: &[u8],
        _amount: &BigInt,
    ) -> Result<bool, Unavailable> {
        Err(Unavailable("OCTB transfer host is unavailable".into()))
    }
    fn cap_live(&mut self, _cap: &Capability) -> Result<bool, Unavailable> {
        Err(Unavailable("OCTB capability host is unavailable".into()))
    }
}
pub struct CallRequest<'a> {
    pub caller: &'a [u8],
    pub target: &'a [u8],
    pub method: &'a [u8],
    pub params: &'a [Value],
    pub limit: i64,
}
pub struct Subcall {
    pub response: Value,
    pub effort: i64,
    pub events: Vec<Event>,
}
pub struct SpawnRequest<'a> {
    pub parent: &'a [u8],
    pub code: &'a [u8],
    pub nonce: i64,
    pub params: &'a [Value],
    pub limit: i64,
}
pub struct Spawned {
    pub address: Vec<u8>,
    pub effort: i64,
    pub events: Vec<Event>,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub contract: Vec<u8>,
    pub depth: i64,
    pub name: Vec<u8>,
    pub values: Vec<Value>,
}
#[derive(Clone, Debug)]
enum Undo {
    Marker,
    Write(Vec<u8>, Option<Vec<u8>>),
    Close(Capability),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Running,
    Finished,
    Refused,
}
pub struct Machine {
    pub regs: [Value; 64],
    pub memory: BTreeMap<i64, Value>,
    pub memory_size: i64,
    pub storage: StorageTable,
    pub effort: i64,
    pub reverted: bool,
    pub output_ready: bool,
    pub pc: usize,
    pub events: Vec<Event>,
    pub closes: Vec<Capability>,
    pub blobs: BTreeMap<Vec<u8>, Vec<u8>>,
    context: Context,
    options: Options,
    undo: Vec<Undo>,
    returns: Vec<(usize, u8, [Value; 64])>,
}
impl Machine {
    pub fn new(context: Context, options: Options, storage: StorageTable) -> Self {
        Self {
            regs: std::array::from_fn(|_| Value::default()),
            memory: BTreeMap::new(),
            memory_size: 0,
            storage,
            effort: 0,
            reverted: false,
            output_ready: false,
            pc: 0,
            events: vec![],
            closes: vec![],
            blobs: BTreeMap::new(),
            context,
            options,
            undo: vec![],
            returns: vec![],
        }
    }
    pub fn run(
        &mut self,
        code: &[Instruction],
        host: &mut impl Host,
        mut budget: Option<&mut Budget>,
    ) -> Result<bool, Unavailable> {
        loop {
            if !host.running() {
                return Err(Unavailable("OCTB execution cancelled".into()));
            }
            match self.step(code, host, budget.as_deref_mut())? {
                Progress::Running => (),
                Progress::Finished => return Ok(true),
                Progress::Refused => return Ok(false),
            }
        }
    }
    pub fn step(
        &mut self,
        code: &[Instruction],
        host: &mut impl Host,
        mut budget: Option<&mut Budget>,
    ) -> Result<Progress, Unavailable> {
        if self.reverted {
            return Ok(Progress::Refused);
        }
        let result = (|| {
            if self.pc < code.len() {
                let op = &code[self.pc];
                self.pc += 1;
                match self.execute(op, host, &mut budget) {
                    Ok(false) => self.pc = code.len(),
                    Ok(true) => (),
                    Err(Trap::Refused) => {
                        self.pc = code.len();
                        return Err(Trap::Refused);
                    }
                    Err(error) => return Err(error),
                }
                if self.reverted {
                    self.pc = code.len();
                    return Ok(Progress::Refused);
                }
            }
            if self.pc >= code.len() {
                self.finish(&mut budget)?;
                Ok(Progress::Finished)
            } else {
                Ok(Progress::Running)
            }
        })();
        match result {
            Ok(p) => Ok(p),
            Err(Trap::Refused | Trap::HostRefused | Trap::Exception) => {
                self.reverted = true;
                self.closes.clear();
                Ok(Progress::Refused)
            }
            Err(Trap::Unavailable(e)) => Err(e),
        }
    }
    fn get(&self, reg: u8) -> Exec<&Value> {
        self.regs.get(usize::from(reg)).ok_or(Trap::Exception)
    }
    fn set(&mut self, reg: u8, value: Value) -> Exec {
        let cell = self.regs.get_mut(usize::from(reg)).ok_or(Trap::Exception)?;
        *cell = value;
        Ok(())
    }
    fn integer(&self, reg: u8) -> Exec<BigInt> {
        Ok(self.get(reg)?.number().into_owned())
    }
    fn index(&self, reg: u8) -> Exec<i64> {
        self.get(reg)?
            .number()
            .to_i64()
            .filter(|v| (-(1_i64 << 62)..=work::MAX_INT).contains(v))
            .ok_or(Trap::Exception)
    }
    fn text(&self, reg: u8) -> Exec<Vec<u8>> {
        Ok(self.get(reg)?.text().into_owned())
    }
    fn charge(&mut self, cost: i64) -> Exec {
        self.effort = work::charge(self.effort, cost, self.options.limit).ok_or(Trap::Refused)?;
        Ok(())
    }
    fn charge_integer(&mut self, cost: &BigInt) -> Exec {
        self.effort =
            work::charge_integer(self.effort, cost, self.options.limit).ok_or(Trap::Refused)?;
        Ok(())
    }
    fn bytes(
        &mut self,
        budget: &mut Option<&mut Budget>,
        base: i64,
        prior: i64,
        requests: &[Request],
    ) -> Exec {
        match budget {
            Some(b) => {
                self.effort = b
                    .charge(self.effort, self.options.limit, base, requests)
                    .ok_or(Trap::Refused)?;
                Ok(())
            }
            None => self.charge(prior),
        }
    }
    fn memory_set(&mut self, index: i64, value: Value) {
        self.memory.insert(index, value);
        if index >= self.memory_size {
            self.memory_size = data::add(index, 1);
        }
    }
    fn write(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        self.undo
            .push(Undo::Write(key.clone(), self.storage.get(&key).cloned()));
        match value {
            Some(v) => self.storage.replace(key, v),
            None => self.storage.remove(&key),
        }
    }
    fn emit(
        &mut self,
        name: Vec<u8>,
        values: Vec<Value>,
        budget: &mut Option<&mut Budget>,
    ) -> Exec {
        if let Some(b) = budget {
            let left = b.event_left();
            let mut used = self.effort;
            let mut strings = Vec::with_capacity(values.len());
            for value in &values {
                used = Self::value_work(value, b, used, self.options.limit)?;
                strings.push(value.text().into_owned());
            }
            let size = work::event_size(
                left - 1,
                &self.context.address,
                self.context.depth,
                &name,
                &strings.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            )
            .ok_or(Trap::Refused)?;
            self.effort = b
                .emit(used, self.options.limit, size + 1)
                .ok_or(Trap::Refused)?;
        }
        self.events.push(Event {
            contract: self.context.address.clone(),
            depth: self.context.depth,
            name,
            values,
        });
        Ok(())
    }
    fn value_work(value: &Value, budget: &mut Budget, used: i64, limit: i64) -> Exec<i64> {
        if value.numeric() {
            let size = i64::try_from(value.number().bits() / 3 + 2).map_err(|_| Trap::Refused)?;
            if size > budget.event_left() {
                return Err(Trap::Refused);
            }
            return budget
                .charge(used, limit, 0, &[Request::Allocate(size)])
                .ok_or(Trap::Refused);
        }
        Ok(used)
    }
    fn finish(&mut self, budget: &mut Option<&mut Budget>) -> Exec {
        if self.output_ready {
            return Ok(());
        }
        if let Some(b) = budget {
            let left = b.event_left() - 16;
            let value = self.regs[0].clone();
            let used = Self::value_work(&value, b, self.effort, self.options.limit)?;
            let text = value.text();
            let mut size = work::text_size(left, &text).ok_or(Trap::Refused)?;
            if matches!(value, Value::Bytes(_) | Value::Bytes32(_)) {
                size = size.max(work::encoded_size(text.len() as i64).ok_or(Trap::Refused)? + 2);
            }
            self.effort = b
                .output(used, self.options.limit, size + 16)
                .ok_or(Trap::Refused)?;
        }
        self.output_ready = true;
        Ok(())
    }
    fn view_guard(&mut self, budget: &mut Option<&mut Budget>) -> Exec {
        if !self.options.is_view {
            return Ok(());
        }
        let _ = self.emit(
            b"Require".to_vec(),
            vec![Value::string(b"write in view context".to_vec())],
            budget,
        );
        Err(Trap::Refused)
    }
    fn execute(
        &mut self,
        op: &Instruction,
        host: &mut impl Host,
        budget: &mut Option<&mut Budget>,
    ) -> Exec<bool> {
        // Missing execution families must remain operational errors even when
        // an incomplete meter could otherwise appear to refuse the instruction.
        if !matches!(op.opcode(), 0x00..=0x2f | 0x3f..=0x55 | 0x7a | 0x7b | 0x89 | 0x8a) {
            return Err(Unavailable(format!(
                "OCTB opcode 0x{:02x} execution is not available",
                op.opcode()
            ))
            .into());
        }
        self.prepare(op, budget)?;
        use Instruction as I;
        match op {
            I::Groth16VerifyBn254(dest, key, proof, inputs) => {
                self.verify_groth16(*dest, *key, *proof, *inputs, host, budget)?;
            }
            I::Add(d, a, b)
            | I::Sub(d, a, b)
            | I::Mul(d, a, b)
            | I::Div(d, a, b)
            | I::Mod(d, a, b) => {
                let kind = match op {
                    I::Add(..) => IntegerOp::Add,
                    I::Sub(..) => IntegerOp::Sub,
                    I::Mul(..) => IntegerOp::Mul,
                    I::Div(..) => IntegerOp::Div,
                    _ => IntegerOp::Mod,
                };
                let value = kind
                    .eval(&self.get(*a)?.number(), &self.get(*b)?.number())
                    .ok_or(Trap::Refused)?;
                self.set(*d, Value::int(value))?;
            }
            I::Neg(d, a) | I::Abs(d, a) => {
                let value = self.get(*a)?.number();
                let value = if matches!(op, I::Neg(..)) {
                    -value.as_ref()
                } else {
                    value.abs()
                };
                self.set(*d, Value::int(value))?;
            }
            I::Eq(d, a, b) | I::Neq(d, a, b) => {
                let same = self.get(*a)?.equal(self.get(*b)?);
                self.set(
                    *d,
                    Value::Bool(if matches!(op, I::Eq(..)) { same } else { !same }),
                )?;
            }
            I::Lt(d, a, b) | I::Gt(d, a, b) => {
                let a = self.get(*a)?;
                let b = self.get(*b)?;
                let yes = !a.private()
                    && !b.private()
                    && if matches!(op, I::Lt(..)) {
                        a.number() < b.number()
                    } else {
                        a.number() > b.number()
                    };
                self.set(*d, Value::Bool(yes))?;
            }
            I::Ldi(d, v) => self.set(*d, Value::from_constant(v))?,
            I::Mov(d, a) => self.set(*d, self.get(*a)?.clone())?,
            I::Sload(d, key) => {
                let value = match self.options.storage_kinds.get(key.as_ref()) {
                    Some(kind) => self
                        .storage
                        .get(key)
                        .map_or_else(
                            || Some(Value::storage_default(*kind)),
                            |v| Value::decode_storage(*kind, v),
                        )
                        .ok_or(Trap::Refused)?,
                    None => Value::string(
                        self.storage
                            .get(key)
                            .cloned()
                            .unwrap_or_else(|| b"0".to_vec()),
                    ),
                };
                self.set(*d, value)?;
            }
            I::Sloadk(d, k) => {
                let key = self.text(*k)?;
                self.set(
                    *d,
                    Value::string(
                        self.storage
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| b"0".to_vec()),
                    ),
                )?;
            }
            I::Sstore(key, source) => {
                self.view_guard(budget)?;
                self.store(key.to_vec(), *source, budget)?;
            }
            I::Sstorek(key, source) => {
                self.view_guard(budget)?;
                if matches!(
                    self.get(*source)?,
                    Value::Capability(_) | Value::Cipher(_) | Value::PublicKey(_)
                ) {
                    return Err(Trap::Refused);
                }
                let key = self.text(*key)?;
                self.store(key, *source, budget)?;
            }
            I::Sdel(key) => {
                self.view_guard(budget)?;
                let key = key.to_vec();
                self.delete(key, budget)?;
            }
            I::Sdelk(key) => {
                self.view_guard(budget)?;
                let key = self.text(*key)?;
                self.delete(key, budget)?;
            }
            I::CapCheck(kind, reg) | I::CapClose(kind, reg) => {
                if matches!(op, I::CapClose(..)) {
                    self.view_guard(budget)?;
                }
                let Value::Capability(cap) = self.get(*reg)? else {
                    return Err(Trap::Refused);
                };
                if !cap.matches(kind) || !host.cap_live(cap)? {
                    return Err(Trap::Refused);
                }
                if matches!(op, I::CapClose(..)) {
                    if self.closes.contains(cap) {
                        return Err(Trap::Refused);
                    }
                    let cap = cap.clone();
                    self.closes.insert(0, cap.clone());
                    self.undo.push(Undo::Close(cap));
                }
            }
            I::Mload(d, index) => {
                let value = self
                    .memory
                    .get(&i64::from(*index))
                    .cloned()
                    .or_else(|| (!self.options.strict).then(Value::default))
                    .ok_or(Trap::Refused)?;
                self.set(*d, value)?;
            }
            I::Mstore(index, source) => {
                self.memory_set(i64::from(*index), self.get(*source)?.clone());
            }
            I::Mloadr(d, source) => {
                let index = self.index(*source)?;
                if !(0..=16_777_216).contains(&index) {
                    return Err(Trap::Refused);
                }
                let value = self
                    .memory
                    .get(&index)
                    .cloned()
                    .or_else(|| (!self.options.strict).then(Value::default))
                    .ok_or(Trap::Refused)?;
                self.set(*d, value)?;
            }
            I::Mstorer(index, source) => {
                let index = self.index(*index)?;
                if !(0..=16_777_216).contains(&index) {
                    return Err(Trap::Refused);
                }
                self.memory_set(index, self.get(*source)?.clone());
            }
            I::Jmp(target) => self.pc = *target as usize,
            I::Jif(r, target) => {
                if self.get(*r)?.truth() {
                    self.pc = *target as usize;
                }
            }
            I::Jdest(..) | I::Nop() => (),
            I::Stop() => {
                let Some((pc, reg, values)) = self.returns.pop() else {
                    return Ok(false);
                };
                let output = self.regs[0].clone();
                self.regs = values;
                self.set(reg, output)?;
                self.pc = pc;
            }
            I::CallInt(reg, target) => {
                if self.returns.len() >= 8 {
                    return Err(Trap::Refused);
                }
                self.returns.push((self.pc, *reg, self.regs.clone()));
                self.pc = *target as usize;
            }
            I::Revert() => return Err(Trap::Refused),
            I::Caller(d) => self.set(*d, Value::Address(self.context.caller.clone().into()))?,
            I::Origin(d) => self.set(*d, Value::Address(self.context.origin.clone().into()))?,
            I::SelfAddr(d) => self.set(*d, Value::Address(self.context.address.clone().into()))?,
            I::Epoch(d) => self.set(*d, Value::int(self.context.epoch))?,
            I::EpochTime(d) => self.set(*d, Value::int(self.context.epoch_time_ms))?,
            I::Value(d) => self.set(*d, Value::int(self.context.value.clone()))?,
            I::Treehash(d) => self.set(*d, Value::string(self.context.tree_hash.clone()))?,
            I::Nodeid(d) => self.set(*d, Value::string(self.context.node_id.clone()))?,
            I::Txhash(d) => self.set(*d, Value::string(self.context.tx_hash.clone()))?,
            I::Balance(d, source) => {
                let amount = if self.get(*source)?.is_address() {
                    host.balance(&self.text(*source)?)?
                } else {
                    BigInt::zero()
                };
                self.set(*d, Value::int(amount))?;
            }
            I::Transfer(d, target, value) => {
                self.view_guard(budget)?;
                let target = self.text(*target)?;
                let yes = if is_valid_address(&target) {
                    let amount = self.integer(*value)?;
                    !amount.is_negative()
                        && (amount.is_zero()
                            || host.transfer(&self.context.address, &target, &amount)?)
                } else {
                    false
                };
                self.set(*d, Value::Bool(yes))?;
            }
            I::Xcall(dest, target, method, base, count) => {
                if u16::from(*base) + u16::from(*count) > 64
                    || *base >= 64
                    || self.context.depth >= 8
                {
                    return Err(Trap::Refused);
                }
                let target = self.get(*target)?.text().into_owned();
                let method = self.get(*method)?.text().into_owned();
                let params = self.regs
                    [usize::from(*base)..usize::from(*base) + usize::from(*count)]
                    .to_vec();
                let limit = if self.options.is_view || self.options.fhe_work || budget.is_some() {
                    (self.options.limit - self.effort).max(0)
                } else {
                    1_000_000
                };
                let result = host.call(
                    CallRequest {
                        caller: &self.context.address,
                        target: &target,
                        method: &method,
                        params: &params,
                        limit,
                    },
                    &mut self.storage,
                    budget.as_deref_mut(),
                )?;
                let Some(result) = result else {
                    return Err(if self.options.async_exec {
                        Trap::HostRefused
                    } else {
                        Trap::Refused
                    });
                };
                self.charge(result.effort).map_err(|error| {
                    if self.options.async_exec {
                        Trap::HostRefused
                    } else {
                        error
                    }
                })?;
                self.events.extend(result.events);
                self.set(*dest, result.response)?;
            }
            I::Spawn(dest, source) => self.spawn(*dest, *source, 0, 0, host, budget)?,
            I::Spawn2(dest, source, base, count) => {
                self.spawn(*dest, *source, *base, *count, host, budget)?;
            }
            I::Checkpoint() => self.undo.push(Undo::Marker),
            I::Rollback() => {
                while let Some(undo) = self.undo.pop() {
                    match undo {
                        Undo::Marker => break,
                        Undo::Write(key, Some(v)) => self.storage.replace(key, v),
                        Undo::Write(key, None) => self.storage.remove(&key),
                        Undo::Close(cap) => {
                            if let Some(at) = self.closes.iter().position(|v| *v == cap) {
                                self.closes.remove(at);
                            }
                        }
                    }
                }
            }
            I::Commit() => {
                if let Some(at) = self.undo.iter().rposition(|v| matches!(v, Undo::Marker)) {
                    if self.options.point_ops
                        && self.undo[..at].iter().any(|v| matches!(v, Undo::Marker))
                    {
                        self.undo.remove(at);
                    } else {
                        self.undo.truncate(at);
                    }
                } else {
                    self.undo.clear();
                }
            }
            I::Emit(name, regs) => {
                if self.events.len() >= 256 {
                    return Err(Trap::Refused);
                }
                let values = regs
                    .iter()
                    .map(|r| self.get(*r).cloned())
                    .collect::<Exec<Vec<_>>>()?;
                self.emit(name.to_vec(), values, budget)?;
            }
            I::Concat(d, a, b) => {
                let left = self.get(*a)?;
                let right = self.get(*b)?;
                let typed = self.options.typed_bytes
                    && matches!((left, right), (Value::Bytes(_), Value::Bytes(_)));
                let left = left.text().into_owned();
                let right = right.text().into_owned();
                self.bytes(
                    budget,
                    0,
                    0,
                    &[Request::Copy(left.len() as i64, right.len() as i64)],
                )?;
                let value = [left, right].concat();
                self.set(
                    *d,
                    if typed {
                        Value::Bytes(value.into())
                    } else {
                        Value::string(value)
                    },
                )?;
            }
            I::Strlen(d, a) => self.set(*d, Value::int(self.get(*a)?.text().len()))?,
            I::Assert(a) => {
                if !self.get(*a)?.truth() {
                    return Err(Trap::Refused);
                }
            }
            I::Effort(d) => self.set(*d, Value::int(self.effort))?,
            I::Isaddr(d, a) => {
                self.set(*d, Value::Bool(is_valid_address(&self.get(*a)?.text())))?;
            }
            I::Ishex(d, a) => {
                let text = self.get(*a)?.text();
                let yes = !text.is_empty() && text.iter().all(u8::is_ascii_hexdigit);
                self.set(*d, Value::Bool(yes))?;
            }
            I::AssertAddr(a) => {
                if !is_valid_address(&self.get(*a)?.text()) {
                    let _ = self.emit(
                        b"Require".to_vec(),
                        vec![Value::string(b"invalid address".to_vec())],
                        budget,
                    );
                    return Err(Trap::Refused);
                }
            }
            I::Substr(d, source, start, len) => {
                let source = self.get(*source)?;
                let typed = self.options.typed_bytes && matches!(source, Value::Bytes(_));
                let bytes = source.text().into_owned();
                self.charge((bytes.len() / 256) as i64)?;
                let start = self.index(*start)?;
                let len = self.index(*len)?;
                let actual = if start < 0 || start as u64 > bytes.len() as u64 || len < 0 {
                    0
                } else {
                    len.min(bytes.len() as i64 - start)
                };
                self.bytes(budget, 0, 0, &[Request::Copy(actual, 0)])?;
                let result = if actual == 0 {
                    vec![]
                } else {
                    bytes[start as usize..(start + actual) as usize].to_vec()
                };
                self.set(
                    *d,
                    if typed {
                        Value::Bytes(result.into())
                    } else {
                        Value::string(result)
                    },
                )?;
            }
            I::Indexof(d, a, b) => {
                let text = self.text(*a)?;
                let pattern = self.text(*b)?;
                self.charge(
                    work::scaled_product(&[text.len() as i64, pattern.len().max(1) as i64], 1024)
                        .ok_or(Trap::Refused)?,
                )?;
                let index = if pattern.is_empty() {
                    0
                } else if pattern.len() > text.len() {
                    -1
                } else {
                    self.bytes(
                        budget,
                        0,
                        0,
                        &[Request::Allocate(
                            (pattern.len() as i64).checked_mul(8).ok_or(Trap::Refused)?,
                        )],
                    )?;
                    data::find(&text, &pattern)
                };
                self.set(*d, Value::int(index))?;
            }
            I::Sha256(d, a) | I::Keccak256(d, a) => {
                let value = self.text(*a)?;
                let cost = (value.len() / 64) as i64;
                self.bytes(budget, cost, cost, &[Request::Copy(64, 0)])?;
                let hash = if matches!(op, I::Sha256(..)) {
                    hex::encode(Sha256::digest(value))
                } else {
                    hex::encode(sha3::Keccak256::digest(value))
                };
                self.set(*d, Value::string(hash.into_bytes()))?;
            }
            I::Ed25519Ok(d, key, message, signature) => {
                let key = self.get(*key)?.bytes().ok_or(Trap::Refused)?.to_vec();
                let message = self.get(*message)?.bytes().ok_or(Trap::Refused)?.to_vec();
                let signature = self.get(*signature)?.bytes().ok_or(Trap::Refused)?.to_vec();
                self.charge((message.len() / 64) as i64)?;
                let decode = |raw: Vec<u8>, size| {
                    if raw.len() == size {
                        Some(raw)
                    } else {
                        octra_node_protocol::transaction::decode_base64(&raw)
                            .ok()
                            .filter(|v| v.len() == size)
                    }
                };
                let yes = match (decode(key, 32), decode(signature, 64)) {
                    (Some(key), Some(signature)) => {
                        octra_node_protocol::network::verify_ed25519(&key, &message, &signature)
                    }
                    _ => false,
                };
                self.set(*d, Value::Bool(yes))?;
            }
            I::Bitand(d, a, b)
            | I::Bitor(d, a, b)
            | I::Bitxor(d, a, b)
            | I::Bitshl(d, a, b)
            | I::Bitshr(d, a, b) => {
                let mask = (BigInt::from(1) << 64) - 1;
                let left = self.get(*a)?.number().as_ref() & &mask;
                let value = if matches!(op, I::Bitshl(..) | I::Bitshr(..)) {
                    let n = self.index(*b)?;
                    if !(0..=63).contains(&n) {
                        BigInt::zero()
                    } else if matches!(op, I::Bitshl(..)) {
                        (left << n as usize) & mask
                    } else {
                        left >> n as usize
                    }
                } else {
                    let right = self.get(*b)?.number().as_ref() & mask;
                    match op {
                        I::Bitand(..) => left & right,
                        I::Bitor(..) => left | right,
                        _ => left ^ right,
                    }
                };
                self.set(*d, Value::int(value))?;
            }
            I::ParseInts(..)
            | I::Skeys(..)
            | I::SkeysPage(..)
            | I::Sloadn(..)
            | I::Sstoren(..)
            | I::Fstore(..)
            | I::Fload(..) => self.data(op, budget)?,
            _ => unreachable!("available opcode selected before metering"),
        }
        Ok(true)
    }
    fn store(&mut self, key: Vec<u8>, source: u8, budget: &mut Option<&mut Budget>) -> Exec {
        if key.first() == Some(&0) {
            return Err(Trap::Refused);
        }
        let value = self.get(source)?;
        if matches!(
            value,
            Value::Capability(_) | Value::Cipher(_) | Value::PublicKey(_)
        ) {
            return Err(Trap::Refused);
        }
        let value = value.text().into_owned();
        if value.len() > 4_194_304 {
            return Err(Trap::Refused);
        }
        self.bytes(
            budget,
            0,
            (value.len() / 32) as i64,
            &[Request::Write(key.len() as i64, value.len() as i64)],
        )?;
        self.write(key, Some(value));
        Ok(())
    }
    fn delete(&mut self, key: Vec<u8>, budget: &mut Option<&mut Budget>) -> Exec {
        if key.first() == Some(&0) {
            return Err(Trap::Refused);
        }
        self.bytes(budget, 0, 0, &[Request::Erase(key.len() as i64)])?;
        self.write(key, None);
        Ok(())
    }
}
/// Relocate verified symbolic labels exactly as Contract.fix_jumps.
pub fn fix_jumps(code: &[Instruction]) -> Vec<Instruction> {
    let targets: BTreeMap<_, _> = code
        .iter()
        .enumerate()
        .filter_map(|(pc, op)| {
            if let Instruction::Jdest(label) = op {
                Some((*label, pc as u32))
            } else {
                None
            }
        })
        .collect();
    code.iter()
        .map(|op| match op {
            Instruction::Jmp(dest) => Instruction::Jmp(*targets.get(dest).unwrap_or(dest)),
            Instruction::Jif(reg, dest) => {
                Instruction::Jif(*reg, *targets.get(dest).unwrap_or(dest))
            }
            Instruction::CallInt(reg, dest) => {
                Instruction::CallInt(*reg, *targets.get(dest).unwrap_or(dest))
            }
            _ => op.clone(),
        })
        .collect()
}
