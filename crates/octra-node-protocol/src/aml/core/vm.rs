// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_vm's standalone AML instruction machine, including the native work-charge
//! and failure mutation order. The Circle contract VM is a separate service.
use super::{machine::Literal, octb::Operation, Natural};
use crate::octb::work::IntegerOp;
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};
use std::sync::Arc;

pub const INPUT_LIMIT: usize = 60;
#[derive(Clone, Debug)]
pub struct Options {
    pub cap: i64,
    pub activate: Option<BigInt>,
    pub epoch: BigInt,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            cap: 1_000_000,
            activate: None,
            epoch: BigInt::zero(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Vm {
    registers: [Literal; 64],
    cap: i64,
    integer_work: bool,
    pc: i64,
    steps: i64,
    work: BigInt,
    halted: bool,
    closes: Vec<(Natural, Natural)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    WorkCap(i64),
    InputCount(usize),
    ProgramCounter(i64),
    ValueType(i64),
    IntegerRange(i64),
    DivideZero(i64),
    ModuloZero(i64),
    CapabilityKind(i64),
    CapabilityReplay(i64),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::WorkCap(cap) => format!("VM work cap reached cap = {cap}"),
            Self::InputCount(actual) => {
                format!("VM input count maximum = {INPUT_LIMIT} actual = {actual}")
            }
            Self::ProgramCounter(pc) => format!("VM program counter is invalid pc = {pc}"),
            Self::ValueType(pc) => format!("VM value type is invalid pc = {pc}"),
            Self::IntegerRange(pc) => format!("VM integer does not fit host index pc = {pc}"),
            Self::DivideZero(pc) => format!("VM integer division rejected pc = {pc}"),
            Self::ModuloZero(pc) => format!("VM integer remainder rejected pc = {pc}"),
            Self::CapabilityKind(pc) => format!("VM capability kind differs pc = {pc}"),
            Self::CapabilityReplay(pc) => format!("VM capability repeats pc = {pc}"),
        }
        .into_bytes()
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
impl Vm {
    /// Like native C_vm.make, an invalid cap is a caller argument error.
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(options: Options) -> Self {
        assert!(options.cap >= 1, "VM work cap is invalid");
        let integer_work = options
            .activate
            .as_ref()
            .is_some_and(|first| first.sign() != Sign::Minus && first <= &options.epoch);
        Self {
            registers: std::array::from_fn(|_| Literal::Int(Arc::new(BigInt::zero()))),
            cap: options.cap,
            integer_work,
            pc: 0,
            steps: 0,
            work: BigInt::zero(),
            halted: false,
            closes: Vec::new(),
        }
    }
    pub fn make_in(options: Options, values: &[Literal]) -> Result<Self> {
        if values.len() > INPUT_LIMIT {
            return Err(Error::InputCount(values.len()));
        }
        let mut state = Self::new(options);
        for (index, value) in values.iter().enumerate() {
            state.registers[index + 1] = value.clone();
        }
        Ok(state)
    }
    pub fn pc(&self) -> i64 {
        self.pc
    }
    pub fn steps(&self) -> i64 {
        self.steps
    }
    pub fn work(&self) -> &BigInt {
        &self.work
    }
    pub fn halted(&self) -> bool {
        self.halted
    }
    /// Operations supplied directly must use the same 0..64 register range as
    /// decoded AML images. Invalid direct register arguments panic, as native.
    pub fn value(&self, register: u8) -> &Literal {
        &self.registers[register as usize]
    }
    pub fn result(&self) -> &Literal {
        self.value(0)
    }
    pub fn closes(&self) -> &[(Natural, Natural)] {
        &self.closes
    }
    fn integer(&self, pc: i64, register: u8) -> Result<Arc<BigInt>> {
        match self.value(register) {
            Literal::Int(value) => Ok(value.clone()),
            _ => Err(Error::ValueType(pc)),
        }
    }
    fn bytes(&self, pc: i64, register: u8) -> Result<Arc<[u8]>> {
        match self.value(register) {
            Literal::Bytes(value) => Ok(value.clone()),
            _ => Err(Error::ValueType(pc)),
        }
    }
    fn boolean(&self, pc: i64, register: u8) -> Result<bool> {
        match self.value(register) {
            Literal::Bool(value) => Ok(*value),
            _ => Err(Error::ValueType(pc)),
        }
    }
    fn set(&mut self, register: u8, value: Literal) {
        self.registers[register as usize] = value;
    }
    fn fixed(op: &Operation) -> i64 {
        match op {
            Operation::Load(..)
            | Operation::Move(..)
            | Operation::Jump(_)
            | Operation::Mark(_)
            | Operation::Noop
            | Operation::Stop => 1,
            Operation::Same(..)
            | Operation::Different(..)
            | Operation::Less(..)
            | Operation::Greater(..) => 2,
            Operation::Plus(..)
            | Operation::Times(..)
            | Operation::Join(..)
            | Operation::Minus(..)
            | Operation::Size(..) => 3,
            Operation::Quotient(..)
            | Operation::Remainder(..)
            | Operation::Negate(..)
            | Operation::Absolute(..)
            | Operation::JumpIf(..)
            | Operation::Slice(..) => 5,
            Operation::CapClose(..) => 50,
        }
    }
    fn cost(&self, op: &Operation) -> BigInt {
        let binary = |kind: IntegerOp, left, right| match (self.value(left), self.value(right)) {
            (Literal::Int(left), Literal::Int(right)) => {
                kind.cost(self.integer_work, Self::fixed(op), left, right)
            }
            _ => Self::fixed(op).into(),
        };
        match op {
            Operation::Plus(_, left, right) => binary(IntegerOp::Add, *left, *right),
            Operation::Minus(_, left, right) => binary(IntegerOp::Sub, *left, *right),
            Operation::Times(_, left, right) => binary(IntegerOp::Mul, *left, *right),
            Operation::Quotient(_, left, right) => binary(IntegerOp::Div, *left, *right),
            Operation::Remainder(_, left, right) => binary(IntegerOp::Mod, *left, *right),
            Operation::Negate(_, src) => binary(IntegerOp::Neg, *src, *src),
            Operation::Absolute(_, src) => binary(IntegerOp::Abs, *src, *src),
            _ => Self::fixed(op).into(),
        }
    }
    fn charge(&mut self, value: BigInt) -> Result<()> {
        if value.sign() == Sign::Minus || &self.work + &value > BigInt::from(self.cap) {
            return Err(Error::WorkCap(self.cap));
        }
        self.work += value;
        Ok(())
    }
    fn index(pc: i64, value: &BigInt) -> Result<Option<usize>> {
        if value.sign() == Sign::Minus {
            return Ok(None);
        }
        Natural::new(value)
            .map(|value| Some(value.get() as usize))
            .ok_or(Error::IntegerRange(pc))
    }
    pub fn step(&mut self, op: &Operation) -> Result<bool> {
        if self.halted {
            return Ok(false);
        }
        let at = self.pc;
        self.charge(self.cost(op))?;
        self.pc = at + 1;
        self.steps += 1;
        self.execute(at, op)
    }
    pub fn run(&mut self, code: &[Operation]) -> Result<()> {
        while !self.halted {
            let at = usize::try_from(self.pc)
                .ok()
                .filter(|at| *at < code.len())
                .ok_or(Error::ProgramCounter(self.pc))?;
            if !self.step(&code[at])? {
                break;
            }
        }
        Ok(())
    }
    fn execute(&mut self, at: i64, op: &Operation) -> Result<bool> {
        match op {
            Operation::Load(dst, value) => self.set(*dst, value.clone()),
            Operation::Move(dst, src) => self.set(*dst, self.value(*src).clone()),
            Operation::Plus(dst, left, right)
            | Operation::Minus(dst, left, right)
            | Operation::Times(dst, left, right)
            | Operation::Quotient(dst, left, right)
            | Operation::Remainder(dst, left, right) => {
                let left = self.integer(at, *left)?;
                let right = self.integer(at, *right)?;
                let value = match op {
                    Operation::Plus(..) => &*left + &*right,
                    Operation::Minus(..) => &*left - &*right,
                    Operation::Times(..) => &*left * &*right,
                    Operation::Quotient(..) => {
                        if right.is_zero() {
                            return Err(Error::DivideZero(at));
                        }
                        &*left / &*right
                    }
                    Operation::Remainder(..) => {
                        if right.is_zero() {
                            return Err(Error::ModuloZero(at));
                        }
                        &*left % &*right
                    }
                    _ => unreachable!(),
                };
                self.set(*dst, Literal::Int(Arc::new(value)));
            }
            Operation::Same(dst, left, right) => self.set(
                *dst,
                Literal::Bool(self.value(*left).equal(self.value(*right))),
            ),
            Operation::Different(dst, left, right)
            | Operation::Less(dst, left, right)
            | Operation::Greater(dst, left, right) => {
                let left = self.integer(at, *left)?;
                let right = self.integer(at, *right)?;
                let value = match op {
                    Operation::Different(..) => left != right,
                    Operation::Less(..) => left < right,
                    _ => left > right,
                };
                self.set(*dst, Literal::Bool(value));
            }
            Operation::Join(dst, left, right) => {
                let left = self.bytes(at, *left)?;
                let right = self.bytes(at, *right)?;
                self.set(
                    *dst,
                    Literal::Bytes([left.as_ref(), right.as_ref()].concat().into()),
                );
            }
            Operation::Negate(dst, src) | Operation::Absolute(dst, src) => {
                let value = self.integer(at, *src)?;
                self.set(
                    *dst,
                    Literal::Int(Arc::new(if matches!(op, Operation::Negate(..)) {
                        -&*value
                    } else {
                        value.abs()
                    })),
                );
            }
            Operation::Size(dst, src) => {
                let value = self.bytes(at, *src)?;
                self.set(*dst, Literal::Int(Arc::new(value.len().into())));
            }
            Operation::Slice(dst, src, first, count) => {
                let value = self.bytes(at, *src)?;
                let first = self.integer(at, *first)?;
                let count = self.integer(at, *count)?;
                let first = Self::index(at, &first)?;
                let count = Self::index(at, &count)?;
                self.charge((value.len() / 256).into())?;
                let selected = match (first, count) {
                    (Some(first), Some(count)) if first <= value.len() => {
                        &value[first..first + count.min(value.len() - first)]
                    }
                    _ => &[],
                };
                self.set(*dst, Literal::Bytes(selected.into()));
            }
            Operation::CapClose(kind, register) => {
                let Literal::Cap(found, id) = self.value(*register) else {
                    return Err(Error::CapabilityKind(at));
                };
                if found != kind {
                    return Err(Error::CapabilityKind(at));
                }
                let item = (*kind, *id);
                if self.closes.contains(&item) {
                    return Err(Error::CapabilityReplay(at));
                }
                self.closes.push(item);
            }
            Operation::Jump(target) => self.pc = i64::from(*target),
            Operation::JumpIf(register, target) => {
                if self.boolean(at, *register)? {
                    self.pc = i64::from(*target);
                }
            }
            Operation::Mark(_) | Operation::Noop => (),
            Operation::Stop => {
                self.halted = true;
                return Ok(false);
            }
        }
        Ok(true)
    }
}
