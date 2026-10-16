// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_call typed call wrappers and whole-image binding. Evidence regeneration,
//! label scoping, call segments and the enclosing image stamp are separate gates.
use super::{
    core::{
        bin::{self, Code, CodeId, Codes},
        types::Type,
    },
    evidence::{self, Evidence},
};
use crate::octb::{admission, Instruction as I, Value as V};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use sha2::{Digest, Sha256};
use std::sync::Arc;
mod codec;
mod labels;
pub use codec::{decode, decode_all, encode};
pub use labels::{ScopeError, ScopedInstruction};
#[derive(Clone, Debug)]
pub struct Call {
    code: Vec<ScopedInstruction>,
    next: i64,
    body: usize,
    size: usize,
    entry: i64,
    first: i64,
    evidence: Evidence,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Evidence(evidence::Error),
    Scope(ScopeError),
    Entry(i64),
    LabelStart(i64),
    LabelSpace(i64),
    Input(Vec<u8>),
    Output(Vec<u8>),
    MissingStop,
    Verify,
    Bits,
    Count(usize),
    Form,
    Repeated(i64),
    Absent(i64),
    Differs(i64),
    Overlap(usize, usize),
    Image,
}
type Result<T> = std::result::Result<T, Error>;
fn fresh(next: &mut i64) -> Result<i64> {
    if *next == labels::MAX {
        return Err(Error::LabelSpace(*next));
    }
    let value = *next;
    *next += 1;
    Ok(value)
}
fn integer(reg: u8, value: i32) -> ScopedInstruction {
    ScopedInstruction::Plain(I::Ldi(reg, Arc::new(V::Int(Arc::new(BigInt::from(value))))))
}
impl Call {
    pub fn make(entry: i64, first: i64, evidence: Evidence) -> Result<Self> {
        if !(0..=labels::MAX).contains(&entry) {
            return Err(Error::Entry(entry));
        }
        if first <= entry {
            return Err(Error::LabelStart(first));
        }
        let runtime = evidence.runtime().map_err(Error::Evidence)?;
        if !matches!(runtime.last(), Some(I::Stop())) {
            return Err(Error::MissingStop);
        }
        let (runtime, mut next) = labels::scope(first, &runtime).map_err(Error::Scope)?;
        let types = evidence.sealed().types();
        let mut inputs = vec![];
        for (index, bind) in evidence.program().inputs.iter().enumerate() {
            let reg = u8::try_from(index + 1).map_err(|_| Error::Verify)?;
            let memory = u16::try_from(1001 + index).map_err(|_| Error::Verify)?;
            inputs.push(ScopedInstruction::Plain(I::Mload(reg, memory)));
            match types.get(bind.typ) {
                Type::Int => inputs.extend([
                    integer(61, 0),
                    ScopedInstruction::Plain(I::Sub(reg, reg, 61)),
                ]),
                Type::Bool => {
                    let label = fresh(&mut next)?;
                    inputs.extend([
                        ScopedInstruction::JumpIf(reg, label),
                        ScopedInstruction::Jump(label),
                        ScopedInstruction::Mark(label),
                    ]);
                }
                _ => return Err(Error::Input(types.text(bind.typ))),
            }
        }
        let output = match types.get(evidence.output()) {
            Type::Int => vec![
                integer(61, 0),
                ScopedInstruction::Plain(I::Sub(0, 0, 61)),
                ScopedInstruction::Plain(I::Stop()),
            ],
            Type::Bool => {
                let label = fresh(&mut next)?;
                vec![
                    ScopedInstruction::JumpIf(0, label),
                    ScopedInstruction::Jump(label),
                    ScopedInstruction::Mark(label),
                    ScopedInstruction::Plain(I::Stop()),
                ]
            }
            _ => return Err(Error::Output(types.text(evidence.output()))),
        };
        let size = runtime.len() - 1;
        let body = 1 + inputs.len();
        let mut code = vec![ScopedInstruction::Mark(entry)];
        code.extend(inputs);
        code.extend_from_slice(&runtime[..size]);
        code.extend(output);
        if !labels::verify(&code) {
            return Err(Error::Verify);
        }
        Ok(Self {
            code,
            next,
            body,
            size,
            entry,
            first,
            evidence,
        })
    }
    pub fn code(&self) -> &[ScopedInstruction] {
        &self.code
    }
    pub fn wire_code(&self) -> Vec<I> {
        self.code.iter().map(ScopedInstruction::wire).collect()
    }
    pub fn next(&self) -> i64 {
        self.next
    }
    pub fn body(&self) -> usize {
        self.body
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn entry(&self) -> i64 {
        self.entry
    }
    pub fn first(&self) -> i64 {
        self.first
    }
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}
pub fn stamp(image: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"octra:aml:call-image");
    hash.update(image);
    hash.finalize().into()
}
fn segment(code: &[I], value: &Call) -> Result<(usize, usize)> {
    let mut start = None;
    for (pc, op) in code.iter().enumerate() {
        if matches!(op, I::Jdest(entry) if i64::from(*entry) == value.entry) {
            if start.is_some() {
                return Err(Error::Repeated(value.entry));
            }
            start = Some(pc);
        }
    }
    let start = start.ok_or(Error::Absent(value.entry))?;
    let end = start
        .checked_add(value.code.len())
        .filter(|end| *end <= code.len())
        .ok_or(Error::Differs(value.entry))?;
    if !value
        .code
        .iter()
        .zip(&code[start..end])
        .all(|(expected, actual)| expected.matches_wire(actual))
    {
        return Err(Error::Differs(value.entry));
    }
    Ok((start, end))
}
pub fn verify(image: &[u8], code: &[I], raw: &[u8]) -> Result<()> {
    admission::verify(code).map_err(|_| Error::Verify)?;
    let (expected, values) = decode_all(raw)?;
    let mut spans = values
        .iter()
        .map(|value| segment(code, value))
        .collect::<Result<Vec<_>>>()?;
    spans.sort_by_key(|(first, _)| *first);
    let mut prior = 0;
    for (first, last) in spans {
        if first < prior {
            return Err(Error::Overlap(prior, first));
        }
        prior = last;
    }
    if expected != stamp(image) {
        return Err(Error::Image);
    }
    Ok(())
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Evidence(error) => {
                [b"call evidence failed reason = ".as_slice(), &error.text()].concat()
            }
            Self::Scope(error) => format!("call label scope failed reason = {error}").into_bytes(),
            Self::Entry(value) => format!("call entry is invalid value = {value}").into_bytes(),
            Self::LabelStart(value) => {
                format!("call label start is invalid value = {value}").into_bytes()
            }
            Self::LabelSpace(value) => {
                format!("call label space is exhausted value = {value}").into_bytes()
            }
            Self::Input(typ) => {
                [b"call input type is unsupported type = ".as_slice(), typ].concat()
            }
            Self::Output(typ) => {
                [b"call output type is unsupported type = ".as_slice(), typ].concat()
            }
            Self::MissingStop => b"call runtime terminator is invalid".to_vec(),
            Self::Verify => b"call runtime verification failed".to_vec(),
            Self::Bits => b"call evidence bits are invalid".to_vec(),
            Self::Count(value) => {
                format!("call evidence count is invalid value = {value}").into_bytes()
            }
            Self::Form => b"call evidence form is invalid".to_vec(),
            Self::Repeated(value) => {
                format!("call evidence entry is repeated value = {value}").into_bytes()
            }
            Self::Absent(value) => {
                format!("call evidence entry is absent value = {value}").into_bytes()
            }
            Self::Differs(value) => {
                format!("call evidence code differs entry = {value}").into_bytes()
            }
            Self::Overlap(left, right) => {
                format!("call evidence code overlaps left = {left} right = {right}").into_bytes()
            }
            Self::Image => b"call image differs".to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
