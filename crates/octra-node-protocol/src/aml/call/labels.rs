// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Call metadata uses native signed 63-bit label identities even though OCTB
//! stores only 32 label bits. Retain full identities until segment verification.
use crate::octb::{admission, Instruction as I};
use std::collections::BTreeMap;
pub(super) const MAX: i64 = (1_i64 << 62) - 1;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopedInstruction {
    Plain(I),
    Jump(i64),
    JumpIf(u8, i64),
    Mark(i64),
    CallInt(u8, i64),
}
impl ScopedInstruction {
    /// Native Bytecode.encode writes the low 32 bits of symbolic label operands.
    pub fn wire(&self) -> I {
        match self {
            Self::Plain(op) => op.clone(),
            Self::Jump(label) => I::Jmp(*label as u32),
            Self::JumpIf(reg, label) => I::Jif(*reg, *label as u32),
            Self::Mark(label) => I::Jdest(*label as u32),
            Self::CallInt(reg, label) => I::CallInt(*reg, *label as u32),
        }
    }
    pub fn matches_wire(&self, op: &I) -> bool {
        match (self, op) {
            (Self::Plain(left), right) => left == right,
            (Self::Jump(left), I::Jmp(right)) | (Self::Mark(left), I::Jdest(right)) => {
                *left == i64::from(*right)
            }
            (Self::JumpIf(lr, left), I::Jif(rr, right))
            | (Self::CallInt(lr, left), I::CallInt(rr, right)) => {
                lr == rr && *left == i64::from(*right)
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeError {
    Start(i64),
    Overflow(i64),
    Duplicate(i64),
    Missing(i64),
}
impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(value) => write!(f, "label scope start is invalid value = {value}"),
            Self::Overflow(value) => write!(f, "label scope exceeds integer range start = {value}"),
            Self::Duplicate(value) => write!(f, "label is repeated value = {value}"),
            Self::Missing(value) => write!(f, "label target is absent value = {value}"),
        }
    }
}
impl std::error::Error for ScopeError {}
pub(super) fn scope(first: i64, code: &[I]) -> Result<(Vec<ScopedInstruction>, i64), ScopeError> {
    if first < 0 {
        return Err(ScopeError::Start(first));
    }
    let mut found = BTreeMap::new();
    let mut count = 0_i64;
    for op in code {
        if let I::Jdest(label) = op {
            if found.insert(*label, count).is_some() {
                return Err(ScopeError::Duplicate(i64::from(*label)));
            }
            count += 1;
        }
    }
    if first > MAX - count {
        return Err(ScopeError::Overflow(first));
    }
    let mapped = |label: u32| {
        found
            .get(&label)
            .map(|index| first + index)
            .ok_or(ScopeError::Missing(i64::from(label)))
    };
    let mut out = Vec::with_capacity(code.len());
    for op in code {
        out.push(match op {
            I::Jdest(label) => ScopedInstruction::Mark(mapped(*label)?),
            I::Jmp(label) => ScopedInstruction::Jump(mapped(*label)?),
            I::Jif(reg, label) => ScopedInstruction::JumpIf(*reg, mapped(*label)?),
            I::CallInt(reg, label) => ScopedInstruction::CallInt(*reg, mapped(*label)?),
            _ => ScopedInstruction::Plain(op.clone()),
        });
    }
    Ok((out, first + count))
}
pub(super) fn verify(code: &[ScopedInstruction]) -> bool {
    if code.is_empty() || code.len() > 1_048_576 {
        return false;
    }
    // The verifier depends on label identity, not magnitude. A dense temporary
    // representation preserves duplicates and missing targets without truncation.
    let mut labels = BTreeMap::new();
    for op in code {
        let label = match op {
            ScopedInstruction::Plain(_) => continue,
            ScopedInstruction::Jump(label)
            | ScopedInstruction::JumpIf(_, label)
            | ScopedInstruction::Mark(label)
            | ScopedInstruction::CallInt(_, label) => *label,
        };
        let next = labels.len() as u32;
        labels.entry(label).or_insert(next);
    }
    let code = code
        .iter()
        .map(|op| match op {
            ScopedInstruction::Plain(op) => op.clone(),
            ScopedInstruction::Jump(label) => I::Jmp(labels[label]),
            ScopedInstruction::JumpIf(reg, label) => I::Jif(*reg, labels[label]),
            ScopedInstruction::Mark(label) => I::Jdest(labels[label]),
            ScopedInstruction::CallInt(reg, label) => I::CallInt(*reg, labels[label]),
        })
        .collect::<Vec<_>>();
    admission::verify(&code).is_ok()
}
