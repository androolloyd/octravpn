// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native marked assembler. Apply occupies a no-op cell until separately
//! sealed host blocks are attached; resolution does not authorize those hosts.
use super::super::{lexer::Span, machine::Literal, maps::Slot, Atom, Natural};
use super::Error;
use crate::octb::{Instruction as I, Value as V};
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Load(u8, Literal),
    Move(u8, u8),
    Plus(u8, u8, u8),
    Times(u8, u8, u8),
    Quotient(u8, u8, u8),
    Remainder(u8, u8, u8),
    Negate(u8, u8),
    Absolute(u8, u8),
    Same(u8, u8, u8),
    Different(u8, u8, u8),
    Less(u8, u8, u8),
    Greater(u8, u8, u8),
    Join(u8, u8, u8),
    Minus(u8, u8, u8),
    Size(u8, u8),
    Slice(u8, u8, u8, u8),
    CapClose(Natural, u8),
    Jump(u32),
    JumpIf(u8, u32),
    Mark(u32),
    Noop,
    Stop,
}
impl Operation {
    pub fn vm(&self) -> Option<I> {
        Some(match self {
            Self::Load(reg, value) => {
                let value = match value {
                    Literal::Bool(value) => V::Bool(*value),
                    Literal::Int(value) => V::Int(value.clone()),
                    Literal::Bytes(value) => V::Bytes(value.clone()),
                    Literal::Data(value) => V::Str(Arc::from(value.encode())),
                    Literal::Cap(..) => return None,
                };
                I::Ldi(*reg, Arc::new(value))
            }
            Self::Move(dst, src) => I::Mov(*dst, *src),
            Self::Plus(dst, left, right) => I::Add(*dst, *left, *right),
            Self::Times(dst, left, right) => I::Mul(*dst, *left, *right),
            Self::Quotient(dst, left, right) => I::Div(*dst, *left, *right),
            Self::Remainder(dst, left, right) => I::Mod(*dst, *left, *right),
            Self::Negate(dst, src) => I::Neg(*dst, *src),
            Self::Absolute(dst, src) => I::Abs(*dst, *src),
            Self::Same(dst, left, right) => I::Eq(*dst, *left, *right),
            Self::Different(dst, left, right) => I::Neq(*dst, *left, *right),
            Self::Less(dst, left, right) => I::Lt(*dst, *left, *right),
            Self::Greater(dst, left, right) => I::Gt(*dst, *left, *right),
            Self::Join(dst, left, right) => I::Concat(*dst, *left, *right),
            Self::Minus(dst, left, right) => I::Sub(*dst, *left, *right),
            Self::Size(dst, src) => I::Strlen(*dst, *src),
            Self::Slice(dst, src, first, count) => I::Substr(*dst, *src, *first, *count),
            Self::CapClose(kind, reg) => I::CapClose(Arc::new(kind.get().into()), *reg),
            Self::Jump(pc) => I::Jmp(*pc),
            Self::JumpIf(reg, pc) => I::Jif(*reg, *pc),
            Self::Mark(pc) => I::Jdest(*pc),
            Self::Noop => I::Nop(),
            Self::Stop => I::Stop(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectLayout {
    pub index: i64,
    pub atom: Atom,
    pub payload: Vec<u8>,
    pub scratch: Vec<u8>,
}
#[derive(Clone, Debug)]
pub enum Asm {
    Op(Operation),
    Goto(u32),
    Branch(u8, u32),
    Place(u32),
    Apply(EffectLayout),
}
#[derive(Clone, Debug)]
pub struct Marked {
    pub asm: Asm,
    pub at: Span,
    pub live: Arc<[Slot]>,
}
#[derive(Clone, Debug)]
pub struct Assembly {
    pub code: Vec<Operation>,
    pub spans: Vec<Span>,
    pub live: Vec<Arc<[Slot]>>,
    pub effects: Vec<EffectLayout>,
}
pub fn resolve(values: &[Marked]) -> Result<Assembly, Error> {
    let mut labels = BTreeMap::new();
    for (pc, value) in values.iter().enumerate() {
        if let Asm::Place(id) = &value.asm {
            if labels
                .insert(*id, u32::try_from(pc).map_err(|_| Error::Label)?)
                .is_some()
            {
                return Err(Error::Label);
            }
        }
    }
    let mut out = Assembly {
        code: vec![],
        spans: vec![],
        live: vec![],
        effects: vec![],
    };
    for value in values {
        let op = match &value.asm {
            Asm::Op(op) => op.clone(),
            Asm::Goto(label) => Operation::Jump(*labels.get(label).ok_or(Error::Label)?),
            Asm::Branch(reg, label) => {
                Operation::JumpIf(*reg, *labels.get(label).ok_or(Error::Label)?)
            }
            Asm::Place(label) => Operation::Mark(*labels.get(label).ok_or(Error::Label)?),
            Asm::Apply(effect) => {
                out.effects.push(effect.clone());
                Operation::Noop
            }
        };
        out.code.push(op);
        out.spans.push(value.at);
        out.live.push(value.live.clone());
    }
    Ok(out)
}
