// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native assembly input retains OCaml integers until verifier/policy checks.
//! Only its final wire projection truncates memory indices and label operands.
use super::{names, Error, Value, I};
use crate::{
    native_exception,
    native_integer::{parse_int63, parse_integer},
    octb::{self, admission},
};
use num_bigint::BigInt;
use std::{collections::BTreeMap, sync::Arc};
mod accepted;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Exception(Vec<u8>),
    Rejected(Error),
    Unavailable(Error),
}
impl Failure {
    fn native(name: &[u8], reason: impl AsRef<[u8]>) -> Self {
        Self::Exception(native_exception::string_argument(name, reason.as_ref()))
    }
    fn rejected(reason: impl Into<String>) -> Self {
        Self::Rejected(Error::Message(reason.into()))
    }
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        if error.is_operational() {
            Self::Unavailable(error)
        } else {
            Self::Rejected(error)
        }
    }
}
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub instructions: usize,
}
enum Op {
    Fixed(u8, Vec<i64>),
    Load(i64, Arc<Value>),
    Get(i64, Arc<[u8]>),
    Set(Arc<[u8]>, i64),
    Delete(Arc<[u8]>),
    Cap(bool, Arc<BigInt>, i64),
    Memory(bool, i64, i64),
    Jump(u8, Option<i64>, i64),
    Emit(Arc<[u8]>, Vec<i64>),
}
fn trim(raw: &[u8]) -> &[u8] {
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw
        .iter()
        .position(|byte| !space(byte))
        .unwrap_or(raw.len());
    let end = raw
        .iter()
        .rposition(|byte| !space(byte))
        .map_or(start, |at| at + 1);
    &raw[start..end]
}
fn quoted(raw: &[u8]) -> Option<&[u8]> {
    (raw.len() >= 2 && raw[0] == b'"' && raw[raw.len() - 1] == b'"').then(|| &raw[1..raw.len() - 1])
}
fn args(raw: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    let mut start = 0;
    let mut string = false;
    for (at, byte) in raw.iter().enumerate() {
        if *byte == b'"' {
            string = !string;
        } else if *byte == b',' && !string {
            out.push(trim(&raw[start..at]));
            start = at + 1;
        }
    }
    let last = trim(&raw[start..]);
    if !last.is_empty() {
        out.push(last);
    }
    out
}
fn integer(raw: &[u8]) -> Result<i64, Failure> {
    parse_int63(trim(raw)).ok_or_else(|| Failure::native(b"Failure", b"int_of_string"))
}
fn number(raw: &[u8]) -> Result<Arc<BigInt>, Failure> {
    parse_integer(trim(raw))
        .map(Arc::new)
        .ok_or_else(|| Failure::native(b"Invalid_argument", b"Z.of_substring_base: invalid digit"))
}
fn reg(raw: &[u8]) -> Result<i64, Failure> {
    let raw = trim(raw);
    if raw.len() >= 2 && raw[0] == b'r' {
        parse_int63(&raw[1..]).ok_or_else(|| Failure::native(b"Failure", b"int_of_string"))
    } else {
        Err(Failure::native(
            b"Failure",
            [b"bad register: ".as_slice(), raw].concat(),
        ))
    }
}
fn value(raw: &[u8]) -> Result<Arc<Value>, Failure> {
    let raw = trim(raw);
    Ok(Arc::new(if let Some(raw) = quoted(raw) {
        Value::Str(raw.into())
    } else if raw == b"true" {
        Value::Bool(true)
    } else if raw == b"false" {
        Value::Bool(false)
    } else {
        Value::Int(number(raw)?)
    }))
}
fn parse_line(raw: &[u8]) -> Result<Option<Op>, Failure> {
    let raw = trim(raw);
    if raw.is_empty() || raw[0] == b';' {
        return Ok(None);
    }
    let split = raw
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(raw.len());
    let name = raw[..split].to_ascii_uppercase();
    let args = args(trim(raw.get(split + 1..).unwrap_or_default()));
    let unknown = || {
        Failure::native(
            b"Failure",
            [b"unknown instruction: ".as_slice(), raw].concat(),
        )
    };
    let tag = names::NAMES
        .iter()
        .position(|value| *value == name.as_slice())
        .ok_or_else(&unknown)? as u8;
    // Native constructor argument evaluation visits the rightmost operand
    // first. EMIT's List.map is the separate left-to-right case below.
    let op = match (tag, args.as_slice()) {
        (0x0b, [dst, val]) => {
            let val = value(val)?;
            Op::Load(reg(dst)?, val)
        }
        (0x0d, [dst, key]) if quoted(key).is_some() => {
            Op::Get(reg(dst)?, quoted(key).expect("quoted guard").into())
        }
        (0x0e, [key, src]) if quoted(key).is_some() => {
            Op::Set(quoted(key).expect("quoted guard").into(), reg(src)?)
        }
        (0x0f, [key]) if quoted(key).is_some() => {
            Op::Delete(quoted(key).expect("quoted guard").into())
        }
        (tag @ (0x89 | 0x8a), [kind, src]) => {
            let src = reg(src)?;
            Op::Cap(tag == 0x8a, number(kind)?, src)
        }
        (0x12, [dst, slot]) => {
            let slot = integer(slot)?;
            Op::Memory(false, slot, reg(dst)?)
        }
        (0x13, [slot, src]) => {
            let src = reg(src)?;
            Op::Memory(true, integer(slot)?, src)
        }
        (tag @ (0x14 | 0x16), [label]) => Op::Jump(tag, None, integer(label)?),
        (tag @ (0x15 | 0x2d), [src, label]) => {
            let label = integer(label)?;
            Op::Jump(tag, Some(reg(src)?), label)
        }
        (0x27, [name, regs @ ..]) if quoted(name).is_some() => Op::Emit(
            quoted(name).expect("quoted guard").into(),
            regs.iter().map(|raw| reg(raw)).collect::<Result<_, _>>()?,
        ),
        _ if accepted::FIXED.contains(&tag) && I::fixed_arity(tag) == Some(args.len()) => {
            let count = matches!(tag, 0x21 | 0x53);
            let mut values = vec![0; args.len()];
            for index in (0..args.len()).rev() {
                values[index] = if count && index + 1 == args.len() {
                    integer(args[index])?
                } else {
                    reg(args[index])?
                };
            }
            Op::Fixed(tag, values)
        }
        _ => return Err(unknown()),
    };
    Ok(Some(op))
}
fn register(pc: usize, reg: i64) -> Result<(), Failure> {
    if (0..=63).contains(&reg) {
        Ok(())
    } else {
        Err(Failure::rejected(format!(
            "invalid register r{reg} at pc {pc}"
        )))
    }
}
fn registers(pc: usize, regs: &[i64]) -> Result<(), Failure> {
    for reg in regs {
        register(pc, *reg)?;
    }
    Ok(())
}
fn span(pc: usize, base: i64, count: i64) -> Result<(), Failure> {
    if !(0..=63).contains(&base) || count < 0 || count > 64 - base {
        Err(Failure::rejected(format!(
            "invalid register span r{base}+{count} at pc {pc}"
        )))
    } else {
        Ok(())
    }
}
fn verify(code: &[Op]) -> Result<BTreeMap<i64, u32>, Failure> {
    if code.is_empty() {
        return Err(Failure::rejected("empty code"));
    }
    if code.len() > 1_048_576 {
        return Err(Failure::rejected(format!(
            "code too large: {} instructions",
            code.len()
        )));
    }
    let mut labels = BTreeMap::new();
    let mut duplicate = None;
    for op in code {
        if let Op::Jump(0x16, _, label) = op {
            let next = labels.len() as u32;
            if labels.insert(*label, next).is_some() {
                duplicate = Some(*label);
            }
        }
    }
    if let Some(label) = duplicate {
        return Err(Failure::rejected(format!("duplicate JDEST {label}")));
    }
    for (pc, op) in code.iter().enumerate() {
        let reserved = |key: &[u8]| {
            if key.first() == Some(&0) {
                Err(Failure::rejected(format!(
                    "write to reserved key at pc {pc}"
                )))
            } else {
                Ok(())
            }
        };
        match op {
            Op::Fixed(0x21, regs) => {
                registers(pc, &regs[..3])?;
                span(pc, regs[3], regs[4])?;
            }
            Op::Fixed(0x53, regs) => {
                registers(pc, &regs[..2])?;
                span(pc, regs[2], regs[3])?;
            }
            Op::Fixed(_, regs) | Op::Emit(_, regs) => registers(pc, regs)?,
            Op::Load(reg, _) | Op::Get(reg, _) | Op::Memory(_, _, reg) => register(pc, *reg)?,
            Op::Set(key, reg) => {
                reserved(key)?;
                register(pc, *reg)?;
            }
            Op::Delete(key) => reserved(key)?,
            Op::Cap(_, kind, reg) => {
                if kind.as_ref() < &BigInt::from(0) || kind.as_ref() > &BigInt::from(1_000_000) {
                    return Err(Failure::rejected(format!(
                        "capability kind {kind} at pc {pc}"
                    )));
                }
                register(pc, *reg)?;
            }
            Op::Jump(0x16, _, _) => (),
            Op::Jump(_, reg, label) => {
                if let Some(reg) = reg {
                    register(pc, *reg)?;
                }
                if !labels.contains_key(label) {
                    return Err(Failure::rejected(format!(
                        "invalid jump destination {label}"
                    )));
                }
            }
        }
    }
    Ok(labels)
}
fn lower(op: &Op, labels: Option<&BTreeMap<i64, u32>>) -> I {
    match op {
        Op::Fixed(tag, regs) => {
            I::from_fixed(*tag, &regs.iter().map(|reg| *reg as u8).collect::<Vec<_>>())
                .expect("parsed fixed arity")
        }
        Op::Load(reg, value) => I::Ldi(*reg as u8, value.clone()),
        Op::Get(reg, key) => I::Sload(*reg as u8, key.clone()),
        Op::Set(key, reg) => I::Sstore(key.clone(), *reg as u8),
        Op::Delete(key) => I::Sdel(key.clone()),
        Op::Cap(false, kind, reg) => I::CapCheck(kind.clone(), *reg as u8),
        Op::Cap(true, kind, reg) => I::CapClose(kind.clone(), *reg as u8),
        Op::Memory(false, slot, reg) => I::Mload(*reg as u8, *slot as u16),
        Op::Memory(true, slot, reg) => I::Mstore(*slot as u16, *reg as u8),
        Op::Jump(tag, reg, label) => {
            let label = labels.map_or(*label as u32, |labels| labels[label]);
            match tag {
                0x14 => I::Jmp(label),
                0x16 => I::Jdest(label),
                0x15 => I::Jif(reg.expect("conditional register") as u8, label),
                0x2d => I::CallInt(reg.expect("call register") as u8, label),
                _ => unreachable!("parsed jump tag"),
            }
        }
        Op::Emit(name, regs) => I::Emit(name.clone(), regs.iter().map(|reg| *reg as u8).collect()),
    }
}
pub fn compile(raw: &[u8]) -> Result<Encoded, Failure> {
    let mut code = vec![];
    for line in raw.split(|byte| *byte == b'\n') {
        if let Some(op) = parse_line(line)? {
            code.push(op);
        }
    }
    let labels = verify(&code)?;
    let checked: Vec<_> = code.iter().map(|op| lower(op, Some(&labels))).collect();
    admission::of_code(checked, false)?;
    let wire: Vec<_> = code.iter().map(|op| lower(op, None)).collect();
    let bytes = octb::encode(&wire, &octb::Metadata::default(), false)?;
    Ok(Encoded {
        bytes,
        instructions: wire.len(),
    })
}
