// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Assembler.emit. Quoted strings intentionally retain raw OCaml bytes;
//! this textual projection does not escape, parse or admit instructions.
use super::{Error, Instruction as I, Value};
mod names;
mod parse;
pub use parse::{compile, Encoded, Failure};

fn add(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.try_reserve(bytes.len())
        .map_err(|_| Error::Allocation)?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn quoted(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    add(out, b"\"")?;
    add(out, bytes)?;
    add(out, b"\"")
}
fn reg(out: &mut Vec<u8>, value: u8) -> Result<(), Error> {
    add(out, format!("r{value}").as_bytes())
}
fn regs(out: &mut Vec<u8>, values: &[u8], count: bool) -> Result<(), Error> {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            add(out, b", ")?;
        }
        if count && index + 1 == values.len() {
            add(out, value.to_string().as_bytes())?;
        } else {
            reg(out, *value)?;
        }
    }
    Ok(())
}
fn value(out: &mut Vec<u8>, value: &Value) -> Result<(), Error> {
    match value {
        Value::Int(value) => add(out, value.to_string().as_bytes()),
        Value::Bool(true) => add(out, b"true"),
        Value::Bool(false) => add(out, b"false"),
        Value::Str(value) | Value::Bytes(value) | Value::Addr(value) => quoted(out, value),
    }
}
pub fn emit(code: &[I]) -> Result<Vec<u8>, Error> {
    let mut out = vec![];
    for (index, op) in code.iter().enumerate() {
        if index > 0 {
            add(&mut out, b"\n")?;
        }
        add(&mut out, names::NAMES[usize::from(op.opcode())])?;
        if let Some(values) = op.fixed_bytes() {
            if !values.is_empty() {
                add(&mut out, b" ")?;
            }
            regs(
                &mut out,
                &values,
                matches!(op, I::Xcall(..) | I::Spawn2(..)),
            )?;
            continue;
        }
        add(&mut out, b" ")?;
        match op {
            I::Ldi(dst, val) => {
                reg(&mut out, *dst)?;
                add(&mut out, b", ")?;
                value(&mut out, val)?;
            }
            I::Sload(dst, key) => {
                reg(&mut out, *dst)?;
                add(&mut out, b", ")?;
                quoted(&mut out, key)?;
            }
            I::Sstore(key, src) => {
                quoted(&mut out, key)?;
                add(&mut out, b", ")?;
                reg(&mut out, *src)?;
            }
            I::Sdel(key) => quoted(&mut out, key)?,
            I::CapCheck(kind, src) | I::CapClose(kind, src) => {
                add(&mut out, kind.to_string().as_bytes())?;
                add(&mut out, b", ")?;
                reg(&mut out, *src)?;
            }
            I::Mload(dst, slot) => {
                reg(&mut out, *dst)?;
                add(&mut out, format!(", {slot}").as_bytes())?;
            }
            I::Mstore(slot, src) => {
                add(&mut out, format!("{slot}, ").as_bytes())?;
                reg(&mut out, *src)?;
            }
            I::Jmp(dst) | I::Jdest(dst) => add(&mut out, dst.to_string().as_bytes())?,
            I::Jif(src, dst) | I::CallInt(src, dst) => {
                reg(&mut out, *src)?;
                add(&mut out, format!(", {dst}").as_bytes())?;
            }
            I::Emit(name, values) => {
                quoted(&mut out, name)?;
                add(&mut out, b", ")?;
                regs(&mut out, values, false)?;
            }
            _ => unreachable!("fixed-byte instructions were emitted above"),
        }
    }
    Ok(out)
}
