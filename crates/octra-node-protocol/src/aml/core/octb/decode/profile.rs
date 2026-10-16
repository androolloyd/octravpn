// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Context, DecodeError, Literal, Natural, Op, Result, I, V};
pub(super) fn reg(pc: usize, value: u8) -> Result<u8> {
    if value >= 64 {
        Err(DecodeError::RegisterRef(pc, u32::from(value)))
    } else {
        Ok(value)
    }
}
fn regs<const N: usize>(pc: usize, values: [u8; N]) -> Result<[u8; N]> {
    // Native constructor argument validation runs from right to left.
    for value in values.iter().rev() {
        reg(pc, *value)?;
    }
    Ok(values)
}
impl Context<'_> {
    fn literal(&mut self, pc: usize, value: &V) -> Result<Literal> {
        Ok(match value {
            V::Int(value) => Literal::Int(value.clone()),
            V::Bool(value) => Literal::Bool(*value),
            V::Bytes(value) => Literal::Bytes(value.clone()),
            V::Str(raw) => Literal::Data(self.data(raw).ok_or(DecodeError::InstructionData(pc))?),
            V::Addr(_) => return Err(DecodeError::InstructionData(pc)),
        })
    }
    pub(super) fn profile(&mut self, pc: usize, value: &I) -> Result<Op> {
        Ok(match value {
            I::Ldi(dst, value) => {
                let literal = self.literal(pc, value)?;
                Op::Load(reg(pc, *dst)?, literal)
            }
            I::Mov(dst, src) => {
                let [dst, src] = regs(pc, [*dst, *src])?;
                Op::Move(dst, src)
            }
            I::Add(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Plus(dst, left, right)
            }
            I::Sub(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Minus(dst, left, right)
            }
            I::Mul(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Times(dst, left, right)
            }
            I::Div(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Quotient(dst, left, right)
            }
            I::Mod(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Remainder(dst, left, right)
            }
            I::Neg(dst, src) => {
                let [dst, src] = regs(pc, [*dst, *src])?;
                Op::Negate(dst, src)
            }
            I::Abs(dst, src) => {
                let [dst, src] = regs(pc, [*dst, *src])?;
                Op::Absolute(dst, src)
            }
            I::Eq(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Same(dst, left, right)
            }
            I::Neq(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Different(dst, left, right)
            }
            I::Lt(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Less(dst, left, right)
            }
            I::Gt(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Greater(dst, left, right)
            }
            I::Concat(dst, left, right) => {
                let [dst, left, right] = regs(pc, [*dst, *left, *right])?;
                Op::Join(dst, left, right)
            }
            I::Strlen(dst, src) => {
                let [dst, src] = regs(pc, [*dst, *src])?;
                Op::Size(dst, src)
            }
            I::Substr(dst, src, first, count) => {
                let [dst, src, first, count] = regs(pc, [*dst, *src, *first, *count])?;
                Op::Slice(dst, src, first, count)
            }
            I::CapClose(kind, src) => {
                let kind = Natural::new(kind).ok_or(DecodeError::InstructionData(pc))?;
                Op::CapClose(kind, reg(pc, *src)?)
            }
            I::Jmp(at) => Op::Jump(*at),
            I::Jif(guard, at) => Op::JumpIf(reg(pc, *guard)?, *at),
            I::Jdest(at) => Op::Mark(*at),
            I::Nop() => Op::Noop,
            I::Stop() => Op::Stop,
            _ => return Err(DecodeError::Opcode(pc, i32::from(value.opcode()))),
        })
    }
}
