// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native runtime type, equality, payable and reentrancy guard templates.
use super::{BigInt, BinOp, Emitter, Result, Syntax, Type, I};
impl Emitter {
    pub fn bytes32_check(&mut self, value: u8) -> Result<()> {
        let length = self.alloc_reg()?;
        let expected = self.alloc_reg()?;
        let compare = self.alloc_reg()?;
        self.emit(I::Strlen(length, value))?;
        self.integer(expected, 32)?;
        self.emit(I::Eq(compare, length, expected))?;
        let ok = self.alloc_label()?;
        self.emit(I::Jif(compare, ok))?;
        self.emit(I::Revert())?;
        self.emit(I::Jdest(ok))
    }
    pub fn unsigned_check(&mut self, value: u8, maximum: BigInt) -> Result<()> {
        let zero = self.alloc_reg()?;
        let max = self.alloc_reg()?;
        let compare = self.alloc_reg()?;
        let fail = self.alloc_label()?;
        let ok = self.alloc_label()?;
        self.integer(zero, 0)?;
        self.integer(max, maximum)?;
        self.emit(I::Lt(compare, value, zero))?;
        self.emit(I::Jif(compare, fail))?;
        self.emit(I::Gt(compare, value, max))?;
        self.emit(I::Jif(compare, fail))?;
        self.emit(I::Jmp(ok))?;
        self.emit(I::Jdest(fail))?;
        self.emit(I::Revert())?;
        self.emit(I::Jdest(ok))
    }
    pub fn type_check(&mut self, value: u8, typ: &Type) -> Result<()> {
        match typ {
            Type::Bytes32 => self.bytes32_check(value),
            Type::U64 => self.unsigned_check(value, (BigInt::from(1u8) << 64usize) - 1),
            Type::U128 => self.unsigned_check(value, (BigInt::from(1u8) << 128usize) - 1),
            Type::U256 => self.unsigned_check(value, (BigInt::from(1u8) << 256usize) - 1),
            _ => Ok(()),
        }
    }
    pub fn result_type_check(&mut self, value: u8, typ: &Type) -> Result<()> {
        if matches!(typ, Type::U64 | Type::U128 | Type::U256) {
            self.type_check(value, typ)
        } else {
            Ok(())
        }
    }
    pub fn equality(
        &mut self,
        typ: &Type,
        op: BinOp,
        destination: u8,
        left: u8,
        right: u8,
    ) -> Result<()> {
        let saved = self.next_reg;
        let (left, right) = if self.syntax == Syntax::Source
            && matches!(typ, Type::Address | Type::Bytes | Type::Bytes32)
        {
            let a = self.alloc_reg()?;
            let b = self.alloc_reg()?;
            self.string(a, b"")?;
            self.emit(I::Concat(a, a, left))?;
            self.string(b, b"")?;
            self.emit(I::Concat(b, b, right))?;
            (a, b)
        } else {
            (left, right)
        };
        match op {
            BinOp::Eq => self.emit(I::Eq(destination, left, right))?,
            BinOp::Neq => self.emit(I::Neq(destination, left, right))?,
            _ => return Err(self.error("comparison is not equality")),
        }
        self.next_reg = saved;
        Ok(())
    }
    pub fn update_value(&mut self, op: BinOp, typ: &Type, left: u8, right: u8) -> Result<u8> {
        let result = self.alloc_reg()?;
        let instruction = match op {
            BinOp::Add if matches!(typ, Type::String | Type::Address) => {
                I::Concat(result, left, right)
            }
            BinOp::Add => I::Add(result, left, right),
            BinOp::Sub => I::Sub(result, left, right),
            BinOp::Mul => I::Mul(result, left, right),
            BinOp::Div => I::Div(result, left, right),
            BinOp::Mod => I::Mod(result, left, right),
            BinOp::Eq => I::Eq(result, left, right),
            BinOp::Neq => I::Neq(result, left, right),
            BinOp::Lt => I::Lt(result, left, right),
            BinOp::Gt => I::Gt(result, left, right),
            _ => return Err(self.error("compound operator is unavailable")),
        };
        self.emit(instruction)?;
        self.type_check(result, typ)?;
        Ok(result)
    }
    pub fn nonpayable_guard(&mut self, ok: u32) -> Result<()> {
        let value = self.alloc_reg()?;
        self.emit(I::Value(value))?;
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        let compare = self.alloc_reg()?;
        self.emit(I::Eq(compare, value, zero))?;
        self.emit(I::Jif(compare, ok))?;
        self.emit(I::Revert())?;
        self.emit(I::Jdest(ok))?;
        self.next_reg = self.base_reg;
        Ok(())
    }
    pub fn nonreentrant_enter(&mut self) -> Result<()> {
        let lock = self.alloc_reg()?;
        self.emit(I::Sload(lock, self.nonreentrant_key().into()))?;
        let one = self.alloc_reg()?;
        self.string(one, b"1")?;
        let locked = self.alloc_reg()?;
        self.emit(I::Eq(locked, lock, one))?;
        let ok = self.alloc_label()?;
        let not_locked = self.alloc_reg()?;
        self.boolean(not_locked, true)?;
        self.emit(I::Neq(not_locked, locked, not_locked))?;
        self.emit(I::Jif(not_locked, ok))?;
        self.emit(I::Revert())?;
        self.emit(I::Jdest(ok))?;
        self.emit(I::Sstore(self.nonreentrant_key().into(), one))?;
        self.next_reg = self.base_reg;
        Ok(())
    }
    pub fn nonreentrant_exit(&mut self) -> Result<()> {
        let zero = self.alloc_reg()?;
        self.string(zero, b"0")?;
        self.emit(I::Sstore(self.nonreentrant_key().into(), zero))
    }
}
