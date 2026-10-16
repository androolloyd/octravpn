// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Source option encoding and storage templates from the adopted generator.
use super::{Emitter, Result, I};
impl Emitter {
    pub fn option_parts(&mut self, value: u8) -> Result<(u8, u8)> {
        let present = self.alloc_reg()?;
        let payload = self.alloc_reg()?;
        let saved = self.next_reg;
        let tag = self.alloc_reg()?;
        let zero = self.alloc_reg()?;
        let one = self.alloc_reg()?;
        let size = self.alloc_reg()?;
        let test = self.alloc_reg()?;
        let done = self.alloc_label()?;
        self.string(payload, b"")?;
        self.string(tag, b"0")?;
        self.emit(I::Neq(present, value, tag))?;
        self.emit(I::Eq(test, value, tag))?;
        self.emit(I::Jif(test, done))?;
        self.integer(zero, 0)?;
        self.integer(one, 1)?;
        self.emit(I::Substr(tag, value, zero, one))?;
        self.string(payload, b"1")?;
        self.emit(I::Eq(test, tag, payload))?;
        self.emit(I::Assert(test))?;
        self.emit(I::Strlen(size, value))?;
        self.emit(I::Sub(size, size, one))?;
        self.emit(I::Substr(payload, value, one, size))?;
        self.emit(I::Jdest(done))?;
        self.next_reg = saved;
        Ok((present, payload))
    }
    pub fn option_load(&mut self, value: u8, mark: u8) -> Result<u8> {
        let result = self.alloc_reg()?;
        let saved = self.next_reg;
        let test = self.alloc_reg()?;
        let some = self.alloc_label()?;
        let done = self.alloc_label()?;
        self.string(result, b"true")?;
        self.emit(I::Eq(test, mark, result))?;
        self.emit(I::Jif(test, some))?;
        self.string(result, b"0")?;
        self.emit(I::Eq(test, mark, result))?;
        self.emit(I::Assert(test))?;
        self.emit(I::Jmp(done))?;
        self.emit(I::Jdest(some))?;
        self.string(result, b"1")?;
        self.emit(I::Concat(result, result, value))?;
        self.emit(I::Jdest(done))?;
        self.next_reg = saved;
        Ok(result)
    }
    pub fn option_store(&mut self, key: u8, mark: u8, value: u8) -> Result<()> {
        let (present, payload) = self.option_parts(value)?;
        let some = self.alloc_label()?;
        let done = self.alloc_label()?;
        self.emit(I::Jif(present, some))?;
        self.emit(I::Sdelk(key))?;
        self.emit(I::Sdelk(mark))?;
        self.emit(I::Jmp(done))?;
        self.emit(I::Jdest(some))?;
        self.emit(I::Sstorek(key, payload))?;
        self.string(present, b"true")?;
        self.emit(I::Sstorek(mark, present))?;
        self.emit(I::Jdest(done))
    }
}
