// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native string expansion, including its register and unused-label allocation.
use super::{Emitter, Result, I};
impl Emitter {
    pub fn netstring_element(&mut self, packed: u8, value: u8) -> Result<()> {
        let text = self.alloc_reg()?;
        self.string(text, b"")?;
        self.emit(I::Concat(text, text, value))?;
        let length = self.alloc_reg()?;
        self.emit(I::Strlen(length, text))?;
        let mark = self.alloc_reg()?;
        self.string(mark, b"#")?;
        self.emit(I::Concat(packed, packed, length))?;
        self.emit(I::Concat(packed, packed, mark))?;
        self.emit(I::Concat(packed, packed, text))
    }
    pub fn netstring_next(&mut self, hash: u8, remaining: u8, local: u8) -> Result<()> {
        let hash_position = self.alloc_reg()?;
        self.emit(I::Indexof(hash_position, remaining, hash))?;
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        let length_text = self.alloc_reg()?;
        self.emit(I::Substr(length_text, remaining, zero, hash_position))?;
        let element_len = self.alloc_reg()?;
        self.emit(I::Add(element_len, zero, length_text))?;
        let one = self.alloc_reg()?;
        self.integer(one, 1)?;
        let payload_start = self.alloc_reg()?;
        self.emit(I::Add(payload_start, hash_position, one))?;
        self.emit(I::Substr(local, remaining, payload_start, element_len))?;
        let next_start = self.alloc_reg()?;
        self.emit(I::Add(next_start, payload_start, element_len))?;
        let total_len = self.alloc_reg()?;
        self.emit(I::Strlen(total_len, remaining))?;
        let remaining_len = self.alloc_reg()?;
        self.emit(I::Sub(remaining_len, total_len, next_start))?;
        self.emit(I::Substr(remaining, remaining, next_start, remaining_len))
    }
    pub fn split_text(&mut self, dest: u8, text: u8, delimiter: u8) -> Result<()> {
        let count = self.alloc_reg()?;
        self.integer(count, 0)?;
        let remaining = self.alloc_reg()?;
        self.emit(I::Mov(remaining, text))?;
        let base = self.alloc_reg()?;
        self.integer(base, 100)?;
        let test = self.alloc_label()?;
        let body = self.alloc_label()?;
        let done = self.alloc_label()?;
        let delimiter_len = self.alloc_reg()?;
        self.emit(I::Strlen(delimiter_len, delimiter))?;
        self.emit(I::Jdest(test))?;
        let position = self.alloc_reg()?;
        self.emit(I::Indexof(position, remaining, delimiter))?;
        let negative_one = self.alloc_reg()?;
        self.integer(negative_one, -1)?;
        let found = self.alloc_reg()?;
        self.emit(I::Neq(found, position, negative_one))?;
        self.emit(I::Jif(found, body))?;
        let slot = self.alloc_reg()?;
        self.emit(I::Add(slot, base, count))?;
        self.emit(I::Mstorer(slot, remaining))?;
        let one = self.alloc_reg()?;
        self.integer(one, 1)?;
        self.emit(I::Add(count, count, one))?;
        self.emit(I::Jmp(done))?;
        self.emit(I::Jdest(body))?;
        let part = self.alloc_reg()?;
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        self.emit(I::Substr(part, remaining, zero, position))?;
        let slot = self.alloc_reg()?;
        self.emit(I::Add(slot, base, count))?;
        self.emit(I::Mstorer(slot, part))?;
        let one = self.alloc_reg()?;
        self.integer(one, 1)?;
        self.emit(I::Add(count, count, one))?;
        let next_start = self.alloc_reg()?;
        self.emit(I::Add(next_start, position, delimiter_len))?;
        let total_len = self.alloc_reg()?;
        self.emit(I::Strlen(total_len, remaining))?;
        let remaining_len = self.alloc_reg()?;
        self.emit(I::Sub(remaining_len, total_len, next_start))?;
        self.emit(I::Substr(remaining, remaining, next_start, remaining_len))?;
        self.emit(I::Jmp(test))?;
        self.emit(I::Jdest(done))?;
        self.emit(I::Mov(dest, count))
    }
    pub fn join_text(&mut self, dest: u8, count: u8, delimiter: u8) -> Result<()> {
        self.string(dest, b"")?;
        let index = self.alloc_reg()?;
        self.integer(index, 0)?;
        let base = self.alloc_reg()?;
        self.integer(base, 100)?;
        let test = self.alloc_label()?;
        let body = self.alloc_label()?;
        self.emit(I::Jmp(test))?;
        self.emit(I::Jdest(body))?;
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        let first = self.alloc_reg()?;
        self.emit(I::Eq(first, index, zero))?;
        let skip = self.alloc_label()?;
        self.emit(I::Jif(first, skip))?;
        self.emit(I::Concat(dest, dest, delimiter))?;
        self.emit(I::Jdest(skip))?;
        let slot = self.alloc_reg()?;
        self.emit(I::Add(slot, base, index))?;
        let part = self.alloc_reg()?;
        self.emit(I::Mloadr(part, slot))?;
        self.emit(I::Concat(dest, dest, part))?;
        let one = self.alloc_reg()?;
        self.integer(one, 1)?;
        self.emit(I::Add(index, index, one))?;
        self.emit(I::Jdest(test))?;
        let compare = self.alloc_reg()?;
        self.emit(I::Lt(compare, index, count))?;
        self.emit(I::Jif(compare, body))
    }
    pub fn replace_text(&mut self, dest: u8, text: u8, old: u8, new: u8) -> Result<()> {
        let position = self.alloc_reg()?;
        self.emit(I::Indexof(position, text, old))?;
        let negative_one = self.alloc_reg()?;
        self.integer(negative_one, -1)?;
        let found = self.alloc_reg()?;
        self.emit(I::Neq(found, position, negative_one))?;
        let replace = self.alloc_label()?;
        let done = self.alloc_label()?;
        self.emit(I::Jif(found, replace))?;
        self.emit(I::Mov(dest, text))?;
        self.emit(I::Jmp(done))?;
        self.emit(I::Jdest(replace))?;
        self.replace_at(dest, text, old, new, position)?;
        self.emit(I::Jdest(done))
    }
    pub fn replace_all_text(&mut self, dest: u8, text: u8, old: u8, new: u8) -> Result<()> {
        self.emit(I::Mov(dest, text))?;
        let body = self.alloc_label()?;
        let _unused = self.alloc_label()?;
        let done = self.alloc_label()?;
        self.emit(I::Jdest(body))?;
        let position = self.alloc_reg()?;
        self.emit(I::Indexof(position, dest, old))?;
        let negative_one = self.alloc_reg()?;
        self.integer(negative_one, -1)?;
        let not_found = self.alloc_reg()?;
        self.emit(I::Eq(not_found, position, negative_one))?;
        self.emit(I::Jif(not_found, done))?;
        self.replace_at(dest, dest, old, new, position)?;
        self.emit(I::Jmp(body))?;
        self.emit(I::Jdest(done))
    }
    fn replace_at(&mut self, dest: u8, text: u8, old: u8, new: u8, position: u8) -> Result<()> {
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        let before = self.alloc_reg()?;
        self.emit(I::Substr(before, text, zero, position))?;
        let old_len = self.alloc_reg()?;
        self.emit(I::Strlen(old_len, old))?;
        let after_start = self.alloc_reg()?;
        self.emit(I::Add(after_start, position, old_len))?;
        let total_len = self.alloc_reg()?;
        self.emit(I::Strlen(total_len, text))?;
        let after_len = self.alloc_reg()?;
        self.emit(I::Sub(after_len, total_len, after_start))?;
        let after = self.alloc_reg()?;
        self.emit(I::Substr(after, text, after_start, after_len))?;
        self.emit(I::Concat(dest, before, new))?;
        self.emit(I::Concat(dest, dest, after))
    }
}
