// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native storage keys and conversions; allocation order is part of emission.
use super::{internal_key, Emitter, Result, I};
impl Emitter {
    pub fn storage_key(&mut self, field: &[u8], keys: &[u8]) -> Result<u8> {
        let key = self.alloc_reg()?;
        if self.is_protocol() {
            self.string(key, [field, b":"].concat())?;
            let separator = if keys.len() > 1 {
                let separator = self.alloc_reg()?;
                self.string(separator, b":")?;
                separator
            } else {
                0
            };
            for (index, source) in keys.iter().enumerate() {
                if index > 0 {
                    self.emit(I::Concat(key, key, separator))?;
                }
                self.emit(I::Concat(key, key, *source))?;
            }
            return Ok(key);
        }
        self.string(key, [internal_key(b"map", field), b"/".to_vec()].concat())?;
        for source in keys {
            let text = self.alloc_reg()?;
            self.string(text, b"")?;
            self.emit(I::Concat(text, text, *source))?;
            let length = self.alloc_reg()?;
            self.emit(I::Strlen(length, text))?;
            let mark = self.alloc_reg()?;
            self.string(mark, b"#")?;
            self.emit(I::Concat(key, key, length))?;
            self.emit(I::Concat(key, key, mark))?;
            self.emit(I::Concat(key, key, text))?;
        }
        Ok(key)
    }
    pub fn int_from_storage(&mut self, value: u8) -> Result<u8> {
        let zero = self.alloc_reg()?;
        self.integer(zero, 0)?;
        self.emit(I::Add(value, zero, value))?;
        Ok(value)
    }
    pub fn bool_from_storage(&mut self, value: u8) -> Result<u8> {
        let true_reg = self.alloc_reg()?;
        let one = self.alloc_reg()?;
        let yes = self.alloc_reg()?;
        let is_true = self.alloc_reg()?;
        let is_one = self.alloc_reg()?;
        let is_yes = self.alloc_reg()?;
        let true_label = self.alloc_label()?;
        let end = self.alloc_label()?;
        self.string(true_reg, b"true")?;
        self.string(one, b"1")?;
        self.string(yes, b"yes")?;
        self.emit(I::Eq(is_true, value, true_reg))?;
        self.emit(I::Jif(is_true, true_label))?;
        self.emit(I::Eq(is_one, value, one))?;
        self.emit(I::Jif(is_one, true_label))?;
        self.emit(I::Eq(is_yes, value, yes))?;
        self.emit(I::Jif(is_yes, true_label))?;
        self.boolean(value, false)?;
        self.emit(I::Jmp(end))?;
        self.emit(I::Jdest(true_label))?;
        self.boolean(value, true)?;
        self.emit(I::Jdest(end))?;
        Ok(value)
    }
    pub fn storage_path_prefix(
        &mut self,
        field: &[u8],
        keys: &[u8],
        path: &[Vec<u8>],
    ) -> Result<u8> {
        let key = if keys.is_empty() {
            let register = self.alloc_reg()?;
            self.string(
                register,
                if self.is_protocol() {
                    field.to_vec()
                } else {
                    internal_key(b"path", field)
                },
            )?;
            register
        } else {
            self.storage_key(field, keys)?
        };
        for segment in path {
            let register = self.alloc_reg()?;
            let separator: &[u8] = if self.is_protocol() { b":" } else { b"/path/" };
            self.string(register, [separator, segment].concat())?;
            self.emit(I::Concat(key, key, register))?;
        }
        Ok(key)
    }
    pub fn dynamic_key(&mut self, prefix: &[u8], key: u8, suffix: &[u8]) -> Result<u8> {
        let prefix_reg = self.alloc_reg()?;
        let full = self.alloc_reg()?;
        let suffix_reg = self.alloc_reg()?;
        self.string(prefix_reg, prefix)?;
        self.emit(I::Mov(full, prefix_reg))?;
        self.emit(I::Concat(full, full, key))?;
        self.string(suffix_reg, suffix)?;
        self.emit(I::Concat(full, full, suffix_reg))?;
        Ok(full)
    }
    pub fn dynamic_load(&mut self, prefix: &[u8], key: u8, suffix: &[u8]) -> Result<u8> {
        let key = self.dynamic_key(prefix, key, suffix)?;
        let value = self.alloc_reg()?;
        self.emit(I::Sloadk(value, key))?;
        Ok(value)
    }
    pub fn dynamic_int(&mut self, prefix: &[u8], key: u8, suffix: &[u8]) -> Result<u8> {
        let value = self.dynamic_load(prefix, key, suffix)?;
        self.int_from_storage(value)
    }
    pub fn dynamic_store(
        &mut self,
        prefix: &[u8],
        key: u8,
        suffix: &[u8],
        value: u8,
    ) -> Result<()> {
        let key = self.dynamic_key(prefix, key, suffix)?;
        self.emit(I::Sstorek(key, value))
    }
    pub fn dynamic_delete(&mut self, prefix: &[u8], key: u8, suffix: &[u8]) -> Result<()> {
        let key = self.dynamic_key(prefix, key, suffix)?;
        self.emit(I::Sdelk(key))
    }
    pub fn dynamic_optional(
        &mut self,
        prefix: &[u8],
        key: u8,
        suffix: &[u8],
        value: u8,
    ) -> Result<()> {
        let empty = self.alloc_reg()?;
        let is_empty = self.alloc_reg()?;
        let delete = self.alloc_label()?;
        let end = self.alloc_label()?;
        self.string(empty, b"")?;
        self.emit(I::Eq(is_empty, value, empty))?;
        self.emit(I::Jif(is_empty, delete))?;
        self.dynamic_store(prefix, key, suffix, value)?;
        self.emit(I::Jmp(end))?;
        self.emit(I::Jdest(delete))?;
        self.dynamic_delete(prefix, key, suffix)?;
        self.emit(I::Jdest(end))
    }
    pub fn joined_key(&mut self, left: u8, right: u8) -> Result<u8> {
        let combined = self.alloc_reg()?;
        let separator = self.alloc_reg()?;
        self.emit(I::Mov(combined, left))?;
        self.string(separator, b":")?;
        self.emit(I::Concat(combined, combined, separator))?;
        self.emit(I::Concat(combined, combined, right))?;
        Ok(combined)
    }
    pub fn some_key_index(&mut self, field: &[u8], keys: &[u8]) -> Result<u8> {
        let key = self.storage_key(field, keys)?;
        let suffix = self.alloc_reg()?;
        self.string(
            suffix,
            if self.is_protocol() {
                b"_some".as_slice()
            } else {
                b"/option-present".as_slice()
            },
        )?;
        self.emit(I::Concat(key, key, suffix))?;
        Ok(key)
    }
}
