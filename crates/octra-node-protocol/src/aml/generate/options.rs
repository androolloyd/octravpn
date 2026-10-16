// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Option builtins have separate legacy storage and Source value encodings.
use super::{Arc, Generator, Result, Type};
use crate::octb::Instruction as I;
impl Generator<'_> {
    pub(super) fn option_field(&mut self, field: &[u8], unwrap: bool) -> Result<u8> {
        let first = self.code.alloc_reg()?;
        let mark = if unwrap {
            first
        } else {
            self.code.alloc_reg()?
        };
        self.code
            .emit(I::Sload(mark, self.code.option_presence_key(field).into()))?;
        let truth = self.code.alloc_reg()?;
        self.code.string(truth, b"true")?;
        let comparison = if unwrap {
            self.code.alloc_reg()?
        } else {
            first
        };
        self.code.emit(I::Eq(comparison, mark, truth))?;
        if !unwrap {
            return Ok(first);
        }
        self.code.emit(I::Assert(comparison))?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sload(value, Arc::from(field)))?;
        self.option_integer(field, value, false)
    }
    pub(super) fn option_index_mark(
        &mut self,
        field: &[u8],
        registers: &[u8],
        unwrap: bool,
    ) -> Result<Option<u8>> {
        let mark_key = self.code.some_key_index(field, registers)?;
        let mark = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(mark, mark_key))?;
        let truth = self.code.alloc_reg()?;
        self.code.string(truth, b"true")?;
        let comparison = if unwrap { self.code.alloc_reg()? } else { mark };
        self.code.emit(I::Eq(comparison, mark, truth))?;
        if !unwrap {
            return Ok(Some(mark));
        }
        self.code.emit(I::Assert(comparison))?;
        Ok(None)
    }
    pub(super) fn option_index_value(&mut self, field: &[u8], registers: &[u8]) -> Result<u8> {
        let key = self.code.storage_key(field, registers)?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(value, key))?;
        self.option_integer(field, value, true)
    }
    fn option_integer(&mut self, field: &[u8], value: u8, indexed: bool) -> Result<u8> {
        if let Some(mut typ) = self.storage_base(field, indexed) {
            if let Type::Option(inner) = self.nodes.typ(typ) {
                typ = *inner;
            }
            if self.integer_storage(typ) {
                return self.code.int_from_storage(value);
            }
        }
        Ok(value)
    }
}
