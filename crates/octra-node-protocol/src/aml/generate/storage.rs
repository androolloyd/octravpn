// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Storage paths share keys with the adopted compiler, including list lengths.
use super::{storage_path_name, Arc, ExprId, Generator, Name, Result, Syntax, Type, TypeId};
use crate::octb::Instruction as I;
impl Generator<'_> {
    pub(super) fn field_type(&self, name: &[u8]) -> Result<TypeId> {
        self.contract
            .state
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.typ)
            .ok_or_else(|| {
                self.code
                    .error([b"undefined field: ".as_slice(), name].concat())
            })
    }
    pub(super) fn path_type(
        &mut self,
        field: &[u8],
        indexed: bool,
        path: &[Name],
    ) -> Result<TypeId> {
        self.storage_type(field, indexed, path).ok_or_else(|| {
            self.code.error(
                [
                    b"unknown storage path: ".as_slice(),
                    &storage_path_name(field, path),
                ]
                .concat(),
            )
        })
    }
    pub(super) fn storage_path_key_regs(
        &mut self,
        field: &[u8],
        keys: &[u8],
        path: &[Name],
    ) -> Result<u8> {
        match self.storage_length(field, !keys.is_empty(), path) {
            Some(prefix) if prefix.is_empty() && keys.is_empty() && !self.code.is_protocol() => {
                let key = self.code.alloc_reg()?;
                self.code.string(key, self.code.list_length_key(field))?;
                Ok(key)
            }
            Some(prefix) => {
                let key = self.code.storage_path_prefix(field, keys, &prefix)?;
                let suffix = self.code.alloc_reg()?;
                self.code.string(suffix, self.code.length_suffix())?;
                self.code.emit(I::Concat(key, key, suffix))?;
                Ok(key)
            }
            None => self.code.storage_path_prefix(field, keys, path),
        }
    }
    pub(super) fn storage_path_key(
        &mut self,
        field: &[u8],
        keys: &[ExprId],
        path: &[Name],
    ) -> Result<u8> {
        let mut registers = Vec::with_capacity(keys.len());
        for key in keys {
            registers.push(self.expression(*key)?);
        }
        self.storage_path_key_regs(field, &registers, path)
    }
    pub(super) fn storage_value(&mut self, typ: TypeId, expr: ExprId) -> Result<u8> {
        let value = self.expression(expr)?;
        self.storage_value_register(typ, value)
    }
    pub(super) fn storage_value_register(&mut self, typ: TypeId, value: u8) -> Result<u8> {
        if self.nodes.typ(typ) == &Type::Bool {
            let text = self.code.alloc_reg()?;
            let true_label = self.code.alloc_label()?;
            let done = self.code.alloc_label()?;
            self.code.emit(I::Jif(value, true_label))?;
            self.code.string(text, b"false")?;
            self.code.emit(I::Jmp(done))?;
            self.code.emit(I::Jdest(true_label))?;
            self.code.string(text, b"true")?;
            self.code.emit(I::Jdest(done))?;
            Ok(text)
        } else {
            self.code.type_check(value, self.nodes.typ(typ))?;
            Ok(value)
        }
    }
    pub(super) fn storage_path_write(
        &mut self,
        field: &[u8],
        keys: &[ExprId],
        path: &[Name],
        expr: ExprId,
    ) -> Result<()> {
        if self.storage_length(field, !keys.is_empty(), path).is_some() {
            return Err(self.code.error(
                [
                    b"cannot assign to storage path: ".as_slice(),
                    &storage_path_name(field, path),
                ]
                .concat(),
            ));
        }
        let typ = self.path_type(field, !keys.is_empty(), path)?;
        self.require_expression(b"storage path assignment type differs", typ, expr)?;
        let key = self.storage_path_key(field, keys, path)?;
        let value = self.storage_value(typ, expr)?;
        self.code.emit(I::Sstorek(key, value))
    }
    pub(super) fn field_read(&mut self, name: &[u8]) -> Result<u8> {
        let typ = self.field_type(name)?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sload(value, Arc::from(name)))?;
        if self.code.syntax == Syntax::Source && matches!(self.nodes.typ(typ), Type::Option(_)) {
            let mark = self.code.alloc_reg()?;
            self.code
                .emit(I::Sload(mark, self.code.option_presence_key(name).into()))?;
            self.code.option_load(value, mark)
        } else if self.typed_storage(typ) {
            Ok(value)
        } else {
            self.simple_storage_loaded(value, typ)
        }
    }
    pub(super) fn index_read(&mut self, name: &[u8], typ: TypeId, keys: &[u8]) -> Result<u8> {
        let key = self.code.storage_key(name, keys)?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(value, key))?;
        let typ = self.map_value(typ);
        if self.code.syntax == Syntax::Source && matches!(self.nodes.typ(typ), Type::Option(_)) {
            let mark_key = self.code.some_key_index(name, keys)?;
            let mark = self.code.alloc_reg()?;
            self.code.emit(I::Sloadk(mark, mark_key))?;
            self.code.option_load(value, mark)
        } else {
            self.simple_storage_loaded(value, typ)
        }
    }
    fn simple_storage_loaded(&mut self, value: u8, typ: TypeId) -> Result<u8> {
        if self.integer_storage(typ) {
            self.code.int_from_storage(value)
        } else if self.nodes.typ(typ) == &Type::Bool {
            let truth = self.code.alloc_reg()?;
            self.code.string(truth, b"true")?;
            self.code.emit(I::Eq(value, value, truth))?;
            Ok(value)
        } else {
            Ok(value)
        }
    }
}
