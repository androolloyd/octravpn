// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native storage-list operations and tuple bindings.
use super::{Error, ExprId, Generator, Name, Result, Type, TypeId};
use crate::octb::Instruction as I;
impl Generator<'_> {
    pub(super) fn list_item_key(&mut self, field: &[u8], index: u8) -> Result<u8> {
        let key = self.code.alloc_reg()?;
        self.code.string(key, self.code.list_item_prefix(field))?;
        self.code.emit(I::Concat(key, key, index))?;
        Ok(key)
    }
    pub(super) fn list_type(&self, field: &[u8]) -> Result<TypeId> {
        let typ = self.field_type(field)?;
        match self.nodes.typ(typ) {
            Type::List(item) => Ok(*item),
            _ => Err(self
                .code
                .error([b"field is not a list: ".as_slice(), field].concat())),
        }
    }
    fn list_length(&mut self, field: &[u8]) -> Result<u8> {
        let length = self.code.alloc_reg()?;
        self.code
            .emit(I::Sload(length, self.code.list_length_key(field).into()))?;
        self.code.int_from_storage(length)
    }
    pub(super) fn field_call(
        &mut self,
        field: &[u8],
        method: &[u8],
        args: &[ExprId],
    ) -> Result<()> {
        if self.code.is_protocol() {
            return match method {
                b"push" => self.list_push(
                    field,
                    *args.first().ok_or_else(|| Error::Failure(b"hd".to_vec()))?,
                ),
                b"delete" => {
                    let index = *args.first().ok_or_else(|| Error::Failure(b"hd".to_vec()))?;
                    let index = self.expression(index)?;
                    let key = self.list_item_key(field, index)?;
                    self.code.emit(I::Sdelk(key))
                }
                b"len" => {
                    let length = self.list_length(field)?;
                    self.code.emit(I::Mov(0, length))
                }
                b"pop" => self.list_pop(field),
                _ => Err(self
                    .code
                    .error([b"unknown method: ".as_slice(), method].concat())),
            };
        }
        let item = self.list_type(field)?;
        match (method, args) {
            (b"push", [value]) => {
                let actual = self.infer(*value)?;
                self.require_type(b"list item type differs", item, actual)?;
                self.list_push(field, *value)
            }
            (b"delete", [index]) => {
                let integer = self.nodes.intern(Type::Int);
                let actual = self.infer(*index)?;
                self.require_type(b"list index type differs", integer, actual)?;
                self.list_delete(field, *index)
            }
            (b"len", []) => {
                let length = self.list_length(field)?;
                self.code.emit(I::Mov(0, length))
            }
            (b"pop", []) => self.list_pop(field),
            (b"push" | b"delete" | b"len" | b"pop", _) => Err(self
                .code
                .error([b"list method arity differs method = ".as_slice(), method].concat())),
            _ => Err(self
                .code
                .error([b"unknown list method = ".as_slice(), method].concat())),
        }
    }
    fn list_push(&mut self, field: &[u8], value: ExprId) -> Result<()> {
        let length = self.list_length(field)?;
        let value = self.expression(value)?;
        let key = self.list_item_key(field, length)?;
        self.code.emit(I::Sstorek(key, value))?;
        let one = self.code.alloc_reg()?;
        self.code.integer(one, 1)?;
        self.code.emit(I::Add(length, length, one))?;
        self.code
            .emit(I::Sstore(self.code.list_length_key(field).into(), length))
    }
    fn list_delete(&mut self, field: &[u8], index: ExprId) -> Result<()> {
        let index = self.expression(index)?;
        let length = self.list_length(field)?;
        let zero = self.code.alloc_reg()?;
        self.code.integer(zero, 0)?;
        let invalid = self.code.alloc_reg()?;
        let fail = self.code.alloc_label()?;
        let valid = self.code.alloc_label()?;
        self.code.emit(I::Lt(invalid, index, zero))?;
        self.code.emit(I::Jif(invalid, fail))?;
        self.code.emit(I::Lt(invalid, index, length))?;
        self.code.emit(I::Jif(invalid, valid))?;
        self.code.emit(I::Jmp(fail))?;
        self.code.emit(I::Jdest(valid))?;
        let one = self.code.alloc_reg()?;
        self.code.integer(one, 1)?;
        let last = self.code.alloc_reg()?;
        self.code.emit(I::Sub(last, length, one))?;
        let iter = self.code.alloc_reg()?;
        self.code.emit(I::Mov(iter, index))?;
        let test = self.code.alloc_label()?;
        let shift = self.code.alloc_label()?;
        self.code.emit(I::Jmp(test))?;
        self.code.emit(I::Jdest(shift))?;
        let next = self.code.alloc_reg()?;
        self.code.emit(I::Add(next, iter, one))?;
        let source = self.list_item_key(field, next)?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(value, source))?;
        let target = self.list_item_key(field, iter)?;
        self.code.emit(I::Sstorek(target, value))?;
        self.code.emit(I::Add(iter, iter, one))?;
        self.code.emit(I::Jdest(test))?;
        let compare = self.code.alloc_reg()?;
        self.code.emit(I::Lt(compare, iter, last))?;
        self.code.emit(I::Jif(compare, shift))?;
        let last_key = self.list_item_key(field, last)?;
        self.code.emit(I::Sdelk(last_key))?;
        self.code
            .emit(I::Sstore(self.code.list_length_key(field).into(), last))?;
        let end = self.code.alloc_label()?;
        self.code.emit(I::Jmp(end))?;
        self.code.emit(I::Jdest(fail))?;
        self.code.emit(I::Revert())?;
        self.code.emit(I::Jdest(end))
    }
    fn list_pop(&mut self, field: &[u8]) -> Result<()> {
        let length = self.list_length(field)?;
        if !self.code.is_protocol() {
            let zero = self.code.alloc_reg()?;
            let has_item = self.code.alloc_reg()?;
            let valid = self.code.alloc_label()?;
            self.code.integer(zero, 0)?;
            self.code.emit(I::Gt(has_item, length, zero))?;
            self.code.emit(I::Jif(has_item, valid))?;
            self.code.emit(I::Revert())?;
            self.code.emit(I::Jdest(valid))?;
        }
        let one = self.code.alloc_reg()?;
        self.code.integer(one, 1)?;
        self.code.emit(I::Sub(length, length, one))?;
        let key = self.list_item_key(field, length)?;
        let value = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(value, key))?;
        self.code.emit(I::Sdelk(key))?;
        self.code
            .emit(I::Sstore(self.code.list_length_key(field).into(), length))?;
        self.code.emit(I::Mov(0, value))
    }
    pub(super) fn tuple_unpack(&mut self, names: &[Name], expr: ExprId) -> Result<()> {
        if !self.code.is_protocol() {
            let actual = self.infer(expr)?;
            let Type::Tuple(types) = self.nodes.typ(actual) else {
                return Err(self.code.error(
                    [
                        b"tuple binding type differs actual = ".as_slice(),
                        self.nodes.typ(actual).name(),
                    ]
                    .concat(),
                ));
            };
            if types.len() != names.len() {
                return Err(self.code.error(format!(
                    "tuple binding arity differs expected = {} actual = {}",
                    names.len(),
                    types.len()
                )));
            }
        }
        // The native unpack helper repeats inference after the statement check.
        let actual = self.infer(expr)?;
        let types = match self.nodes.typ(actual) {
            Type::Tuple(types) => types.clone(),
            _ => vec![],
        };
        let hash = self.code.reserve_local()?;
        let remaining = self.code.reserve_local()?;
        let source = self.expression(expr)?;
        self.code.string(hash, b"#")?;
        self.code.emit(I::Mov(remaining, source))?;
        for (index, name) in names.iter().enumerate() {
            let typ = types
                .get(index)
                .copied()
                .unwrap_or_else(|| self.nodes.intern(Type::String));
            let register = self.code.reserve_local()?;
            self.code.netstring_next(hash, remaining, register)?;
            if !self.code.is_protocol() {
                self.storage_loaded(register, typ)?;
            }
            self.bind(name.clone(), register, typ);
        }
        Ok(())
    }
}
