// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native field/map write encodings retain the legacy option special cases.
use super::{Arc, BinOp, Expr, ExprId, Generator, Name, Result, Syntax, Type, TypeId};
use crate::octb::Instruction as I;
impl Generator<'_> {
    pub(super) fn field_write(&mut self, name: &[u8], expr: ExprId) -> Result<()> {
        self.code.storage_write()?;
        let typ = self.field_type(name)?;
        self.require_expression(b"state assignment type differs", typ, expr)?;
        if matches!(self.nodes.typ(typ), Type::Option(_)) {
            if self.code.syntax == Syntax::Source {
                let key = self.code.alloc_reg()?;
                let mark = self.code.alloc_reg()?;
                self.code.string(key, name)?;
                self.code
                    .string(mark, self.code.option_presence_key(name))?;
                let value = self.expression(expr)?;
                return self.code.option_store(key, mark, value);
            }
            if matches!(self.nodes.expression(expr), Expr::Call(call, args) if call == b"none" && args.is_empty())
            {
                self.code.emit(I::Sdel(Arc::from(name)))?;
                return self
                    .code
                    .emit(I::Sdel(self.code.option_presence_key(name).into()));
            }
            let expr = self.legacy_some(expr);
            let value = self.expression(expr)?;
            self.code.emit(I::Sstore(Arc::from(name), value))?;
            let truth = self.code.alloc_reg()?;
            self.code.string(truth, b"true")?;
            return self
                .code
                .emit(I::Sstore(self.code.option_presence_key(name).into(), truth));
        }
        let value = self.expression(expr)?;
        let value = if self.nodes.typ(typ) == &Type::Bool && !self.typed_storage(typ) {
            self.storage_value_register(typ, value)?
        } else {
            self.code.type_check(value, self.nodes.typ(typ))?;
            value
        };
        self.code.emit(I::Sstore(Arc::from(name), value))
    }
    fn legacy_some(&self, expr: ExprId) -> ExprId {
        match self.nodes.expression(expr) {
            Expr::Call(name, args) if name == b"some" && args.len() == 1 => args[0],
            _ => expr,
        }
    }
    pub(super) fn key_registers(&mut self, keys: &[ExprId]) -> Result<Vec<u8>> {
        let mut registers = Vec::with_capacity(keys.len());
        for key in keys {
            registers.push(self.expression(*key)?);
        }
        Ok(registers)
    }
    pub(super) fn index_write(&mut self, name: &[u8], keys: &[ExprId], expr: ExprId) -> Result<()> {
        self.code.storage_write()?;
        let typ = self.map_value(self.field_type(name)?);
        self.require_expression(b"indexed assignment type differs", typ, expr)?;
        let registers = self.key_registers(keys)?;
        if matches!(self.nodes.typ(typ), Type::Option(_)) {
            let key = self.code.storage_key(name, &registers)?;
            if self.code.syntax == Syntax::Source {
                let mark = self.code.some_key_index(name, &registers)?;
                let value = self.expression(expr)?;
                return self.code.option_store(key, mark, value);
            }
            if matches!(self.nodes.expression(expr), Expr::Call(call, args) if call == b"none" && args.is_empty())
            {
                let mark = self.code.some_key_index(name, &registers)?;
                self.code.emit(I::Sdelk(key))?;
                return self.code.emit(I::Sdelk(mark));
            }
            let expr = self.legacy_some(expr);
            let value = self.expression(expr)?;
            self.code.emit(I::Sstorek(key, value))?;
            let mark_registers = if self.code.is_protocol() {
                self.key_registers(keys)?
            } else {
                registers
            };
            let mark = self.code.some_key_index(name, &mark_registers)?;
            let truth = self.code.alloc_reg()?;
            self.code.string(truth, b"true")?;
            return self.code.emit(I::Sstorek(mark, truth));
        }
        let key = self.code.storage_key(name, &registers)?;
        let value = self.expression(expr)?;
        self.code.type_check(value, self.nodes.typ(typ))?;
        self.code.emit(I::Sstorek(key, value))
    }
    pub(super) fn index_update(
        &mut self,
        name: &[u8],
        keys: &[ExprId],
        op: BinOp,
        expr: ExprId,
    ) -> Result<()> {
        self.code.storage_write()?;
        let typ = self.map_value(self.field_type(name)?);
        self.require_expression(b"indexed update type differs", typ, expr)?;
        let registers = self.key_registers(keys)?;
        let key = self.code.storage_key(name, &registers)?;
        self.update_key(key, typ, op, expr)
    }
    pub(super) fn path_update(
        &mut self,
        field: &[u8],
        keys: &[ExprId],
        path: &[Name],
        op: BinOp,
        expr: ExprId,
    ) -> Result<()> {
        self.code.storage_write()?;
        let typ = self.path_type(field, !keys.is_empty(), path)?;
        self.require_expression(b"storage path update type differs", typ, expr)?;
        let registers = self.key_registers(keys)?;
        let key = self.storage_path_key_regs(field, &registers, path)?;
        self.update_key(key, typ, op, expr)
    }
    fn update_key(&mut self, key: u8, typ: TypeId, op: BinOp, expr: ExprId) -> Result<()> {
        let left = self.code.alloc_reg()?;
        self.code.emit(I::Sloadk(left, key))?;
        self.storage_loaded(left, typ)?;
        let right = self.expression(expr)?;
        let value = self
            .code
            .update_value(op, self.nodes.typ(typ), left, right)?;
        self.code.emit(I::Sstorek(key, value))
    }
}
