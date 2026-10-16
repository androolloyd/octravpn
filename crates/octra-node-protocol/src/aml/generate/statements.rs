// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Iterative statement emission preserves the adopted loop/scope compatibility
//! mode, including branch-local leakage when that mode is disabled.
use super::{Arc, Error, ExprId, Generator, Local, Name, Result, Stmt, StmtId, Type, TypeId};
use crate::octb::Instruction as I;
#[derive(Clone)]
struct Scope {
    locals: Arc<Vec<Local>>,
    base: u32,
}
enum Task {
    Statement(StmtId),
    ElseDone(Scope, u32, u32, Vec<StmtId>),
    IfDone(Scope, u32),
    WhileDone(Scope, u32, u32, ExprId),
    RangeDone(Scope, Vec<u8>, u8, u8, u32, u32),
    ForeachDone(Scope, u8, u8, u32, u32),
    MatchArm(Arc<Vec<(u32, Vec<StmtId>)>>, usize, Scope, u8, u32),
    MatchArmDone(Arc<Vec<(u32, Vec<StmtId>)>>, usize, Scope, u8, u32),
}
fn push_block(tasks: &mut Vec<Task>, body: Vec<StmtId>) {
    tasks.extend(body.into_iter().rev().map(Task::Statement));
}
impl Generator<'_> {
    pub(super) fn require_expression(
        &mut self,
        context: &[u8],
        expected: TypeId,
        expr: ExprId,
    ) -> Result<()> {
        if self.code.is_protocol() {
            return Ok(());
        }
        let actual = self.infer(expr)?;
        self.require_type(context, expected, actual)
    }
    fn scope(&self) -> Scope {
        Scope {
            locals: self.locals.clone(),
            base: self.code.base_reg,
        }
    }
    fn restore_scope(&mut self, scope: Scope) {
        self.locals = scope.locals;
        self.code.base_reg = scope.base;
        self.code.next_reg = scope.base;
    }
    fn reserve_foreach(&mut self) -> Result<u8> {
        if self.code.is_protocol() && self.code.base_reg > 63 {
            return Err(self.code.error("too many local variables"));
        }
        self.code.reserve_local()
    }
    pub fn block(&mut self, body: &[StmtId]) -> Result<()> {
        let mut tasks = vec![];
        push_block(&mut tasks, body.to_vec());
        while let Some(task) = tasks.pop() {
            match task {
                Task::Statement(id) => {
                    self.code.next_reg = self.code.base_reg;
                    match self.nodes.statement(id).clone() {
                        Stmt::Located(line, column, child) => {
                            self.code.position = super::super::emit::Position { line, column };
                            tasks.push(Task::Statement(child));
                        }
                        Stmt::Let(name, annotation, expr) => {
                            let (typ, value) = if self.code.is_protocol() {
                                let value = self.expression(expr)?;
                                let typ = match annotation {
                                    Some(typ) => typ,
                                    None => self.infer(expr)?,
                                };
                                (typ, value)
                            } else {
                                let actual = self.infer(expr)?;
                                let typ = annotation.unwrap_or(actual);
                                self.require_type(b"local initializer type differs", typ, actual)?;
                                (typ, self.expression(expr)?)
                            };
                            self.code.type_check(value, self.nodes.typ(typ))?;
                            if self.code.base_reg > 63 {
                                return Err(self
                                    .code
                                    .error("too many local variables (max 63 registers)"));
                            }
                            let register = self.code.base_reg as u8;
                            if value != register {
                                self.code.emit(I::Mov(register, value))?;
                            }
                            self.code.base_reg += 1;
                            self.code.next_reg = self.code.base_reg;
                            self.bind(name, register, typ);
                        }
                        Stmt::LetTuple(names, expr) => self.tuple_unpack(&names, expr)?,
                        Stmt::Assign(name, expr) => {
                            let local = self.local(&name).cloned().ok_or_else(|| {
                                self.code
                                    .error([b"undefined variable: ".as_slice(), &name].concat())
                            })?;
                            if !self.code.is_protocol()
                                && self.loops
                                && self.code.pure
                                && self.loop_regs.contains(&local.register)
                            {
                                return Err(self.code.error(
                                    [b"pure loop index is immutable = ".as_slice(), &name].concat(),
                                ));
                            }
                            self.require_expression(b"assignment type differs", local.typ, expr)?;
                            let value = self.expression(expr)?;
                            self.code.type_check(value, self.nodes.typ(local.typ))?;
                            if value != local.register {
                                self.code.emit(I::Mov(local.register, value))?;
                            }
                        }
                        Stmt::FieldSet(name, expr) => self.field_write(&name, expr)?,
                        Stmt::IndexSet(name, keys, expr) => self.index_write(&name, &keys, expr)?,
                        Stmt::IndexUpdate(name, keys, op, expr) => {
                            self.index_update(&name, &keys, op, expr)?;
                        }
                        Stmt::Return(expr) => {
                            let void = self.nodes.typ(self.function_return) == &Type::Void;
                            if let Some(expr) = expr {
                                if void && !self.code.is_protocol() {
                                    return Err(self
                                        .code
                                        .error("void function cannot return a value"));
                                }
                                self.require_expression(
                                    b"return type differs",
                                    self.function_return,
                                    expr,
                                )?;
                                let register = self.expression(expr)?;
                                if register != 0 {
                                    self.code.emit(I::Mov(0, register))?;
                                }
                            } else if !void && !self.code.is_protocol() {
                                return Err(self.code.error(
                                    [
                                        b"return value is required type = ".as_slice(),
                                        self.nodes.typ(self.function_return).name(),
                                    ]
                                    .concat(),
                                ));
                            }
                            if self.in_nonreentrant {
                                self.code.nonreentrant_exit()?;
                            }
                            self.code.emit(I::Stop())?;
                        }
                        Stmt::Assert(expr) => {
                            let boolean = self.nodes.intern(Type::Bool);
                            self.require_expression(
                                b"assert condition type differs",
                                boolean,
                                expr,
                            )?;
                            let value = self.expression(expr)?;
                            self.code.emit(I::Assert(value))?;
                        }
                        Stmt::Require(condition, message) => {
                            let boolean = self.nodes.intern(Type::Bool);
                            self.require_expression(
                                b"require condition type differs",
                                boolean,
                                condition,
                            )?;
                            let condition = self.expression(condition)?;
                            let ok = self.code.alloc_label()?;
                            self.code.emit(I::Jif(condition, ok))?;
                            let message = self.expression(message)?;
                            self.code
                                .emit(I::Emit(Arc::from(b"Require".as_slice()), vec![message]))?;
                            self.code.emit(I::Revert())?;
                            self.code.emit(I::Jdest(ok))?;
                        }
                        Stmt::Emit(name, args) => {
                            self.code.event()?;
                            if name != b"Log"
                                && name != b"Require"
                                && !self.contract.events.iter().any(|event| event.name == name)
                            {
                                return Err(self
                                    .code
                                    .error([b"undefined event: ".as_slice(), &name].concat()));
                            }
                            let registers = self.key_registers(&args)?;
                            self.code.emit(I::Emit(name.into(), registers))?;
                        }
                        Stmt::If(condition, yes, no) => {
                            let boolean = self.nodes.intern(Type::Bool);
                            self.require_expression(
                                b"if condition type differs",
                                boolean,
                                condition,
                            )?;
                            let condition = self.expression(condition)?;
                            let scope = self.scope();
                            let then_label = self.code.alloc_label()?;
                            let end = self.code.alloc_label()?;
                            self.code.emit(I::Jif(condition, then_label))?;
                            tasks.push(Task::ElseDone(scope, then_label, end, yes));
                            if let Some(no) = no {
                                push_block(&mut tasks, no);
                            }
                        }
                        Stmt::While(condition, body) => {
                            self.code.pure_while()?;
                            let boolean = self.nodes.intern(Type::Bool);
                            self.require_expression(
                                b"while condition type differs",
                                boolean,
                                condition,
                            )?;
                            let scope = self.scope();
                            let test = self.code.alloc_label()?;
                            let loop_label = self.code.alloc_label()?;
                            self.code.emit(I::Jmp(test))?;
                            self.code.emit(I::Jdest(loop_label))?;
                            tasks.push(Task::WhileDone(scope, test, loop_label, condition));
                            push_block(&mut tasks, body);
                        }
                        Stmt::For(name, start, end, body) => {
                            let integer = self.nodes.intern(Type::Int);
                            self.require_expression(b"range start type differs", integer, start)?;
                            self.require_expression(b"range end type differs", integer, end)?;
                            let saved_base = self.code.base_reg;
                            let pinned = !self.code.is_protocol() || self.loops;
                            if pinned && saved_base + 1 > 63 {
                                return Err(self
                                    .code
                                    .error("register capacity exceeded maximum = 64"));
                            }
                            if pinned {
                                self.code.base_reg = saved_base + 2;
                                self.code.next_reg = self.code.base_reg;
                            }
                            let start = self.expression(start)?;
                            let end = self.expression(end)?;
                            let iter_base = if pinned {
                                saved_base
                            } else {
                                self.code.base_reg
                            };
                            if iter_base > 63 {
                                return Err(self
                                    .code
                                    .error("too many local variables (max 63 registers)"));
                            }
                            let iter = iter_base as u8;
                            self.code.emit(I::Mov(iter, start))?;
                            let end_register = if pinned {
                                let register = iter + 1;
                                self.code.emit(I::Mov(register, end))?;
                                register
                            } else {
                                self.code.base_reg = iter_base + 1;
                                end
                            };
                            self.code.next_reg = self.code.base_reg;
                            let scope = Scope {
                                locals: self.locals.clone(),
                                base: if self.code.is_protocol() {
                                    iter_base
                                } else {
                                    saved_base
                                },
                            };
                            self.bind(name, iter, integer);
                            let test = self.code.alloc_label()?;
                            let loop_label = self.code.alloc_label()?;
                            self.code.emit(I::Jmp(test))?;
                            self.code.emit(I::Jdest(loop_label))?;
                            let saved_regs = self.loop_regs.clone();
                            if !self.code.is_protocol() {
                                self.loop_regs.push(end_register);
                                self.loop_regs.push(iter);
                            }
                            tasks.push(Task::RangeDone(
                                scope,
                                saved_regs,
                                iter,
                                end_register,
                                test,
                                loop_label,
                            ));
                            push_block(&mut tasks, body);
                        }
                        Stmt::ForEach(name, field, body) => {
                            let typ = if self.code.is_protocol() {
                                self.nodes.intern(Type::String)
                            } else {
                                self.list_type(&field)?
                            };
                            let length = self.reserve_foreach()?;
                            let iter = self.reserve_foreach()?;
                            self.code
                                .emit(I::Sload(length, self.code.list_length_key(&field).into()))?;
                            self.code.int_from_storage(length)?;
                            self.code.integer(iter, 0)?;
                            let scope = Scope {
                                locals: self.locals.clone(),
                                base: length.into(),
                            };
                            let test = self.code.alloc_label()?;
                            let loop_label = self.code.alloc_label()?;
                            self.code.emit(I::Jmp(test))?;
                            self.code.emit(I::Jdest(loop_label))?;
                            let item = self.reserve_foreach()?;
                            let key = self.list_item_key(&field, iter)?;
                            self.code.emit(I::Sloadk(item, key))?;
                            if !self.code.is_protocol() {
                                self.storage_loaded(item, typ)?;
                            }
                            self.bind(name, item, typ);
                            tasks.push(Task::ForeachDone(scope, length, iter, test, loop_label));
                            push_block(&mut tasks, body);
                        }
                        Stmt::Match(expr, arms) => {
                            self.match_exhaustive(&arms)?;
                            let locals = self.locals.clone();
                            let value = self.expression(expr)?;
                            let matched = u8::try_from(self.code.base_reg).map_err(|_| {
                                Error::Unavailable("compiler match-register transport exhausted")
                            })?;
                            if value != matched {
                                self.code.emit(I::Mov(matched, value))?;
                            }
                            self.code.base_reg += 1;
                            self.code.next_reg = self.code.base_reg;
                            let end = self.code.alloc_label()?;
                            let mut labels = Vec::with_capacity(arms.len());
                            for _ in &arms {
                                labels.push(self.code.alloc_label()?);
                            }
                            for ((name, variant, _), label) in arms.iter().zip(&labels) {
                                self.code.next_reg = self.code.base_reg;
                                let index = self.enum_index(name, variant)?;
                                let variant = self.code.alloc_reg()?;
                                let compare = self.code.alloc_reg()?;
                                self.code.integer(variant, index)?;
                                self.code.emit(I::Eq(compare, matched, variant))?;
                                self.code.emit(I::Jif(compare, *label))?;
                            }
                            self.code.emit(I::Revert())?;
                            let arms = arms
                                .into_iter()
                                .zip(labels)
                                .map(|((_, _, body), label)| (label, body))
                                .collect();
                            tasks.push(Task::MatchArm(
                                Arc::new(arms),
                                0,
                                Scope {
                                    locals,
                                    base: matched.into(),
                                },
                                matched,
                                end,
                            ));
                        }
                        Stmt::StoragePathSet(field, keys, path, expr) => {
                            self.code.storage_write()?;
                            self.storage_path_write(&field, &keys, &path, expr)?;
                        }
                        Stmt::StoragePathUpdate(field, keys, path, op, expr) => {
                            self.path_update(&field, &keys, &path, op, expr)?;
                        }
                        Stmt::IndexFieldSet(field, keys, prop, expr) => {
                            self.code.storage_write()?;
                            self.storage_path_write(&field, &keys, &[prop], expr)?;
                        }
                        Stmt::FieldCall(field, method, args) => {
                            self.field_call(&field, &method, &args)?;
                        }
                        Stmt::Expr(expr) => {
                            self.expression(expr)?;
                        }
                        Stmt::RevertError(name, args) => {
                            let definition = self
                                .contract
                                .errors
                                .iter()
                                .find(|item| item.name == name)
                                .cloned()
                                .ok_or_else(|| {
                                    self.code
                                        .error([b"undefined error: ".as_slice(), &name].concat())
                                })?;
                            let code = self.code.alloc_reg()?;
                            self.code.integer(code, definition.code)?;
                            let message = self.code.alloc_reg()?;
                            self.code.string(message, definition.message)?;
                            let mut registers = vec![code, message];
                            registers.extend(self.key_registers(&args)?);
                            self.code.emit(I::Emit(
                                [b"Error:".as_slice(), &name].concat().into(),
                                registers,
                            ))?;
                            if self.in_nonreentrant {
                                self.code.nonreentrant_exit()?;
                            }
                            self.code.emit(I::Revert())?;
                        }
                    }
                }
                Task::ElseDone(scope, then_label, end, yes) => {
                    self.code.emit(I::Jmp(end))?;
                    if self.loops {
                        self.restore_scope(scope.clone());
                    }
                    self.code.emit(I::Jdest(then_label))?;
                    tasks.push(Task::IfDone(scope, end));
                    push_block(&mut tasks, yes);
                }
                Task::IfDone(scope, end) => {
                    self.code.emit(I::Jdest(end))?;
                    if self.loops {
                        self.restore_scope(scope);
                    }
                }
                Task::WhileDone(scope, test, loop_label, condition) => {
                    if self.loops {
                        self.locals = scope.locals;
                        self.code.base_reg = scope.base;
                    }
                    self.code.emit(I::Jdest(test))?;
                    self.code.next_reg = self.code.base_reg;
                    let condition = self.expression(condition)?;
                    self.code.emit(I::Jif(condition, loop_label))?;
                }
                Task::RangeDone(scope, registers, iter, end, test, loop_label) => {
                    self.loop_regs = registers;
                    self.loop_increment(iter, end, test, loop_label)?;
                    self.restore_scope(scope);
                }
                Task::ForeachDone(scope, length, iter, test, loop_label) => {
                    self.loop_increment(iter, length, test, loop_label)?;
                    self.restore_scope(scope);
                }
                Task::MatchArm(arms, index, scope, matched, end) => {
                    if let Some((label, body)) = arms.get(index) {
                        let label = *label;
                        let body = body.clone();
                        if self.loops {
                            self.locals = scope.locals.clone();
                            self.code.base_reg = u32::from(matched) + 1;
                            self.code.next_reg = self.code.base_reg;
                        }
                        self.code.emit(I::Jdest(label))?;
                        tasks.push(Task::MatchArmDone(arms, index, scope, matched, end));
                        push_block(&mut tasks, body);
                    } else {
                        self.code.emit(I::Jdest(end))?;
                        if self.loops {
                            self.locals = scope.locals;
                        }
                        self.code.base_reg = matched.into();
                        self.code.next_reg = self.code.base_reg;
                    }
                }
                Task::MatchArmDone(arms, index, scope, matched, end) => {
                    self.code.emit(I::Jmp(end))?;
                    tasks.push(Task::MatchArm(arms, index + 1, scope, matched, end));
                }
            }
        }
        Ok(())
    }
    fn loop_increment(&mut self, iter: u8, end: u8, test: u32, loop_label: u32) -> Result<()> {
        self.code.next_reg = self.code.base_reg;
        let one = self.code.alloc_reg()?;
        self.code.integer(one, 1)?;
        self.code.emit(I::Add(iter, iter, one))?;
        self.code.emit(I::Jdest(test))?;
        self.code.next_reg = self.code.base_reg;
        let compare = self.code.alloc_reg()?;
        self.code.emit(I::Lt(compare, iter, end))?;
        self.code.emit(I::Jif(compare, loop_label))
    }
    fn match_exhaustive(&self, arms: &[(Name, Name, Vec<StmtId>)]) -> Result<()> {
        let Some((name, _, _)) = arms.first() else {
            return Err(self.code.error("empty match expression"));
        };
        if let Some(enumeration) = self.contract.enums.iter().find(|item| item.name == *name) {
            let missing: Vec<_> = enumeration
                .variants
                .iter()
                .filter(|variant| !arms.iter().any(|(_, value, _)| value == *variant))
                .collect();
            if !missing.is_empty() {
                let mut variants = vec![];
                for variant in missing {
                    if !variants.is_empty() {
                        variants.extend(b", ");
                    }
                    variants.extend(variant);
                }
                return Err(self.code.error(
                    [
                        b"non-exhaustive match on ".as_slice(),
                        name,
                        b": missing ",
                        &variants,
                    ]
                    .concat(),
                ));
            }
        }
        Ok(())
    }
}
