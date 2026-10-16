// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat expression emission retains native evaluation and register order without
//! recursive descent through long arithmetic chains or constant expansions.
use super::{
    types, Arc, BinOp, Binding, Declaration, Error, Expr, ExprId, Generator, Local, Name, Result,
    Syntax, Type, TypeId, UnOp,
};
use crate::octb::Instruction as I;

struct Orbit {
    count: u32,
    index: u32,
    turns: Option<u8>,
    state: u8,
    first: u32,
    binding: Binding,
    body: ExprId,
}
enum Task {
    Expr(ExprId),
    ConstantDone(Name),
    Balance,
    Index(Name, TypeId, usize),
    Path(Name, Vec<Name>, TypeId, usize),
    Pack(u8, Arc<Vec<ExprId>>, usize),
    Packed(u8),
    Call(Name, Vec<ExprId>, bool),
    Some,
    Address,
    SourceOption(bool, TypeId),
    OptionIndex(Name, Vec<ExprId>, bool),
    OptionIndexValue(Name, usize),
    Equal(TypeId),
    Let(Binding, ExprId),
    Restore(Arc<Vec<Local>>),
    Split(Binding, Binding, ExprId),
    OrbitTurns(u32, bool, ExprId, Binding, ExprId),
    OrbitSeed(u32, Option<u8>, Binding, ExprId),
    OrbitStep(Orbit),
    OrbitApplied(Orbit, Option<u32>, Arc<Vec<Local>>),
    TernaryGuard(ExprId, ExprId),
    TernaryElse(u8, u32, u32, ExprId),
    TernaryThen(u8, u32),
    BinaryLeft(ExprId, BinOp, ExprId, ExprId),
    BinaryRight(ExprId, BinOp, ExprId, ExprId, u8),
    ShortRight(u8, u32, u32, bool),
    Unary(UnOp),
}
impl Generator<'_> {
    pub(super) fn emit_user(
        &mut self,
        name: &[u8],
        args: &[ExprId],
        registers: &[u8],
        dest: u8,
    ) -> Result<()> {
        let label = self.function_labels.get(name).copied().ok_or_else(|| {
            self.code
                .error([b"unknown function: ".as_slice(), name].concat())
        })?;
        let target = self
            .contract
            .functions
            .iter()
            .find(|function| function.name == name)
            .ok_or(Error::Unavailable(
                "compiler function-label transport differs",
            ))?;
        let params = target.params.clone();
        if self.code.is_protocol() {
            for (index, _) in params.iter().enumerate() {
                let register = if let Some(register) = registers.get(index) {
                    *register
                } else {
                    let zero = self.code.alloc_reg()?;
                    self.code.integer(zero, 0)?;
                    zero
                };
                let slot = u16::try_from(1001 + index)
                    .map_err(|_| Error::Unavailable("compiler call-slot transport exhausted"))?;
                self.code.emit(I::Mstore(slot, register))?;
            }
            return self.code.emit(I::CallInt(dest, label));
        }
        if params.len() != args.len() {
            return Err(self.code.error(
                [
                    b"function argument count differs function = ".as_slice(),
                    name,
                    format!(" expected = {} actual = {}", params.len(), args.len()).as_bytes(),
                ]
                .concat(),
            ));
        }
        for (arg, param) in args.iter().zip(params) {
            let actual = self.infer(*arg)?;
            self.require_type(b"function argument type differs", param.typ, actual)?;
        }
        for (index, register) in registers.iter().enumerate() {
            let slot = u16::try_from(1001 + index)
                .map_err(|_| Error::Unavailable("compiler call-slot transport exhausted"))?;
            self.code.emit(I::Mstore(slot, *register))?;
        }
        self.code.emit(I::CallInt(dest, label))
    }
    pub fn expression(&mut self, root: ExprId) -> Result<u8> {
        let mut tasks = vec![Task::Expr(root)];
        let mut values: Vec<u8> = vec![];
        let mut constants: Vec<Name> = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Expr(id) => match self.nodes.expression(id).clone() {
                    Expr::Int(value) => {
                        let register = self.code.alloc_reg()?;
                        self.code.integer(register, value)?;
                        values.push(register);
                    }
                    Expr::Bool(value) => {
                        let register = self.code.alloc_reg()?;
                        self.code.boolean(register, value)?;
                        values.push(register);
                    }
                    Expr::String(value) => {
                        let register = self.code.alloc_reg()?;
                        self.code.string(register, value)?;
                        values.push(register);
                    }
                    Expr::Caller
                    | Expr::Origin
                    | Expr::SelfAddr
                    | Expr::Epoch
                    | Expr::EpochTime
                    | Expr::Value
                    | Expr::TreeHash
                    | Expr::NodeId
                    | Expr::TxHash => {
                        let expr = self.nodes.expression(id);
                        let context = match expr {
                            Expr::Epoch => Some(b"epoch".as_slice()),
                            Expr::EpochTime => Some(b"epoch_time".as_slice()),
                            Expr::Value => Some(b"value".as_slice()),
                            _ => None,
                        };
                        if self.code.protocol_checked() == Some(true) {
                            if let Some(local) = context.and_then(|name| self.local(name)) {
                                values.push(local.register);
                                continue;
                            }
                        }
                        if expr == &Expr::EpochTime
                            && self.contract.declaration != Declaration::Program
                        {
                            return Err(self.code.error("epoch_time is available only in Program"));
                        }
                        let register = self.code.alloc_reg()?;
                        self.code.emit(match expr {
                            Expr::Caller => I::Caller(register),
                            Expr::Origin => I::Origin(register),
                            Expr::SelfAddr => I::SelfAddr(register),
                            Expr::Epoch => I::Epoch(register),
                            Expr::EpochTime => I::EpochTime(register),
                            Expr::Value => I::Value(register),
                            Expr::TreeHash => I::Treehash(register),
                            Expr::NodeId => I::Nodeid(register),
                            Expr::TxHash => I::Txhash(register),
                            _ => unreachable!("context expression"),
                        })?;
                        values.push(register);
                    }
                    Expr::Balance(address) => {
                        tasks.push(Task::Balance);
                        tasks.push(Task::Expr(address));
                    }
                    Expr::Var(name) => {
                        if let Some(checked) = self
                            .code
                            .protocol_checked()
                            .filter(|_| !self.code.is_prior())
                        {
                            if matches!(name.as_slice(), b"epoch" | b"epoch_time" | b"value")
                                && (!checked || self.local(&name).is_none())
                            {
                                if name == b"epoch_time"
                                    && self.contract.declaration != Declaration::Program
                                {
                                    return Err(self
                                        .code
                                        .error("epoch_time is available only in Program"));
                                }
                                let register = self.code.alloc_reg()?;
                                self.code.emit(match name.as_slice() {
                                    b"epoch" => I::Epoch(register),
                                    b"epoch_time" => I::EpochTime(register),
                                    _ => I::Value(register),
                                })?;
                                values.push(register);
                                continue;
                            }
                        }
                        if let Some(constant) =
                            self.contract.consts.iter().find(|item| item.name == name)
                        {
                            // Native generation would not terminate on an unchecked
                            // typed constant cycle. A host failure grants no rejection.
                            if constants.contains(&name) {
                                return Err(Error::Unavailable(
                                    "compiler constant expansion is cyclic",
                                ));
                            }
                            constants.push(name.clone());
                            tasks.push(Task::ConstantDone(name));
                            tasks.push(Task::Expr(constant.value));
                        } else if let Some(local) = self.local(&name) {
                            values.push(local.register);
                        } else {
                            return Err(self
                                .code
                                .error([b"undefined variable: ".as_slice(), &name].concat()));
                        }
                    }
                    Expr::Field(name) => values.push(self.field_read(&name)?),
                    Expr::Index(name, keys) => {
                        let typ = self.field_type(&name)?;
                        tasks.push(Task::Index(name, typ, keys.len()));
                        for key in keys.into_iter().rev() {
                            tasks.push(Task::Expr(key));
                        }
                    }
                    Expr::Array(items) | Expr::Tuple(items) => {
                        let packed = self.code.alloc_reg()?;
                        self.code.string(packed, b"")?;
                        tasks.push(Task::Pack(packed, Arc::new(items), 0));
                    }
                    Expr::Equal(declared, left, right) => {
                        self.require_expression(b"equality left type differs", declared, left)?;
                        self.require_expression(b"equality right type differs", declared, right)?;
                        tasks.push(Task::Equal(declared));
                        tasks.push(Task::Expr(right));
                        tasks.push(Task::Expr(left));
                    }
                    Expr::Let(binding, input, body) => {
                        self.require_expression(
                            b"local initializer type differs",
                            binding.typ,
                            input,
                        )?;
                        tasks.push(Task::Let(binding, body));
                        tasks.push(Task::Expr(input));
                    }
                    Expr::Split(input, left, right, body) => {
                        let declared = self.nodes.intern(Type::Tuple(vec![left.typ, right.typ]));
                        self.require_expression(b"split type differs", declared, input)?;
                        tasks.push(Task::Split(left, right, body));
                        tasks.push(Task::Expr(input));
                    }
                    Expr::Orbit(count, turns, seed, binding, body) => {
                        if let Some(turns) = turns {
                            let integer = self.nodes.intern(Type::Int);
                            self.require_expression(b"orbit count type differs", integer, turns)?;
                            tasks.push(Task::OrbitTurns(count.get(), true, seed, binding, body));
                            tasks.push(Task::Expr(turns));
                        } else {
                            tasks.push(Task::OrbitTurns(count.get(), false, seed, binding, body));
                        }
                    }
                    Expr::Action(..) => {
                        return Err(self.code.error(if self.code.is_protocol() {
                            "direct form expression is unavailable"
                        } else {
                            "effect action requires sealed form"
                        }))
                    }
                    Expr::Use(value) => {
                        if self.code.is_protocol() {
                            return Err(self.code.error("direct form expression is unavailable"));
                        }
                        self.infer(id)?;
                        let mut args = value.caps;
                        args.push(value.arg);
                        tasks.push(Task::Let(value.binding, value.body));
                        tasks.push(Task::Call(value.name, args.clone(), true));
                        for arg in args.into_iter().rev() {
                            tasks.push(Task::Expr(arg));
                        }
                    }
                    Expr::Call(name, mut args) => {
                        if self.is_form(&name) && !self.is_direct(&name) {
                            return Err(self.code.error(
                                [b"form requires explicit use = ".as_slice(), &name].concat(),
                            ));
                        }
                        let user = self.is_direct(&name);
                        if !user {
                            match name.as_slice() {
                                b"to_address" if self.code.syntax == Syntax::Source => {
                                    self.infer(id)?;
                                    tasks.push(Task::Address);
                                    tasks.push(Task::Expr(args[0]));
                                    continue;
                                }
                                b"some" => {
                                    let [expr] = args.as_slice() else {
                                        return Err(self
                                            .code
                                            .error("Some: need exactly 1 argument"));
                                    };
                                    if self.code.syntax == Syntax::Source {
                                        tasks.push(Task::Some);
                                    }
                                    tasks.push(Task::Expr(*expr));
                                    continue;
                                }
                                b"none" => {
                                    if self.code.syntax == Syntax::Source && !args.is_empty() {
                                        return Err(self.code.error("none requires no arguments"));
                                    }
                                    let result = self.code.alloc_reg()?;
                                    self.code.string(
                                        result,
                                        if self.code.syntax == Syntax::Source {
                                            b"0".as_slice()
                                        } else {
                                            b"".as_slice()
                                        },
                                    )?;
                                    values.push(result);
                                    continue;
                                }
                                b"unwrap" | b"is_some_opt" => {
                                    let unwrap = name == b"unwrap";
                                    if self.code.syntax == Syntax::Source {
                                        let typ = self.infer(id)?;
                                        tasks.push(Task::SourceOption(unwrap, typ));
                                        tasks.push(Task::Expr(args[0]));
                                    } else {
                                        let message = if unwrap {
                                            b"unwrap: argument must be self.field or self.map[key]"
                                                .as_slice()
                                        } else {
                                            b"is_some: argument must be self.field or self.map[key]"
                                        };
                                        let [expr] = args.as_slice() else {
                                            return Err(self.code.error(message));
                                        };
                                        match self.nodes.expression(*expr).clone() {
                                            Expr::Field(field) => {
                                                values.push(self.option_field(&field, unwrap)?);
                                            }
                                            Expr::Index(field, keys) => {
                                                tasks.push(Task::OptionIndex(
                                                    field,
                                                    keys.clone(),
                                                    unwrap,
                                                ));
                                                for key in keys.into_iter().rev() {
                                                    tasks.push(Task::Expr(key));
                                                }
                                            }
                                            _ => return Err(self.code.error(message)),
                                        }
                                    }
                                    continue;
                                }
                                _ => (),
                            }
                            while name == b"call" && args.len() == 3 {
                                let (Expr::Array(items) | Expr::Tuple(items)) =
                                    self.nodes.expression(args[2])
                                else {
                                    break;
                                };
                                let mut unpacked = args[..2].to_vec();
                                unpacked.extend(items);
                                args = unpacked;
                            }
                        }
                        tasks.push(Task::Call(name, args.clone(), user));
                        for arg in args.into_iter().rev() {
                            tasks.push(Task::Expr(arg));
                        }
                    }
                    Expr::StoragePath(field, keys, path) => {
                        let typ = self.path_type(&field, !keys.is_empty(), &path)?;
                        tasks.push(Task::Path(field, path, typ, keys.len()));
                        for key in keys.into_iter().rev() {
                            tasks.push(Task::Expr(key));
                        }
                    }
                    Expr::FieldProp(field, prop) => {
                        let path = vec![prop];
                        let typ = self.path_type(&field, false, &path)?;
                        tasks.push(Task::Path(field, path, typ, 0));
                    }
                    Expr::IndexField(field, keys, prop) => {
                        let path = vec![prop];
                        let typ = self.path_type(&field, !keys.is_empty(), &path)?;
                        tasks.push(Task::Path(field, path, typ, keys.len()));
                        for key in keys.into_iter().rev() {
                            tasks.push(Task::Expr(key));
                        }
                    }
                    Expr::EnumVariant(name, variant) => {
                        let index = self.enum_index(&name, &variant)?;
                        let register = self.code.alloc_reg()?;
                        self.code.integer(register, index)?;
                        values.push(register);
                    }
                    Expr::Ternary(condition, yes, no) => {
                        tasks.push(Task::TernaryGuard(yes, no));
                        tasks.push(Task::Expr(condition));
                    }
                    Expr::Binop(op, left, right) => {
                        tasks.push(Task::BinaryLeft(id, op, left, right));
                        tasks.push(Task::Expr(left));
                    }
                    Expr::Unop(op, input) => {
                        tasks.push(Task::Unary(op));
                        tasks.push(Task::Expr(input));
                    }
                },
                Task::ConstantDone(name) => {
                    let previous = constants.pop();
                    debug_assert_eq!(previous.as_ref(), Some(&name));
                }
                Task::Balance => {
                    let address = values.pop().expect("balance address");
                    let register = self.code.alloc_reg()?;
                    self.code.emit(I::Balance(register, address))?;
                    values.push(register);
                }
                Task::Index(field, typ, count) => {
                    let keys = values.split_off(values.len() - count);
                    values.push(self.index_read(&field, typ, &keys)?);
                }
                Task::Path(field, path, typ, count) => {
                    let keys = values.split_off(values.len() - count);
                    let key = self.storage_path_key_regs(&field, &keys, &path)?;
                    let register = self.code.alloc_reg()?;
                    self.code.emit(I::Sloadk(register, key))?;
                    values.push(self.storage_loaded(register, typ)?);
                }
                Task::Pack(packed, items, index) => {
                    if let Some(item) = items.get(index) {
                        let item = *item;
                        tasks.push(Task::Pack(packed, items, index + 1));
                        tasks.push(Task::Packed(packed));
                        tasks.push(Task::Expr(item));
                    } else {
                        values.push(packed);
                    }
                }
                Task::Packed(packed) => self
                    .code
                    .netstring_element(packed, values.pop().expect("pack element"))?,
                Task::Call(name, args, user) => {
                    let registers = values.split_off(values.len() - args.len());
                    let (dest, builtin) = if user {
                        (self.code.alloc_reg()?, false)
                    } else {
                        self.code.builtin_registers(
                            &name,
                            &registers,
                            self.contract.declaration == Declaration::Program,
                        )?
                    };
                    if !builtin {
                        self.emit_user(&name, &args, &registers, dest)?;
                    }
                    values.push(dest);
                }
                Task::Some => {
                    let value = values.pop().expect("some value");
                    let result = self.code.alloc_reg()?;
                    self.code.string(result, b"1")?;
                    self.code.emit(I::Concat(result, result, value))?;
                    values.push(result);
                }
                Task::Address => {
                    self.code
                        .emit(I::AssertAddr(*values.last().expect("address value")))?;
                }
                Task::SourceOption(unwrap, typ) => {
                    let value = values.pop().expect("source option value");
                    let (present, payload) = self.code.option_parts(value)?;
                    if unwrap {
                        self.code.emit(I::Assert(present))?;
                        let result = self.storage_loaded(payload, typ)?;
                        self.code.type_check(result, self.nodes.typ(typ))?;
                        values.push(result);
                    } else {
                        values.push(present);
                    }
                }
                Task::OptionIndex(field, keys, unwrap) => {
                    let registers = values.split_off(values.len() - keys.len());
                    if let Some(result) = self.option_index_mark(&field, &registers, unwrap)? {
                        values.push(result);
                    } else {
                        tasks.push(Task::OptionIndexValue(field, keys.len()));
                        for key in keys.into_iter().rev() {
                            tasks.push(Task::Expr(key));
                        }
                    }
                }
                Task::OptionIndexValue(field, count) => {
                    let registers = values.split_off(values.len() - count);
                    values.push(self.option_index_value(&field, &registers)?);
                }
                Task::Equal(typ) => {
                    let right = values.pop().expect("equality right");
                    let left = values.pop().expect("equality left");
                    let dest = self.code.alloc_reg()?;
                    self.code
                        .equality(self.nodes.typ(typ), BinOp::Eq, dest, left, right)?;
                    values.push(dest);
                }
                Task::Let(binding, body) => {
                    let register = values.pop().expect("let value");
                    let saved = self.locals.clone();
                    self.bind(binding.name, register, binding.typ);
                    tasks.push(Task::Restore(saved));
                    tasks.push(Task::Expr(body));
                }
                Task::Restore(saved) => self.locals = saved,
                Task::Split(left, right, body) => {
                    let source = values.pop().expect("split source");
                    let hash = self.code.alloc_reg()?;
                    let remaining = self.code.alloc_reg()?;
                    let left_register = self.code.alloc_reg()?;
                    let right_register = self.code.alloc_reg()?;
                    self.code.string(hash, b"#")?;
                    self.code.emit(I::Mov(remaining, source))?;
                    self.code.netstring_next(hash, remaining, left_register)?;
                    self.storage_loaded(left_register, left.typ)?;
                    self.code.netstring_next(hash, remaining, right_register)?;
                    self.storage_loaded(right_register, right.typ)?;
                    let saved = self.locals.clone();
                    self.bind(left.name, left_register, left.typ);
                    self.bind(right.name, right_register, right.typ);
                    tasks.push(Task::Restore(saved));
                    tasks.push(Task::Expr(body));
                }
                Task::OrbitTurns(count, has_turns, seed, binding, body) => {
                    let turns = has_turns.then(|| values.pop().expect("orbit turns"));
                    self.require_expression(b"orbit seed type differs", binding.typ, seed)?;
                    tasks.push(Task::OrbitSeed(count, turns, binding, body));
                    tasks.push(Task::Expr(seed));
                }
                Task::OrbitSeed(count, turns, binding, body) => {
                    let seed = values.pop().expect("orbit seed");
                    let state = self.code.alloc_reg()?;
                    self.code.emit(I::Mov(state, seed))?;
                    tasks.push(Task::OrbitStep(Orbit {
                        count,
                        index: 0,
                        turns,
                        state,
                        first: self.code.next_reg,
                        binding,
                        body,
                    }));
                }
                Task::OrbitStep(orbit) => {
                    if orbit.index == orbit.count {
                        values.push(orbit.state);
                        continue;
                    }
                    let next = if let Some(turns) = orbit.turns {
                        let apply = self.code.alloc_label()?;
                        let next = self.code.alloc_label()?;
                        let index = self.code.alloc_reg()?;
                        let active = self.code.alloc_reg()?;
                        self.code.integer(index, orbit.index)?;
                        self.code.emit(I::Lt(active, index, turns))?;
                        self.code.emit(I::Jif(active, apply))?;
                        self.code.emit(I::Jmp(next))?;
                        self.code.emit(I::Jdest(apply))?;
                        Some(next)
                    } else {
                        None
                    };
                    let saved = self.locals.clone();
                    self.bind(orbit.binding.name.clone(), orbit.state, orbit.binding.typ);
                    let body = orbit.body;
                    tasks.push(Task::OrbitApplied(orbit, next, saved));
                    tasks.push(Task::Expr(body));
                }
                Task::OrbitApplied(mut orbit, next, saved) => {
                    self.locals = saved;
                    self.code
                        .emit(I::Mov(orbit.state, values.pop().expect("orbit body")))?;
                    if let Some(next) = next {
                        self.code.emit(I::Jdest(next))?;
                    }
                    self.code.next_reg = orbit.first;
                    orbit.index += 1;
                    tasks.push(Task::OrbitStep(orbit));
                }
                Task::TernaryGuard(yes, no) => {
                    let condition = values.pop().expect("ternary condition");
                    let result = self.code.alloc_reg()?;
                    let then_label = self.code.alloc_label()?;
                    let end = self.code.alloc_label()?;
                    self.code.emit(I::Jif(condition, then_label))?;
                    tasks.push(Task::TernaryElse(result, then_label, end, yes));
                    tasks.push(Task::Expr(no));
                }
                Task::TernaryElse(result, then_label, end, yes) => {
                    self.code
                        .emit(I::Mov(result, values.pop().expect("ternary else")))?;
                    self.code.emit(I::Jmp(end))?;
                    self.code.emit(I::Jdest(then_label))?;
                    tasks.push(Task::TernaryThen(result, end));
                    tasks.push(Task::Expr(yes));
                }
                Task::TernaryThen(result, end) => {
                    self.code
                        .emit(I::Mov(result, values.pop().expect("ternary then")))?;
                    self.code.emit(I::Jdest(end))?;
                    values.push(result);
                }
                Task::BinaryLeft(whole, op, left_expr, right_expr) => {
                    let left = values.pop().expect("binary left");
                    if matches!(op, BinOp::And | BinOp::Or) {
                        let result = self.code.alloc_reg()?;
                        let short = self.code.alloc_label()?;
                        let end = self.code.alloc_label()?;
                        let truth = op == BinOp::Or;
                        if truth {
                            self.code.emit(I::Jif(left, short))?;
                        } else {
                            self.code.boolean(result, true)?;
                            self.code.emit(I::Neq(result, left, result))?;
                            self.code.emit(I::Jif(result, short))?;
                        }
                        tasks.push(Task::ShortRight(result, short, end, truth));
                    } else {
                        tasks.push(Task::BinaryRight(whole, op, left_expr, right_expr, left));
                    }
                    tasks.push(Task::Expr(right_expr));
                }
                Task::BinaryRight(whole, op, left_expr, right_expr, left) => {
                    let right = values.pop().expect("binary right");
                    let dest = self.code.alloc_reg()?;
                    match op {
                        BinOp::Add => {
                            let left_type = self.infer(left_expr)?;
                            let right_type = self.infer(right_expr)?;
                            self.code.emit(
                                if types::text(self.nodes.typ(left_type))
                                    || types::text(self.nodes.typ(right_type))
                                {
                                    I::Concat(dest, left, right)
                                } else {
                                    I::Add(dest, left, right)
                                },
                            )?;
                        }
                        BinOp::Sub => self.code.emit(I::Sub(dest, left, right))?,
                        BinOp::Mul => self.code.emit(I::Mul(dest, left, right))?,
                        BinOp::Div => self.code.emit(I::Div(dest, left, right))?,
                        BinOp::Mod => self.code.emit(I::Mod(dest, left, right))?,
                        BinOp::Eq | BinOp::Neq => {
                            if self.code.is_protocol() {
                                self.code.emit(if op == BinOp::Eq {
                                    I::Eq(dest, left, right)
                                } else {
                                    I::Neq(dest, left, right)
                                })?;
                            } else {
                                let typ = self.infer(left_expr)?;
                                self.code
                                    .equality(self.nodes.typ(typ), op, dest, left, right)?;
                            }
                        }
                        BinOp::Lt => self.code.emit(I::Lt(dest, left, right))?,
                        BinOp::Gt => self.code.emit(I::Gt(dest, left, right))?,
                        BinOp::Le | BinOp::Ge => {
                            self.code.emit(if op == BinOp::Le {
                                I::Gt(dest, left, right)
                            } else {
                                I::Lt(dest, left, right)
                            })?;
                            let truth = self.code.alloc_reg()?;
                            self.code.boolean(truth, true)?;
                            self.code.emit(I::Neq(dest, dest, truth))?;
                        }
                        BinOp::And | BinOp::Or => unreachable!("short circuit emitted separately"),
                    }
                    let typ = self.infer(whole)?;
                    self.code.result_type_check(dest, self.nodes.typ(typ))?;
                    values.push(dest);
                }
                Task::ShortRight(result, short, end, truth) => {
                    self.code
                        .emit(I::Mov(result, values.pop().expect("logical right")))?;
                    self.code.emit(I::Jmp(end))?;
                    self.code.emit(I::Jdest(short))?;
                    self.code.boolean(result, truth)?;
                    self.code.emit(I::Jdest(end))?;
                    values.push(result);
                }
                Task::Unary(op) => {
                    let value = values.pop().expect("unary operand");
                    let dest = self.code.alloc_reg()?;
                    match op {
                        UnOp::Neg => self.code.emit(I::Neg(dest, value))?,
                        UnOp::Not => {
                            self.code.boolean(dest, true)?;
                            self.code.emit(I::Neq(dest, value, dest))?;
                        }
                    }
                    values.push(dest);
                }
            }
        }
        Ok(values.pop().expect("expression result"))
    }
}
