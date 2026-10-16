// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Expression type inference with native error precedence and explicit frames.
use super::{
    invalid, types, Arc, BinOp, Binding, Checker, Env, Expr, ExprId, Name, Result, Type, TypeId,
    UnOp,
};
use num_traits::Zero;
enum Aggregate {
    Call(Name),
    Array,
    Tuple,
}
enum Task {
    Infer(ExprId, Env),
    Unary(UnOp),
    Binary(BinOp, ExprId, ExprId),
    Aggregate(Aggregate, usize),
    Require(&'static [u8], TypeId, TypeId),
    Guard(ExprId, ExprId, Env),
    Branches,
    EqualLeft(TypeId, ExprId, Env),
    Let(Binding, ExprId, Env),
    Split(Binding, Binding, ExprId, Env),
    OrbitTurns(ExprId, Binding, ExprId, Env),
    OrbitSeed(Binding, ExprId, Env),
}
impl Checker<'_> {
    pub(super) fn binary(
        &mut self,
        op: BinOp,
        left: TypeId,
        right: TypeId,
        left_expr: Option<ExprId>,
        right_expr: Option<ExprId>,
    ) -> Result<TypeId> {
        if matches!(op, BinOp::And | BinOp::Or) {
            let boolean = self.nodes.intern(Type::Bool);
            self.require(b"logical left operand type differs", boolean, left)?;
            self.require(b"logical right operand type differs", boolean, right)?;
            return Ok(boolean);
        }
        let (left_type, right_type) = (self.nodes.typ(left), self.nodes.typ(right));
        let error = |context: &[u8]| {
            invalid(
                [
                    context,
                    b" left = ",
                    left_type.name(),
                    b" right = ",
                    right_type.name(),
                ]
                .concat(),
            )
        };
        let typ = match op {
            BinOp::Add if types::text(left_type) || types::text(right_type) => Type::String,
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                if !types::numeric(left_type) || !types::numeric(right_type) {
                    return Err(error(b"arithmetic operand type differs"));
                }
                types::numeric_result(left_type, right_type)
            }
            BinOp::Eq | BinOp::Neq => {
                let zero = |id: Option<ExprId>| {
                    id.is_some_and(|id| matches!(self.nodes.expression(id), Expr::Int(value) if value.is_zero()))
                };
                if !(types::compatible(self.nodes, left, right)
                    || types::opaque(left_type) && zero(right_expr)
                    || types::opaque(right_type) && zero(left_expr))
                {
                    return Err(error(b"equality operand type differs"));
                }
                Type::Bool
            }
            BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
                if !types::numeric(left_type) || !types::numeric(right_type) {
                    return Err(error(b"comparison operand type differs"));
                }
                Type::Bool
            }
            BinOp::And | BinOp::Or => unreachable!("logical operands were checked"),
        };
        Ok(self.nodes.intern(typ))
    }
    pub(super) fn infer(&mut self, env: &Env, id: ExprId) -> Result<TypeId> {
        let mut tasks = vec![Task::Infer(id, env.clone())];
        let mut values: Vec<TypeId> = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Infer(id, mut env) => {
                    let expr = self.nodes.expression(id).clone();
                    let typ = match expr {
                        Expr::Int(_) => Type::Int,
                        Expr::Bool(_) => Type::Bool,
                        Expr::String(_) | Expr::TreeHash | Expr::NodeId | Expr::TxHash => {
                            Type::String
                        }
                        Expr::Caller | Expr::Origin | Expr::SelfAddr => Type::Address,
                        Expr::Epoch | Expr::EpochTime | Expr::Value => {
                            let name = match self.nodes.expression(id) {
                                Expr::Epoch => b"epoch".as_slice(),
                                Expr::EpochTime => b"epoch_time",
                                _ => b"value",
                            };
                            let typ = env
                                .local(name)
                                .unwrap_or_else(|| self.nodes.intern(Type::Int));
                            values.push(typ);
                            continue;
                        }
                        Expr::Var(name) => {
                            if let Some(typ) = env.local(&name) {
                                values.push(typ);
                                continue;
                            }
                            if let Some(constant) = self
                                .contract
                                .consts
                                .iter()
                                .find(|constant| constant.name == name)
                            {
                                if env.active.contains(&name) {
                                    return Err(invalid(
                                        [
                                            b"constant dependency is cyclic name = ".as_slice(),
                                            &name,
                                        ]
                                        .concat(),
                                    ));
                                }
                                if self.nodes.typ(constant.typ) == &Type::Void {
                                    Arc::make_mut(&mut env.active).push(name);
                                    tasks.push(Task::Infer(constant.value, env));
                                } else {
                                    values.push(constant.typ);
                                }
                                continue;
                            }
                            if matches!(name.as_slice(), b"epoch" | b"epoch_time" | b"value") {
                                Type::Int
                            } else {
                                return Err(invalid(
                                    [b"variable is undefined name = ".as_slice(), &name].concat(),
                                ));
                            }
                        }
                        Expr::Field(name) => {
                            values.push(self.field(&name)?);
                            continue;
                        }
                        Expr::Index(name, keys) => {
                            values.push(self.state_index(&env, &name, &keys)?);
                            continue;
                        }
                        Expr::StoragePath(name, keys, path) => {
                            values.push(self.storage_path(&env, &name, &keys, &path)?);
                            continue;
                        }
                        Expr::FieldProp(name, field) => {
                            values.push(self.storage_path(&env, &name, &[], &[field])?);
                            continue;
                        }
                        Expr::IndexField(name, keys, field) => {
                            values.push(self.storage_path(&env, &name, &keys, &[field])?);
                            continue;
                        }
                        Expr::EnumVariant(name, variant) => {
                            let enumeration = self
                                .contract
                                .enums
                                .iter()
                                .find(|item| item.name == name)
                                .ok_or_else(|| {
                                    invalid(
                                        [b"enum is undefined name = ".as_slice(), &name].concat(),
                                    )
                                })?;
                            if !enumeration.variants.contains(&variant) {
                                return Err(invalid(
                                    [
                                        b"enum variant is undefined name = ".as_slice(),
                                        &name,
                                        b".",
                                        &variant,
                                    ]
                                    .concat(),
                                ));
                            }
                            Type::Enum(name)
                        }
                        Expr::Balance(address) => {
                            let expected = self.nodes.intern(Type::Address);
                            let result = self.nodes.intern(Type::Int);
                            tasks.push(Task::Require(
                                b"balance address type differs",
                                expected,
                                result,
                            ));
                            tasks.push(Task::Infer(address, env));
                            continue;
                        }
                        Expr::Binop(op, left, right) => {
                            tasks.push(Task::Binary(op, left, right));
                            tasks.push(Task::Infer(right, env.clone()));
                            tasks.push(Task::Infer(left, env));
                            continue;
                        }
                        Expr::Unop(op, value) => {
                            tasks.push(Task::Unary(op));
                            tasks.push(Task::Infer(value, env));
                            continue;
                        }
                        Expr::Call(name, args) => {
                            tasks.push(Task::Aggregate(Aggregate::Call(name), args.len()));
                            for arg in args.into_iter().rev() {
                                tasks.push(Task::Infer(arg, env.clone()));
                            }
                            continue;
                        }
                        Expr::Array(items) | Expr::Tuple(items) => {
                            let tuple = matches!(self.nodes.expression(id), Expr::Tuple(_));
                            tasks.push(Task::Aggregate(
                                if tuple {
                                    Aggregate::Tuple
                                } else {
                                    Aggregate::Array
                                },
                                items.len(),
                            ));
                            for item in items.into_iter().rev() {
                                tasks.push(Task::Infer(item, env.clone()));
                            }
                            continue;
                        }
                        Expr::Ternary(guard, yes, no) => {
                            tasks.push(Task::Guard(yes, no, env.clone()));
                            tasks.push(Task::Infer(guard, env));
                            continue;
                        }
                        Expr::Equal(declared, left, right) => {
                            tasks.push(Task::EqualLeft(declared, right, env.clone()));
                            tasks.push(Task::Infer(left, env));
                            continue;
                        }
                        Expr::Let(binding, input, body) => {
                            tasks.push(Task::Let(binding, body, env.clone()));
                            tasks.push(Task::Infer(input, env));
                            continue;
                        }
                        Expr::Split(input, left, right, body) => {
                            tasks.push(Task::Split(left, right, body, env.clone()));
                            tasks.push(Task::Infer(input, env));
                            continue;
                        }
                        Expr::Orbit(_, turns, seed, binding, body) => {
                            if let Some(turns) = turns {
                                tasks.push(Task::OrbitTurns(seed, binding, body, env.clone()));
                                tasks.push(Task::Infer(turns, env));
                            } else {
                                tasks.push(Task::OrbitSeed(binding, body, env.clone()));
                                tasks.push(Task::Infer(seed, env));
                            }
                            continue;
                        }
                        Expr::Action(..) | Expr::Use(_) => {
                            return Err(invalid("direct form expression requires AML compilation"))
                        }
                    };
                    values.push(self.nodes.intern(typ));
                }
                Task::Unary(op) => {
                    let actual = values.pop().expect("unary operand");
                    let result = match op {
                        UnOp::Neg => {
                            if !types::numeric(self.nodes.typ(actual)) {
                                return Err(invalid(
                                    [
                                        b"negation operand type differs actual = ".as_slice(),
                                        self.nodes.typ(actual).name(),
                                    ]
                                    .concat(),
                                ));
                            }
                            actual
                        }
                        UnOp::Not => {
                            let boolean = self.nodes.intern(Type::Bool);
                            self.require(b"logical negation type differs", boolean, actual)?;
                            boolean
                        }
                    };
                    values.push(result);
                }
                Task::Binary(op, left, right) => {
                    let right_type = values.pop().expect("binary right operand");
                    let left_type = values.pop().expect("binary left operand");
                    values.push(self.binary(op, left_type, right_type, Some(left), Some(right))?);
                }
                Task::Aggregate(kind, count) => {
                    let types = values.split_off(values.len() - count);
                    let typ = match kind {
                        Aggregate::Call(name) => self.call(&name, &types)?,
                        Aggregate::Tuple => self.nodes.intern(Type::Tuple(types)),
                        Aggregate::Array => {
                            let first = types
                                .first()
                                .copied()
                                .unwrap_or_else(|| self.nodes.intern(Type::Void));
                            for actual in types.iter().skip(1) {
                                self.require(b"list item type differs", first, *actual)?;
                            }
                            self.nodes.intern(Type::List(first))
                        }
                    };
                    values.push(typ);
                }
                Task::Require(context, expected, result) => {
                    self.require(
                        context,
                        expected,
                        values.pop().expect("required expression type"),
                    )?;
                    values.push(result);
                }
                Task::Guard(yes, no, env) => {
                    let boolean = self.nodes.intern(Type::Bool);
                    self.require(
                        b"ternary condition type differs",
                        boolean,
                        values.pop().expect("ternary guard"),
                    )?;
                    tasks.push(Task::Branches);
                    tasks.push(Task::Infer(no, env.clone()));
                    tasks.push(Task::Infer(yes, env));
                }
                Task::Branches => {
                    let no = values.pop().expect("ternary no branch");
                    let yes = values.pop().expect("ternary yes branch");
                    self.require(b"ternary branch type differs", yes, no)?;
                    values.push(yes);
                }
                Task::EqualLeft(declared, right, env) => {
                    self.require(
                        b"equality left type differs",
                        declared,
                        values.pop().expect("equality left operand"),
                    )?;
                    let boolean = self.nodes.intern(Type::Bool);
                    tasks.push(Task::Require(
                        b"equality right type differs",
                        declared,
                        boolean,
                    ));
                    tasks.push(Task::Infer(right, env));
                }
                Task::Let(binding, body, mut env) => {
                    self.require(
                        b"local initializer type differs",
                        binding.typ,
                        values.pop().expect("let initializer"),
                    )?;
                    env.add(binding.name, binding.typ);
                    tasks.push(Task::Infer(body, env));
                }
                Task::Split(left, right, body, mut env) => {
                    let expected = self.nodes.intern(Type::Tuple(vec![left.typ, right.typ]));
                    self.require(
                        b"split type differs",
                        expected,
                        values.pop().expect("split pair"),
                    )?;
                    env.add(left.name, left.typ);
                    env.add(right.name, right.typ);
                    tasks.push(Task::Infer(body, env));
                }
                Task::OrbitTurns(seed, binding, body, env) => {
                    let integer = self.nodes.intern(Type::Int);
                    self.require(
                        b"orbit count type differs",
                        integer,
                        values.pop().expect("orbit count"),
                    )?;
                    tasks.push(Task::OrbitSeed(binding, body, env.clone()));
                    tasks.push(Task::Infer(seed, env));
                }
                Task::OrbitSeed(binding, body, mut env) => {
                    self.require(
                        b"orbit seed type differs",
                        binding.typ,
                        values.pop().expect("orbit seed"),
                    )?;
                    env.add(binding.name, binding.typ);
                    tasks.push(Task::Require(
                        b"orbit body type differs",
                        binding.typ,
                        binding.typ,
                    ));
                    tasks.push(Task::Infer(body, env));
                }
            }
        }
        Ok(values.pop().expect("inferred root type"))
    }
}
