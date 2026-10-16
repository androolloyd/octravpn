// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_gen inference deliberately differs from Oct_check: constants precede
//! locals, and many calls classify their result without inspecting arguments.
use super::{
    storage_path_name, types, Arc, BinOp, Binding, Expr, ExprId, Generator, Local, Name, Result,
    Syntax, Type, TypeId, UnOp,
};
use num_traits::Zero;

#[derive(Clone)]
struct Env {
    locals: Arc<Vec<Local>>,
    constants: Arc<Vec<Name>>,
}
impl Env {
    fn bind(&mut self, binding: Binding) {
        Arc::make_mut(&mut self.locals).push(Local {
            name: binding.name,
            register: 0,
            typ: binding.typ,
        });
    }
}
enum One {
    Option(Name),
    Numeric,
    Address,
    Some,
    List,
}
enum Task {
    Infer(ExprId, Env),
    Unary(UnOp),
    Binary(BinOp, ExprId, ExprId),
    One(One),
    Tuple(usize),
    Require(&'static [u8], TypeId, TypeId),
    Argument(TypeId),
    Use(TypeId, Binding, ExprId, Env),
    Guard(ExprId, ExprId, Env),
    Branches,
    EqualLeft(TypeId, ExprId, Env),
    Let(Binding, ExprId, Env),
    Split(Binding, Binding, ExprId, Env),
    OrbitTurns(ExprId, Binding, ExprId, Env),
    OrbitSeed(Binding, ExprId, Env),
}
impl Generator<'_> {
    pub(super) fn binary_type(
        &mut self,
        op: BinOp,
        left: TypeId,
        right: TypeId,
        left_expr: ExprId,
        right_expr: ExprId,
    ) -> Result<TypeId> {
        if matches!(op, BinOp::And | BinOp::Or) {
            let boolean = self.nodes.intern(Type::Bool);
            self.require_type(b"logical left operand type differs", boolean, left)?;
            self.require_type(b"logical right operand type differs", boolean, right)?;
            return Ok(boolean);
        }
        let (left_type, right_type) = (self.nodes.typ(left), self.nodes.typ(right));
        let error = |context: &[u8]| {
            self.code.located_error(
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
                    return Err(error(if op == BinOp::Add {
                        b"addition operand type differs"
                    } else {
                        b"arithmetic operand type differs"
                    }));
                }
                types::numeric_result(left_type, right_type)
            }
            BinOp::Eq | BinOp::Neq => {
                let zero =
                    |id| matches!(self.nodes.expression(id), Expr::Int(value) if value.is_zero());
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
            BinOp::And | BinOp::Or => unreachable!("logical operands checked above"),
        };
        Ok(self.nodes.intern(typ))
    }
    fn storage_expression_type(
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
    pub fn infer(&mut self, id: ExprId) -> Result<TypeId> {
        if self.code.is_protocol() {
            return self.protocol_infer(id);
        }
        let root = Env {
            locals: self.locals.clone(),
            constants: Arc::new(vec![]),
        };
        let mut tasks = vec![Task::Infer(id, root)];
        let mut values: Vec<TypeId> = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Infer(id, mut env) => {
                    let typ = match self.nodes.expression(id).clone() {
                        Expr::Bool(_) => Type::Bool,
                        Expr::String(_) | Expr::TreeHash | Expr::NodeId | Expr::TxHash => {
                            Type::String
                        }
                        Expr::Caller | Expr::Origin | Expr::SelfAddr => Type::Address,
                        Expr::Int(_)
                        | Expr::Epoch
                        | Expr::EpochTime
                        | Expr::Value
                        | Expr::Balance(_) => Type::Int,
                        Expr::Var(name) => {
                            if env.constants.contains(&name) {
                                return Err(self.code.located_error(
                                    [b"constant dependency is cyclic name = ".as_slice(), &name]
                                        .concat(),
                                ));
                            }
                            if let Some(constant) =
                                self.contract.consts.iter().find(|item| item.name == name)
                            {
                                if self.nodes.typ(constant.typ) == &Type::Void {
                                    Arc::make_mut(&mut env.constants).push(name);
                                    tasks.push(Task::Infer(constant.value, env));
                                } else {
                                    values.push(constant.typ);
                                }
                            } else if let Some(local) =
                                env.locals.iter().rev().find(|local| local.name == name)
                            {
                                values.push(local.typ);
                            } else {
                                return Err(self.code.located_error(
                                    [b"undefined variable: ".as_slice(), &name].concat(),
                                ));
                            }
                            continue;
                        }
                        Expr::Field(name) | Expr::Index(name, _) => {
                            let indexed = matches!(self.nodes.expression(id), Expr::Index(..));
                            let typ = self.storage_base(&name, indexed).ok_or_else(|| {
                                self.code.located_error(
                                    [b"undefined field: ".as_slice(), &name].concat(),
                                )
                            })?;
                            values.push(typ);
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
                        Expr::Action(_, value) => {
                            tasks.push(Task::Infer(value, env));
                            continue;
                        }
                        Expr::Use(value) => {
                            let target = self
                                .contract
                                .functions
                                .iter()
                                .find(|item| item.name == value.name && self.is_form(&item.name))
                                .ok_or_else(|| {
                                    self.code.located_error(
                                        [b"form is absent = ".as_slice(), &value.name].concat(),
                                    )
                                })?;
                            if self.code.pure && !target.pure {
                                return Err(self.code.located_error(
                                    [
                                        b"pure function form marks are not empty = ".as_slice(),
                                        &value.name,
                                    ]
                                    .concat(),
                                ));
                            }
                            let mut args = value.caps;
                            args.push(value.arg);
                            if target.params.len() != args.len() {
                                return Err(self.code.located_error(
                                    [
                                        b"function argument count differs function = ".as_slice(),
                                        &value.name,
                                        format!(
                                            " expected = {} actual = {}",
                                            target.params.len(),
                                            args.len()
                                        )
                                        .as_bytes(),
                                    ]
                                    .concat(),
                                ));
                            }
                            tasks.push(Task::Use(
                                target.ret,
                                value.binding,
                                value.body,
                                env.clone(),
                            ));
                            for (arg, param) in args.into_iter().zip(&target.params).rev() {
                                tasks.push(Task::Argument(param.typ));
                                tasks.push(Task::Infer(arg, env.clone()));
                            }
                            continue;
                        }
                        Expr::Call(name, args) => {
                            if self.is_form(&name) && !self.is_direct(&name) {
                                return Err(self.code.located_error(
                                    [b"form requires explicit use = ".as_slice(), &name].concat(),
                                ));
                            }
                            if self.is_direct(&name) {
                                if let Some(function) = self
                                    .contract
                                    .functions
                                    .iter()
                                    .find(|item| item.name == name)
                                {
                                    values.push(function.ret);
                                    continue;
                                }
                            }
                            let one = match name.as_slice() {
                                b"unwrap" | b"is_some_opt"
                                    if self.code.syntax == Syntax::Source =>
                                {
                                    if args.len() != 1 {
                                        return Err(self.code.located_error(
                                            [name.as_slice(), b" requires one argument"].concat(),
                                        ));
                                    }
                                    Some(One::Option(name.clone()))
                                }
                                b"min" | b"max" | b"abs" | b"to_int" | b"parse_ints" | b"mget"
                                | b"pow" | b"vecdot" | b"vecdot_fp" | b"vecdot_q16"
                                | b"argmax_fp" | b"argmax_q16" | b"exp_lut" | b"exp_q16"
                                | b"unwrap" => {
                                    if args.len() == 1 {
                                        Some(One::Numeric)
                                    } else {
                                        values.push(self.nodes.intern(Type::Int));
                                        continue;
                                    }
                                }
                                b"split" => {
                                    let typ = if self.code.syntax == Syntax::Forms {
                                        let string = self.nodes.intern(Type::String);
                                        Type::List(string)
                                    } else {
                                        Type::Int
                                    };
                                    values.push(self.nodes.intern(typ));
                                    continue;
                                }
                                b"to_address" if self.code.syntax == Syntax::Source => {
                                    if args.len() != 1 {
                                        return Err(self
                                            .code
                                            .located_error("to_address requires one argument"));
                                    }
                                    Some(One::Address)
                                }
                                b"some" => {
                                    if args.len() == 1 {
                                        Some(One::Some)
                                    } else {
                                        let void = self.nodes.intern(Type::Void);
                                        values.push(self.nodes.intern(Type::Option(void)));
                                        continue;
                                    }
                                }
                                b"none" => {
                                    if self.code.syntax == Syntax::Source && !args.is_empty() {
                                        return Err(self
                                            .code
                                            .located_error("none requires no arguments"));
                                    }
                                    let void = self.nodes.intern(Type::Void);
                                    values.push(self.nodes.intern(Type::Option(void)));
                                    continue;
                                }
                                _ => None,
                            };
                            if let Some(one) = one {
                                tasks.push(Task::One(one));
                                tasks.push(Task::Infer(args[0], env));
                            } else if let Some(typ) = super::super::check::builtin(&name) {
                                values.push(self.nodes.intern(typ));
                            } else if let Some(function) = self
                                .contract
                                .functions
                                .iter()
                                .find(|item| item.name == name)
                            {
                                values.push(function.ret);
                            } else {
                                return Err(self.code.located_error(
                                    [b"unknown function: ".as_slice(), &name].concat(),
                                ));
                            }
                            continue;
                        }
                        Expr::StoragePath(field, keys, path) => {
                            values.push(self.storage_expression_type(
                                &field,
                                !keys.is_empty(),
                                &path,
                            )?);
                            continue;
                        }
                        Expr::FieldProp(field, prop) | Expr::IndexField(field, _, prop) => {
                            let indexed = matches!(self.nodes.expression(id), Expr::IndexField(_, keys, _) if !keys.is_empty());
                            values.push(self.storage_expression_type(&field, indexed, &[prop])?);
                            continue;
                        }
                        Expr::EnumVariant(name, _) => Type::Enum(name),
                        Expr::Array(items) => {
                            if let Some(first) = items.first() {
                                tasks.push(Task::One(One::List));
                                tasks.push(Task::Infer(*first, env));
                                continue;
                            }
                            Type::List(self.nodes.intern(Type::Void))
                        }
                        Expr::Tuple(items) => {
                            tasks.push(Task::Tuple(items.len()));
                            for item in items.into_iter().rev() {
                                tasks.push(Task::Infer(item, env.clone()));
                            }
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
                        Expr::Ternary(guard, yes, no) => {
                            tasks.push(Task::Guard(yes, no, env.clone()));
                            tasks.push(Task::Infer(guard, env));
                            continue;
                        }
                    };
                    values.push(self.nodes.intern(typ));
                }
                Task::Unary(op) => {
                    let actual = values.pop().expect("unary operand");
                    let typ = match op {
                        UnOp::Neg => {
                            if !types::numeric(self.nodes.typ(actual)) {
                                return Err(self.code.located_error(
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
                            self.require_type(b"logical negation type differs", boolean, actual)?;
                            boolean
                        }
                    };
                    values.push(typ);
                }
                Task::Binary(op, left, right) => {
                    let right_type = values.pop().expect("binary right operand");
                    let left_type = values.pop().expect("binary left operand");
                    values.push(self.binary_type(op, left_type, right_type, left, right)?);
                }
                Task::One(one) => {
                    let actual = values.pop().expect("single argument type");
                    let typ = match one {
                        One::Option(name) => {
                            let Type::Option(inner) = self.nodes.typ(actual) else {
                                return Err(self.code.located_error(
                                    [
                                        name.as_slice(),
                                        b" requires option actual = ",
                                        self.nodes.typ(actual).name(),
                                    ]
                                    .concat(),
                                ));
                            };
                            if name == b"unwrap" {
                                *inner
                            } else {
                                self.nodes.intern(Type::Bool)
                            }
                        }
                        One::Numeric => match self.nodes.typ(actual) {
                            Type::Option(inner) => *inner,
                            _ => self.nodes.intern(Type::Int),
                        },
                        One::Address => {
                            if !types::text(self.nodes.typ(actual)) {
                                return Err(self.code.located_error(
                                    [
                                        b"address input type differs actual = ".as_slice(),
                                        self.nodes.typ(actual).name(),
                                    ]
                                    .concat(),
                                ));
                            }
                            self.nodes.intern(Type::Address)
                        }
                        One::Some => self.nodes.intern(Type::Option(actual)),
                        One::List => self.nodes.intern(Type::List(actual)),
                    };
                    values.push(typ);
                }
                Task::Tuple(count) => {
                    let items = values.split_off(values.len() - count);
                    values.push(self.nodes.intern(Type::Tuple(items)));
                }
                Task::Require(context, expected, result) => {
                    self.require_type(context, expected, values.pop().expect("required type"))?;
                    values.push(result);
                }
                Task::Argument(expected) => {
                    self.require_type(
                        b"function argument type differs",
                        expected,
                        values.pop().expect("argument type"),
                    )?;
                }
                Task::Use(expected, binding, body, mut env) => {
                    self.require_type(b"use result type differs", expected, binding.typ)?;
                    env.bind(binding);
                    tasks.push(Task::Infer(body, env));
                }
                Task::Guard(yes, no, env) => {
                    let boolean = self.nodes.intern(Type::Bool);
                    self.require_type(
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
                    self.require_type(b"ternary branch type differs", yes, no)?;
                    values.push(yes);
                }
                Task::EqualLeft(declared, right, env) => {
                    self.require_type(
                        b"equality left type differs",
                        declared,
                        values.pop().expect("left equality type"),
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
                    self.require_type(
                        b"local initializer type differs",
                        binding.typ,
                        values.pop().expect("initializer type"),
                    )?;
                    env.bind(binding);
                    tasks.push(Task::Infer(body, env));
                }
                Task::Split(left, right, body, mut env) => {
                    let tuple = self.nodes.intern(Type::Tuple(vec![left.typ, right.typ]));
                    self.require_type(
                        b"split type differs",
                        tuple,
                        values.pop().expect("split input type"),
                    )?;
                    env.bind(left);
                    env.bind(right);
                    tasks.push(Task::Infer(body, env));
                }
                Task::OrbitTurns(seed, binding, body, env) => {
                    let integer = self.nodes.intern(Type::Int);
                    self.require_type(
                        b"orbit count type differs",
                        integer,
                        values.pop().expect("orbit turns type"),
                    )?;
                    tasks.push(Task::OrbitSeed(binding, body, env.clone()));
                    tasks.push(Task::Infer(seed, env));
                }
                Task::OrbitSeed(binding, body, mut env) => {
                    self.require_type(
                        b"orbit seed type differs",
                        binding.typ,
                        values.pop().expect("orbit seed type"),
                    )?;
                    tasks.push(Task::Require(
                        b"orbit body type differs",
                        binding.typ,
                        binding.typ,
                    ));
                    env.bind(binding);
                    tasks.push(Task::Infer(body, env));
                }
            }
        }
        Ok(values.pop().expect("inferred expression type"))
    }
}
