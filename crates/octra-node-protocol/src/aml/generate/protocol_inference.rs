// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_emit type projection is intentionally weaker than Oct_gen inference.
//! It classifies comparisons and containers without visiting their operands.
use super::{
    types, Arc, BinOp, Binding, Expr, ExprId, Generator, Local, Result, Type, TypeId, UnOp,
};
#[derive(Clone)]
struct Env(Arc<Vec<Local>>);
impl Env {
    fn find(&self, name: &[u8]) -> Option<TypeId> {
        self.0
            .iter()
            .rev()
            .find(|local| local.name == name)
            .map(|local| local.typ)
    }
    fn bind(mut self, bind: Binding) -> Self {
        Arc::make_mut(&mut self.0).push(Local {
            name: bind.name,
            register: 0,
            typ: bind.typ,
        });
        self
    }
}
enum Task {
    Infer(ExprId, Env),
    Merge(BinOp),
}
impl Generator<'_> {
    pub(super) fn protocol_infer(&mut self, root: ExprId) -> Result<TypeId> {
        let checked = self
            .code
            .protocol_checked()
            .expect("Protocol inference backend");
        let mut pending = vec![Task::Infer(root, Env(self.locals.clone()))];
        let mut values = vec![];
        while let Some(task) = pending.pop() {
            let typ = match task {
                Task::Infer(id, env) => match self.nodes.expression(id).clone() {
                    Expr::Bool(_) | Expr::Unop(UnOp::Not, _) | Expr::Equal(..) => Type::Bool,
                    Expr::String(_)
                    | Expr::TreeHash
                    | Expr::NodeId
                    | Expr::TxHash
                    | Expr::Array(_)
                    | Expr::Tuple(_) => Type::String,
                    Expr::Caller | Expr::Origin | Expr::SelfAddr => Type::Address,
                    Expr::Epoch | Expr::EpochTime | Expr::Value => {
                        let name: &[u8] = match self.nodes.expression(id) {
                            Expr::Epoch => b"epoch",
                            Expr::EpochTime => b"epoch_time",
                            _ => b"value",
                        };
                        if checked {
                            if let Some(typ) = env.find(name) {
                                values.push(typ);
                                continue;
                            }
                        }
                        Type::Int
                    }
                    Expr::Var(name) => {
                        let context =
                            matches!(name.as_slice(), b"epoch" | b"epoch_time" | b"value");
                        if !self.code.is_prior()
                            && context
                            && (!checked || env.find(&name).is_none())
                        {
                            Type::Int
                        } else if let Some(constant) =
                            self.contract.consts.iter().find(|item| item.name == name)
                        {
                            values.push(constant.typ);
                            continue;
                        } else if let Some(typ) = env.find(&name) {
                            values.push(typ);
                            continue;
                        } else {
                            return Err(self
                                .code
                                .error([b"undefined variable: ".as_slice(), &name].concat()));
                        }
                    }
                    Expr::Field(name) => {
                        values.push(self.field_type(&name)?);
                        continue;
                    }
                    Expr::Index(name, _) => {
                        let typ = self.field_type(&name)?;
                        values.push(self.map_value(typ));
                        continue;
                    }
                    Expr::Binop(op, left, right) => {
                        if matches!(
                            op,
                            BinOp::Eq
                                | BinOp::Neq
                                | BinOp::Lt
                                | BinOp::Gt
                                | BinOp::Le
                                | BinOp::Ge
                                | BinOp::And
                                | BinOp::Or
                        ) {
                            Type::Bool
                        } else {
                            pending.push(Task::Merge(op));
                            if op == BinOp::Add {
                                pending.push(Task::Infer(right, env.clone()));
                                pending.push(Task::Infer(left, env));
                            } else {
                                pending.push(Task::Infer(left, env.clone()));
                                pending.push(Task::Infer(right, env));
                            }
                            continue;
                        }
                    }
                    Expr::Call(name, args) => match name.as_slice() {
                        b"some" if args.len() == 1 => {
                            pending.push(Task::Infer(args[0], env));
                            continue;
                        }
                        b"some" | b"unwrap" => Type::Int,
                        b"none" => Type::String,
                        _ => {
                            let added = self.code.is_prior()
                                && matches!(
                                    name.as_slice(),
                                    b"pedersen_add" | b"pedersen_sub" | b"pedersen_identity"
                                );
                            if let Some(typ) = (!added)
                                .then(|| super::super::check::builtin(&name))
                                .flatten()
                            {
                                typ
                            } else if let Some(function) = self
                                .contract
                                .functions
                                .iter()
                                .find(|function| function.name == name)
                            {
                                values.push(function.ret);
                                continue;
                            } else {
                                return Err(self
                                    .code
                                    .error([b"unknown function: ".as_slice(), &name].concat()));
                            }
                        }
                    },
                    Expr::StoragePath(field, keys, path) => {
                        values.push(self.path_type(&field, !keys.is_empty(), &path)?);
                        continue;
                    }
                    Expr::FieldProp(field, prop) => {
                        values.push(self.path_type(&field, false, &[prop])?);
                        continue;
                    }
                    Expr::IndexField(field, keys, prop) => {
                        values.push(self.path_type(&field, !keys.is_empty(), &[prop])?);
                        continue;
                    }
                    Expr::Int(_)
                    | Expr::Balance(_)
                    | Expr::Unop(UnOp::Neg, _)
                    | Expr::EnumVariant(..) => Type::Int,
                    Expr::Let(bind, _, body) => {
                        pending.push(Task::Infer(body, env.bind(bind)));
                        continue;
                    }
                    Expr::Split(_, left, right, body) => {
                        pending.push(Task::Infer(body, env.bind(left).bind(right)));
                        continue;
                    }
                    Expr::Orbit(_, _, _, bind, _) => {
                        values.push(bind.typ);
                        continue;
                    }
                    Expr::Ternary(_, yes, _) => {
                        pending.push(Task::Infer(yes, env));
                        continue;
                    }
                    Expr::Action(..) | Expr::Use(_) => {
                        return Err(self.code.error("direct form expression is unavailable"))
                    }
                },
                Task::Merge(op) => {
                    let last = values.pop().expect("Protocol final operand type");
                    let first = values.pop().expect("Protocol first operand type");
                    let (left, right) = if op == BinOp::Add {
                        (first, last)
                    } else {
                        (last, first)
                    };
                    if op == BinOp::Add
                        && (types::text(self.nodes.typ(left)) || types::text(self.nodes.typ(right)))
                    {
                        Type::String
                    } else {
                        types::numeric_result(self.nodes.typ(left), self.nodes.typ(right))
                    }
                }
            };
            values.push(self.nodes.intern(typ));
        }
        Ok(values.pop().expect("Protocol inferred root"))
    }
}
