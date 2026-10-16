// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Iterative C_poly substitution preserves native left-to-right error order
//! without making deeply nested source own the Rust host stack.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{Ast, Bind, Declaration, Error, ExprId, Name, Result, TypeId};
use crate::aml::core::{declaration::Declarations, lexer::Span, parse::ast::Expr};

enum TypeTask {
    Visit(TypeId),
    Finish(Declaration),
}
pub(super) fn typ(
    declarations: &mut Declarations,
    environment: &[(Name, TypeId)],
    root: TypeId,
) -> Result<TypeId> {
    let mut tasks = vec![TypeTask::Visit(root)];
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            TypeTask::Visit(id) => match declarations.get(id).clone() {
                Declaration::Var(name) => {
                    let value = environment
                        .iter()
                        .find(|(key, _)| key == &name)
                        .map(|(_, value)| *value)
                        .ok_or_else(|| Error::Name(name.text().to_vec()))?;
                    values.push(value);
                }
                Declaration::Vec(length, child) => {
                    tasks.push(TypeTask::Finish(Declaration::Vec(length, child)));
                    tasks.push(TypeTask::Visit(child));
                }
                Declaration::Seq(capacity, child) => {
                    tasks.push(TypeTask::Finish(Declaration::Seq(capacity, child)));
                    tasks.push(TypeTask::Visit(child));
                }
                Declaration::Pair(left, right) => {
                    tasks.push(TypeTask::Finish(Declaration::Pair(left, right)));
                    tasks.push(TypeTask::Visit(right));
                    tasks.push(TypeTask::Visit(left));
                }
                Declaration::Result(left, right) => {
                    tasks.push(TypeTask::Finish(Declaration::Result(left, right)));
                    tasks.push(TypeTask::Visit(right));
                    tasks.push(TypeTask::Visit(left));
                }
                Declaration::Unit
                | Declaration::Bool
                | Declaration::Int
                | Declaration::Num(..)
                | Declaration::Bytes(_)
                | Declaration::Cap(_)
                | Declaration::Exact(_) => values.push(id),
            },
            TypeTask::Finish(value) => {
                let right = values.pop().expect("C_poly type child");
                let value = match value {
                    Declaration::Vec(length, _) => Declaration::Vec(length, right),
                    Declaration::Seq(capacity, _) => Declaration::Seq(capacity, right),
                    Declaration::Pair(_, _) => {
                        Declaration::Pair(values.pop().expect("C_poly type left"), right)
                    }
                    Declaration::Result(_, _) => {
                        Declaration::Result(values.pop().expect("C_poly type left"), right)
                    }
                    _ => unreachable!("C_poly composite declaration"),
                };
                values.push(declarations.push(value));
            }
        }
    }
    Ok(values.pop().expect("C_poly substituted declaration"))
}
pub(super) fn bind(ast: &mut Ast, environment: &[(Name, TypeId)], value: &Bind) -> Result<Bind> {
    Ok(Bind {
        name: value.name.clone(),
        multiplicity: value.multiplicity,
        typ: typ(&mut ast.declarations, environment, value.typ)?,
    })
}
enum Action {
    Visit(ExprId),
    Type(TypeId),
    Bind(Bind),
    Build(Expr, Option<Span>, usize),
}
enum Value {
    Expr(ExprId),
    Type(TypeId),
    Bind(Bind),
}
struct Children(std::vec::IntoIter<Value>);
impl Children {
    fn expr(&mut self) -> ExprId {
        match self.0.next().expect("C_poly expression slot") {
            Value::Expr(id) => id,
            _ => unreachable!("C_poly expression slot kind"),
        }
    }
    fn typ(&mut self) -> TypeId {
        match self.0.next().expect("C_poly type slot") {
            Value::Type(id) => id,
            _ => unreachable!("C_poly type slot kind"),
        }
    }
    fn bind(&mut self) -> Bind {
        match self.0.next().expect("C_poly binder slot") {
            Value::Bind(bind) => bind,
            _ => unreachable!("C_poly binder slot kind"),
        }
    }
    fn expressions(&mut self, count: usize) -> Vec<ExprId> {
        (0..count).map(|_| self.expr()).collect()
    }
}
fn actions(expr: &Expr) -> Vec<Action> {
    use Action::{Bind as B, Type as T, Visit as E};
    match expr {
        Expr::Unit
        | Expr::Bool(_)
        | Expr::Int(_)
        | Expr::Bytes(_)
        | Expr::Var(_)
        | Expr::Syn(_) => Vec::new(),
        Expr::Vec(typ, values) | Expr::Seq(_, typ, values) => {
            let mut out = vec![T(*typ)];
            out.extend(values.iter().map(|value| E(*value)));
            out
        }
        Expr::Let(bind, value, body) => vec![B(bind.clone()), E(*value), E(*body)],
        Expr::If(guard, yes, no) => vec![E(*guard), E(*yes), E(*no)],
        Expr::Pair(left, right)
        | Expr::Add(left, right)
        | Expr::Sub(left, right)
        | Expr::Mul(left, right)
        | Expr::Div(left, right)
        | Expr::Mod(left, right)
        | Expr::Cmp(_, left, right)
        | Expr::Cat(left, right)
        | Expr::Vcat(left, right)
        | Expr::Step(left, right) => vec![E(*left), E(*right)],
        Expr::Unpair(value, left, right, body) => {
            vec![E(*value), B(left.clone()), B(right.clone()), E(*body)]
        }
        Expr::Fst(value)
        | Expr::Snd(value)
        | Expr::Act(_, value)
        | Expr::Neg(value)
        | Expr::Abs(value)
        | Expr::Wide(value)
        | Expr::Length(value)
        | Expr::Take(_, value)
        | Expr::Drop(_, value)
        | Expr::At(_, value)
        | Expr::Uncons(value)
        | Expr::Close(value)
        | Expr::DataMake(_, _, value) => vec![E(*value)],
        Expr::Inl(value, typ) => vec![E(*value), T(*typ)],
        Expr::Inr(typ, value) | Expr::Fit(typ, value) => vec![T(*typ), E(*value)],
        Expr::Case(value, left, yes, right, no) => vec![
            E(*value),
            B(left.clone()),
            E(*yes),
            B(right.clone()),
            E(*no),
        ],
        Expr::Eq(typ, left, right) => vec![T(*typ), E(*left), E(*right)],
        Expr::Fold(vector, seed, item, state, body) => vec![
            E(*vector),
            E(*seed),
            B(item.clone()),
            B(state.clone()),
            E(*body),
        ],
        Expr::DataCase(_, value, arms) => {
            let mut out = vec![E(*value)];
            for (_, bind, body) in arms {
                out.push(B(bind.clone()));
                out.push(E(*body));
            }
            out
        }
        Expr::RecordMake(_, items) => items.iter().map(|(_, value)| E(*value)).collect(),
        Expr::RecordSplit(_, value, picks, body) => {
            let mut out = vec![E(*value)];
            out.extend(picks.iter().map(|(_, bind)| B(bind.clone())));
            out.push(E(*body));
            out
        }
        Expr::Quant(_, source, item, body)
        | Expr::Orbit(_, source, item, body)
        | Expr::Wake(_, source, item, body) => vec![E(*source), B(item.clone()), E(*body)],
        Expr::Weave(_, typ, source, item, body) => {
            vec![T(*typ), E(*source), B(item.clone()), E(*body)]
        }
        Expr::Braid(_, typ, left, right, first, second, body) => vec![
            T(*typ),
            E(*left),
            E(*right),
            B(first.clone()),
            B(second.clone()),
            E(*body),
        ],
        Expr::Loom(_, typ, item, body) => vec![T(*typ), B(item.clone()), E(*body)],
        Expr::OrbitTo(_, turns, seed, item, body) => {
            vec![E(*turns), E(*seed), B(item.clone()), E(*body)]
        }
        Expr::Rift(_, _, typ, source) => vec![T(*typ), E(*source)],
        Expr::DirectCall(_, values, _) => values.iter().map(|value| E(*value)).collect(),
    }
}
fn build(expr: Expr, children: &mut Children) -> Expr {
    match expr {
        value @ (Expr::Unit
        | Expr::Bool(_)
        | Expr::Int(_)
        | Expr::Bytes(_)
        | Expr::Var(_)
        | Expr::Syn(_)) => value,
        Expr::Vec(_, values) => {
            let typ = children.typ();
            Expr::Vec(typ, children.expressions(values.len()))
        }
        Expr::Seq(capacity, _, values) => {
            let typ = children.typ();
            Expr::Seq(capacity, typ, children.expressions(values.len()))
        }
        Expr::Let(_, _, _) => {
            let bind = children.bind();
            let value = children.expr();
            let body = children.expr();
            Expr::Let(bind, value, body)
        }
        Expr::If(_, _, _) => {
            let guard = children.expr();
            let yes = children.expr();
            let no = children.expr();
            Expr::If(guard, yes, no)
        }
        Expr::Pair(_, _) => Expr::Pair(children.expr(), children.expr()),
        Expr::Unpair(_, _, _, _) => {
            let value = children.expr();
            let left = children.bind();
            let right = children.bind();
            let body = children.expr();
            Expr::Unpair(value, left, right, body)
        }
        Expr::Fst(_) => Expr::Fst(children.expr()),
        Expr::Snd(_) => Expr::Snd(children.expr()),
        Expr::Inl(_, _) => {
            let value = children.expr();
            let typ = children.typ();
            Expr::Inl(value, typ)
        }
        Expr::Inr(_, _) => {
            let typ = children.typ();
            let value = children.expr();
            Expr::Inr(typ, value)
        }
        Expr::Case(_, _, _, _, _) => {
            let value = children.expr();
            let left = children.bind();
            let yes = children.expr();
            let right = children.bind();
            let no = children.expr();
            Expr::Case(value, left, yes, right, no)
        }
        Expr::Act(atom, _) => Expr::Act(atom, children.expr()),
        Expr::Add(_, _) => Expr::Add(children.expr(), children.expr()),
        Expr::Sub(_, _) => Expr::Sub(children.expr(), children.expr()),
        Expr::Mul(_, _) => Expr::Mul(children.expr(), children.expr()),
        Expr::Div(_, _) => Expr::Div(children.expr(), children.expr()),
        Expr::Mod(_, _) => Expr::Mod(children.expr(), children.expr()),
        Expr::Neg(_) => Expr::Neg(children.expr()),
        Expr::Abs(_) => Expr::Abs(children.expr()),
        Expr::Fit(_, _) => {
            let typ = children.typ();
            let value = children.expr();
            Expr::Fit(typ, value)
        }
        Expr::Wide(_) => Expr::Wide(children.expr()),
        Expr::Length(_) => Expr::Length(children.expr()),
        Expr::Eq(_, _, _) => {
            let typ = children.typ();
            let left = children.expr();
            let right = children.expr();
            Expr::Eq(typ, left, right)
        }
        Expr::Cmp(relation, _, _) => Expr::Cmp(relation, children.expr(), children.expr()),
        Expr::Cat(_, _) => Expr::Cat(children.expr(), children.expr()),
        Expr::Take(at, _) => Expr::Take(at, children.expr()),
        Expr::Drop(at, _) => Expr::Drop(at, children.expr()),
        Expr::Vcat(_, _) => Expr::Vcat(children.expr(), children.expr()),
        Expr::At(at, _) => Expr::At(at, children.expr()),
        Expr::Uncons(_) => Expr::Uncons(children.expr()),
        Expr::Fold(_, _, _, _, _) => {
            let vector = children.expr();
            let seed = children.expr();
            let item = children.bind();
            let state = children.bind();
            let body = children.expr();
            Expr::Fold(vector, seed, item, state, body)
        }
        Expr::Step(_, _) => Expr::Step(children.expr(), children.expr()),
        Expr::Close(_) => Expr::Close(children.expr()),
        Expr::DataMake(declaration, name, _) => Expr::DataMake(declaration, name, children.expr()),
        Expr::DataCase(declaration, _, arms) => {
            let value = children.expr();
            let arms = arms
                .into_iter()
                .map(|(name, _, _)| {
                    let bind = children.bind();
                    let body = children.expr();
                    (name, bind, body)
                })
                .collect();
            Expr::DataCase(declaration, value, arms)
        }
        Expr::RecordMake(declaration, items) => Expr::RecordMake(
            declaration,
            items
                .into_iter()
                .map(|(name, _)| (name, children.expr()))
                .collect(),
        ),
        Expr::RecordSplit(declaration, _, picks, _) => {
            let value = children.expr();
            let picks = picks
                .into_iter()
                .map(|(name, _)| (name, children.bind()))
                .collect();
            let body = children.expr();
            Expr::RecordSplit(declaration, value, picks, body)
        }
        Expr::Quant(mode, _, _, _) => {
            let source = children.expr();
            let item = children.bind();
            let body = children.expr();
            Expr::Quant(mode, source, item, body)
        }
        Expr::Weave(count, _, _, _, _) => {
            let typ = children.typ();
            let source = children.expr();
            let item = children.bind();
            let body = children.expr();
            Expr::Weave(count, typ, source, item, body)
        }
        Expr::Braid(count, _, _, _, _, _, _) => {
            let typ = children.typ();
            let left = children.expr();
            let right = children.expr();
            let first = children.bind();
            let second = children.bind();
            let body = children.expr();
            Expr::Braid(count, typ, left, right, first, second, body)
        }
        Expr::Loom(count, _, _, _) => {
            let typ = children.typ();
            let item = children.bind();
            let body = children.expr();
            Expr::Loom(count, typ, item, body)
        }
        Expr::Orbit(count, _, _, _) => {
            let seed = children.expr();
            let item = children.bind();
            let body = children.expr();
            Expr::Orbit(count, seed, item, body)
        }
        Expr::OrbitTo(count, _, _, _, _) => {
            let turns = children.expr();
            let seed = children.expr();
            let item = children.bind();
            let body = children.expr();
            Expr::OrbitTo(count, turns, seed, item, body)
        }
        Expr::Wake(count, _, _, _) => {
            let seed = children.expr();
            let item = children.bind();
            let body = children.expr();
            Expr::Wake(count, seed, item, body)
        }
        Expr::Rift(cut, rest, _, _) => {
            let typ = children.typ();
            let source = children.expr();
            Expr::Rift(cut, rest, typ, source)
        }
        Expr::DirectCall(function, values, slot) => {
            Expr::DirectCall(function, children.expressions(values.len()), slot)
        }
    }
}
pub(super) fn term(ast: &mut Ast, environment: &[(Name, TypeId)], root: ExprId) -> Result<ExprId> {
    let mut tasks = vec![Action::Visit(root)];
    let mut values = Vec::new();
    while let Some(action) = tasks.pop() {
        match action {
            Action::Visit(id) => {
                let located = ast.expression(id).clone();
                let actions = actions(&located.value);
                tasks.push(Action::Build(located.value, located.mark, actions.len()));
                tasks.extend(actions.into_iter().rev());
            }
            Action::Type(id) => {
                values.push(Value::Type(typ(&mut ast.declarations, environment, id)?));
            }
            Action::Bind(value) => values.push(Value::Bind(bind(ast, environment, &value)?)),
            Action::Build(expr, mark, count) => {
                let mut children = Children(values.split_off(values.len() - count).into_iter());
                let expr = build(expr, &mut children);
                debug_assert!(children.0.next().is_none(), "C_poly child slots consumed");
                values.push(Value::Expr(ast.push_expr(expr, mark)));
            }
        }
    }
    match values.pop().expect("C_poly substituted root") {
        Value::Expr(root) => Ok(root),
        _ => unreachable!("C_poly substituted root kind"),
    }
}
