// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Preserve the native heuristic's syntactic scope and guard rules. In
//! particular, a discovered guard is not a proof of control-flow dominance.
use super::{
    blocks, expression_text, unsigned, Analysis, BinOp, Env, Expr, ExprId, Name, Nodes, Stmt,
    StmtId, Type, TypeId, UnOp,
};
use num_traits::Zero;
pub(super) fn children(nodes: &Nodes, id: ExprId) -> Vec<ExprId> {
    let mut expression = nodes.expression(id).clone();
    let mut children = vec![];
    expression.map_exprs(&mut |id| {
        children.push(id);
        id
    });
    children
}
impl Analysis<'_> {
    fn mentions(&self, name: &[u8], root: ExprId) -> bool {
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            match self.ast.nodes.expression(id) {
                Expr::Var(found) | Expr::Field(found) if found == name => return true,
                Expr::Index(found, keys) => {
                    if found == name {
                        return true;
                    }
                    pending.extend(keys.iter().rev().copied());
                }
                Expr::StoragePath(field, keys, path) => {
                    if field == name || path.iter().any(|part| part == name) {
                        return true;
                    }
                    pending.extend(keys.iter().rev().copied());
                }
                Expr::FieldProp(field, prop) => {
                    if field == name || prop == name {
                        return true;
                    }
                }
                Expr::IndexField(field, keys, prop) => {
                    if field == name || prop == name {
                        return true;
                    }
                    pending.extend(keys.iter().rev().copied());
                }
                Expr::Let(bind, value, body) => {
                    if bind.name != name {
                        pending.push(*body);
                    }
                    pending.push(*value);
                }
                Expr::Split(value, left, right, body) => {
                    if left.name != name && right.name != name {
                        pending.push(*body);
                    }
                    pending.push(*value);
                }
                Expr::Orbit(_, turns, seed, bind, body) => {
                    if bind.name != name {
                        pending.push(*body);
                    }
                    pending.push(*seed);
                    if let Some(turns) = turns {
                        pending.push(*turns);
                    }
                }
                Expr::Use(value) => {
                    if value.binding.name != name {
                        pending.push(value.body);
                    }
                    pending.extend(value.caps.iter().rev().copied());
                    pending.push(value.arg);
                }
                _ => pending.extend(children(&self.ast.nodes, id).into_iter().rev()),
            }
        }
        false
    }
    fn positive_guard(&self, name: &[u8], root: ExprId) -> bool {
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            match self.ast.nodes.expression(id) {
                Expr::Binop(BinOp::Gt, left, right) => {
                    if matches!(self.ast.nodes.expression(*left), Expr::Var(found) if found == name)
                        && matches!(self.ast.nodes.expression(*right), Expr::Int(value) if value.is_zero())
                    {
                        return true;
                    }
                }
                Expr::Binop(BinOp::And, left, right) => {
                    pending.push(*right);
                    pending.push(*left);
                }
                _ => (),
            }
        }
        false
    }
    fn assertions(&self, body: &[StmtId], mut select: impl FnMut(ExprId) -> bool) -> bool {
        blocks(&self.ast.nodes, body)
            .into_iter()
            .any(|id| match self.ast.nodes.statement(id) {
                Stmt::Require(guard, _) | Stmt::Assert(guard) => select(*guard),
                _ => false,
            })
    }
    pub(super) fn checks_var(&self, name: &[u8], body: &[StmtId]) -> bool {
        self.assertions(body, |id| self.mentions(name, id))
    }
    pub(super) fn positive(&self, name: &[u8], body: &[StmtId]) -> bool {
        self.assertions(body, |id| self.positive_guard(name, id))
    }
    pub(super) fn expression_type(&mut self, env: &Env, root: ExprId) -> Option<TypeId> {
        enum Task {
            Visit(ExprId, Env),
            Combine,
        }
        let mut tasks = vec![Task::Visit(root, env.clone())];
        let mut values: Vec<Option<TypeId>> = vec![];
        while let Some(task) = tasks.pop() {
            let value = match task {
                Task::Visit(id, env) => match self.ast.nodes.expression(id) {
                    Expr::Var(name) => env.find(name),
                    Expr::Index(field, _)
                    | Expr::StoragePath(field, _, _)
                    | Expr::Field(field)
                    | Expr::FieldProp(field, _)
                    | Expr::IndexField(field, _, _) => self.field_type(field),
                    Expr::Int(_) | Expr::Unop(UnOp::Neg, _) => Some(self.host.intern(Type::Int)),
                    Expr::Binop(_, left, right) | Expr::Ternary(_, left, right) => {
                        tasks.push(Task::Combine);
                        tasks.push(Task::Visit(*right, env.clone()));
                        tasks.push(Task::Visit(*left, env));
                        continue;
                    }
                    Expr::Equal(..) | Expr::Bool(_) => Some(self.host.intern(Type::Bool)),
                    Expr::Let(bind, _, body) => {
                        tasks.push(Task::Visit(*body, env.add(bind.name.clone(), bind.typ)));
                        continue;
                    }
                    Expr::Split(_, left, right, body) => {
                        tasks.push(Task::Visit(
                            *body,
                            env.add(left.name.clone(), left.typ)
                                .add(right.name.clone(), right.typ),
                        ));
                        continue;
                    }
                    Expr::Orbit(_, _, _, bind, _) => Some(bind.typ),
                    Expr::Action(_, value) => {
                        tasks.push(Task::Visit(*value, env));
                        continue;
                    }
                    Expr::Use(value) => Some(value.binding.typ),
                    Expr::String(_) => Some(self.host.intern(Type::String)),
                    Expr::Caller | Expr::Origin | Expr::SelfAddr => {
                        Some(self.host.intern(Type::Address))
                    }
                    Expr::Value => Some(self.host.intern(Type::U128)),
                    Expr::Array(_)
                    | Expr::Tuple(_)
                    | Expr::Call(..)
                    | Expr::Unop(UnOp::Not, _)
                    | Expr::Balance(_)
                    | Expr::Epoch
                    | Expr::EpochTime
                    | Expr::TreeHash
                    | Expr::NodeId
                    | Expr::TxHash
                    | Expr::EnumVariant(..) => None,
                },
                Task::Combine => {
                    let right = values.pop().expect("safety right type");
                    let left = values.pop().expect("safety left type");
                    if left.is_some_and(|typ| matches!(self.host.typ(typ), Type::Int))
                        || right.is_some_and(|typ| matches!(self.host.typ(typ), Type::Int))
                    {
                        Some(self.host.intern(Type::Int))
                    } else {
                        left.or(right)
                    }
                }
            };
            values.push(value);
        }
        values.pop().expect("safety inferred type")
    }
    pub(super) fn signed_source(&self, env: &Env, root: ExprId) -> Option<Name> {
        let mut pending = vec![(root, env.clone())];
        while let Some((id, env)) = pending.pop() {
            let values = match self.ast.nodes.expression(id) {
                Expr::Var(name) => {
                    if env
                        .find(name)
                        .is_some_and(|typ| matches!(self.host.typ(typ), Type::Int))
                    {
                        return Some(name.clone());
                    }
                    vec![]
                }
                Expr::Index(field, keys)
                | Expr::StoragePath(field, keys, _)
                | Expr::IndexField(field, keys, _) => {
                    if self
                        .field_type(field)
                        .is_some_and(|typ| matches!(self.host.typ(typ), Type::Int))
                    {
                        return Some(field.clone());
                    }
                    keys.clone()
                }
                Expr::Field(field) | Expr::FieldProp(field, _) => {
                    if self
                        .field_type(field)
                        .is_some_and(|typ| matches!(self.host.typ(typ), Type::Int))
                    {
                        return Some(field.clone());
                    }
                    vec![]
                }
                Expr::Unop(UnOp::Neg, _) => return Some(b"literal".to_vec()),
                Expr::Binop(_, left, right) => vec![*left, *right],
                Expr::Unop(_, value) | Expr::Balance(value) | Expr::Action(_, value) => {
                    vec![*value]
                }
                Expr::Call(_, values) | Expr::Array(values) | Expr::Tuple(values) => values.clone(),
                Expr::Ternary(cond, yes, no) => vec![*cond, *yes, *no],
                Expr::Let(bind, _, body) | Expr::Orbit(_, _, _, bind, body) => {
                    pending.push((*body, env.add(bind.name.clone(), bind.typ)));
                    continue;
                }
                Expr::Split(_, left, right, body) => {
                    pending.push((
                        *body,
                        env.add(left.name.clone(), left.typ)
                            .add(right.name.clone(), right.typ),
                    ));
                    continue;
                }
                Expr::Use(value) => {
                    let mut args = vec![value.arg];
                    args.extend(&value.caps);
                    args.push(value.body);
                    args
                }
                Expr::Equal(..)
                | Expr::Int(_)
                | Expr::Bool(_)
                | Expr::String(_)
                | Expr::Caller
                | Expr::Origin
                | Expr::SelfAddr
                | Expr::Epoch
                | Expr::EpochTime
                | Expr::Value
                | Expr::TreeHash
                | Expr::NodeId
                | Expr::TxHash
                | Expr::EnumVariant(..) => vec![],
            };
            pending.extend(values.into_iter().rev().map(|id| (id, env.clone())));
        }
        None
    }
    fn proves_subtraction(&self, left: ExprId, right: ExprId, body: &[StmtId]) -> bool {
        let left = expression_text(&self.ast.nodes, left);
        let right = expression_text(&self.ast.nodes, right);
        self.assertions(body, |root| {
            let mut pending = vec![root];
            while let Some(id) = pending.pop() {
                match self.ast.nodes.expression(id) {
                    Expr::Binop(BinOp::Ge | BinOp::Gt, guard_left, guard_right) => {
                        if expression_text(&self.ast.nodes, *guard_left) == left
                            && expression_text(&self.ast.nodes, *guard_right) == right
                        {
                            return true;
                        }
                    }
                    Expr::Binop(BinOp::And, left, right) => {
                        pending.push(*right);
                        pending.push(*left);
                    }
                    _ => (),
                }
            }
            false
        })
    }
    pub(super) fn unproven_arithmetic(&mut self, env: &Env, body: &[StmtId], root: ExprId) -> bool {
        let mut pending = vec![(root, env.clone())];
        while let Some((id, env)) = pending.pop() {
            let values = match self.ast.nodes.expression(id).clone() {
                Expr::Binop(op, left, right) => {
                    let arithmetic = matches!(
                        op,
                        BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod
                    );
                    let left_type = self.expression_type(&env, left);
                    let right_type = self.expression_type(&env, right);
                    let unsigned_op = arithmetic
                        && (left_type.is_some_and(|typ| unsigned(self.host.typ(typ)))
                            || right_type.is_some_and(|typ| unsigned(self.host.typ(typ))));
                    if unsigned_op
                        && !(op == BinOp::Sub && self.proves_subtraction(left, right, body))
                    {
                        return true;
                    }
                    vec![left, right]
                }
                Expr::Let(bind, value, next) => {
                    pending.push((next, env.clone().add(bind.name, bind.typ)));
                    pending.push((value, env));
                    continue;
                }
                Expr::Split(value, left, right, next) => {
                    pending.push((
                        next,
                        env.clone()
                            .add(left.name, left.typ)
                            .add(right.name, right.typ),
                    ));
                    pending.push((value, env));
                    continue;
                }
                Expr::Orbit(_, turns, seed, bind, next) => {
                    pending.push((next, env.clone().add(bind.name, bind.typ)));
                    pending.push((seed, env.clone()));
                    if let Some(turns) = turns {
                        pending.push((turns, env));
                    }
                    continue;
                }
                Expr::Use(value) => {
                    let mut values = vec![value.arg];
                    values.extend(value.caps);
                    values.push(value.body);
                    values
                }
                _ => children(&self.ast.nodes, id),
            };
            pending.extend(values.into_iter().rev().map(|id| (id, env.clone())));
        }
        false
    }
}
