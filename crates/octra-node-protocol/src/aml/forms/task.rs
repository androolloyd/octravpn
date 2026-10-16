// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, core, syn, Arc, Checked, Core, Env};
pub(super) enum Source {
    Expression(ast::ExprId),
    Block(Arc<Owner>),
}
pub(super) struct Owner {
    pub name: ast::Name,
    pub line: usize,
    pub body: Arc<[ast::StmtId]>,
}
// Native bounded task/snapshot records remain inline without extra allocations.
#[allow(clippy::large_enum_variant)]
pub(super) enum Task {
    Expression(ast::ExprId, Env),
    Flow(Arc<Owner>, Arc<[ast::StmtId]>, usize, Env),
    Finish(Finish),
}
// Native bounded task/snapshot records remain inline without extra allocations.
#[allow(clippy::large_enum_variant)]
pub(super) enum Finish {
    Binary(ast::BinOp),
    Unary(ast::UnOp),
    Abs,
    Pair,
    Equal(syn::TypeId),
    Branch(Option<(usize, usize)>),
    Action(ast::Atom),
    LetStart(ast::Binding, ast::ExprId, Env),
    LetEnd(syn::Bind, Core, bool),
    SplitStart(ast::Binding, ast::Binding, ast::ExprId, Env),
    SplitEnd(syn::Bind, syn::Bind, Core),
    OrbitSeed(
        core::Natural,
        Option<ast::ExprId>,
        ast::Binding,
        ast::ExprId,
        Env,
    ),
    OrbitBody(core::Natural, Option<ast::ExprId>, syn::Bind, Core, Env),
    OrbitTurns(core::Natural, syn::Bind, Core, Core),
    Call(ast::Name, usize),
    UseArgs(ast::Use, Env),
    UseBody(Checked, syn::Bind, Vec<Core>),
    FlowLocal(
        Arc<Owner>,
        Arc<[ast::StmtId]>,
        usize,
        Env,
        ast::Name,
        Option<ast::TypeId>,
        usize,
        usize,
    ),
}
