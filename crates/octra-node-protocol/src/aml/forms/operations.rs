// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, located, syn, term, Core, Elaborator, Result};
impl Elaborator<'_> {
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn binary(&mut self, op: ast::BinOp, left: Core, right: Core) -> Result<Core> {
        use ast::BinOp as B;
        use syn::Term as T;
        let integer = self.syntax.add_type(syn::Type::Int);
        let boolean = self.syntax.add_type(syn::Type::Bool);
        let (expected, reason, out) = match op {
            B::Add => (integer, "direct form addition requires int", integer),
            B::Sub => (integer, "direct form subtraction requires int", integer),
            B::Mul => (integer, "direct form multiplication requires int", integer),
            B::Div => (integer, "direct form division requires int", integer),
            B::Mod => (integer, "direct form remainder requires int", integer),
            B::Lt | B::Le | B::Gt | B::Ge => {
                (integer, "direct form comparison requires int", boolean)
            }
            B::Eq | B::Neq => (left.typ, "direct form equality type differs", boolean),
            B::And => (boolean, "direct form conjunction requires bool", boolean),
            B::Or => (boolean, "direct form disjunction requires bool", boolean),
        };
        self.same(expected, left.typ, reason)?;
        self.same(expected, right.typ, reason)?;
        let (term, extra) = match op {
            B::Add => (T::Add(left.term, right.term), 1),
            B::Sub => (T::Sub(left.term, right.term), 1),
            B::Mul => (T::Mul(left.term, right.term), 1),
            B::Div => (T::Div(left.term, right.term), 1),
            B::Mod => (T::Mod(left.term, right.term), 1),
            B::Lt => (T::Cmp(term::Relation::Lt, left.term, right.term), 1),
            B::Le => (T::Cmp(term::Relation::Le, left.term, right.term), 1),
            B::Gt => (T::Cmp(term::Relation::Gt, left.term, right.term), 1),
            B::Ge => (T::Cmp(term::Relation::Ge, left.term, right.term), 1),
            B::Eq => (T::Eq(left.typ, left.term, right.term), 1),
            B::Neq => {
                let equal = self.syntax.add_term(T::Eq(left.typ, left.term, right.term));
                let no = self.syntax.add_term(T::Bool(false));
                (T::Eq(boolean, equal, no), 3)
            }
            B::And => {
                let no = self.syntax.add_term(T::Bool(false));
                (T::If(left.term, right.term, no), 2)
            }
            B::Or => {
                let yes = self.syntax.add_term(T::Bool(true));
                (T::If(left.term, yes, right.term), 2)
            }
        };
        self.node(
            term,
            out,
            left.nodes + right.nodes + extra,
            left.depth.max(right.depth),
            left.calls.max(right.calls),
        )
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn unary(&mut self, op: Option<ast::UnOp>, value: Core) -> Result<Core> {
        let (typ, reason) = match op {
            Some(ast::UnOp::Not) => (syn::Type::Bool, "direct form negation requires bool"),
            Some(ast::UnOp::Neg) => (syn::Type::Int, "direct form negation requires int"),
            None => (syn::Type::Int, "direct form absolute value requires int"),
        };
        let typ = self.syntax.add_type(typ);
        self.same(typ, value.typ, reason)?;
        let term = match op {
            Some(ast::UnOp::Not) => {
                let no = self.syntax.add_term(syn::Term::Bool(false));
                syn::Term::Eq(typ, value.term, no)
            }
            Some(ast::UnOp::Neg) => syn::Term::Neg(value.term),
            None => syn::Term::Abs(value.term),
        };
        // Oct_form counts unary Not as one metadata node, despite its literal.
        self.node(term, typ, value.nodes + 1, value.depth, value.calls)
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn branch(
        &mut self,
        location: Option<(usize, usize)>,
        guard: Core,
        yes: Core,
        no: Core,
    ) -> Result<Core> {
        let boolean = self.syntax.add_type(syn::Type::Bool);
        let (guard_reason, branch_reason) = match location {
            Some((line, column)) => (
                located(line, column, b"direct pure function guard requires bool").0,
                located(line, column, b"direct pure function branch type differs").0,
            ),
            None => (
                b"direct form guard requires bool".to_vec(),
                b"direct form branch type differs".to_vec(),
            ),
        };
        self.same(boolean, guard.typ, guard_reason)?;
        self.same(yes.typ, no.typ, branch_reason)?;
        let typ = yes.typ;
        let nodes = guard.nodes + yes.nodes + no.nodes + 1;
        let depth = guard.depth.max(yes.depth).max(no.depth);
        let calls = guard.calls.max(yes.calls).max(no.calls);
        self.node(
            syn::Term::If(guard.term, yes.term, no.term),
            typ,
            nodes,
            depth,
            calls,
        )
    }
}
