// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Transitive effect-form reachability through ordinary function calls.
use super::{ast, error, located, types, BTreeMap, Result};
use std::collections::BTreeSet;
#[derive(Clone, Default)]
struct Row {
    forms: BTreeSet<ast::Name>,
    calls: BTreeSet<ast::Name>,
}
enum Job {
    Expression(ast::ExprId),
    Statement(ast::StmtId),
}
fn references(ast: &ast::Ast, roots: Vec<Job>) -> Row {
    let mut pending = roots;
    let mut expressions = BTreeSet::new();
    let mut statements = BTreeSet::new();
    let mut row = Row::default();
    while let Some(job) = pending.pop() {
        match job {
            Job::Expression(id) => {
                if !expressions.insert(id) {
                    continue;
                }
                let mut expr = ast.nodes.expression(id).clone();
                match &expr {
                    ast::Expr::Use(value) => {
                        row.forms.insert(value.name.clone());
                    }
                    ast::Expr::Call(name, _)
                        if ast
                            .contract
                            .functions
                            .iter()
                            .any(|function| &function.name == name) =>
                    {
                        row.calls.insert(name.clone());
                    }
                    _ => (),
                }
                expr.map_exprs(&mut |id| {
                    pending.push(Job::Expression(id));
                    id
                });
            }
            Job::Statement(id) => {
                if !statements.insert(id) {
                    continue;
                }
                let mut statement = ast.nodes.statement(id).clone();
                if let ast::Stmt::Located(_, _, child) = statement {
                    pending.push(Job::Statement(child));
                    continue;
                }
                statement.map_exprs(&mut |id| {
                    pending.push(Job::Expression(id));
                    id
                });
                statement
                    .blocks(&mut |body| pending.extend(body.iter().map(|id| Job::Statement(*id))));
            }
        }
    }
    row
}
fn write(mark: &ast::FormMark) -> bool {
    matches!(mark.atom, ast::Atom::Write(_) | ast::Atom::Close(_))
}
fn first<'a>(
    ast: &'a ast::Ast,
    forms: &BTreeSet<ast::Name>,
    select: impl Fn(&ast::FormMark) -> bool,
) -> Option<&'a ast::Form> {
    ast.contract
        .forms
        .iter()
        .find(|form| forms.contains(&form.name) && form.marks.iter().any(&select))
}
pub(super) fn check(ast: &ast::Ast) -> Result<()> {
    let mut rows: BTreeMap<_, _> = ast
        .contract
        .functions
        .iter()
        .map(|function| {
            (
                function.name.clone(),
                references(
                    ast,
                    function.body.iter().map(|id| Job::Statement(*id)).collect(),
                ),
            )
        })
        .collect();
    loop {
        let mut next = rows.clone();
        let mut changed = false;
        for (name, row) in &rows {
            let output = &mut next.get_mut(name).expect("function reachability row").forms;
            for target in &row.calls {
                if let Some(called) = rows.get(target) {
                    let before = output.len();
                    output.extend(called.forms.iter().cloned());
                    changed |= before != output.len();
                }
            }
        }
        rows = next;
        if !changed {
            break;
        }
    }
    for function in &ast.contract.functions {
        let forms = &rows
            .get(&function.name)
            .expect("function reachability row")
            .forms;
        let rejected = if function.pure {
            first(ast, forms, |_| true)
        } else if function.view {
            first(ast, forms, write)
        } else {
            None
        };
        if let Some(form) = rejected {
            let reason: &[u8] = if function.pure {
                b"pure function form marks are not empty = "
            } else {
                b"view function form writes storage = "
            };
            return Err(located(
                types::block_line(&ast.nodes, &function.body),
                1,
                [reason, &form.name].concat(),
            ));
        }
    }
    let check_static = |label: &[u8], id| -> Result<()> {
        let row = references(ast, vec![Job::Expression(id)]);
        let mut forms = row.forms;
        for called in row.calls {
            if let Some(row) = rows.get(&called) {
                forms.extend(row.forms.iter().cloned());
            }
        }
        if let Some(form) = first(ast, &forms, |_| true) {
            Err(error(
                [label, b" form marks are not empty = ", &form.name].concat(),
            ))
        } else {
            Ok(())
        }
    };
    for value in &ast.contract.consts {
        check_static(b"constant", value.value)?;
    }
    for value in &ast.contract.invariants {
        check_static(b"invariant", value.expr)?;
    }
    Ok(())
}
