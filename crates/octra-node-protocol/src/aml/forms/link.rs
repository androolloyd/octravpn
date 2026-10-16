// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, error, evidence, located, modes, named, Elaborator, Result};
use std::collections::BTreeSet;
#[derive(Clone, Debug)]
pub struct Linked {
    pub ast: ast::Ast,
    pub direct: Vec<ast::Name>,
    pub calls: Vec<(ast::Name, evidence::Evidence)>,
}
fn lower(nodes: &mut ast::Nodes, form: &ast::Form) -> ast::Function {
    let result = nodes.stmt(ast::Stmt::Return(Some(form.body)));
    let body = vec![nodes.stmt(ast::Stmt::Located(form.line, form.column, result))];
    ast::Function {
        name: form.name.clone(),
        params: form
            .params
            .iter()
            .map(|param| ast::Param {
                name: param.name.clone(),
                typ: param.typ,
                refine: None,
            })
            .collect(),
        ret: form.ret,
        view: form.marks.iter().all(|mark| match mark.atom {
            ast::Atom::Write(_) | ast::Atom::Close(_) => false,
            ast::Atom::Emit(_) => !form.public,
            ast::Atom::Read(_) | ast::Atom::Fail(_) => true,
        }),
        pure: form.marks.is_empty(),
        payable: false,
        nonreentrant: false,
        visibility: if form.public {
            ast::Visibility::Public
        } else {
            ast::Visibility::Internal
        },
        body,
    }
}
/// Link all forms only after checking their bodies, call sites, and transitive
/// effect modes. Return a new AST so a failure cannot partially lower its input.
pub fn link(ast: &ast::Ast) -> Result<Linked> {
    if !ast.contract.forms.is_empty() && ast.contract.declaration != ast::Declaration::Program {
        return Err(error(b"form declarations require Program"));
    }
    let mut seen = BTreeSet::new();
    for name in ast
        .contract
        .functions
        .iter()
        .map(|function| &function.name)
        .chain(ast.contract.forms.iter().map(|form| &form.name))
    {
        if !seen.insert(name) {
            return Err(named(b"callable name is repeated = ", name));
        }
    }
    if let Some(form) = ast.contract.forms.iter().find(|form| {
        form.public
            && !form.marks.is_empty()
            && matches!(ast.nodes.typ(form.ret), ast::Type::Tuple(_))
    }) {
        return Err(located(
            form.line,
            form.column,
            b"public main effect result has no proved ABI = tuple",
        ));
    }
    let mut elaborator = Elaborator::new(ast);
    for form in &ast.contract.forms {
        elaborator.build(&form.name)?;
    }
    if let Some(constructor) = &ast.contract.constructor {
        elaborator.check_function(constructor)?;
    }
    for value in &ast.contract.consts {
        elaborator.check_expression(1, 1, &[], value.value)?;
    }
    for value in &ast.contract.invariants {
        elaborator.check_expression(1, 1, &[], value.expr)?;
    }
    for function in &ast.contract.functions {
        elaborator.check_function(function)?;
    }
    modes::check(ast)?;
    let direct = elaborator
        .cache
        .iter()
        .filter(|(_, checked)| checked.direct)
        .map(|(name, _)| name.clone())
        .collect();
    let mut calls = vec![];
    for form in &ast.contract.forms {
        if form.marks.is_empty() {
            continue;
        }
        let checked = elaborator
            .cache
            .get(&form.name)
            .cloned()
            .ok_or_else(|| named(b"direct form is absent = ", &form.name))?;
        calls.push((form.name.clone(), elaborator.evidence(form, &checked)?));
    }
    let mut linked = ast.clone();
    for form in &ast.contract.forms {
        linked
            .contract
            .functions
            .push(lower(&mut linked.nodes, form));
    }
    Ok(Linked {
        ast: linked,
        direct,
        calls,
    })
}
