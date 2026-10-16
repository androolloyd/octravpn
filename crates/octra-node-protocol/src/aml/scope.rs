// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Oct_scope name resolution and pure-loop index checks.
use super::ast::{Ast, Expr, ExprId, Name, Nodes, Stmt, StmtId};
use std::{collections::BTreeSet, sync::Arc};
#[derive(Clone)]
struct Env {
    values: Arc<BTreeSet<Name>>,
    calls: Arc<BTreeSet<Name>>,
}
impl Env {
    fn add(&mut self, name: Name) {
        Arc::make_mut(&mut self.values).insert(name);
    }
}
enum ExprTask {
    Visit(ExprId, Env),
    Finish(Expr, usize),
}
fn expression(nodes: &mut Nodes, env: &Env, root: ExprId) -> ExprId {
    let mut tasks = vec![ExprTask::Visit(root, env.clone())];
    let mut results = vec![];
    while let Some(task) = tasks.pop() {
        match task {
            ExprTask::Visit(id, env) => {
                let mut expr = nodes.expression(id).clone();
                match &expr {
                    Expr::Var(name) if !env.values.contains(name) => {
                        let builtin = match name.as_slice() {
                            b"epoch" => Some(Expr::Epoch),
                            b"epoch_time" => Some(Expr::EpochTime),
                            b"value" => Some(Expr::Value),
                            _ => None,
                        };
                        results.push(builtin.map_or(id, |expr| nodes.expr(expr)));
                        continue;
                    }
                    Expr::Call(name, args)
                        if name == b"balance" && args.len() == 1 && !env.calls.contains(name) =>
                    {
                        expr = Expr::Balance(args[0]);
                    }
                    Expr::Index(..)
                    | Expr::Binop(..)
                    | Expr::Unop(..)
                    | Expr::Balance(_)
                    | Expr::Call(..)
                    | Expr::Array(_)
                    | Expr::Tuple(_)
                    | Expr::StoragePath(..)
                    | Expr::IndexField(..)
                    | Expr::Ternary(..)
                    | Expr::Use(_) => (),
                    // Direct let/split/orbit/action terms are intentionally
                    // opaque to Oct_scope; their own elaborator resolves them.
                    _ => {
                        results.push(id);
                        continue;
                    }
                }
                let bind = match &expr {
                    Expr::Use(value) => Some(value.binding.name.clone()),
                    _ => None,
                };
                let mut children = vec![];
                expr.map_exprs(&mut |id| {
                    children.push(id);
                    id
                });
                let count = children.len();
                tasks.push(ExprTask::Finish(expr, count));
                for (index, child) in children.into_iter().enumerate().rev() {
                    let mut scope = env.clone();
                    if index + 1 == count {
                        if let Some(name) = &bind {
                            scope.add(name.clone());
                        }
                    }
                    tasks.push(ExprTask::Visit(child, scope));
                }
            }
            ExprTask::Finish(mut expr, count) => {
                let mut children = results.split_off(results.len() - count).into_iter();
                expr.map_exprs(&mut |_| children.next().expect("resolved expression child"));
                results.push(nodes.expr(expr));
            }
        }
    }
    results.pop().expect("resolved expression root")
}
enum Output {
    Statement(StmtId, Env),
    Block(Vec<StmtId>),
}
enum Task {
    Block(Vec<StmtId>, Env),
    Statement(StmtId, Env),
    Next(std::vec::IntoIter<StmtId>, Vec<StmtId>),
    Finish(Stmt, Vec<(usize, usize)>, Env, usize),
}
fn block(nodes: &mut Nodes, env: &Env, body: Vec<StmtId>) -> Vec<StmtId> {
    let mut tasks = vec![Task::Block(body, env.clone())];
    let mut results = vec![];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Block(body, env) => {
                let mut remaining = body.into_iter();
                match remaining.next() {
                    None => results.push(Output::Block(vec![])),
                    Some(id) => {
                        tasks.push(Task::Next(remaining, vec![]));
                        tasks.push(Task::Statement(id, env));
                    }
                }
            }
            Task::Next(mut remaining, mut out) => {
                let Some(Output::Statement(id, env)) = results.pop() else {
                    unreachable!("resolved block item")
                };
                out.push(id);
                match remaining.next() {
                    None => results.push(Output::Block(out)),
                    Some(id) => {
                        tasks.push(Task::Next(remaining, out));
                        tasks.push(Task::Statement(id, env));
                    }
                }
            }
            Task::Statement(id, env) => {
                let mut spans = vec![];
                let mut stmt = nodes.statement(id).clone();
                while let Stmt::Located(line, column, inner) = stmt {
                    spans.push((line, column));
                    stmt = nodes.statement(inner).clone();
                }
                stmt.map_exprs(&mut |id| expression(nodes, &env, id));
                let mut next = env.clone();
                match &stmt {
                    Stmt::Let(name, ..) => next.add(name.clone()),
                    Stmt::LetTuple(names, _) => {
                        for name in names {
                            next.add(name.clone());
                        }
                    }
                    _ => (),
                }
                let mut child_env = env;
                if let Stmt::For(name, ..) | Stmt::ForEach(name, ..) = &stmt {
                    child_env.add(name.clone());
                }
                let mut children = vec![];
                stmt.blocks(&mut |body| children.push(body.clone()));
                let count = children.len();
                tasks.push(Task::Finish(stmt, spans, next, count));
                for body in children.into_iter().rev() {
                    tasks.push(Task::Block(body, child_env.clone()));
                }
            }
            Task::Finish(mut stmt, spans, env, count) => {
                let mut children = results.split_off(results.len() - count).into_iter();
                stmt.blocks(&mut |body| {
                    let Some(Output::Block(child)) = children.next() else {
                        unreachable!("resolved child block")
                    };
                    *body = child;
                });
                let mut id = nodes.stmt(stmt);
                for (line, column) in spans.into_iter().rev() {
                    id = nodes.stmt(Stmt::Located(line, column, id));
                }
                results.push(Output::Statement(id, env));
            }
        }
    }
    let Some(Output::Block(body)) = results.pop() else {
        unreachable!("resolved root block")
    };
    body
}
pub fn resolve(mut ast: Ast) -> Ast {
    let root = Env {
        values: Arc::new(
            ast.contract
                .consts
                .iter()
                .map(|value| value.name.clone())
                .collect(),
        ),
        calls: Arc::new(
            ast.contract
                .functions
                .iter()
                .map(|value| value.name.clone())
                .chain(ast.contract.forms.iter().map(|value| value.name.clone()))
                .chain(
                    ast.contract
                        .interfaces
                        .iter()
                        .flat_map(|value| value.methods.iter().map(|method| method.name.clone())),
                )
                .collect(),
        ),
    };
    for value in &mut ast.contract.consts {
        value.value = expression(&mut ast.nodes, &root, value.value);
    }
    for value in &mut ast.contract.invariants {
        value.expr = expression(&mut ast.nodes, &root, value.expr);
    }
    for function in ast
        .contract
        .constructor
        .iter_mut()
        .chain(ast.contract.functions.iter_mut())
    {
        let mut env = root.clone();
        for param in &function.params {
            env.add(param.name.clone());
        }
        function.body = block(&mut ast.nodes, &env, std::mem::take(&mut function.body));
    }
    for form in &mut ast.contract.forms {
        let mut env = root.clone();
        for param in &form.params {
            env.add(param.name.clone());
        }
        form.body = expression(&mut ast.nodes, &env, form.body);
    }
    ast
}

struct LoopFrame {
    body: std::vec::IntoIter<StmtId>,
    indices: BTreeSet<Name>,
    line: usize,
    column: usize,
}
/// Returns the native diagnostic bytes; this check is invoked by compilation,
/// rather than turning an otherwise parsable program into a syntax error.
pub fn check_loops(ast: &Ast) -> std::result::Result<(), Vec<u8>> {
    for function in ast
        .contract
        .functions
        .iter()
        .filter(|function| function.pure)
    {
        let mut frames = vec![LoopFrame {
            body: function.body.clone().into_iter(),
            indices: BTreeSet::new(),
            line: 0,
            column: 0,
        }];
        while let Some(frame) = frames.last_mut() {
            let Some(id) = frame.body.next() else {
                frames.pop();
                continue;
            };
            let (mut line, mut column) = (frame.line, frame.column);
            let mut stmt = ast.nodes.statement(id);
            while let Stmt::Located(next_line, next_column, inner) = stmt {
                line = *next_line;
                column = *next_column;
                stmt = ast.nodes.statement(*inner);
            }
            match stmt {
                Stmt::Let(name, ..) => {
                    frame.indices.remove(name);
                }
                Stmt::LetTuple(names, _) => {
                    for name in names {
                        frame.indices.remove(name);
                    }
                }
                Stmt::Assign(name, _) if frame.indices.contains(name) => {
                    return Err([
                        format!("line {line} column {column}: pure loop index is immutable = ")
                            .as_bytes(),
                        name,
                    ]
                    .concat());
                }
                _ => {
                    let mut indices = frame.indices.clone();
                    match stmt {
                        Stmt::For(name, ..) => {
                            indices.insert(name.clone());
                        }
                        Stmt::ForEach(name, ..) => {
                            indices.remove(name);
                        }
                        _ => (),
                    }
                    let mut stmt = stmt.clone();
                    let mut children = vec![];
                    stmt.blocks(&mut |body| children.push(body.clone()));
                    for body in children.into_iter().rev() {
                        frames.push(LoopFrame {
                            body: body.into_iter(),
                            indices: indices.clone(),
                            line,
                            column,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}
