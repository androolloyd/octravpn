// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    analysis, blocks, uniq, Analysis, BTreeMap, Expr, ExprId, Function, Name, Nodes, Stmt, StmtId,
    Summary, Type,
};
fn expression_calls(nodes: &Nodes, roots: &[ExprId]) -> Vec<Name> {
    let mut pending: Vec<_> = roots.iter().rev().copied().collect();
    let mut calls = vec![];
    while let Some(id) = pending.pop() {
        let children = match nodes.expression(id) {
            Expr::Call(name, args) => {
                calls.push(name.clone());
                args.clone()
            }
            Expr::Use(value) => {
                calls.push(value.name.clone());
                let mut args = vec![value.arg];
                args.extend(&value.caps);
                args.push(value.body);
                args
            }
            _ => analysis::children(nodes, id),
        };
        pending.extend(children.into_iter().rev());
    }
    calls
}
pub(super) fn direct_calls(nodes: &Nodes, body: &[StmtId]) -> Vec<Name> {
    let mut calls = vec![];
    for id in blocks(nodes, body) {
        let expressions = match nodes.statement(id) {
            Stmt::Let(_, _, value)
            | Stmt::Assign(_, value)
            | Stmt::FieldSet(_, value)
            | Stmt::IndexSet(_, _, value)
            | Stmt::Return(Some(value))
            | Stmt::Assert(value)
            | Stmt::Require(value, _)
            | Stmt::StoragePathSet(_, _, _, value)
            | Stmt::IndexFieldSet(_, _, _, value)
            | Stmt::LetTuple(_, value)
            | Stmt::Expr(value) => vec![*value],
            Stmt::IndexUpdate(_, keys, _, value)
            | Stmt::StoragePathUpdate(_, keys, _, _, value) => {
                let mut values = vec![*value];
                values.extend(keys);
                values
            }
            Stmt::Emit(_, args) | Stmt::FieldCall(_, _, args) | Stmt::RevertError(_, args) => {
                args.clone()
            }
            Stmt::If(cond, _, _) | Stmt::While(cond, _) | Stmt::Match(cond, _) => vec![*cond],
            Stmt::For(_, first, last, _) => vec![*first, *last],
            Stmt::Return(None) | Stmt::ForEach(..) | Stmt::Located(..) => vec![],
        };
        calls.extend(expression_calls(nodes, &expressions));
    }
    calls
}
pub(super) fn direct_writes(nodes: &Nodes, body: &[StmtId]) -> Vec<Name> {
    blocks(nodes, body)
        .into_iter()
        .filter_map(|id| match nodes.statement(id) {
            Stmt::FieldSet(field, _)
            | Stmt::IndexSet(field, _, _)
            | Stmt::IndexUpdate(field, _, _, _)
            | Stmt::StoragePathSet(field, _, _, _)
            | Stmt::StoragePathUpdate(field, _, _, _, _)
            | Stmt::IndexFieldSet(field, _, _, _) => Some(field.clone()),
            _ => None,
        })
        .collect()
}
enum State {
    Visiting,
    Complete(Vec<Name>),
}
enum Task {
    Visit(Name),
    Finish(Name, Vec<Name>, usize),
}
fn transitive(
    analysis: &Analysis<'_>,
    functions: &BTreeMap<Name, &Function>,
    states: &mut BTreeMap<Name, State>,
    name: &[u8],
) -> Vec<Name> {
    let mut pending = vec![Task::Visit(name.to_vec())];
    let mut values = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Task::Visit(name) => {
                if let Some(state) = states.get(&name) {
                    values.push(match state {
                        State::Visiting => vec![],
                        State::Complete(writes) => writes.clone(),
                    });
                    continue;
                }
                let Some(function) = functions.get(&name) else {
                    values.push(vec![]);
                    continue;
                };
                states.insert(name.clone(), State::Visiting);
                let direct = direct_writes(&analysis.ast.nodes, &function.body);
                let calls: Vec<_> = direct_calls(&analysis.ast.nodes, &function.body)
                    .into_iter()
                    .filter(|name| functions.contains_key(name))
                    .collect();
                pending.push(Task::Finish(name, direct, calls.len()));
                pending.extend(calls.into_iter().rev().map(Task::Visit));
            }
            Task::Finish(name, mut direct, count) => {
                let nested = values.split_off(values.len() - count);
                direct.extend(nested.into_iter().flatten());
                let writes = uniq(direct);
                states.insert(name, State::Complete(writes.clone()));
                values.push(writes);
            }
        }
    }
    values.pop().expect("transitive safety writes")
}
pub(super) fn summarize(analysis: &Analysis<'_>, functions: &[&Function]) -> Vec<Summary> {
    let by_name = functions
        .iter()
        .map(|function| (function.name.clone(), *function))
        .collect();
    let mut states = BTreeMap::new();
    functions
        .iter()
        .map(|function| {
            let direct_writes = direct_writes(&analysis.ast.nodes, &function.body);
            let transitive_writes = transitive(analysis, &by_name, &mut states, &function.name);
            Summary {
                name: function.name.clone(),
                visibility: function.visibility,
                direct_calls: uniq(direct_calls(&analysis.ast.nodes, &function.body)),
                direct_writes: uniq(direct_writes),
                value_writes: uniq(
                    transitive_writes
                        .iter()
                        .filter(|name| analysis.value_storage(name))
                        .cloned(),
                ),
                transitive_writes,
                signed_params: function
                    .params
                    .iter()
                    .filter(|param| matches!(analysis.host.typ(param.typ), Type::Int))
                    .map(|param| param.name.clone())
                    .collect(),
            }
        })
        .collect()
}
