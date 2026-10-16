// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Source_abi preserves structured type names and constructor/parameter names.
use super::{Ast, Nodes, Type, TypeId, Visibility};
use crate::transaction::json_string;
pub fn type_name(nodes: &Nodes, root: TypeId) -> Vec<u8> {
    enum Task {
        Type(TypeId),
        Text(&'static [u8]),
    }
    let mut pending = vec![Task::Type(root)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Task::Text(text) => out.extend_from_slice(text),
            Task::Type(id) => match nodes.typ(id) {
                Type::Map(key, item) => {
                    pending.extend([
                        Task::Type(*item),
                        Task::Text(b"]"),
                        Task::Type(*key),
                        Task::Text(b"map["),
                    ]);
                }
                Type::List(item) | Type::Option(item) => {
                    let prefix: &[u8] = if matches!(nodes.typ(id), Type::List(_)) {
                        b"list["
                    } else {
                        b"option["
                    };
                    out.extend_from_slice(prefix);
                    pending.push(Task::Text(b"]"));
                    pending.push(Task::Type(*item));
                }
                Type::Tuple(items) => {
                    out.push(b'(');
                    pending.push(Task::Text(b")"));
                    for (index, item) in items.iter().enumerate().rev() {
                        pending.push(Task::Type(*item));
                        if index > 0 {
                            pending.push(Task::Text(b","));
                        }
                    }
                }
                typ => out.extend_from_slice(typ.name()),
            },
        }
    }
    out
}
fn boolean(out: &mut Vec<u8>, value: bool) {
    out.extend_from_slice(if value { b"true" } else { b"false" });
}
fn method(out: &mut Vec<u8>, nodes: &Nodes, function: &super::super::ast::Function) {
    out.extend_from_slice(b"{\"name\":");
    json_string(out, &function.name);
    out.extend_from_slice(b",\"inputs\":[");
    for (index, param) in function.params.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, &type_name(nodes, param.typ));
    }
    out.extend_from_slice(b"],\"input_names\":[");
    for (index, param) in function.params.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(out, &param.name);
    }
    out.extend_from_slice(b"],\"output\":");
    json_string(out, &type_name(nodes, function.ret));
    out.extend_from_slice(b",\"view\":");
    boolean(out, function.view || function.pure);
    out.extend_from_slice(b",\"payable\":");
    boolean(out, function.payable);
    out.push(b'}');
}
pub fn encode(ast: &Ast) -> Vec<u8> {
    let mut out = b"{\"declaration\":".to_vec();
    json_string(&mut out, ast.contract.declaration.name());
    out.extend_from_slice(b",\"constructor\":");
    if let Some(constructor) = &ast.contract.constructor {
        method(&mut out, &ast.nodes, constructor);
    } else {
        out.extend_from_slice(b"null");
    }
    out.extend_from_slice(b",\"functions\":[");
    for (index, function) in ast
        .contract
        .functions
        .iter()
        .filter(|function| function.visibility == Visibility::Public)
        .enumerate()
    {
        if index > 0 {
            out.push(b',');
        }
        method(&mut out, &ast.nodes, function);
    }
    out.extend_from_slice(b"],\"events\":[");
    for (index, event) in ast.contract.events.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        json_string(&mut out, &event.name);
        out.extend_from_slice(b",\"fields\":[");
        for (index, (name, typ, indexed)) in event.fields.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"name\":");
            json_string(&mut out, name);
            out.extend_from_slice(b",\"type\":");
            json_string(&mut out, &type_name(&ast.nodes, *typ));
            out.extend_from_slice(b",\"indexed\":");
            boolean(&mut out, *indexed);
            out.push(b'}');
        }
        out.extend_from_slice(b"]}");
    }
    out.extend_from_slice(b"]}");
    out
}
