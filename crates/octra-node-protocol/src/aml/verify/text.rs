// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{BinOp, Binding, Expr, ExprId, Mult, Nodes, UnOp};
use crate::native_exception::quoted;
fn binary(op: BinOp) -> &'static [u8] {
    match op {
        BinOp::Add => b" + ",
        BinOp::Sub => b" - ",
        BinOp::Mul => b" * ",
        BinOp::Div => b" / ",
        BinOp::Mod => b" % ",
        BinOp::Eq => b" == ",
        BinOp::Neq => b" != ",
        BinOp::Lt => b" < ",
        BinOp::Gt => b" > ",
        BinOp::Le => b" <= ",
        BinOp::Ge => b" >= ",
        BinOp::And => b" && ",
        BinOp::Or => b" || ",
    }
}
fn mult(value: Mult) -> &'static [u8] {
    match value {
        Mult::Once => b"once",
        Mult::Many => b"many",
    }
}
enum Task {
    Expr(ExprId),
    Text(Vec<u8>),
}
fn text(pending: &mut Vec<Task>, value: impl AsRef<[u8]>) {
    pending.push(Task::Text(value.as_ref().to_vec()));
}
fn list(pending: &mut Vec<Task>, values: &[ExprId]) {
    for (index, value) in values.iter().enumerate().rev() {
        pending.push(Task::Expr(*value));
        if index > 0 {
            text(pending, b",");
        }
    }
}
fn binding(nodes: &Nodes, bind: &Binding) -> Vec<u8> {
    [
        mult(bind.mult),
        b" ",
        &bind.name,
        b": ",
        nodes.typ(bind.typ).name(),
    ]
    .concat()
}
pub fn expression_text(nodes: &Nodes, root: ExprId) -> Vec<u8> {
    let mut pending = vec![Task::Expr(root)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        let id = match task {
            Task::Text(text) => {
                out.extend(text);
                continue;
            }
            Task::Expr(id) => id,
        };
        match nodes.expression(id) {
            Expr::Int(value) => out.extend(value.to_string().as_bytes()),
            Expr::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
            Expr::String(value) => quoted(&mut out, value),
            Expr::Var(name) | Expr::Field(name) => out.extend_from_slice(name),
            Expr::Index(name, keys) => {
                out.extend(name);
                out.push(b'[');
                text(&mut pending, b"]");
                list(&mut pending, keys);
            }
            Expr::Binop(op, left, right) => {
                pending.push(Task::Expr(*right));
                text(&mut pending, binary(*op));
                pending.push(Task::Expr(*left));
            }
            Expr::Unop(op, value) => {
                out.extend_from_slice(match op {
                    UnOp::Neg => b"-",
                    UnOp::Not => b"!",
                });
                pending.push(Task::Expr(*value));
            }
            Expr::Caller => out.extend_from_slice(b"caller"),
            Expr::Origin => out.extend_from_slice(b"origin"),
            Expr::SelfAddr => out.extend_from_slice(b"self_addr"),
            Expr::Epoch => out.extend_from_slice(b"epoch"),
            Expr::EpochTime => out.extend_from_slice(b"epoch_time"),
            Expr::Value => out.extend_from_slice(b"value"),
            Expr::TreeHash => out.extend_from_slice(b"tree_hash"),
            Expr::NodeId => out.extend_from_slice(b"node_id"),
            Expr::TxHash => out.extend_from_slice(b"tx_hash"),
            Expr::Balance(value) => {
                out.extend_from_slice(b"balance(");
                text(&mut pending, b")");
                pending.push(Task::Expr(*value));
            }
            Expr::Call(name, args) => {
                out.extend(name);
                out.push(b'(');
                text(&mut pending, b")");
                list(&mut pending, args);
            }
            Expr::Array(values) | Expr::Tuple(values) => {
                let tuple = matches!(nodes.expression(id), Expr::Tuple(_));
                out.push(if tuple { b'(' } else { b'[' });
                text(&mut pending, if tuple { b")" } else { b"]" });
                list(&mut pending, values);
            }
            Expr::StoragePath(field, keys, path) => {
                out.extend(field);
                out.push(b'[');
                let mut suffix = b"].".to_vec();
                for (index, name) in path.iter().enumerate() {
                    if index > 0 {
                        suffix.push(b'.');
                    }
                    suffix.extend(name);
                }
                text(&mut pending, suffix);
                list(&mut pending, keys);
            }
            Expr::FieldProp(field, prop) | Expr::EnumVariant(field, prop) => {
                out.extend(field);
                out.push(b'.');
                out.extend(prop);
            }
            Expr::IndexField(field, keys, prop) => {
                out.extend(field);
                out.push(b'[');
                text(&mut pending, [b"].".as_slice(), prop].concat());
                list(&mut pending, keys);
            }
            Expr::Ternary(cond, yes, no) => {
                pending.push(Task::Expr(*no));
                text(&mut pending, b" : ");
                pending.push(Task::Expr(*yes));
                text(&mut pending, b" ? ");
                pending.push(Task::Expr(*cond));
            }
            Expr::Equal(typ, left, right) => {
                out.extend_from_slice(b"equal[");
                out.extend(nodes.typ(*typ).name());
                out.extend_from_slice(b"](");
                text(&mut pending, b")");
                list(&mut pending, &[*left, *right]);
            }
            Expr::Let(bind, value, body) => {
                out.extend_from_slice(b"let ");
                out.extend(binding(nodes, bind));
                out.extend_from_slice(b" = ");
                pending.push(Task::Expr(*body));
                text(&mut pending, b" in ");
                pending.push(Task::Expr(*value));
            }
            Expr::Split(value, left, right, body) => {
                out.extend_from_slice(b"split ");
                pending.push(Task::Expr(*body));
                text(
                    &mut pending,
                    [
                        b" as ".as_slice(),
                        &binding(nodes, left),
                        b", ",
                        &binding(nodes, right),
                        b" in ",
                    ]
                    .concat(),
                );
                pending.push(Task::Expr(*value));
            }
            Expr::Orbit(count, turns, seed, bind, body) => {
                out.extend_from_slice(b"orbit[");
                out.extend(count.get().to_string().as_bytes());
                pending.push(Task::Expr(*body));
                text(
                    &mut pending,
                    [b" with ".as_slice(), &binding(nodes, bind), b" => "].concat(),
                );
                pending.push(Task::Expr(*seed));
                text(&mut pending, b"] from ");
                if let Some(turns) = turns {
                    pending.push(Task::Expr(*turns));
                    text(&mut pending, b",");
                }
            }
            Expr::Action(atom, value) => {
                out.extend_from_slice(b"action[");
                out.extend(super::super::core::atom_text(*atom));
                out.extend_from_slice(b"](");
                text(&mut pending, b")");
                pending.push(Task::Expr(*value));
            }
            Expr::Use(value) => {
                out.extend_from_slice(b"use ");
                out.extend(&value.name);
                out.push(b'(');
                pending.push(Task::Expr(value.body));
                text(&mut pending, b") in ");
                let mut args = value.caps.clone();
                args.push(value.arg);
                list(&mut pending, &args);
            }
        }
    }
    out
}
