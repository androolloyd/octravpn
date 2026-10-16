// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Oct_types compatibility and return-flow helpers.
use super::ast::{Nodes, Stmt, StmtId, Type, TypeId};
use std::collections::BTreeMap;
pub fn numeric(typ: &Type) -> bool {
    matches!(
        typ,
        Type::Int | Type::U64 | Type::U128 | Type::U256 | Type::Enum(_)
    )
}
pub fn text(typ: &Type) -> bool {
    matches!(typ, Type::String | Type::Address)
}
pub fn opaque(typ: &Type) -> bool {
    matches!(typ, Type::Cipher | Type::PubKey)
}
pub fn numeric_result(left: &Type, right: &Type) -> Type {
    if matches!(left, Type::U256) || matches!(right, Type::U256) {
        Type::U256
    } else if matches!(left, Type::U128) || matches!(right, Type::U128) {
        Type::U128
    } else if matches!(left, Type::U64) || matches!(right, Type::U64) {
        Type::U64
    } else {
        Type::Int
    }
}
/// Directional native compatibility, including option[void] as an actual value.
/// Interned IDs compare structurally within the caller's own syntax arena.
pub fn compatible(nodes: &Nodes, expected: TypeId, actual: TypeId) -> bool {
    let mut pending = vec![(expected, actual)];
    while let Some((expected, actual)) = pending.pop() {
        if expected == actual {
            continue;
        }
        let (expected, actual) = (nodes.typ(expected), nodes.typ(actual));
        if numeric(expected) && numeric(actual) {
            continue;
        }
        match (expected, actual) {
            (Type::Bytes, Type::String) | (Type::String, Type::Bytes) => (),
            (Type::Struct(left), Type::Enum(right)) | (Type::Enum(left), Type::Struct(right))
                if left == right => {}
            (Type::Option(_), Type::Option(right)) if matches!(nodes.typ(*right), Type::Void) => (),
            (Type::Option(left), Type::Option(right)) | (Type::List(left), Type::List(right)) => {
                pending.push((*left, *right));
            }
            (Type::Map(left_key, left_value), Type::Map(right_key, right_value)) => {
                pending.push((*left_value, *right_value));
                pending.push((*left_key, *right_key));
            }
            (Type::Tuple(left), Type::Tuple(right)) if left.len() == right.len() => {
                pending.extend(left.iter().copied().zip(right.iter().copied()).rev());
            }
            _ => return false,
        }
    }
    true
}

/// Arena builders only admit existing child IDs, so return-flow values can be
/// computed once in allocation order without recursing through else-if chains.
pub struct Returns(BTreeMap<StmtId, bool>);
impl Returns {
    pub fn new(nodes: &Nodes) -> Self {
        let mut out = Self(BTreeMap::new());
        for (id, stmt) in nodes.statements() {
            let value = match stmt {
                Stmt::Located(_, _, child) => out.statement(*child),
                Stmt::Return(_) | Stmt::RevertError(..) => true,
                Stmt::If(_, yes, Some(no)) => out.block(yes) && out.block(no),
                Stmt::Match(_, arms) => {
                    !arms.is_empty() && arms.iter().all(|(_, _, body)| out.block(body))
                }
                _ => false,
            };
            out.0.insert(id, value);
        }
        out
    }
    pub fn statement(&self, id: StmtId) -> bool {
        *self.0.get(&id).expect("return-flow child precedes parent")
    }
    pub fn block(&self, body: &[StmtId]) -> bool {
        body.iter().any(|id| self.statement(*id))
    }
}
pub fn statement_line(nodes: &Nodes, id: StmtId) -> usize {
    match nodes.statement(id) {
        Stmt::Located(line, _, _) => *line,
        _ => 0,
    }
}
pub fn block_line(nodes: &Nodes, body: &[StmtId]) -> usize {
    body.first().map_or(0, |id| statement_line(nodes, *id))
}
