// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_low type shape checking precedes natural conversion and final validity.
use super::super::types::{Type, TypeId, Types, MAX_DEPTH, MAX_NODES};
use super::{natural, syn, Error, Natural, Result};
enum Task {
    Visit(syn::TypeId),
    Finish(syn::TypeId, Option<Natural>, usize),
}
pub fn typ(syntax: &syn::Syntax, types: &mut Types, root: syn::TypeId) -> Result<TypeId> {
    let mut pending = vec![(0, root)];
    let mut count = 0;
    while let Some((depth, id)) = pending.pop() {
        if depth > MAX_DEPTH || count >= MAX_NODES {
            return Err(Error::Type);
        }
        let typ = syntax.typ(id);
        match typ {
            syn::Type::Bytes(value)
            | syn::Type::Cap(value)
            | syn::Type::Vec(value, _)
            | syn::Type::Seq(value, _) => {
                natural(value)?;
            }
            _ => (),
        }
        pending.extend(
            typ.children()
                .into_iter()
                .rev()
                .map(|child| (depth + 1, child)),
        );
        count += 1;
    }
    let mut tasks = vec![Task::Visit(root)];
    let mut values = vec![];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Visit(id) => {
                let typ = match syntax.typ(id) {
                    syn::Type::Unit => Type::Unit,
                    syn::Type::Bool => Type::Bool,
                    syn::Type::Int => Type::Int,
                    syn::Type::Num(sign, bits) => Type::Num(*sign, natural(bits)?),
                    syn::Type::Bytes(length) => Type::Bytes(natural(length)?),
                    syn::Type::Cap(kind) => Type::Cap(natural(kind)?),
                    syn::Type::Vec(length, child) | syn::Type::Seq(length, child) => {
                        let length = natural(length)?;
                        tasks.push(Task::Finish(id, Some(length), 1));
                        tasks.push(Task::Visit(*child));
                        continue;
                    }
                    syn::Type::Pair(left, right) | syn::Type::Sum(left, right) => {
                        tasks.push(Task::Finish(id, None, 2));
                        tasks.push(Task::Visit(*right));
                        tasks.push(Task::Visit(*left));
                        continue;
                    }
                };
                values.push(types.intern(typ));
            }
            Task::Finish(id, natural, count) => {
                let children = values.split_off(values.len() - count);
                let typ = match syntax.typ(id) {
                    syn::Type::Vec(..) => Type::Vec(natural.expect("vector length"), children[0]),
                    syn::Type::Seq(..) => {
                        Type::Seq(natural.expect("sequence capacity"), children[0])
                    }
                    syn::Type::Pair(..) => Type::Pair(children[0], children[1]),
                    syn::Type::Sum(..) => Type::Sum(children[0], children[1]),
                    _ => unreachable!("composite type"),
                };
                values.push(types.intern(typ));
            }
        }
    }
    let typ = values.pop().expect("lowered type");
    if types.valid(typ) {
        Ok(typ)
    } else {
        Err(Error::Type)
    }
}
