// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Literal projection and capture-avoiding substitution preserve binder scopes.
use super::super::{eval::Value, term::Term, types::Type};
use super::{Natural, TermId, Terms, TypeId, Types, ValueId, Values};
use num_traits::ToPrimitive;
use std::sync::Arc;
enum Projection {
    Visit(TypeId, ValueId),
    Vec(TypeId, usize),
    Seq(Natural, TypeId, usize),
    Pair,
    Inl(TypeId),
    Inr(TypeId),
}
pub fn term_of(
    types: &Types,
    values: &mut Values,
    terms: &mut Terms,
    typ: TypeId,
    value: ValueId,
) -> Option<TermId> {
    if !values.typed(types, typ, value) {
        return None;
    }
    let mut pending = vec![Projection::Visit(typ, value)];
    let mut out: Vec<TermId> = vec![];
    while let Some(task) = pending.pop() {
        let term = match task {
            Projection::Visit(typ, id) => match (types.get(typ), values.get(id).clone()) {
                (Type::Unit, Value::Unit) => Term::Unit,
                (Type::Bool, Value::Bool(value)) => Term::Bool(value),
                (Type::Int, Value::Int(value)) => Term::Int(value.as_ref().clone()),
                (Type::Num(..), Value::Int(value)) => Term::Narrow(typ, value.as_ref().clone()),
                (Type::Bytes(_), Value::Bytes(value)) => Term::Bytes(value.to_vec()),
                (Type::Vec(_, elem), Value::Vec(items)) => {
                    pending.push(Projection::Vec(*elem, items.len()));
                    pending.extend(
                        items
                            .iter()
                            .rev()
                            .map(|item| Projection::Visit(*elem, *item)),
                    );
                    continue;
                }
                (Type::Seq(capacity, elem), Value::Pair(length, vector)) => {
                    let (Value::Int(length), Value::Vec(items)) =
                        (values.get(length), values.get(vector))
                    else {
                        return None;
                    };
                    let count = length.to_usize()?;
                    pending.push(Projection::Seq(*capacity, *elem, count));
                    pending.extend(
                        items[..count]
                            .iter()
                            .rev()
                            .map(|item| Projection::Visit(*elem, *item)),
                    );
                    continue;
                }
                (Type::Pair(left_type, right_type), Value::Pair(left, right)) => {
                    pending.push(Projection::Pair);
                    pending.push(Projection::Visit(*right_type, right));
                    pending.push(Projection::Visit(*left_type, left));
                    continue;
                }
                (Type::Sum(left, right), Value::Inl(value)) => {
                    pending.push(Projection::Inl(*right));
                    pending.push(Projection::Visit(*left, value));
                    continue;
                }
                (Type::Sum(left, right), Value::Inr(value)) => {
                    pending.push(Projection::Inr(*left));
                    pending.push(Projection::Visit(*right, value));
                    continue;
                }
                _ => return None,
            },
            Projection::Vec(elem, count) => {
                Term::Vec(elem, out.split_off(out.len().checked_sub(count)?))
            }
            Projection::Seq(capacity, elem, count) => {
                Term::Seq(capacity, elem, out.split_off(out.len().checked_sub(count)?))
            }
            Projection::Pair => {
                let right = out.pop()?;
                let left = out.pop()?;
                Term::Pair(left, right)
            }
            Projection::Inl(right) => Term::Inl(out.pop()?, right),
            Projection::Inr(left) => Term::Inr(left, out.pop()?),
        };
        out.push(terms.push(term));
    }
    out.pop()
}
type Replacements = Arc<Vec<(Natural, TermId)>>;
fn without(values: &Replacements, ids: &[Natural]) -> Replacements {
    Arc::new(
        values
            .iter()
            .filter(|(id, _)| !ids.contains(id))
            .copied()
            .collect(),
    )
}
enum Substitution {
    Visit(TermId, Replacements),
    Finish(Term, usize),
}
pub fn substitute(terms: &mut Terms, replacements: &[(Natural, TermId)], root: TermId) -> TermId {
    let mut pending = vec![Substitution::Visit(root, Arc::new(replacements.to_vec()))];
    let mut out: Vec<TermId> = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Substitution::Visit(id, replacements) => {
                let term = terms.get(id).clone();
                if let Term::Var(name) = term {
                    out.push(
                        replacements
                            .iter()
                            .rev()
                            .find(|(key, _)| *key == name)
                            .map_or(id, |(_, value)| *value),
                    );
                    continue;
                }
                let children = term.children();
                if children.is_empty() {
                    out.push(id);
                    continue;
                }
                let scopes = match &term {
                    Term::Let(bind, _, _) => {
                        vec![replacements.clone(), without(&replacements, &[bind.id])]
                    }
                    Term::Unpair(_, left, right, _) => vec![
                        replacements.clone(),
                        without(&replacements, &[left.id, right.id]),
                    ],
                    Term::Case(_, left, _, right, _) => vec![
                        replacements.clone(),
                        without(&replacements, &[left.id]),
                        without(&replacements, &[right.id]),
                    ],
                    Term::Vfold(_, _, fold) => vec![
                        replacements.clone(),
                        replacements.clone(),
                        without(&replacements, &[fold.item.id, fold.state.id]),
                    ],
                    _ => vec![replacements; children.len()],
                };
                pending.push(Substitution::Finish(term, children.len()));
                pending.extend(
                    children
                        .into_iter()
                        .zip(scopes)
                        .rev()
                        .map(|(child, scope)| Substitution::Visit(child, scope)),
                );
            }
            Substitution::Finish(term, count) => {
                let children = out.split_off(out.len() - count);
                let mut children = children.into_iter();
                let term = term.map_terms(|_| children.next().expect("substituted child"));
                out.push(terms.push(term));
            }
        }
    }
    out.pop().expect("substituted root")
}
