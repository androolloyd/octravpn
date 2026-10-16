// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat replay values preserve empty-vector element shapes independently of
//! their payload. Machine projection is stricter than literal flattening.
use super::super::list::{ListId, Lists};
use super::super::{
    eval::{Value, ValueId, Values},
    types::{Type, TypeId, Types},
    Natural,
};
use super::{projection, Literal, Shape, ShapeId, Shapes};
use num_bigint::BigInt;
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Id(usize);
#[derive(Clone, Debug)]
pub(super) enum Item {
    Unit,
    Atom(Literal),
    Pair(Id, Id),
    Vec(ShapeId, ListId),
    Sum(bool, Id),
}
#[derive(Default)]
pub(super) struct Items {
    values: Vec<Item>,
    forms: Vec<ShapeId>,
    pub lists: Lists<Id>,
}
impl Items {
    pub(super) fn get(&self, id: Id) -> &Item {
        &self.values[id.0]
    }
    pub(super) fn shape(&self, id: Id) -> ShapeId {
        self.forms[id.0]
    }
    pub(super) fn push(&mut self, shapes: &mut Shapes, value: Item) -> Id {
        let shape = match &value {
            Item::Unit => Shape::Unit,
            Item::Atom(Literal::Cap(kind, _)) => Shape::Cap(*kind),
            Item::Atom(_) => Shape::Atom,
            Item::Pair(left, right) => Shape::Pair(self.shape(*left), self.shape(*right)),
            Item::Vec(elem, values) => Shape::Vec(
                Natural::new(&BigInt::from(self.lists.len(*values)))
                    .unwrap_or_else(|| Natural::from_u32(0).expect("zero")),
                *elem,
            ),
            Item::Sum(_, payload) => Shape::Sum(self.shape(*payload)),
        };
        let id = Id(self.values.len());
        self.values.push(value);
        self.forms.push(shapes.intern(shape));
        id
    }
    // This imports a core value into the existing machine arena.
    #[allow(clippy::wrong_self_convention)]
    pub(super) fn from_core(
        &mut self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        typ: TypeId,
        root: ValueId,
    ) -> Option<Id> {
        enum Task {
            Visit(TypeId, ValueId),
            Pair,
            Vector(ShapeId, usize),
            Sum(bool),
        }
        let mut pending = vec![Task::Visit(typ, root)];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Pair => {
                    let right = out.pop().expect("machine pair right");
                    let left = out.pop().expect("machine pair left");
                    out.push(self.push(shapes, Item::Pair(left, right)));
                }
                Task::Vector(elem, count) => {
                    let items = out.split_off(out.len() - count);
                    let items = self.lists.array(items);
                    out.push(self.push(shapes, Item::Vec(elem, items)));
                }
                Task::Sum(side) => {
                    let value = out.pop().expect("machine sum payload");
                    out.push(self.push(shapes, Item::Sum(side, value)));
                }
                Task::Visit(typ, id) => {
                    if let Some(lit) = projection::scalar(types, values, typ, id) {
                        out.push(self.push(shapes, Item::Atom(lit)));
                        continue;
                    }
                    match (types.get(typ).clone(), values.get(id).clone()) {
                        (Type::Unit, Value::Unit) => out.push(self.push(shapes, Item::Unit)),
                        (Type::Vec(length, elem), Value::Vec(items))
                            if length.get() as usize == items.len() =>
                        {
                            let form = shapes.from_type(types, elem)?;
                            pending.push(Task::Vector(form, items.len()));
                            pending.extend(items.iter().rev().map(|item| Task::Visit(elem, *item)));
                        }
                        (Type::Seq(..), _) if values.typed(types, typ, id) => {
                            pending.push(Task::Visit(types.repr(typ), id));
                        }
                        (Type::Pair(lhs, rhs), Value::Pair(left, right)) => {
                            pending.push(Task::Pair);
                            pending.push(Task::Visit(rhs, right));
                            pending.push(Task::Visit(lhs, left));
                        }
                        (Type::Sum(left, right), Value::Inl(item) | Value::Inr(item)) => {
                            if shapes.from_type(types, left)? != shapes.from_type(types, right)? {
                                return None;
                            }
                            let side = matches!(values.get(id), Value::Inl(_));
                            pending.push(Task::Sum(side));
                            pending.push(Task::Visit(if side { left } else { right }, item));
                        }
                        _ => return None,
                    }
                }
            }
        }
        out.pop()
    }
    pub(super) fn zero(
        &mut self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        typ: TypeId,
    ) -> Option<Id> {
        let zero = values.zero(types, typ)?;
        self.from_core(shapes, types, values, typ, zero)
    }
    pub(super) fn atom(
        &mut self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        typ: TypeId,
        literal: &Literal,
    ) -> Option<Id> {
        let valid = match (types.get(typ), literal) {
            (Type::Bool, Literal::Bool(_)) => true,
            (Type::Int | Type::Num(..), Literal::Int(value)) => types.admits(typ, value),
            (Type::Bytes(length), Literal::Bytes(value)) => length.get() as usize == value.len(),
            (Type::Cap(expected), Literal::Cap(kind, _)) => expected == kind,
            (_, Literal::Data(record)) if typ == record.typ() => {
                return self.from_core(shapes, types, values, typ, record.value())
            }
            _ => false,
        };
        valid.then(|| self.push(shapes, Item::Atom(literal.clone())))
    }
    pub(super) fn eval(&self, values: &mut Values, root: Id) -> Option<ValueId> {
        let mut pending = vec![(root, false)];
        let mut memo = BTreeMap::new();
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            let children = match self.get(id) {
                Item::Pair(left, right) => vec![*left, *right],
                Item::Vec(_, values) => self.lists.collect(*values),
                Item::Sum(_, payload) => vec![*payload],
                _ => vec![],
            };
            if !finish {
                pending.push((id, true));
                pending.extend(children.into_iter().rev().map(|child| (child, false)));
                continue;
            }
            let value = match self.get(id) {
                Item::Unit => Value::Unit,
                Item::Atom(Literal::Bool(value)) => Value::Bool(*value),
                Item::Atom(Literal::Int(value)) => Value::Int(value.clone()),
                Item::Atom(Literal::Bytes(value)) => Value::Bytes(value.clone()),
                Item::Atom(Literal::Cap(kind, id)) => Value::Cap(*kind, *id),
                Item::Atom(Literal::Data(record)) => {
                    memo.insert(id, record.value());
                    continue;
                }
                Item::Pair(left, right) => Value::Pair(memo[left], memo[right]),
                Item::Vec(_, items) => Value::Vec(
                    self.lists
                        .collect(*items)
                        .iter()
                        .map(|item| memo[item])
                        .collect::<Vec<_>>()
                        .into(),
                ),
                Item::Sum(true, payload) => Value::Inl(memo[payload]),
                Item::Sum(false, payload) => Value::Inr(memo[payload]),
            };
            memo.insert(id, values.push(value));
        }
        memo.remove(&root)
    }
    pub(super) fn same_shapes(&self, left: &[Id], right: &[Id]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(left, right)| self.shape(*left) == self.shape(*right))
    }
}
