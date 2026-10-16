// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::super::term::Relation;
use super::{Action, Arc, Atom, Engine, Item, Literal, Op, Value};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
impl Engine<'_> {
    fn pop_atom(&mut self) -> Option<Literal> {
        let Item::Atom(lit) = self.items.get(self.stack.pop()?).clone() else {
            return None;
        };
        Some(lit)
    }
    fn pop_integer(&mut self) -> Option<Arc<BigInt>> {
        let Literal::Int(value) = self.pop_atom()? else {
            return None;
        };
        Some(value)
    }
    fn pop_bytes(&mut self) -> Option<Arc<[u8]>> {
        let Literal::Bytes(value) = self.pop_atom()? else {
            return None;
        };
        Some(value)
    }
    pub(super) fn linear(&mut self, op: &Op) -> Option<()> {
        match op {
            Op::Push(value) => self.push(Item::Atom(value.clone())),
            Op::Void => self.push(Item::Unit),
            Op::Get(id, form) => {
                let value = self.take(*id)?;
                if self.items.shape(value) != *form {
                    return None;
                }
                self.stack.push(value);
            }
            Op::Plus | Op::Minus | Op::Times | Op::Quot | Op::Rem => {
                let right = self.pop_integer()?;
                let left = self.pop_integer()?;
                let value = match op {
                    Op::Plus => &*left + &*right,
                    Op::Minus => &*left - &*right,
                    Op::Times => &*left * &*right,
                    Op::Quot if !right.is_zero() => &*left / &*right,
                    Op::Rem if !right.is_zero() => &*left % &*right,
                    _ => return None,
                };
                self.push(Item::Atom(Literal::Int(Arc::new(value))));
            }
            Op::Negate | Op::Absolute => {
                let value = self.pop_integer()?;
                let value = if matches!(op, Op::Negate) {
                    -&*value
                } else {
                    value.abs()
                };
                self.push(Item::Atom(Literal::Int(Arc::new(value))));
            }
            Op::Same => {
                let right = self.pop_atom()?;
                let left = self.pop_atom()?;
                self.push(Item::Atom(Literal::Bool(left.equal(&right))));
            }
            Op::Different | Op::Order(_) => {
                let right = self.pop_integer()?;
                let left = self.pop_integer()?;
                let value = match op {
                    Op::Different => left != right,
                    Op::Order(Relation::Lt) => left < right,
                    Op::Order(Relation::Le) => left <= right,
                    Op::Order(Relation::Gt) => left > right,
                    Op::Order(Relation::Ge) => left >= right,
                    _ => unreachable!("integer comparison"),
                };
                self.push(Item::Atom(Literal::Bool(value)));
            }
            Op::Join => {
                let right = self.pop_bytes()?;
                let left = self.pop_bytes()?;
                self.push(Item::Atom(Literal::Bytes(
                    [left.as_ref(), right.as_ref()].concat().into(),
                )));
            }
            Op::Clip(count) | Op::Skip(count) => {
                let value = self.pop_bytes()?;
                let count = count.get() as usize;
                let raw = if matches!(op, Op::Clip(_)) {
                    value.get(..count)?
                } else {
                    value.get(count..)?
                };
                self.push(Item::Atom(Literal::Bytes(raw.into())));
            }
            Op::Duo => {
                let right = self.stack.pop()?;
                let left = self.stack.pop()?;
                self.push(Item::Pair(left, right));
            }
            Op::First | Op::Second => {
                let Item::Pair(left, right) = self.items.get(self.stack.pop()?) else {
                    return None;
                };
                self.stack.push(if matches!(op, Op::First) {
                    *left
                } else {
                    *right
                });
            }
            Op::Empty(elem) => {
                let empty = self.items.lists.array(vec![]);
                self.push(Item::Vec(*elem, empty));
            }
            Op::Cons => {
                let Item::Vec(elem, list) = self.items.get(self.stack.pop()?).clone() else {
                    return None;
                };
                let item = self.stack.pop()?;
                if self.items.shape(item) != elem {
                    return None;
                }
                let list = self.items.lists.cons(item, list);
                self.push(Item::Vec(elem, list));
            }
            Op::Append => {
                let Item::Vec(re, rhs) = self.items.get(self.stack.pop()?).clone() else {
                    return None;
                };
                let Item::Vec(le, lhs) = self.items.get(self.stack.pop()?).clone() else {
                    return None;
                };
                if le != re {
                    return None;
                }
                let list = self.items.lists.append(lhs, rhs);
                self.push(Item::Vec(le, list));
            }
            Op::Pick(index) => {
                let Item::Vec(_, list) = self.items.get(self.stack.pop()?) else {
                    return None;
                };
                self.stack
                    .push(self.items.lists.nth(*list, index.get() as usize)?);
            }
            Op::Unhead => {
                let Item::Vec(elem, list) = self.items.get(self.stack.pop()?).clone() else {
                    return None;
                };
                let (head, list) = self.items.lists.uncons(list)?;
                let tail = self.items.push(self.shapes, Item::Vec(elem, list));
                self.push(Item::Pair(head, tail));
            }
            Op::Left | Op::Right => {
                let payload = self.stack.pop()?;
                self.push(Item::Sum(matches!(op, Op::Left), payload));
            }
            Op::Pack(capacity, typ) => {
                let Item::Vec(form, list) = self.items.get(self.stack.pop()?).clone() else {
                    return None;
                };
                let expected = self.shapes.from_type(self.types, *typ)?;
                let zero = self
                    .items
                    .zero(self.shapes, self.types, self.values, *typ)?;
                let count = self.items.lists.len(list);
                if count > capacity.get() as usize
                    || form != expected
                    || form != self.items.shape(zero)
                {
                    return None;
                }
                let pad = self
                    .items
                    .lists
                    .array(vec![zero; capacity.get() as usize - count]);
                let list = self.items.lists.append(list, pad);
                let length = self.items.push(
                    self.shapes,
                    Item::Atom(Literal::Int(Arc::new(BigInt::from(count)))),
                );
                let vector = self.items.push(self.shapes, Item::Vec(form, list));
                self.push(Item::Pair(length, vector));
            }
            Op::Fit(typ) => {
                let value = self.pop_integer()?;
                let side = self.types.admits(*typ, &value);
                let payload = self
                    .items
                    .push(self.shapes, Item::Atom(Literal::Int(value)));
                self.push(Item::Sum(side, payload));
            }
            Op::Wide => {
                if !matches!(
                    self.items.get(*self.stack.last()?),
                    Item::Atom(Literal::Int(_))
                ) {
                    return None;
                }
            }
            Op::Close(kind) => {
                let Literal::Cap(found, id) = self.pop_atom()? else {
                    return None;
                };
                if found != *kind {
                    return None;
                }
                let unit = self.values.push(Value::Unit);
                self.actions
                    .push(Action::held(Atom::Close(*kind), unit, *kind, id));
                self.push(Item::Unit);
            }
            _ => return None,
        }
        Some(())
    }
}
