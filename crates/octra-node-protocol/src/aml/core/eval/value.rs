// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat C_eval values; aggregate clone and destruction do not recurse.
use super::super::{field::Field, text::Text, Natural};
use num_bigint::{BigInt, Sign};
use std::sync::Arc;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValueId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Unit,
    Bool(bool),
    Int(Arc<BigInt>),
    Bytes(Arc<[u8]>),
    Vec(Arc<[ValueId]>),
    Cap(Natural, Natural),
    Enc(Natural, Natural, Field),
    Pair(ValueId, ValueId),
    Inl(ValueId),
    Inr(ValueId),
}
impl Value {
    pub fn children(&self) -> Vec<ValueId> {
        match self {
            Self::Vec(values) => values.to_vec(),
            Self::Pair(left, right) => vec![*left, *right],
            Self::Inl(value) | Self::Inr(value) => vec![*value],
            _ => vec![],
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Values {
    items: Vec<Value>,
}
impl Values {
    pub fn try_get(&self, id: ValueId) -> Option<&Value> {
        self.items.get(id.0)
    }
    pub(crate) fn require(&self, id: ValueId) -> Result<(), super::super::arena::Reference> {
        self.try_get(id)
            .map(|_| ())
            .ok_or(super::super::arena::Reference {
                kind: super::super::arena::Kind::Value,
                index: id.0,
                length: self.items.len(),
            })
    }
    pub fn insert(&mut self, value: Value) -> Result<ValueId, super::super::arena::Reference> {
        for child in value.children() {
            self.require(child)?;
        }
        Ok(self.push(value))
    }
    pub fn get(&self, id: ValueId) -> &Value {
        &self.items[id.0]
    }
    /// All child IDs must belong to this arena (or to its unchanged clone).
    pub fn push(&mut self, value: Value) -> ValueId {
        for child in value.children() {
            assert!(
                child.0 < self.items.len(),
                "core value child precedes parent"
            );
        }
        let id = ValueId(self.items.len());
        self.items.push(value);
        id
    }
    pub fn integer(&mut self, value: impl Into<BigInt>) -> ValueId {
        self.push(Value::Int(Arc::new(value.into())))
    }
    pub fn equal(&self, left: ValueId, right: ValueId) -> bool {
        let mut pending = vec![(left, right)];
        while let Some((left, right)) = pending.pop() {
            if left == right {
                continue;
            }
            match (self.get(left), self.get(right)) {
                (Value::Unit, Value::Unit) => (),
                (Value::Bool(left), Value::Bool(right)) if left == right => (),
                (Value::Int(left), Value::Int(right)) if left == right => (),
                (Value::Bytes(left), Value::Bytes(right)) if left == right => (),
                (Value::Vec(left), Value::Vec(right)) if left.len() == right.len() => {
                    pending.extend(left.iter().copied().zip(right.iter().copied()).rev());
                }
                (Value::Cap(lk, li), Value::Cap(rk, ri)) if lk == rk && li == ri => (),
                (Value::Enc(lk, lr, lf), Value::Enc(rk, rr, rf))
                    if lk == rk && lr == rr && lf == rf => {}
                (Value::Pair(la, lb), Value::Pair(ra, rb)) => {
                    pending.push((*lb, *rb));
                    pending.push((*la, *ra));
                }
                (Value::Inl(left), Value::Inl(right)) | (Value::Inr(left), Value::Inr(right)) => {
                    pending.push((*left, *right));
                }
                _ => return false,
            }
        }
        true
    }
    pub fn text(&self, root: ValueId) -> Vec<u8> {
        enum Part {
            Value(ValueId),
            Text(&'static [u8]),
            Hex(Arc<[u8]>, usize),
            Vector(Arc<[ValueId]>, usize),
        }
        let mut out = Text::default();
        let mut pending = vec![Part::Value(root)];
        while let Some(part) = pending.pop() {
            if out.full() {
                break;
            }
            let value = match part {
                Part::Text(text) => {
                    out.add(text);
                    continue;
                }
                Part::Hex(raw, index) => {
                    if let Some(byte) = raw.get(index) {
                        out.add(&[
                            b"0123456789abcdef"[(byte >> 4) as usize],
                            b"0123456789abcdef"[(byte & 15) as usize],
                        ]);
                        pending.push(Part::Hex(raw, index + 1));
                    }
                    continue;
                }
                Part::Vector(values, index) => {
                    if let Some(value) = values.get(index) {
                        let value = *value;
                        if index > 0 {
                            out.add(b", ");
                        }
                        pending.push(Part::Vector(values, index + 1));
                        pending.push(Part::Value(value));
                    } else {
                        out.add(b"]");
                    }
                    continue;
                }
                Part::Value(id) => self.get(id),
            };
            match value {
                Value::Unit => out.add(b"()"),
                Value::Bool(true) => out.add(b"true"),
                Value::Bool(false) => out.add(b"false"),
                Value::Int(value) => out.add(&int_text(value)),
                Value::Bytes(value) => {
                    out.add(b"0x");
                    pending.push(Part::Hex(value.clone(), 0));
                }
                Value::Vec(values) => {
                    out.add(b"[");
                    pending.push(Part::Vector(values.clone(), 0));
                }
                Value::Cap(kind, id) => {
                    out.add(format!("cap[{}]#{}", kind.get(), id.get()).as_bytes());
                }
                Value::Enc(key, remaining, _) => {
                    out.add(format!("enc[{},{}]", key.get(), remaining.get()).as_bytes());
                }
                Value::Pair(left, right) => {
                    out.add(b"(");
                    pending.push(Part::Text(b")"));
                    pending.push(Part::Value(*right));
                    pending.push(Part::Text(b", "));
                    pending.push(Part::Value(*left));
                }
                Value::Inl(value) => {
                    out.add(b"inl ");
                    pending.push(Part::Value(*value));
                }
                Value::Inr(value) => {
                    out.add(b"inr ");
                    pending.push(Part::Value(*value));
                }
            }
        }
        out.finish()
    }
}
pub fn int_text(value: &BigInt) -> Vec<u8> {
    if value.bits() <= 256 {
        value.to_string().into_bytes()
    } else {
        format!(
            "{}int[{}]",
            if value.sign() == Sign::Minus { "-" } else { "" },
            value.bits()
        )
        .into_bytes()
    }
}
