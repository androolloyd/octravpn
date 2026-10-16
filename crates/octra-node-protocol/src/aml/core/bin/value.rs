// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_bin value projection, distinct from runtime feed/input shape limits.
use super::super::{
    eval::{Value, ValueId, Values},
    field::Field as Element,
    types::MAX_DEPTH,
};
use super::{decode, encode, Bits, Code, CodeId, Codes};
use num_traits::ToPrimitive;
use std::collections::BTreeMap;
pub fn value_valid(values: &Values, root: ValueId) -> bool {
    let maximum = super::super::rule::LOCAL.get(super::super::rule::Field::Nat) as usize;
    let mut pending = vec![(0, root)];
    let mut nodes = 0;
    while let Some((depth, id)) = pending.pop() {
        if nodes >= maximum || depth > MAX_DEPTH {
            return false;
        }
        match values.get(id) {
            Value::Bytes(raw) if raw.len() > maximum => return false,
            Value::Vec(items) => {
                if items.len() > maximum {
                    return false;
                }
                pending.extend(items.iter().map(|item| (depth + 1, *item)));
            }
            Value::Pair(left, right) => {
                pending.push((depth + 1, *right));
                pending.push((depth + 1, *left));
            }
            Value::Inl(value) | Value::Inr(value) => pending.push((depth + 1, *value)),
            _ => (),
        }
        nodes += 1;
    }
    true
}
enum Put {
    Value(ValueId),
    Finish(ValueId),
}
enum Get {
    Value(CodeId, usize),
    Finish(u8, usize),
}
impl Codes {
    pub fn bytes_code(&mut self, raw: &[u8]) -> CodeId {
        let mut rest = self.nil();
        for byte in raw.iter().rev() {
            let byte = self.num(*byte);
            rest = self.cons(byte, rest);
        }
        rest
    }
    pub fn bytes_get(&self, mut input: CodeId) -> Option<Vec<u8>> {
        let mut out = vec![];
        loop {
            match self.get(input) {
                Code::Nil => return Some(out),
                Code::Cons(first, rest) => {
                    let Code::Num(byte) = self.get(*first) else {
                        return None;
                    };
                    out.push(byte.to_u8()?);
                    input = *rest;
                }
                _ => return None,
            }
        }
    }
    /// Raw value_code does not apply the canonical wrapper's value_valid guard.
    pub fn value_code(&mut self, values: &Values, root: ValueId) -> CodeId {
        let mut pending = vec![Put::Value(root)];
        let mut memo = BTreeMap::new();
        while let Some(task) = pending.pop() {
            let id = match task {
                Put::Value(id) => {
                    if memo.contains_key(&id) {
                        continue;
                    }
                    pending.push(Put::Finish(id));
                    pending.extend(values.get(id).children().into_iter().rev().map(Put::Value));
                    continue;
                }
                Put::Finish(id) => id,
            };
            let (tag, body) = match values.get(id) {
                Value::Unit => (0, self.nil()),
                Value::Bool(value) => (1, self.num(u8::from(*value))),
                Value::Int(value) => (2, self.push(Code::Int(value.clone()))),
                Value::Bytes(raw) => (3, self.bytes_code(raw)),
                Value::Vec(items) => {
                    let items: Vec<_> = items.iter().map(|item| memo[item]).collect();
                    (4, self.list(&items))
                }
                Value::Cap(kind, id) => {
                    let fields = [self.num(kind.get()), self.num(id.get())];
                    (5, self.list(&fields))
                }
                Value::Pair(left, right) => (6, self.list(&[memo[left], memo[right]])),
                Value::Inl(value) => (7, memo[value]),
                Value::Inr(value) => (8, memo[value]),
                Value::Enc(key, remaining, field) => {
                    let fields = [
                        self.num(key.get()),
                        self.num(remaining.get()),
                        self.integer(field.value().clone()),
                    ];
                    (9, self.list(&fields))
                }
            };
            memo.insert(id, self.tag(tag, body));
        }
        memo.remove(&root).expect("value code root")
    }
    /// Raw value_get has depth fuel and reduces field encodings modulo p. A
    /// canonical decoder must additionally re-encode and compare the bits.
    pub fn value_get(&self, values: &mut Values, root: CodeId) -> Option<ValueId> {
        let mut pending = vec![Get::Value(root, MAX_DEPTH + 1)];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            let value = match task {
                Get::Value(id, fuel) => {
                    if fuel == 0 {
                        return None;
                    }
                    let fuel = fuel - 1;
                    let Code::Tag(tag, body) = self.get(id) else {
                        return None;
                    };
                    let tag = tag.to_u8()?;
                    match tag {
                        0 if self.get(*body) == &Code::Nil => Value::Unit,
                        1 => {
                            let Code::Num(value) = self.get(*body) else {
                                return None;
                            };
                            match value.to_u8()? {
                                0 => Value::Bool(false),
                                1 => Value::Bool(true),
                                _ => return None,
                            }
                        }
                        2 => {
                            let Code::Int(value) = self.get(*body) else {
                                return None;
                            };
                            Value::Int(value.clone())
                        }
                        3 => Value::Bytes(self.bytes_get(*body)?.into()),
                        4 => {
                            let items = self.list_get(*body)?;
                            pending.push(Get::Finish(tag, items.len()));
                            pending
                                .extend(items.into_iter().rev().map(|item| Get::Value(item, fuel)));
                            continue;
                        }
                        5 => {
                            let fields = self.list_get(*body)?;
                            let [kind, id] = fields.as_slice() else {
                                return None;
                            };
                            Value::Cap(self.natural_get(*kind)?, self.natural_get(*id)?)
                        }
                        6 => {
                            let fields = self.list_get(*body)?;
                            let [left, right] = fields.as_slice() else {
                                return None;
                            };
                            pending.push(Get::Finish(tag, 2));
                            pending.push(Get::Value(*right, fuel));
                            pending.push(Get::Value(*left, fuel));
                            continue;
                        }
                        7 | 8 => {
                            pending.push(Get::Finish(tag, 1));
                            pending.push(Get::Value(*body, fuel));
                            continue;
                        }
                        9 => {
                            let fields = self.list_get(*body)?;
                            let [key, remaining, field] = fields.as_slice() else {
                                return None;
                            };
                            let key = self.natural_get(*key)?;
                            let remaining = self.natural_get(*remaining)?;
                            let Code::Int(field) = self.get(*field) else {
                                return None;
                            };
                            Value::Enc(key, remaining, Element::reduce(field))
                        }
                        _ => return None,
                    }
                }
                Get::Finish(tag, count) => {
                    let children = out.split_off(out.len().checked_sub(count)?);
                    match tag {
                        4 => Value::Vec(children.into()),
                        6 => Value::Pair(children[0], children[1]),
                        7 => Value::Inl(children[0]),
                        8 => Value::Inr(children[0]),
                        _ => unreachable!("aggregate value tag"),
                    }
                }
            };
            out.push(values.push(value));
        }
        out.pop()
    }
}
pub fn encode_value(values: &Values, root: ValueId) -> Option<Bits> {
    if !value_valid(values, root) {
        return None;
    }
    let mut codes = Codes::default();
    let root = codes.value_code(values, root);
    encode(&codes, root)
}
pub fn decode_value(values: &mut Values, bits: &[bool]) -> Option<ValueId> {
    let decoded = decode(bits)?;
    let value = decoded.codes.value_get(values, decoded.root)?;
    (encode_value(values, value)?.as_slice() == bits).then_some(value)
}
