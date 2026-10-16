// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Runtime value typing, defaults and work preserve sequence padding rules.
use super::{
    BTreeMap, BTreeSet, BigInt, Field, Natural, Signed, ToPrimitive, Type, TypeId, Types, Value,
    ValueId, Values, Zero, LOCAL,
};
pub(super) type ZeroCache = BTreeMap<TypeId, Option<ValueId>>;
enum DefaultTask {
    Type(TypeId),
    Vector(TypeId, Natural, bool),
    PairLeft(TypeId, TypeId),
    PairRight(TypeId, ValueId),
    SumLeft(TypeId, TypeId),
    SumRight(TypeId),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShapeError {
    Form,
    Capability(Natural, Natural),
}
impl Values {
    pub fn zero(&mut self, types: &Types, root: TypeId) -> Option<ValueId> {
        self.zero_cached(types, root, &mut ZeroCache::new())
    }
    pub(super) fn zero_cached(
        &mut self,
        types: &Types,
        root: TypeId,
        cache: &mut ZeroCache,
    ) -> Option<ValueId> {
        let mut pending = vec![DefaultTask::Type(root)];
        let mut values: Vec<Option<ValueId>> = vec![];
        while let Some(task) = pending.pop() {
            let (typ, result) = match task {
                DefaultTask::Type(typ) => {
                    if let Some(value) = cache.get(&typ) {
                        values.push(*value);
                        continue;
                    }
                    let result = match types.get(typ) {
                        Type::Unit => Some(self.push(Value::Unit)),
                        Type::Bool => Some(self.push(Value::Bool(false))),
                        Type::Int | Type::Num(..) => Some(self.integer(0)),
                        Type::Bytes(length) => {
                            Some(self.push(Value::Bytes(vec![0; length.get() as usize].into())))
                        }
                        Type::Vec(length, elem) | Type::Seq(length, elem) => {
                            pending.push(DefaultTask::Vector(
                                typ,
                                *length,
                                matches!(types.get(typ), Type::Seq(..)),
                            ));
                            pending.push(DefaultTask::Type(*elem));
                            continue;
                        }
                        Type::Pair(left, right) => {
                            pending.push(DefaultTask::PairLeft(typ, *right));
                            pending.push(DefaultTask::Type(*left));
                            continue;
                        }
                        Type::Sum(left, right) => {
                            pending.push(DefaultTask::SumLeft(typ, *right));
                            pending.push(DefaultTask::Type(*left));
                            continue;
                        }
                        Type::Cap(_) | Type::Enc(..) => None,
                    };
                    (typ, result)
                }
                DefaultTask::Vector(typ, length, sequence) => {
                    let result = values.pop().expect("default element").map(|value| {
                        let vector =
                            self.push(Value::Vec(vec![value; length.get() as usize].into()));
                        if sequence {
                            let length = self.integer(0);
                            self.push(Value::Pair(length, vector))
                        } else {
                            vector
                        }
                    });
                    (typ, result)
                }
                DefaultTask::PairLeft(typ, right) => match values.pop().expect("default pair left")
                {
                    Some(left) => {
                        pending.push(DefaultTask::PairRight(typ, left));
                        pending.push(DefaultTask::Type(right));
                        continue;
                    }
                    None => (typ, None),
                },
                DefaultTask::PairRight(typ, left) => (
                    typ,
                    values
                        .pop()
                        .expect("default pair right")
                        .map(|right| self.push(Value::Pair(left, right))),
                ),
                DefaultTask::SumLeft(typ, right) => {
                    if let Some(value) = values.pop().expect("default sum left") {
                        (typ, Some(self.push(Value::Inl(value))))
                    } else {
                        pending.push(DefaultTask::SumRight(typ));
                        pending.push(DefaultTask::Type(right));
                        continue;
                    }
                }
                DefaultTask::SumRight(typ) => (
                    typ,
                    values
                        .pop()
                        .expect("default sum right")
                        .map(|value| self.push(Value::Inr(value))),
                ),
            };
            cache.insert(typ, result);
            values.push(result);
        }
        values.pop().expect("default root")
    }
    pub fn typed(&mut self, types: &Types, root_type: TypeId, root: ValueId) -> bool {
        enum Task {
            Typed(TypeId, ValueId),
            Equal(ValueId, ValueId),
        }
        let mut pending = vec![Task::Typed(root_type, root)];
        let mut defaults = ZeroCache::new();
        while let Some(task) = pending.pop() {
            let (typ, id) = match task {
                Task::Equal(left, right) => {
                    if !self.equal(left, right) {
                        return false;
                    }
                    continue;
                }
                Task::Typed(typ, id) => (typ, id),
            };
            match (types.get(typ), self.get(id).clone()) {
                (Type::Unit, Value::Unit)
                | (Type::Bool, Value::Bool(_))
                | (Type::Int, Value::Int(_)) => (),
                (Type::Num(..), Value::Int(value)) if types.admits(typ, &value) => (),
                (Type::Bytes(length), Value::Bytes(value))
                    if length.get() as usize == value.len() => {}
                (Type::Vec(length, elem), Value::Vec(values))
                    if length.get() as usize == values.len() =>
                {
                    pending.extend(values.iter().rev().map(|value| Task::Typed(*elem, *value)));
                }
                (Type::Seq(capacity, elem), Value::Pair(length, vector)) => {
                    let (Value::Int(length), Value::Vec(values)) =
                        (self.get(length).clone(), self.get(vector).clone())
                    else {
                        return false;
                    };
                    if values.len() != capacity.get() as usize
                        || length.is_negative()
                        || *length > BigInt::from(capacity.get())
                    {
                        return false;
                    }
                    let Some(empty) = self.zero_cached(types, *elem, &mut defaults) else {
                        return false;
                    };
                    let used = length.to_usize().expect("bounded sequence count");
                    for (index, value) in values.iter().enumerate().rev() {
                        if index >= used {
                            pending.push(Task::Equal(*value, empty));
                        }
                        pending.push(Task::Typed(*elem, *value));
                    }
                }
                (Type::Cap(kind), Value::Cap(actual, _)) if *kind == actual => (),
                (Type::Enc(key, remaining), Value::Enc(actual_key, actual_remaining, _))
                    if *key == actual_key && *remaining == actual_remaining => {}
                (Type::Pair(left_type, right_type), Value::Pair(left, right)) => {
                    pending.push(Task::Typed(*right_type, right));
                    pending.push(Task::Typed(*left_type, left));
                }
                (Type::Sum(left, _), Value::Inl(value)) => pending.push(Task::Typed(*left, value)),
                (Type::Sum(_, right), Value::Inr(value)) => {
                    pending.push(Task::Typed(*right, value));
                }
                _ => return false,
            }
        }
        true
    }
    pub fn value_work(&self, types: &Types, typ: TypeId, root: ValueId) -> BigInt {
        let mut pending = vec![(typ, root)];
        let mut work = BigInt::zero();
        while let Some((typ, id)) = pending.pop() {
            work += 1;
            match (types.get(typ), self.get(id)) {
                (Type::Bytes(_), Value::Bytes(value)) => work += value.len(),
                (Type::Vec(_, elem), Value::Vec(values)) => {
                    pending.extend(values.iter().rev().map(|value| (*elem, *value)));
                }
                (Type::Seq(_, elem), Value::Pair(length, vector)) => {
                    if let (Value::Int(_), Value::Vec(values)) =
                        (self.get(*length), self.get(*vector))
                    {
                        work += 1;
                        pending.extend(values.iter().rev().map(|value| (*elem, *value)));
                    }
                }
                (Type::Pair(left_type, right_type), Value::Pair(left, right)) => {
                    pending.push((*right_type, *right));
                    pending.push((*left_type, *left));
                }
                (Type::Sum(left, _), Value::Inl(value)) => pending.push((*left, *value)),
                (Type::Sum(_, right), Value::Inr(value)) => pending.push((*right, *value)),
                _ => (),
            }
        }
        work
    }
    /// C_feed.shape: this only checks structure and capability uniqueness.
    /// Feed encoding and type attachment perform their own additional checks.
    pub fn shape(&self, roots: &[ValueId]) -> std::result::Result<(), ShapeError> {
        let mut pending: Vec<_> = roots.iter().rev().map(|root| (0, *root)).collect();
        let mut seen = BTreeSet::new();
        let mut nodes = 0;
        while let Some((depth, id)) = pending.pop() {
            if nodes >= LOCAL.get(Field::TermNodes) as usize
                || depth > LOCAL.get(Field::TermDepth) as usize
            {
                return Err(ShapeError::Form);
            }
            let value = self.get(id);
            match value {
                Value::Cap(kind, id) if !seen.insert((*kind, *id)) => {
                    return Err(ShapeError::Capability(*kind, *id))
                }
                Value::Vec(values) => {
                    pending.extend(values.iter().map(|value| (depth + 1, *value)));
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
        Ok(())
    }
}
