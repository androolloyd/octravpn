// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach scalar and aggregate projections. Flattening does not imply that a
//! type has an admissible machine shape; callers check that separately.
use super::super::{
    eval::{Value, ValueId, Values},
    result::Record,
    types::{Type, TypeId, Types},
};
use super::Literal;

pub(super) fn scalar(
    types: &Types,
    values: &Values,
    typ: TypeId,
    value: ValueId,
) -> Option<Literal> {
    Some(match (types.get(typ), values.get(value)) {
        (Type::Bool, Value::Bool(value)) => Literal::Bool(*value),
        (Type::Int, Value::Int(value)) => Literal::Int(value.clone()),
        (Type::Num(..), Value::Int(value)) if types.admits(typ, value) => {
            Literal::Int(value.clone())
        }
        (Type::Bytes(length), Value::Bytes(value)) if length.get() as usize == value.len() => {
            Literal::Bytes(value.clone())
        }
        (Type::Cap(kind), Value::Cap(found, id)) if kind == found => Literal::Cap(*kind, *id),
        _ => return None,
    })
}

pub fn literal(types: &Types, values: &mut Values, typ: TypeId, value: ValueId) -> Option<Literal> {
    scalar(types, values, typ, value).or_else(|| {
        Record::make(types, values, typ, value)
            .ok()
            .map(Literal::Data)
    })
}

pub fn atoms(
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    value: ValueId,
) -> Option<Vec<Literal>> {
    enum Task {
        Visit(TypeId, ValueId),
        Vector(TypeId, std::sync::Arc<[ValueId]>, usize),
    }
    let mut pending = vec![Task::Visit(typ, value)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        let (typ, id) = match task {
            Task::Visit(typ, id) => (typ, id),
            Task::Vector(elem, items, index) => {
                if let Some(id) = items.get(index).copied() {
                    pending.push(Task::Vector(elem, items, index + 1));
                    pending.push(Task::Visit(elem, id));
                }
                continue;
            }
        };
        if let Some(value) = scalar(types, values, typ, id) {
            out.push(value);
            continue;
        }
        match (types.get(typ), values.get(id).clone()) {
            (Type::Unit, Value::Unit) => (),
            (Type::Vec(length, elem), Value::Vec(items))
                if length.get() as usize == items.len() =>
            {
                pending.push(Task::Vector(*elem, items, 0));
            }
            (Type::Seq(_, elem), Value::Pair(length, vector)) if values.typed(types, typ, id) => {
                let (Value::Int(length), Value::Vec(items)) =
                    (values.get(length), values.get(vector))
                else {
                    return None;
                };
                out.push(Literal::Int(length.clone()));
                pending.push(Task::Vector(*elem, items.clone(), 0));
            }
            (Type::Pair(lhs, rhs), Value::Pair(left, right)) => {
                pending.push(Task::Visit(*rhs, right));
                pending.push(Task::Visit(*lhs, left));
            }
            (Type::Sum(lhs, _), Value::Inl(value)) => {
                out.push(Literal::Bool(true));
                pending.push(Task::Visit(*lhs, value));
            }
            (Type::Sum(_, rhs), Value::Inr(value)) => {
                out.push(Literal::Bool(false));
                pending.push(Task::Visit(*rhs, value));
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Reconstruct a value and report how many leading literals were consumed.
/// A Data literal is intentionally not an aggregate substitute in this format.
pub fn value(
    types: &mut Types,
    values: &mut Values,
    typ: TypeId,
    input: &[Literal],
) -> Option<(ValueId, usize)> {
    enum Task {
        Type(TypeId),
        PairRight(TypeId),
        PairFinish(ValueId),
        VectorNext(TypeId, usize, Vec<ValueId>),
        VectorItem(TypeId, usize, Vec<ValueId>),
        Sum(bool),
        Sequence(TypeId),
    }
    let mut pending = vec![Task::Type(typ)];
    let mut out = vec![];
    let mut cursor = 0;
    while let Some(task) = pending.pop() {
        match task {
            Task::PairRight(right) => {
                let left = out.pop().expect("machine pair left");
                pending.push(Task::PairFinish(left));
                pending.push(Task::Type(right));
            }
            Task::PairFinish(left) => {
                let right = out.pop().expect("machine pair right");
                out.push(values.push(Value::Pair(left, right)));
            }
            Task::VectorNext(elem, remaining, items) => {
                if remaining == 0 {
                    out.push(values.push(Value::Vec(items.into())));
                } else {
                    pending.push(Task::VectorItem(elem, remaining - 1, items));
                    pending.push(Task::Type(elem));
                }
            }
            Task::VectorItem(elem, remaining, mut items) => {
                items.push(out.pop().expect("machine vector element"));
                pending.push(Task::VectorNext(elem, remaining, items));
            }
            Task::Sum(left) => {
                let value = out.pop().expect("machine sum payload");
                out.push(values.push(if left {
                    Value::Inl(value)
                } else {
                    Value::Inr(value)
                }));
            }
            Task::Sequence(typ) => {
                if !values.typed(types, typ, *out.last().expect("machine sequence")) {
                    return None;
                }
            }
            Task::Type(typ) => {
                match types.get(typ).clone() {
                    Type::Unit => {
                        out.push(values.push(Value::Unit));
                        continue;
                    }
                    Type::Vec(length, elem) => {
                        pending.push(Task::VectorNext(elem, length.get() as usize, vec![]));
                        continue;
                    }
                    Type::Seq(..) => {
                        pending.push(Task::Sequence(typ));
                        pending.push(Task::Type(types.repr(typ)));
                        continue;
                    }
                    Type::Pair(left, right) => {
                        pending.push(Task::PairRight(right));
                        pending.push(Task::Type(left));
                        continue;
                    }
                    Type::Sum(left, right) => {
                        let Literal::Bool(side) = input.get(cursor)? else {
                            return None;
                        };
                        cursor += 1;
                        pending.push(Task::Sum(*side));
                        pending.push(Task::Type(if *side { left } else { right }));
                        continue;
                    }
                    _ => (),
                }
                let value = match (types.get(typ), input.get(cursor)?) {
                    (Type::Bool, Literal::Bool(value)) => Value::Bool(*value),
                    (Type::Int, Literal::Int(value)) => Value::Int(value.clone()),
                    (Type::Num(..), Literal::Int(value)) if types.admits(typ, value) => {
                        Value::Int(value.clone())
                    }
                    (Type::Bytes(length), Literal::Bytes(value))
                        if length.get() as usize == value.len() =>
                    {
                        Value::Bytes(value.clone())
                    }
                    (Type::Cap(kind), Literal::Cap(found, id)) if kind == found => {
                        Value::Cap(*kind, *id)
                    }
                    _ => return None,
                };
                cursor += 1;
                out.push(values.push(value));
            }
        }
    }
    Some((out.pop().expect("machine value root"), cursor))
}
