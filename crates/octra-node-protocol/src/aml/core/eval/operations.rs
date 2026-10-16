// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_eval operations and dynamic integer metering.
use super::{
    host_length,
    machine::{Binary, Unary},
    Action, Arc, Atom, BigInt, Done, Error, Evaluator, IntegerOp, Natural, Relation, Result,
    Signed, Value, ValueId, Zero,
};
impl Evaluator<'_> {
    fn equal_charge(&mut self, left: ValueId, right: ValueId) -> Result<()> {
        let mut pending = vec![(left, right)];
        while let Some((left, right)) = pending.pop() {
            match (
                self.values.get(left).clone(),
                self.values.get(right).clone(),
            ) {
                (Value::Int(left), Value::Int(right)) => {
                    self.charge(IntegerOp::Sub.cost(true, 3, &left, &right))?;
                }
                (Value::Vec(left), Value::Vec(right)) if left.len() == right.len() => {
                    pending.extend(left.iter().copied().zip(right.iter().copied()).rev());
                }
                (Value::Pair(la, lb), Value::Pair(ra, rb)) => {
                    pending.push((lb, rb));
                    pending.push((la, ra));
                }
                (Value::Inl(left), Value::Inl(right)) | (Value::Inr(left), Value::Inr(right)) => {
                    pending.push((left, right));
                }
                _ => (),
            }
        }
        Ok(())
    }
    pub(super) fn binary(&mut self, op: Binary, left: Done, right: Done) -> Result<Done> {
        let mut extra = BigInt::zero();
        let mut action = None;
        let value = match op {
            Binary::Pair => self.values.push(Value::Pair(left.value, right.value)),
            Binary::Integer(op) => {
                let (Value::Int(a), Value::Int(b)) = (
                    self.values.get(left.value).clone(),
                    self.values.get(right.value).clone(),
                ) else {
                    return Err(Error::NeedInt);
                };
                let reject = match op {
                    IntegerOp::Div => Error::DivideZero,
                    IntegerOp::Mod => Error::ModuloZero,
                    _ => Error::NeedInt,
                };
                let value = self.integer(op, reject, &a, &b)?;
                self.values.integer(value)
            }
            Binary::Equal(typ) => {
                self.equal_charge(left.value, right.value)?;
                let same = self.values.equal(left.value, right.value);
                extra = self
                    .values
                    .value_work(self.types, typ, left.value)
                    .max(self.values.value_work(self.types, typ, right.value));
                let value = self.values.push(Value::Bool(same));
                let mut done = self.sequence(left, right, value);
                done.work += extra;
                return Ok(done);
            }
            Binary::Compare(relation) => {
                let (Value::Int(a), Value::Int(b)) = (
                    self.values.get(left.value).clone(),
                    self.values.get(right.value).clone(),
                ) else {
                    return Err(Error::NeedInt);
                };
                self.charge(IntegerOp::Sub.cost(true, 3, &a, &b))?;
                let value = match relation {
                    Relation::Lt => a < b,
                    Relation::Le => a <= b,
                    Relation::Gt => a > b,
                    Relation::Ge => a >= b,
                };
                self.values.push(Value::Bool(value))
            }
            Binary::Cat => {
                let (Value::Bytes(a), Value::Bytes(b)) =
                    (self.values.get(left.value), self.values.get(right.value))
                else {
                    return Err(Error::NeedBytes);
                };
                let mut raw = Vec::with_capacity(a.len() + b.len());
                raw.extend_from_slice(a);
                raw.extend_from_slice(b);
                extra = BigInt::from(host_length(raw.len())?.get());
                self.values.push(Value::Bytes(raw.into()))
            }
            Binary::Vcat => {
                let (Value::Vec(a), Value::Vec(b)) =
                    (self.values.get(left.value), self.values.get(right.value))
                else {
                    return Err(Error::NeedVector);
                };
                let mut values = Vec::with_capacity(a.len() + b.len());
                values.extend_from_slice(a);
                values.extend_from_slice(b);
                extra = BigInt::from(host_length(values.len())?.get());
                self.values.push(Value::Vec(values.into()))
            }
            Binary::Step => {
                let Value::Cap(kind, id) = self.values.get(left.value) else {
                    return Err(Error::NeedCapability);
                };
                action = Some(Action::held(Atom::Write(*kind), right.value, *kind, *id));
                self.values.push(Value::Pair(left.value, right.value))
            }
        };
        let mut done = self.sequence(left, right, value);
        done.steps += &extra;
        done.work += extra;
        if let Some(action) = action {
            let action = self.traces.atom(action);
            done.trace = self.traces.cat(done.trace, action);
        }
        Ok(done)
    }
    pub(super) fn unary(&mut self, op: Unary, mut done: Done) -> Result<Done> {
        let mut extra = BigInt::zero();
        match op {
            Unary::Fst | Unary::Snd => {
                let Value::Pair(left, right) = self.values.get(done.value) else {
                    return Err(Error::NeedPair);
                };
                done.value = if matches!(op, Unary::Fst) {
                    *left
                } else {
                    *right
                };
            }
            Unary::Inl => done.value = self.values.push(Value::Inl(done.value)),
            Unary::Inr => done.value = self.values.push(Value::Inr(done.value)),
            Unary::Act(atom) => {
                let action = self.traces.atom(Action::direct(atom, done.value));
                done.trace = self.traces.cat(action, done.trace);
            }
            Unary::Integer(op) => {
                let Value::Int(number) = self.values.get(done.value).clone() else {
                    return Err(Error::NeedInt);
                };
                let result = self.integer(op, Error::NeedInt, &number, &number)?;
                done.value = self.values.integer(result);
            }
            Unary::Fit(target) => {
                let Value::Int(number) = self.values.get(done.value) else {
                    return Err(Error::NeedInt);
                };
                done.value = if self.types.admits(target, number) {
                    self.values.push(Value::Inl(done.value))
                } else {
                    self.values.push(Value::Inr(done.value))
                };
                done.steps += 1;
                done.work += 12;
                return Ok(done);
            }
            Unary::Wide => {
                if !matches!(self.values.get(done.value), Value::Int(_)) {
                    return Err(Error::NeedInt);
                }
            }
            Unary::Length => {
                let Value::Pair(length, vector) = self.values.get(done.value) else {
                    return Err(Error::NeedSequence);
                };
                let (Value::Int(number), Value::Vec(items)) =
                    (self.values.get(*length), self.values.get(*vector))
                else {
                    return Err(Error::NeedSequence);
                };
                if number.is_negative() || **number > BigInt::from(items.len()) {
                    return Err(Error::NeedSequence);
                }
                done.value = *length;
            }
            Unary::Take(length) | Unary::Drop(length) => {
                let Value::Bytes(raw) = self.values.get(done.value).clone() else {
                    return Err(Error::NeedBytes);
                };
                let total = host_length(raw.len())?;
                let result = if matches!(op, Unary::Take(_)) {
                    if length > total {
                        return Err(Error::ByteIndex(length, total));
                    }
                    &raw[..length.get() as usize]
                } else {
                    total
                        .checked_sub(length)
                        .ok_or(Error::ByteIndex(length, total))?;
                    &raw[length.get() as usize..]
                };
                extra = BigInt::from(result.len());
                done.value = self.values.push(Value::Bytes(Arc::from(result)));
            }
            Unary::At(index) => {
                let Value::Vec(values) = self.values.get(done.value) else {
                    return Err(Error::NeedVector);
                };
                let length = host_length(values.len())?;
                if index >= length {
                    return Err(Error::VectorIndex(index, length));
                }
                done.value = values[index.get() as usize];
            }
            Unary::Uncons => {
                let Value::Vec(values) = self.values.get(done.value).clone() else {
                    return Err(Error::NeedVector);
                };
                if values.is_empty() {
                    return Err(Error::VectorIndex(
                        Natural::from_u32(0).expect("native zero"),
                        host_length(values.len())?,
                    ));
                }
                let length = host_length(values.len() - 1)?;
                let tail = self.values.push(Value::Vec(values[1..].to_vec().into()));
                done.value = self.values.push(Value::Pair(values[0], tail));
                extra = BigInt::from(length.get());
            }
            Unary::Close => {
                let Value::Cap(kind, id) = self.values.get(done.value) else {
                    return Err(Error::NeedCapability);
                };
                let (kind, id) = (*kind, *id);
                let unit = self.values.push(Value::Unit);
                let action = self
                    .traces
                    .atom(Action::held(Atom::Close(kind), unit, kind, id));
                done.trace = self.traces.cat(done.trace, action);
                done.value = unit;
            }
        }
        done.steps += extra.clone() + 1;
        done.work += extra + 1;
        Ok(done)
    }
}
