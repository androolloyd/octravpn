// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    types, Arc, Asm, BigInt, Context, Core, Error, Layout, Literal, Op, Span, State, Type,
};
impl Context<'_> {
    pub(super) fn linear(&mut self, state: &mut State, at: Span, op: &Core) -> Result<(), Error> {
        match op {
            Core::Push(value) => {
                let dst = state.generator.fresh()?;
                self.push(state, Layout::Atom(dst));
                Self::ops(state, at, [Op::Load(dst, value.clone())]);
            }
            Core::Void => self.push(state, Layout::Unit),
            Core::Get(id, form) => {
                let moves = state.env.moves_sequence(self.types, *id);
                let src = state.env.take(*id).ok_or(Error::Slot)?;
                if !self.layouts.fits(&self.shapes, *form, src) {
                    return Err(Error::Stack);
                }
                if moves {
                    state.stack.push(src);
                } else {
                    let (dst, moves) = self.layouts.clone_layout(src, &mut state.generator)?;
                    state.stack.push(dst);
                    Self::ops(
                        state,
                        at,
                        moves.into_iter().map(|(dst, src)| Op::Move(dst, src)),
                    );
                }
            }
            Core::Plus
            | Core::Minus
            | Core::Times
            | Core::Quot
            | Core::Rem
            | Core::Same
            | Core::Different
            | Core::Order(_)
            | Core::Join => {
                let right = self.pop(state)?;
                let right = self.atom(right)?;
                let left = self.pop(state)?;
                let left = self.atom(left)?;
                state.generator.release(right);
                self.push(state, Layout::Atom(left));
                let ops = match op {
                    Core::Plus => vec![Op::Plus(left, left, right)],
                    Core::Minus => vec![Op::Minus(left, left, right)],
                    Core::Times => vec![Op::Times(left, left, right)],
                    Core::Quot => vec![Op::Quotient(left, left, right)],
                    Core::Rem => vec![Op::Remainder(left, left, right)],
                    Core::Same => vec![Op::Same(left, left, right)],
                    Core::Different => vec![Op::Different(left, left, right)],
                    Core::Join => vec![Op::Join(left, left, right)],
                    Core::Order(rel) => match rel {
                        super::super::super::term::Relation::Lt => {
                            vec![Op::Less(left, left, right)]
                        }
                        super::super::super::term::Relation::Gt => {
                            vec![Op::Greater(left, left, right)]
                        }
                        super::super::super::term::Relation::Le => vec![
                            Op::Greater(left, left, right),
                            Op::Load(right, Literal::Bool(false)),
                            Op::Same(left, left, right),
                        ],
                        super::super::super::term::Relation::Ge => vec![
                            Op::Less(left, left, right),
                            Op::Load(right, Literal::Bool(false)),
                            Op::Same(left, left, right),
                        ],
                    },
                    _ => unreachable!("binary machine operation"),
                };
                Self::ops(state, at, ops);
            }
            Core::Negate | Core::Absolute => {
                let reg = self.atom(*state.stack.last().ok_or(Error::Stack)?)?;
                Self::ops(
                    state,
                    at,
                    [if matches!(op, Core::Negate) {
                        Op::Negate(reg, reg)
                    } else {
                        Op::Absolute(reg, reg)
                    }],
                );
            }
            Core::Clip(length) | Core::Skip(length) => {
                let src = self.atom(*state.stack.last().ok_or(Error::Stack)?)?;
                let first = state.generator.fresh()?;
                let count = state.generator.fresh()?;
                state.generator.release(first);
                state.generator.release(count);
                if matches!(op, Core::Clip(_)) {
                    Self::ops(
                        state,
                        at,
                        [
                            Op::Load(first, integer(0)),
                            Op::Load(count, integer(length.get())),
                            Op::Slice(src, src, first, count),
                        ],
                    );
                } else {
                    Self::ops(
                        state,
                        at,
                        [
                            Op::Load(first, integer(length.get())),
                            Op::Size(count, src),
                            Op::Minus(count, count, first),
                            Op::Slice(src, src, first, count),
                        ],
                    );
                }
            }
            Core::Duo => {
                let right = self.pop(state)?;
                let left = self.pop(state)?;
                self.push(state, Layout::Pair(left, right));
            }
            Core::First | Core::Second => {
                let value = self.pop(state)?;
                let Layout::Pair(left, right) = self.layouts.get(value).clone() else {
                    return Err(Error::Stack);
                };
                let (take, drop) = if matches!(op, Core::First) {
                    (left, right)
                } else {
                    (right, left)
                };
                self.layouts.release(drop, &mut state.generator);
                state.stack.push(take);
            }
            Core::Empty(elem) => {
                let empty = self.layouts.vectors.array(vec![]);
                self.push(state, Layout::Vec(*elem, empty));
            }
            Core::Cons => {
                let vector = self.pop(state)?;
                let first = self.pop(state)?;
                let Layout::Vec(elem, values) = self.layouts.get(vector).clone() else {
                    return Err(Error::Stack);
                };
                if !self.layouts.fits(&self.shapes, elem, first) {
                    return Err(Error::Stack);
                }
                let out = self.layouts.vectors.cons(first, values);
                self.push(state, Layout::Vec(elem, out));
            }
            Core::Append => {
                let right = self.pop(state)?;
                let left = self.pop(state)?;
                let (Layout::Vec(re, right), Layout::Vec(le, left)) = (
                    self.layouts.get(right).clone(),
                    self.layouts.get(left).clone(),
                ) else {
                    return Err(Error::Stack);
                };
                if le != re {
                    return Err(Error::Stack);
                }
                let out = self.layouts.vectors.append(left, right);
                self.push(state, Layout::Vec(le, out));
            }
            Core::Pick(index) => {
                let vector = self.pop(state)?;
                let Layout::Vec(_, values) = self.layouts.get(vector) else {
                    return Err(Error::Stack);
                };
                let values = self.layouts.vectors.collect(*values);
                state.stack.push(
                    self.layouts
                        .pick(index.get() as usize, &values, &mut state.generator)
                        .ok_or(Error::Stack)?,
                );
            }
            Core::Unhead => {
                let vector = self.pop(state)?;
                let Layout::Vec(elem, values) = self.layouts.get(vector).clone() else {
                    return Err(Error::Stack);
                };
                let (first, values) = self.layouts.vectors.uncons(values).ok_or(Error::Stack)?;
                let tail = self.layouts.push(Layout::Vec(elem, values));
                self.push(state, Layout::Pair(first, tail));
            }
            Core::Left | Core::Right => {
                let payload = self.pop(state)?;
                let tag = state.generator.fresh()?;
                self.push(state, Layout::Sum(tag, payload));
                Self::ops(
                    state,
                    at,
                    [Op::Load(tag, Literal::Bool(matches!(op, Core::Left)))],
                );
            }
            Core::Pack(capacity, typ) => {
                let vector = self.pop(state)?;
                let Layout::Vec(form, values) = self.layouts.get(vector).clone() else {
                    return Err(Error::Stack);
                };
                let expected = self
                    .shapes
                    .from_type(self.types, *typ)
                    .ok_or(Error::Stack)?;
                let count = self.layouts.vectors.len(values);
                if count > capacity.get() as usize || form != expected {
                    return Err(Error::Stack);
                }
                let length = state.generator.fresh()?;
                // Native load_zeros requests a default even when no padding is needed.
                let zero = self.values.zero(self.types, *typ).ok_or(Error::Stack)?;
                Self::ops(state, at, [Op::Load(length, integer(count))]);
                let mut pad = vec![];
                for _ in count..capacity.get() as usize {
                    pad.push(self.load_value(state, at, *typ, zero)?);
                }
                let pad = self.layouts.vectors.array(pad);
                let out = self.layouts.vectors.append(values, pad);
                let len = self.layouts.push(Layout::Atom(length));
                let vector = self.layouts.push(Layout::Vec(form, out));
                self.push(state, Layout::Pair(len, vector));
            }
            Core::Fit(typ) => {
                let value = self.pop(state)?;
                let value_reg = self.atom(value)?;
                let Type::Num(sign, bits) = self.types.get(*typ) else {
                    return Err(Error::Stack);
                };
                let (low, high) = types::range(*sign, *bits).ok_or(Error::Stack)?;
                let tag = state.generator.fresh()?;
                let scratch = state.generator.fresh()?;
                let low_at = state.generator.fresh_label()?;
                let bad_at = state.generator.fresh_label()?;
                let done_at = state.generator.fresh_label()?;
                state.generator.release(scratch);
                self.push(state, Layout::Sum(tag, value));
                Self::ops(
                    state,
                    at,
                    [
                        Op::Load(scratch, integer(low)),
                        Op::Less(tag, value_reg, scratch),
                    ],
                );
                Self::emit(state, at, Asm::Branch(tag, low_at));
                Self::ops(
                    state,
                    at,
                    [
                        Op::Load(scratch, integer(high)),
                        Op::Greater(tag, value_reg, scratch),
                    ],
                );
                Self::emit(state, at, Asm::Branch(tag, bad_at));
                Self::ops(state, at, [Op::Load(tag, Literal::Bool(true))]);
                Self::emit(state, at, Asm::Goto(done_at));
                Self::emit(state, at, Asm::Place(low_at));
                Self::ops(state, at, (0..7).map(|_| Op::Noop));
                Self::emit(state, at, Asm::Place(bad_at));
                Self::ops(state, at, [Op::Load(tag, Literal::Bool(false))]);
                Self::emit(state, at, Asm::Place(done_at));
            }
            Core::Wide => {
                self.atom(*state.stack.last().ok_or(Error::Stack)?)?;
                Self::ops(state, at, [Op::Noop]);
            }
            Core::Close(kind) => {
                let value = self.pop(state)?;
                let reg = self.atom(value)?;
                state.generator.release(reg);
                self.push(state, Layout::Unit);
                Self::ops(state, at, [Op::CapClose(*kind, reg)]);
            }
            _ => return Err(Error::Map),
        }
        Ok(())
    }
}
pub(super) fn integer(value: impl Into<BigInt>) -> Literal {
    Literal::Int(Arc::new(value.into()))
}
