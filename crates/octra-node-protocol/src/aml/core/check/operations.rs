// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_check scalar, aggregate and capability operation rules.
use super::{
    infer::{Binary, Unary},
    Atom, BigInt, Checker, Error, Info, Kind, Limit, Natural, Origin, Result, Site, Type,
};
impl Checker<'_> {
    pub(super) fn binary(&mut self, op: Binary, left: Info, right: Info) -> Result<Info> {
        Ok(match op {
            Binary::Pair => {
                let typ = self.types.intern(Type::Pair(left.typ, right.typ));
                self.sequence(typ, left, right)
            }
            Binary::Arithmetic | Binary::Compare => {
                let integer = self.integer();
                self.need(integer, right.typ)?;
                let typ = if matches!(op, Binary::Compare) {
                    self.boolean()
                } else {
                    integer
                };
                self.sequence(typ, left, right)
            }
            Binary::Equal(typ) => {
                self.need(typ, left.typ)?;
                self.need(typ, right.typ)?;
                if !self.types.equatable(typ) {
                    return Err(Error::Access(typ));
                }
                let boolean = self.boolean();
                let mut info = self.sequence(boolean, left, right);
                info.resources = info
                    .resources
                    .add(&Limit::effort(self.types.equality_work(typ)));
                info
            }
            Binary::Cat => match (
                self.types.get(left.typ).clone(),
                self.types.get(right.typ).clone(),
            ) {
                (Type::Bytes(left_len), Type::Bytes(right_len)) => {
                    let length = left_len.checked_add(right_len).ok_or(Error::Size)?;
                    let typ = self.types.intern(Type::Bytes(length));
                    self.copy_sequence(typ, length, left, right)
                }
                (Type::Bytes(_), _) => return Err(Error::Need(self.empty_bytes(), right.typ)),
                _ => return Err(Error::Need(self.empty_bytes(), left.typ)),
            },
            Binary::Vcat => match (
                self.types.get(left.typ).clone(),
                self.types.get(right.typ).clone(),
            ) {
                (Type::Vec(left_len, left_elem), Type::Vec(right_len, right_elem)) => {
                    self.need(left_elem, right_elem)?;
                    let length = left_len.checked_add(right_len).ok_or(Error::Size)?;
                    let typ = self.types.intern(Type::Vec(length, left_elem));
                    self.copy_sequence(typ, length, left, right)
                }
                (Type::Vec(..), _) => return Err(Error::Need(self.empty_vector(), right.typ)),
                _ => return Err(Error::Need(self.empty_vector(), left.typ)),
            },
            Binary::Step => {
                let Type::Cap(kind) = self.types.get(left.typ) else {
                    return Err(Error::Need(self.empty_capability(), left.typ));
                };
                let kind = *kind;
                let payload = right.typ;
                let typ = self.types.intern(Type::Pair(left.typ, right.typ));
                let mut info = self.sequence(typ, left, right);
                let atom = Atom::Write(kind);
                let action = self.flows.action(Site {
                    atom,
                    payload,
                    origin: Origin::Held(kind),
                });
                info.effects.insert(atom);
                info.flow = self.flows.sequence(info.flow, action);
                info
            }
        })
    }
    pub(super) fn unary(&mut self, op: Unary, mut info: Info) -> Result<Info> {
        match op {
            Unary::Fst | Unary::Snd => {
                let Type::Pair(left, right) = self.types.get(info.typ).clone() else {
                    return Err(Error::Need(self.unit_pair(), info.typ));
                };
                let (kept, dropped) = if matches!(op, Unary::Fst) {
                    (left, right)
                } else {
                    (right, left)
                };
                if self.types.kind(dropped) == Kind::Resource {
                    return Err(Error::DropResource(dropped));
                }
                info.typ = kept;
                info.resources = info.resources.successor();
            }
            Unary::Inl(right) => {
                info.typ = self.types.intern(Type::Sum(info.typ, right));
                info.resources = info.resources.successor();
            }
            Unary::Inr(left) => {
                info.typ = self.types.intern(Type::Sum(left, info.typ));
                info.resources = info.resources.successor();
            }
            Unary::Act(atom) => {
                let action = self.flows.action(Site {
                    atom,
                    payload: info.typ,
                    origin: Origin::Direct,
                });
                info.effects.insert(atom);
                info.resources = info.resources.successor();
                info.flow = self.flows.sequence(action, info.flow);
            }
            Unary::Negate => {
                let integer = self.integer();
                self.need(integer, info.typ)?;
                info.resources = info.resources.successor();
            }
            Unary::Fit(target) => {
                let integer = self.integer();
                self.need(integer, info.typ)?;
                info.typ = self.types.intern(Type::Sum(target, integer));
                info.resources = info
                    .resources
                    .add(&Limit::used(BigInt::from(1), BigInt::from(12)));
            }
            Unary::Wide => {
                if !matches!(self.types.get(info.typ), Type::Num(..)) {
                    return Err(Error::RangeType(info.typ));
                }
                info.typ = self.integer();
                info.resources = info.resources.successor();
            }
            Unary::Length => {
                if !matches!(self.types.get(info.typ), Type::Seq(..)) {
                    return Err(Error::Need(self.empty_sequence(), info.typ));
                }
                info.typ = self.integer();
                info.resources = info.resources.successor();
            }
            Unary::Take(length) | Unary::Drop(length) => {
                let Type::Bytes(total) = self.types.get(info.typ) else {
                    return Err(Error::Need(self.empty_bytes(), info.typ));
                };
                let total = *total;
                let length = if matches!(op, Unary::Take(_)) {
                    if length > total {
                        return Err(Error::ByteIndex(length, total));
                    }
                    length
                } else {
                    total
                        .checked_sub(length)
                        .ok_or(Error::ByteIndex(length, total))?
                };
                let typ = self.types.intern(Type::Bytes(length));
                info = self.copy_one(typ, length, info);
            }
            Unary::At(index) => {
                let Type::Vec(length, element) = self.types.get(info.typ).clone() else {
                    return Err(Error::Need(self.empty_vector(), info.typ));
                };
                if index >= length {
                    return Err(Error::VecIndex(index, length));
                }
                if self.types.kind(element) == Kind::Resource {
                    return Err(Error::Access(element));
                }
                info.typ = element;
                info.resources = info.resources.successor();
            }
            Unary::Uncons => {
                let Type::Vec(length, element) = self.types.get(info.typ).clone() else {
                    return Err(Error::Need(self.empty_vector(), info.typ));
                };
                let one = Natural::from_u32(1).expect("native one");
                let remaining = length
                    .checked_sub(one)
                    .ok_or_else(|| Error::VecIndex(self.zero(), self.zero()))?;
                let tail = self.types.intern(Type::Vec(remaining, element));
                let typ = self.types.intern(Type::Pair(element, tail));
                info = self.copy_one(typ, remaining, info);
            }
            Unary::Close => {
                let Type::Cap(kind) = self.types.get(info.typ) else {
                    return Err(Error::Need(self.empty_capability(), info.typ));
                };
                let kind = *kind;
                let unit = self.unit();
                let atom = Atom::Close(kind);
                let action = self.flows.action(Site {
                    atom,
                    payload: unit,
                    origin: Origin::Held(kind),
                });
                info.typ = unit;
                info.effects.insert(atom);
                info.resources = info.resources.successor();
                info.flow = self.flows.sequence(info.flow, action);
            }
        }
        Ok(info)
    }
}
