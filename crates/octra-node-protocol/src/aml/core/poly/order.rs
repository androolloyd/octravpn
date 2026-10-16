// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{types, Ordering, Types};
use types::{Type, TypeId};
fn tag(typ: &Type) -> u8 {
    match typ {
        Type::Unit => 0,
        Type::Bool => 1,
        Type::Int => 2,
        Type::Num(..) => 3,
        Type::Bytes(_) => 4,
        Type::Vec(..) => 5,
        Type::Seq(..) => 6,
        Type::Cap(_) => 7,
        Type::Enc(..) => 8,
        Type::Pair(..) => 9,
        Type::Sum(..) => 10,
    }
}
pub(super) fn typ(types: &Types, left: TypeId, right: TypeId) -> Ordering {
    let mut pending = vec![(left, right)];
    while let Some((left, right)) = pending.pop() {
        let (left, right) = (types.get(left), types.get(right));
        let order = tag(left).cmp(&tag(right));
        if order != Ordering::Equal {
            return order;
        }
        let order = match (left, right) {
            (Type::Unit, Type::Unit) | (Type::Bool, Type::Bool) | (Type::Int, Type::Int) => {
                Ordering::Equal
            }
            (Type::Num(ls, lb), Type::Num(rs, rb)) => ls.cmp(rs).then_with(|| lb.cmp(rb)),
            (Type::Bytes(lhs), Type::Bytes(rhs)) | (Type::Cap(lhs), Type::Cap(rhs)) => lhs.cmp(rhs),
            (Type::Enc(lk, lr), Type::Enc(rk, rr)) => lk.cmp(rk).then_with(|| lr.cmp(rr)),
            (Type::Vec(ln, lhs), Type::Vec(rn, rhs)) | (Type::Seq(ln, lhs), Type::Seq(rn, rhs)) => {
                pending.push((*lhs, *rhs));
                ln.cmp(rn)
            }
            (Type::Pair(la, lb), Type::Pair(ra, rb)) | (Type::Sum(la, lb), Type::Sum(ra, rb)) => {
                pending.push((*lb, *rb));
                pending.push((*la, *ra));
                Ordering::Equal
            }
            _ => unreachable!("equal C_type tags"),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}
