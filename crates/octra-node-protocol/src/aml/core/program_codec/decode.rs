// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Raw C_pbin term reconstruction uses the native term fuel. Vector cons
//! spines do not consume additional term depth; their elements share next fuel.
use super::{
    bind_get, fields, number, relation_get, Atom, BigInt, Bind, Code, CodeId, Codes, Field, Fold,
    Natural, Relation, Term, TermId, Terms, ToPrimitive, Type, TypeId, Types, Zero, LOCAL,
};
enum Kind {
    Plain(u32),
    Typed(u32, TypeId),
    Natural(u32, Natural),
    Let(Bind),
    Unpair(Bind, Bind),
    Case(Bind, Bind),
    Act(Atom),
    Fold(Bind, Bind),
    Compare(Relation),
    Vec(TypeId),
    Seq(Natural, TypeId),
}
enum Task {
    Visit(CodeId, usize),
    Finish(Kind, usize),
}
fn list(codes: &Codes, mut id: CodeId, maximum: usize) -> Option<Vec<CodeId>> {
    let mut out = vec![];
    loop {
        match codes.get(id) {
            Code::Nil => return Some(out),
            Code::Cons(first, rest) if out.len() < maximum => {
                out.push(*first);
                id = *rest;
            }
            _ => return None,
        }
    }
}
pub(super) fn term(
    codes: &Codes,
    types: &mut Types,
    terms: &mut Terms,
    root: CodeId,
) -> Option<TermId> {
    let mut pending = vec![Task::Visit(root, LOCAL.get(Field::TermDepth) as usize + 1)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        let (id, fuel) = match task {
            Task::Visit(id, fuel) if fuel > 0 => (id, fuel),
            Task::Visit(_, _) => return None,
            Task::Finish(kind, count) => {
                let children = out.split_off(out.len() - count);
                let c = children.as_slice();
                let term = match kind {
                    Kind::Plain(5) => Term::If(c[0], c[1], c[2]),
                    Kind::Plain(6) => Term::Pair(c[0], c[1]),
                    Kind::Plain(8) => Term::Fst(c[0]),
                    Kind::Plain(9) => Term::Snd(c[0]),
                    Kind::Plain(14) => Term::Add(c[0], c[1]),
                    Kind::Plain(16) => Term::Cat(c[0], c[1]),
                    Kind::Plain(20) => Term::Vcat(c[0], c[1]),
                    Kind::Plain(22) => Term::Uncons(c[0]),
                    Kind::Plain(24) => Term::Step(c[0], c[1]),
                    Kind::Plain(25) => Term::Close(c[0]),
                    Kind::Plain(26) => Term::Sub(c[0], c[1]),
                    Kind::Plain(27) => Term::Mul(c[0], c[1]),
                    Kind::Plain(28) => Term::Div(c[0], c[1]),
                    Kind::Plain(29) => Term::Mod(c[0], c[1]),
                    Kind::Plain(30) => Term::Neg(c[0]),
                    Kind::Plain(31) => Term::Abs(c[0]),
                    Kind::Plain(36) => Term::Wide(c[0]),
                    Kind::Plain(37) => Term::Length(c[0]),
                    Kind::Typed(10, typ) => Term::Inl(c[0], typ),
                    Kind::Typed(11, typ) => Term::Inr(typ, c[0]),
                    Kind::Typed(15, typ) => Term::Eq(typ, c[0], c[1]),
                    Kind::Typed(35, typ) => Term::Fit(typ, c[0]),
                    Kind::Natural(17, value) => Term::Take(value, c[0]),
                    Kind::Natural(18, value) => Term::Drop(value, c[0]),
                    Kind::Natural(21, value) => Term::At(value, c[0]),
                    Kind::Let(bind) => Term::Let(bind, c[0], c[1]),
                    Kind::Unpair(first, second) => Term::Unpair(c[0], first, second, c[1]),
                    Kind::Case(first, second) => Term::Case(c[0], first, c[1], second, c[2]),
                    Kind::Act(atom) => Term::Act(atom, c[0]),
                    Kind::Fold(item, state) => Term::Vfold(
                        c[0],
                        c[1],
                        Fold {
                            item,
                            state,
                            body: c[2],
                        },
                    ),
                    Kind::Compare(rel) => Term::Cmp(rel, c[0], c[1]),
                    Kind::Vec(elem) => Term::Vec(elem, children),
                    Kind::Seq(capacity, elem) => Term::Seq(capacity, elem, children),
                    _ => return None,
                };
                out.push(terms.push(term));
                continue;
            }
        };
        let next = fuel - 1;
        let Code::Tag(tag, body) = codes.get(id) else {
            return None;
        };
        let tag = tag.to_u32()?;
        let (kind, children) = match tag {
            0 => {
                let [value, typ] = fields::<2>(codes, *body)?;
                let typ = codes.type_get(types, typ)?;
                let Code::Tag(tag, value) = codes.get(value) else {
                    return None;
                };
                let term = match (tag.to_u32()?, types.get(typ), codes.get(*value)) {
                    (0, Type::Unit, Code::Nil) => Term::Unit,
                    (1, Type::Bool, Code::Num(bit)) if bit.is_zero() => Term::Bool(false),
                    (1, Type::Bool, Code::Num(bit)) if **bit == BigInt::from(1) => Term::Bool(true),
                    (2, Type::Int, Code::Int(value)) => Term::Int((**value).clone()),
                    _ => return None,
                };
                out.push(terms.push(term));
                continue;
            }
            1 => {
                let raw = codes.bytes_get(*body)?;
                out.push(terms.push(Term::Bytes(raw)));
                continue;
            }
            2 | 19 => {
                let mut spine = id;
                let mut children = vec![];
                let elem = loop {
                    if children.len() > LOCAL.get(Field::TermNodes) as usize {
                        return None;
                    }
                    let Code::Tag(tag, body) = codes.get(spine) else {
                        return None;
                    };
                    match tag.to_u32()? {
                        2 => break codes.type_get(types, *body)?,
                        19 => {
                            let [first, rest] = fields::<2>(codes, *body)?;
                            children.push(first);
                            spine = rest;
                        }
                        _ => return None,
                    }
                };
                (Kind::Vec(elem), children)
            }
            3 => {
                let id = number(codes, *body)?;
                out.push(terms.push(Term::Var(id)));
                continue;
            }
            4 => {
                let [bind, value, body] = fields::<3>(codes, *body)?;
                (Kind::Let(bind_get(codes, types, bind)?), vec![value, body])
            }
            5 => (Kind::Plain(5), fields::<3>(codes, *body)?.to_vec()),
            6 | 14 | 16 | 20 | 24 | 26 | 27 | 28 | 29 => {
                (Kind::Plain(tag), fields::<2>(codes, *body)?.to_vec())
            }
            7 => {
                let [pair, first, second, body] = fields::<4>(codes, *body)?;
                (
                    Kind::Unpair(
                        bind_get(codes, types, first)?,
                        bind_get(codes, types, second)?,
                    ),
                    vec![pair, body],
                )
            }
            8 | 9 | 22 | 25 | 30 | 31 | 36 | 37 => (Kind::Plain(tag), vec![*body]),
            10 => {
                let [value, other] = fields::<2>(codes, *body)?;
                (Kind::Typed(10, codes.type_get(types, other)?), vec![value])
            }
            11 | 35 => {
                let [typ, value] = fields::<2>(codes, *body)?;
                (Kind::Typed(tag, codes.type_get(types, typ)?), vec![value])
            }
            12 => {
                let [value, first, yes, second, no] = fields::<5>(codes, *body)?;
                (
                    Kind::Case(
                        bind_get(codes, types, first)?,
                        bind_get(codes, types, second)?,
                    ),
                    vec![value, yes, no],
                )
            }
            13 => {
                let [action, body] = fields::<2>(codes, *body)?;
                (Kind::Act(codes.atom_get(action)?), vec![body])
            }
            15 => {
                let [typ, first, second] = fields::<3>(codes, *body)?;
                (
                    Kind::Typed(15, codes.type_get(types, typ)?),
                    vec![first, second],
                )
            }
            17 | 18 | 21 => {
                let [number_code, value] = fields::<2>(codes, *body)?;
                (Kind::Natural(tag, number(codes, number_code)?), vec![value])
            }
            23 => {
                let [len, vector, seed, item, state, body] = fields::<6>(codes, *body)?;
                // The raw getter only checks the Num constructor. Canonical
                // re-encoding later binds this field to the actual vector length.
                if !matches!(codes.get(len), Code::Num(_)) {
                    return None;
                }
                (
                    Kind::Fold(
                        bind_get(codes, types, item)?,
                        bind_get(codes, types, state)?,
                    ),
                    vec![vector, seed, body],
                )
            }
            32 => {
                let [rel, first, second] = fields::<3>(codes, *body)?;
                (
                    Kind::Compare(relation_get(codes, rel)?),
                    vec![first, second],
                )
            }
            33 => {
                let [typ, value] = fields::<2>(codes, *body)?;
                let typ = codes.type_get(types, typ)?;
                let Code::Int(value) = codes.get(value) else {
                    return None;
                };
                if !types.admits(typ, value) {
                    return None;
                }
                out.push(terms.push(Term::Narrow(typ, (**value).clone())));
                continue;
            }
            34 => {
                let [capacity, elem, values] = fields::<3>(codes, *body)?;
                let capacity = number(codes, capacity)?;
                let elem = codes.type_get(types, elem)?;
                let children = list(codes, values, LOCAL.get(Field::TermNodes) as usize)?;
                if children.len() > capacity.get() as usize {
                    return None;
                }
                (Kind::Seq(capacity, elem), children)
            }
            _ => return None,
        };
        pending.push(Task::Finish(kind, children.len()));
        pending.extend(
            children
                .into_iter()
                .rev()
                .map(|child| Task::Visit(child, next)),
        );
    }
    out.pop()
}
