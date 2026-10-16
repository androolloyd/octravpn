// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_print bounded, iterative core-term diagnostics.
use super::{
    eval::{self, Value, Values},
    term::{Bind, Relation, Term, TermId, Terms},
    text::Text,
    types::{Type, Types},
    Natural,
};
use std::sync::Arc;

enum Part<'a> {
    Term(TermId),
    Text(Vec<u8>),
    Terms(&'a [TermId]),
}
fn text(value: &[u8]) -> Part<'_> {
    Part::Text(value.to_vec())
}
fn var(value: Natural) -> Vec<u8> {
    format!("v{}", value.get()).into_bytes()
}
fn bind(types: &Types, value: Bind) -> Vec<u8> {
    [
        value.multiplicity.text(),
        b" ",
        &var(value.id),
        b" : ",
        &types.text(value.typ),
    ]
    .concat()
}
fn push<'a, const N: usize>(pending: &mut Vec<Part<'a>>, values: [Part<'a>; N]) {
    pending.extend(values.into_iter().rev());
}
pub fn term(types: &Types, terms: &Terms, root: TermId) -> Vec<u8> {
    let mut out = Text::default();
    let mut pending = vec![Part::Term(root)];
    while let Some(part) = pending.pop() {
        if out.full() {
            break;
        }
        let value = match part {
            Part::Text(value) => {
                out.add(&value);
                continue;
            }
            Part::Terms(values) => {
                if let Some((first, rest)) = values.split_first() {
                    if rest.is_empty() {
                        pending.push(Part::Term(*first));
                    } else {
                        push(
                            &mut pending,
                            [Part::Term(*first), text(b", "), Part::Terms(rest)],
                        );
                    }
                }
                continue;
            }
            Part::Term(id) => terms.get(id),
        };
        match value {
            Term::Unit => out.add(b"()"),
            Term::Bool(true) => out.add(b"true"),
            Term::Bool(false) => out.add(b"false"),
            Term::Int(value) => out.add(&eval::int_text(value)),
            Term::Narrow(typ, value) => {
                out.add(&[b"(narrow ".as_slice(), &types.text(*typ), b" "].concat());
                out.add(&eval::int_text(value));
                pending.push(text(b")"));
            }
            Term::Bytes(value) => {
                let mut values = Values::default();
                let id = values.push(Value::Bytes(Arc::from(value.as_slice())));
                out.add(&values.text(id));
            }
            Term::Vec(typ, values) => {
                out.add(&[b"(vec<".as_slice(), &types.text(*typ), b"> ["].concat());
                push(&mut pending, [Part::Terms(values), text(b"])")]);
            }
            Term::Seq(cap, typ, values) => {
                out.add(
                    &[
                        format!("(seq<{},", cap.get()).as_bytes(),
                        &types.text(*typ),
                        b"> [",
                    ]
                    .concat(),
                );
                push(&mut pending, [Part::Terms(values), text(b"])")]);
            }
            Term::Var(id) => out.add(&var(*id)),
            Term::Let(binding, value, body) => {
                out.add(&[b"(let ".as_slice(), &bind(types, *binding), b" = "].concat());
                push(
                    &mut pending,
                    [
                        Part::Term(*value),
                        text(b" in "),
                        Part::Term(*body),
                        text(b")"),
                    ],
                );
            }
            Term::If(guard, yes, no) => {
                out.add(b"(if ");
                push(
                    &mut pending,
                    [
                        Part::Term(*guard),
                        text(b" then "),
                        Part::Term(*yes),
                        text(b" else "),
                        Part::Term(*no),
                        text(b")"),
                    ],
                );
            }
            Term::Pair(left, right) => {
                out.add(b"(");
                push(
                    &mut pending,
                    [
                        Part::Term(*left),
                        text(b", "),
                        Part::Term(*right),
                        text(b")"),
                    ],
                );
            }
            Term::Unpair(pair, left, right, body) => {
                out.add(
                    &[
                        b"(let (".as_slice(),
                        &var(left.id),
                        b", ",
                        &var(right.id),
                        b") = ",
                    ]
                    .concat(),
                );
                push(
                    &mut pending,
                    [
                        Part::Term(*pair),
                        text(b" in "),
                        Part::Term(*body),
                        text(b")"),
                    ],
                );
            }
            Term::Fst(child) | Term::Snd(child) => {
                out.add(if matches!(value, Term::Fst(_)) {
                    b"(fst "
                } else {
                    b"(snd "
                });
                push(&mut pending, [Part::Term(*child), text(b")")]);
            }
            Term::Inl(value, right) => {
                out.add(b"(inl ");
                push(
                    &mut pending,
                    [
                        Part::Term(*value),
                        Part::Text([b" : ".as_slice(), &types.text(*right), b")"].concat()),
                    ],
                );
            }
            Term::Inr(left, value) => {
                out.add(&[b"(inr ".as_slice(), &types.text(*left), b" : "].concat());
                push(&mut pending, [Part::Term(*value), text(b")")]);
            }
            Term::Case(value, left, yes, right, no) => {
                out.add(b"(case ");
                push(
                    &mut pending,
                    [
                        Part::Term(*value),
                        Part::Text([b" of inl ".as_slice(), &var(left.id), b" -> "].concat()),
                        Part::Term(*yes),
                        Part::Text([b" | inr ".as_slice(), &var(right.id), b" -> "].concat()),
                        Part::Term(*no),
                        text(b")"),
                    ],
                );
            }
            Term::Act(atom, body) => {
                out.add(&[b"(".as_slice(), &super::atom_text(*atom), b"; "].concat());
                push(&mut pending, [Part::Term(*body), text(b")")]);
            }
            Term::Add(left, right)
            | Term::Sub(left, right)
            | Term::Mul(left, right)
            | Term::Div(left, right)
            | Term::Mod(left, right) => {
                let op = match value {
                    Term::Add(..) => b" + ",
                    Term::Sub(..) => b" - ",
                    Term::Mul(..) => b" * ",
                    Term::Div(..) => b" / ",
                    _ => b" % ",
                };
                out.add(b"(");
                push(
                    &mut pending,
                    [Part::Term(*left), text(op), Part::Term(*right), text(b")")],
                );
            }
            Term::Neg(child)
            | Term::Abs(child)
            | Term::Wide(child)
            | Term::Length(child)
            | Term::Uncons(child)
            | Term::Close(child) => {
                out.add(match value {
                    Term::Neg(_) => b"(-",
                    Term::Abs(_) => b"abs(",
                    Term::Wide(_) => b"(wide ",
                    Term::Length(_) => b"(length ",
                    Term::Uncons(_) => b"(uncons ",
                    _ => b"(close ",
                });
                push(&mut pending, [Part::Term(*child), text(b")")]);
            }
            Term::Fit(typ, value) => {
                out.add(&[b"(fit ".as_slice(), &types.text(*typ), b" "].concat());
                push(&mut pending, [Part::Term(*value), text(b")")]);
            }
            Term::Eq(typ, left, right) => {
                let int = matches!(types.get(*typ), Type::Int);
                if int {
                    out.add(b"(");
                } else {
                    out.add(&[b"equal[".as_slice(), &types.text(*typ), b"]("].concat());
                }
                push(
                    &mut pending,
                    [
                        Part::Term(*left),
                        text(if int { b" == " } else { b", " }),
                        Part::Term(*right),
                        text(b")"),
                    ],
                );
            }
            Term::Cmp(rel, left, right) => {
                let op: &[u8] = match rel {
                    Relation::Lt => b" < ",
                    Relation::Le => b" <= ",
                    Relation::Gt => b" > ",
                    Relation::Ge => b" >= ",
                };
                out.add(b"(");
                push(
                    &mut pending,
                    [Part::Term(*left), text(op), Part::Term(*right), text(b")")],
                );
            }
            Term::Cat(left, right) | Term::Vcat(left, right) | Term::Step(left, right) => {
                out.add(match value {
                    Term::Cat(..) => b"(cat ",
                    Term::Vcat(..) => b"(vcat ",
                    _ => b"(step ",
                });
                push(
                    &mut pending,
                    [
                        Part::Term(*left),
                        text(b" "),
                        Part::Term(*right),
                        text(b")"),
                    ],
                );
            }
            Term::Take(size, child) | Term::Drop(size, child) | Term::At(size, child) => {
                let op = match value {
                    Term::Take(..) => "take",
                    Term::Drop(..) => "drop",
                    _ => "at",
                };
                out.add(format!("({op} {} ", size.get()).as_bytes());
                push(&mut pending, [Part::Term(*child), text(b")")]);
            }
            Term::Vfold(vector, seed, fold) => {
                out.add(b"(vfold ");
                push(
                    &mut pending,
                    [
                        Part::Term(*vector),
                        text(b" from "),
                        Part::Term(*seed),
                        Part::Text(
                            [
                                b" with ".as_slice(),
                                &bind(types, fold.item),
                                b", ",
                                &bind(types, fold.state),
                                b" -> ",
                            ]
                            .concat(),
                        ),
                        Part::Term(fold.body),
                        text(b")"),
                    ],
                );
            }
        }
    }
    out.finish()
}
