// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    bind_code, relation_code, Arc, BigInt, Bind, CodeId, Codes, Multiplicity, Natural, Term,
    TermId, Terms, Type, TypeId, Types,
};
#[derive(Clone, Default)]
pub(super) struct Env(Arc<Vec<(Natural, TypeId)>>);
impl Env {
    pub(super) fn bind(&self, bind: Bind) -> Self {
        if bind.multiplicity == Multiplicity::Zero {
            return self.clone();
        }
        let mut next = self.0.as_ref().clone();
        next.push((bind.id, bind.typ));
        Self(Arc::new(next))
    }
}
fn vector_length(types: &Types, terms: &Terms, root: TermId, env: &Env) -> Option<Natural> {
    enum Task {
        Visit(TermId),
        Add,
    }
    let mut pending = vec![Task::Visit(root)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        let value = match task {
            Task::Visit(id) => match terms.get(id) {
                Term::Vec(_, items) => Natural::new(&BigInt::from(items.len()))?,
                Term::Seq(capacity, ..) => *capacity,
                Term::Var(id) => {
                    let (_, typ) = env.0.iter().rev().find(|(key, _)| key == id)?;
                    match types.get(*typ) {
                        Type::Vec(length, _) | Type::Seq(length, _) => *length,
                        _ => return None,
                    }
                }
                Term::Vcat(left, right) => {
                    pending.push(Task::Add);
                    pending.push(Task::Visit(*right));
                    pending.push(Task::Visit(*left));
                    continue;
                }
                _ => return None,
            },
            Task::Add => {
                let right: Natural = out.pop()?;
                out.pop()?.checked_add(right)?
            }
        };
        out.push(value);
    }
    out.pop()
}
enum Task {
    Visit(TermId, Env),
    Finish(TermId, usize, Option<Natural>),
}
pub(super) fn term(
    codes: &mut Codes,
    types: &mut Types,
    terms: &Terms,
    root: TermId,
    env: Env,
) -> Option<CodeId> {
    let mut pending = vec![Task::Visit(root, env)];
    let mut out = vec![];
    while let Some(task) = pending.pop() {
        let (id, count, length) = match task {
            Task::Visit(id, env) => {
                let node = terms.get(id);
                let children = node.children();
                let length = if let Term::Vfold(vector, ..) = node {
                    Some(vector_length(types, terms, *vector, &env)?)
                } else {
                    None
                };
                pending.push(Task::Finish(id, children.len(), length));
                let envs = match node {
                    Term::Let(bind, ..) => vec![env.clone(), env.bind(*bind)],
                    Term::Unpair(_, left, right, _) => {
                        vec![env.clone(), env.bind(*left).bind(*right)]
                    }
                    Term::Case(_, left, _, right, _) => {
                        vec![env.clone(), env.bind(*left), env.bind(*right)]
                    }
                    Term::Vfold(_, _, fold) => vec![
                        env.clone(),
                        env.clone(),
                        env.bind(fold.item).bind(fold.state),
                    ],
                    _ => vec![env; children.len()],
                };
                pending.extend(
                    children
                        .into_iter()
                        .zip(envs)
                        .rev()
                        .map(|(id, env)| Task::Visit(id, env)),
                );
                continue;
            }
            Task::Finish(id, count, length) => (id, count, length),
        };
        let children = out.split_off(out.len() - count);
        let node = terms.get(id);
        let (tag, fields) = match node {
            Term::Unit | Term::Bool(_) | Term::Int(_) => {
                let (typ, value) = match node {
                    Term::Unit => (Type::Unit, codes.tag(0, codes.nil())),
                    Term::Bool(value) => {
                        let bit = codes.num(u8::from(*value));
                        (Type::Bool, codes.tag(1, bit))
                    }
                    Term::Int(value) => {
                        let integer = codes.integer(value.clone());
                        (Type::Int, codes.tag(2, integer))
                    }
                    _ => unreachable!(),
                };
                let typ = types.intern(typ);
                let typ = codes.type_code(types, typ);
                (0, vec![value, typ])
            }
            Term::Narrow(typ, value) => {
                let typ = codes.type_code(types, *typ);
                let value = codes.integer(value.clone());
                (33, vec![typ, value])
            }
            Term::Bytes(raw) => {
                let bytes = codes.bytes_code(raw);
                out.push(codes.tag(1, bytes));
                continue;
            }
            Term::Vec(elem, _) => {
                let elem = codes.type_code(types, *elem);
                let mut value = codes.tag(2, elem);
                for child in children.iter().rev() {
                    let fields = codes.list(&[*child, value]);
                    value = codes.tag(19, fields);
                }
                out.push(value);
                continue;
            }
            Term::Seq(capacity, elem, _) => {
                let capacity = codes.num(capacity.get());
                let elem = codes.type_code(types, *elem);
                let items = codes.list(&children);
                (34, vec![capacity, elem, items])
            }
            Term::Var(id) => {
                let id = codes.num(id.get());
                out.push(codes.tag(3, id));
                continue;
            }
            Term::Let(bind, ..) => {
                let bind = bind_code(codes, types, *bind);
                (4, vec![bind, children[0], children[1]])
            }
            Term::If(..) => (5, children),
            Term::Pair(..) => (6, children),
            Term::Unpair(_, first, second, _) => {
                let first = bind_code(codes, types, *first);
                let second = bind_code(codes, types, *second);
                (7, vec![children[0], first, second, children[1]])
            }
            Term::Inl(_, typ) => {
                let typ = codes.type_code(types, *typ);
                (10, vec![children[0], typ])
            }
            Term::Inr(typ, _) => {
                let typ = codes.type_code(types, *typ);
                (11, vec![typ, children[0]])
            }
            Term::Case(_, first, _, second, _) => {
                let first = bind_code(codes, types, *first);
                let second = bind_code(codes, types, *second);
                (
                    12,
                    vec![children[0], first, children[1], second, children[2]],
                )
            }
            Term::Act(atom, _) => {
                let atom = codes.atom_code(*atom);
                (13, vec![atom, children[0]])
            }
            Term::Add(..) => (14, children),
            Term::Eq(typ, ..) => {
                let typ = codes.type_code(types, *typ);
                (15, vec![typ, children[0], children[1]])
            }
            Term::Cat(..) => (16, children),
            Term::Take(number, _) | Term::Drop(number, _) | Term::At(number, _) => {
                let tag = match node {
                    Term::Take(..) => 17,
                    Term::Drop(..) => 18,
                    _ => 21,
                };
                let number = codes.num(number.get());
                (tag, vec![number, children[0]])
            }
            Term::Vcat(..) => (20, children),
            Term::Vfold(_, _, fold) => {
                let length = codes.num(length.expect("fold vector length").get());
                let item = bind_code(codes, types, fold.item);
                let state = bind_code(codes, types, fold.state);
                (
                    23,
                    vec![length, children[0], children[1], item, state, children[2]],
                )
            }
            Term::Step(..) => (24, children),
            Term::Sub(..) => (26, children),
            Term::Mul(..) => (27, children),
            Term::Div(..) => (28, children),
            Term::Mod(..) => (29, children),
            Term::Cmp(rel, ..) => {
                let rel = relation_code(codes, *rel);
                (32, vec![rel, children[0], children[1]])
            }
            Term::Fit(typ, _) => {
                let typ = codes.type_code(types, *typ);
                (35, vec![typ, children[0]])
            }
            Term::Fst(_)
            | Term::Snd(_)
            | Term::Uncons(_)
            | Term::Close(_)
            | Term::Neg(_)
            | Term::Abs(_)
            | Term::Wide(_)
            | Term::Length(_) => {
                let tag = match node {
                    Term::Fst(_) => 8,
                    Term::Snd(_) => 9,
                    Term::Uncons(_) => 22,
                    Term::Close(_) => 25,
                    Term::Neg(_) => 30,
                    Term::Abs(_) => 31,
                    Term::Wide(_) => 36,
                    _ => 37,
                };
                out.push(codes.tag(tag, children[0]));
                continue;
            }
        };
        let fields = codes.list(&fields);
        out.push(codes.tag(tag, fields));
    }
    out.pop()
}
