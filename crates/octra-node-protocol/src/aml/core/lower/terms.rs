// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_low binder numbering and conversion without recursive lowering frames.
use super::core;
use super::{core_types, natural, syn, typ, Atom, Env, Error, Lowerer, Natural, Result};
use core_types::TypeId;
enum Op {
    Vec(TypeId),
    Seq(Natural, TypeId),
    If,
    Pair,
    Let(core::Bind, core::TermId),
    Unpair(core::TermId, core::Bind, core::Bind),
    Case(core::TermId, core::Bind, core::TermId, core::Bind),
    Fold(core::TermId, core::TermId, core::Bind, core::Bind),
    Fst,
    Snd,
    Inr(TypeId),
    Act(Atom),
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Abs,
    Fit(TypeId),
    Wide,
    Length,
    Eq(TypeId),
    Cmp(core::Relation),
    Cat,
    Take(Natural),
    Drop(Natural),
    Vcat,
    At(Natural),
    Uncons,
    Step,
    Close,
}
impl Op {
    fn make(self, children: Vec<core::TermId>) -> core::Term {
        use core::Term as T;
        match self {
            Self::Vec(elem) => T::Vec(elem, children),
            Self::Seq(capacity, elem) => T::Seq(capacity, elem, children),
            Self::If => T::If(children[0], children[1], children[2]),
            Self::Pair => T::Pair(children[0], children[1]),
            Self::Let(bind, value) => T::Let(bind, value, children[0]),
            Self::Unpair(pair, left, right) => T::Unpair(pair, left, right, children[0]),
            Self::Case(value, left, yes, right) => T::Case(value, left, yes, right, children[0]),
            Self::Fold(vector, seed, item, state) => T::Vfold(
                vector,
                seed,
                core::Fold {
                    item,
                    state,
                    body: children[0],
                },
            ),
            Self::Fst => T::Fst(children[0]),
            Self::Snd => T::Snd(children[0]),
            Self::Inr(typ) => T::Inr(typ, children[0]),
            Self::Act(atom) => T::Act(atom, children[0]),
            Self::Add => T::Add(children[0], children[1]),
            Self::Sub => T::Sub(children[0], children[1]),
            Self::Mul => T::Mul(children[0], children[1]),
            Self::Div => T::Div(children[0], children[1]),
            Self::Mod => T::Mod(children[0], children[1]),
            Self::Neg => T::Neg(children[0]),
            Self::Abs => T::Abs(children[0]),
            Self::Fit(typ) => T::Fit(typ, children[0]),
            Self::Wide => T::Wide(children[0]),
            Self::Length => T::Length(children[0]),
            Self::Eq(typ) => T::Eq(typ, children[0], children[1]),
            Self::Cmp(order) => T::Cmp(order, children[0], children[1]),
            Self::Cat => T::Cat(children[0], children[1]),
            Self::Take(length) => T::Take(length, children[0]),
            Self::Drop(length) => T::Drop(length, children[0]),
            Self::Vcat => T::Vcat(children[0], children[1]),
            Self::At(index) => T::At(index, children[0]),
            Self::Uncons => T::Uncons(children[0]),
            Self::Step => T::Step(children[0], children[1]),
            Self::Close => T::Close(children[0]),
        }
    }
}
enum Task {
    Lower(syn::TermId, Env),
    Finish(Op, usize),
    Inl(syn::TypeId),
    LetValue(syn::Bind, syn::TermId, Env),
    UnpairValue(syn::Bind, syn::Bind, syn::TermId, Env),
    CaseValue(syn::Bind, syn::TermId, syn::Bind, syn::TermId, Env),
    CaseYes(core::TermId, core::Bind, syn::Bind, syn::TermId, Env),
    FoldInputs(syn::Fold, Env),
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn schedule(tasks: &mut Vec<Task>, op: Op, children: Vec<syn::TermId>, env: Env) {
    tasks.push(Task::Finish(op, children.len()));
    for child in children.into_iter().rev() {
        tasks.push(Task::Lower(child, env.clone()));
    }
}
fn atom(atom: &syn::Atom) -> Result<Atom> {
    Ok(match atom {
        syn::Atom::Read(kind) => Atom::Read(natural(kind)?),
        syn::Atom::Write(kind) => Atom::Write(natural(kind)?),
        syn::Atom::Emit(kind) => Atom::Emit(natural(kind)?),
        syn::Atom::Fail(kind) => Atom::Fail(natural(kind)?),
        syn::Atom::Close(kind) => Atom::Close(natural(kind)?),
    })
}
impl Lowerer<'_> {
    pub(super) fn lower(&mut self, env: Env, root: syn::TermId) -> Result<core::TermId> {
        let mut tasks = vec![Task::Lower(root, env)];
        let mut values: Vec<core::TermId> = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Lower(id, env) => {
                    let raw = self.syntax.term(id).clone();
                    let term = match raw {
                        syn::Term::Unit => core::Term::Unit,
                        syn::Term::Bool(value) => core::Term::Bool(value),
                        syn::Term::Int(value) => core::Term::Int(value),
                        syn::Term::Bytes(value) => core::Term::Bytes(value),
                        syn::Term::Var(name) => {
                            core::Term::Var(env.find(&name).ok_or(Error::Free(name))?)
                        }
                        syn::Term::Vec(elem, children) => {
                            let elem = typ(self.syntax, self.types, elem)?;
                            schedule(&mut tasks, Op::Vec(elem), children, env);
                            continue;
                        }
                        syn::Term::Seq(capacity, elem, children) => {
                            let elem = typ(self.syntax, self.types, elem)?;
                            schedule(&mut tasks, Op::Seq(capacity, elem), children, env);
                            continue;
                        }
                        syn::Term::Let(bind, value, body) => {
                            tasks.push(Task::LetValue(bind, body, env.clone()));
                            tasks.push(Task::Lower(value, env));
                            continue;
                        }
                        syn::Term::Unpair(pair, left, right, body) => {
                            Self::distinct(&left, &right)?;
                            tasks.push(Task::UnpairValue(left, right, body, env.clone()));
                            tasks.push(Task::Lower(pair, env));
                            continue;
                        }
                        syn::Term::Case(value, left, yes, right, no) => {
                            tasks.push(Task::CaseValue(left, yes, right, no, env.clone()));
                            tasks.push(Task::Lower(value, env));
                            continue;
                        }
                        syn::Term::Vfold(vector, seed, fold) => {
                            Self::distinct(&fold.item, &fold.state)?;
                            tasks.push(Task::FoldInputs(fold, env.clone()));
                            tasks.push(Task::Lower(seed, env.clone()));
                            tasks.push(Task::Lower(vector, env));
                            continue;
                        }
                        syn::Term::Inl(value, right) => {
                            tasks.push(Task::Inl(right));
                            tasks.push(Task::Lower(value, env));
                            continue;
                        }
                        syn::Term::If(guard, yes, no) => {
                            schedule(&mut tasks, Op::If, vec![guard, yes, no], env);
                            continue;
                        }
                        syn::Term::Pair(left, right)
                        | syn::Term::Add(left, right)
                        | syn::Term::Sub(left, right)
                        | syn::Term::Mul(left, right)
                        | syn::Term::Div(left, right)
                        | syn::Term::Mod(left, right)
                        | syn::Term::Eq(_, left, right)
                        | syn::Term::Cmp(_, left, right)
                        | syn::Term::Cat(left, right)
                        | syn::Term::Vcat(left, right)
                        | syn::Term::Step(left, right) => {
                            let op = match self.syntax.term(id) {
                                syn::Term::Pair(..) => Op::Pair,
                                syn::Term::Add(..) => Op::Add,
                                syn::Term::Sub(..) => Op::Sub,
                                syn::Term::Mul(..) => Op::Mul,
                                syn::Term::Div(..) => Op::Div,
                                syn::Term::Mod(..) => Op::Mod,
                                syn::Term::Eq(kind, ..) => {
                                    Op::Eq(typ(self.syntax, self.types, *kind)?)
                                }
                                syn::Term::Cmp(order, ..) => Op::Cmp(*order),
                                syn::Term::Cat(..) => Op::Cat,
                                syn::Term::Vcat(..) => Op::Vcat,
                                syn::Term::Step(..) => Op::Step,
                                _ => unreachable!("binary syntax"),
                            };
                            schedule(&mut tasks, op, vec![left, right], env);
                            continue;
                        }
                        syn::Term::Fst(value)
                        | syn::Term::Snd(value)
                        | syn::Term::Inr(_, value)
                        | syn::Term::Act(_, value)
                        | syn::Term::Neg(value)
                        | syn::Term::Abs(value)
                        | syn::Term::Fit(_, value)
                        | syn::Term::Wide(value)
                        | syn::Term::Length(value)
                        | syn::Term::Take(_, value)
                        | syn::Term::Drop(_, value)
                        | syn::Term::At(_, value)
                        | syn::Term::Uncons(value)
                        | syn::Term::Close(value) => {
                            let op = match self.syntax.term(id) {
                                syn::Term::Fst(_) => Op::Fst,
                                syn::Term::Snd(_) => Op::Snd,
                                syn::Term::Inr(kind, _) => {
                                    Op::Inr(typ(self.syntax, self.types, *kind)?)
                                }
                                syn::Term::Act(action, _) => Op::Act(atom(action)?),
                                syn::Term::Neg(_) => Op::Neg,
                                syn::Term::Abs(_) => Op::Abs,
                                syn::Term::Fit(kind, _) => {
                                    Op::Fit(typ(self.syntax, self.types, *kind)?)
                                }
                                syn::Term::Wide(_) => Op::Wide,
                                syn::Term::Length(_) => Op::Length,
                                syn::Term::Take(length, _) => Op::Take(natural(length)?),
                                syn::Term::Drop(length, _) => Op::Drop(natural(length)?),
                                syn::Term::At(index, _) => Op::At(natural(index)?),
                                syn::Term::Uncons(_) => Op::Uncons,
                                syn::Term::Close(_) => Op::Close,
                                _ => unreachable!("unary syntax"),
                            };
                            schedule(&mut tasks, op, vec![value], env);
                            continue;
                        }
                    };
                    values.push(self.terms.push(term));
                }
                Task::Finish(op, count) => {
                    let children = values.split_off(values.len() - count);
                    values.push(self.terms.push(op.make(children)));
                }
                Task::Inl(right) => {
                    let value = values.pop().expect("left injection value");
                    let right = typ(self.syntax, self.types, right)?;
                    values.push(self.terms.push(core::Term::Inl(value, right)));
                }
                Task::LetValue(bind, body, mut env) => {
                    let value = values.pop().expect("let initializer");
                    let core = self.bind(&bind)?;
                    env.put(bind.name, core.id);
                    schedule(&mut tasks, Op::Let(core, value), vec![body], env);
                }
                Task::UnpairValue(left, right, body, mut env) => {
                    let pair = values.pop().expect("unpair input");
                    let left_core = self.bind(&left)?;
                    let right_core = self.bind(&right)?;
                    env.put(left.name, left_core.id);
                    env.put(right.name, right_core.id);
                    schedule(
                        &mut tasks,
                        Op::Unpair(pair, left_core, right_core),
                        vec![body],
                        env,
                    );
                }
                Task::CaseValue(left, yes, right, no, env) => {
                    let value = values.pop().expect("case input");
                    let left_core = self.bind(&left)?;
                    let mut yes_env = env.clone();
                    yes_env.put(left.name, left_core.id);
                    tasks.push(Task::CaseYes(value, left_core, right, no, env));
                    tasks.push(Task::Lower(yes, yes_env));
                }
                Task::CaseYes(value, left, right, no, mut env) => {
                    let yes = values.pop().expect("case yes");
                    let right_core = self.bind(&right)?;
                    env.put(right.name, right_core.id);
                    schedule(
                        &mut tasks,
                        Op::Case(value, left, yes, right_core),
                        vec![no],
                        env,
                    );
                }
                Task::FoldInputs(fold, mut env) => {
                    let seed = values.pop().expect("fold seed");
                    let vector = values.pop().expect("fold vector");
                    let item = self.bind(&fold.item)?;
                    let state = self.bind(&fold.state)?;
                    env.put(fold.item.name, item.id);
                    env.put(fold.state.name, state.id);
                    schedule(
                        &mut tasks,
                        Op::Fold(vector, seed, item, state),
                        vec![fold.body],
                        env,
                    );
                }
            }
        }
        Ok(values.pop().expect("lowered term root"))
    }
}
