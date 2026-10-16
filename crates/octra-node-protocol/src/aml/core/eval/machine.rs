// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Iterative C_eval control flow; erased initializers are never evaluated.
use super::{
    host_length, Arc, Atom, BigInt, Bind, Done, Env, Error, Evaluator, Fold, IntegerOp,
    Multiplicity, Natural, Relation, Result, Signed, Term, TermId, ToPrimitive, TraceId, TypeId,
    Value, ValueId,
};
#[derive(Clone, Copy)]
pub(super) enum Binary {
    Pair,
    Integer(IntegerOp),
    Equal(TypeId),
    Compare(Relation),
    Cat,
    Vcat,
    Step,
}
#[derive(Clone, Copy)]
pub(super) enum Unary {
    Fst,
    Snd,
    Inl,
    Inr,
    Act(Atom),
    Integer(IntegerOp),
    Fit(TypeId),
    Wide,
    Length,
    Take(Natural),
    Drop(Natural),
    At(Natural),
    Uncons,
    Close,
}
struct Vector {
    children: Arc<Vec<TermId>>,
    index: usize,
    values: Vec<ValueId>,
    env: Env,
    trace: TraceId,
    steps: BigInt,
    work: BigInt,
}
struct Folding {
    items: Arc<[ValueId]>,
    used: usize,
    index: usize,
    done: Done,
    env: Env,
    fold: Fold,
}
enum Task {
    Eval(TermId, Env),
    Successor,
    Unary(Unary),
    BinaryLeft(Binary, TermId, Env),
    BinaryRight(Binary, Done),
    LetValue(Bind, TermId, Env),
    Body(Done),
    Guard(TermId, TermId, Env),
    Unpair(Bind, Bind, TermId, Env),
    Case(Bind, TermId, Bind, TermId, Env),
    FoldVector(TermId, Fold, Env),
    FoldSeed(Done, Fold, Env),
    FoldStep(Folding),
    FoldBody(Folding),
    Vector(Vector),
    VectorValue(Vector),
    Sequence(Natural, TypeId, usize),
}
impl Evaluator<'_> {
    pub(super) fn evaluate(&mut self, env: Env, root: TermId) -> Result<Done> {
        let mut pending = vec![Task::Eval(root, env)];
        let mut results: Vec<Done> = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Eval(id, env) => match self.terms.get(id).clone() {
                    Term::Unit => results.push(Done::item(self.values.push(Value::Unit))),
                    Term::Bool(value) => {
                        results.push(Done::item(self.values.push(Value::Bool(value))));
                    }
                    Term::Int(value) => results.push(Done::item(self.values.integer(value))),
                    Term::Narrow(typ, value) => {
                        if !self.types.admits(typ, &value) {
                            return Err(Error::NeedInt);
                        }
                        results.push(Done::item(self.values.integer(value)));
                    }
                    Term::Bytes(raw) => {
                        let length = host_length(raw.len())?;
                        let count: BigInt = BigInt::from(length.get()) + 1;
                        results.push(Done {
                            value: self.values.push(Value::Bytes(raw.into())),
                            trace: TraceId(0),
                            steps: count.clone(),
                            work: count,
                        });
                    }
                    Term::Vec(_, children) | Term::Seq(_, _, children) => {
                        if let Term::Seq(capacity, elem, _) = self.terms.get(id) {
                            if children.len() > capacity.get() as usize {
                                return Err(match host_length(children.len()) {
                                    Ok(actual) => Error::VectorIndex(actual, *capacity),
                                    Err(_) => Error::NeedSequence,
                                });
                            }
                            pending.push(Task::Sequence(*capacity, *elem, children.len()));
                        }
                        pending.push(Task::Vector(Vector {
                            children: Arc::new(children),
                            index: 0,
                            values: vec![],
                            env,
                            trace: TraceId(0),
                            steps: BigInt::from(1),
                            work: BigInt::from(1),
                        }));
                    }
                    Term::Var(id) => results.push(Done::item(env.get(id)?)),
                    Term::Let(bind, value, body) => {
                        if bind.multiplicity == Multiplicity::Zero {
                            pending.push(Task::Successor);
                            pending.push(Task::Eval(body, env));
                        } else {
                            pending.push(Task::LetValue(bind, body, env.clone()));
                            pending.push(Task::Eval(value, env));
                        }
                    }
                    Term::If(guard, yes, no) => {
                        pending.push(Task::Guard(yes, no, env.clone()));
                        pending.push(Task::Eval(guard, env));
                    }
                    Term::Unpair(pair, left, right, body) => {
                        pending.push(Task::Unpair(left, right, body, env.clone()));
                        pending.push(Task::Eval(pair, env));
                    }
                    Term::Case(value, left, yes, right, no) => {
                        pending.push(Task::Case(left, yes, right, no, env.clone()));
                        pending.push(Task::Eval(value, env));
                    }
                    Term::Vfold(vector, seed, fold) => {
                        pending.push(Task::FoldVector(seed, fold, env.clone()));
                        pending.push(Task::Eval(vector, env));
                    }
                    Term::Pair(left, right)
                    | Term::Add(left, right)
                    | Term::Sub(left, right)
                    | Term::Mul(left, right)
                    | Term::Div(left, right)
                    | Term::Mod(left, right)
                    | Term::Eq(_, left, right)
                    | Term::Cmp(_, left, right)
                    | Term::Cat(left, right)
                    | Term::Vcat(left, right)
                    | Term::Step(left, right) => {
                        let binary = match self.terms.get(id) {
                            Term::Pair(..) => Binary::Pair,
                            Term::Add(..) => Binary::Integer(IntegerOp::Add),
                            Term::Sub(..) => Binary::Integer(IntegerOp::Sub),
                            Term::Mul(..) => Binary::Integer(IntegerOp::Mul),
                            Term::Div(..) => Binary::Integer(IntegerOp::Div),
                            Term::Mod(..) => Binary::Integer(IntegerOp::Mod),
                            Term::Eq(typ, ..) => Binary::Equal(*typ),
                            Term::Cmp(rel, ..) => Binary::Compare(*rel),
                            Term::Cat(..) => Binary::Cat,
                            Term::Vcat(..) => Binary::Vcat,
                            Term::Step(..) => Binary::Step,
                            _ => unreachable!("binary core term"),
                        };
                        pending.push(Task::BinaryLeft(binary, right, env.clone()));
                        pending.push(Task::Eval(left, env));
                    }
                    Term::Fst(value)
                    | Term::Snd(value)
                    | Term::Inl(value, _)
                    | Term::Inr(_, value)
                    | Term::Act(_, value)
                    | Term::Neg(value)
                    | Term::Abs(value)
                    | Term::Fit(_, value)
                    | Term::Wide(value)
                    | Term::Length(value)
                    | Term::Take(_, value)
                    | Term::Drop(_, value)
                    | Term::At(_, value)
                    | Term::Uncons(value)
                    | Term::Close(value) => {
                        let unary = match self.terms.get(id) {
                            Term::Fst(_) => Unary::Fst,
                            Term::Snd(_) => Unary::Snd,
                            Term::Inl(..) => Unary::Inl,
                            Term::Inr(..) => Unary::Inr,
                            Term::Act(atom, _) => Unary::Act(*atom),
                            Term::Neg(_) => Unary::Integer(IntegerOp::Neg),
                            Term::Abs(_) => Unary::Integer(IntegerOp::Abs),
                            Term::Fit(typ, _) => Unary::Fit(*typ),
                            Term::Wide(_) => Unary::Wide,
                            Term::Length(_) => Unary::Length,
                            Term::Take(length, _) => Unary::Take(*length),
                            Term::Drop(length, _) => Unary::Drop(*length),
                            Term::At(index, _) => Unary::At(*index),
                            Term::Uncons(_) => Unary::Uncons,
                            Term::Close(_) => Unary::Close,
                            _ => unreachable!("unary core term"),
                        };
                        pending.push(Task::Unary(unary));
                        pending.push(Task::Eval(value, env));
                    }
                },
                Task::Successor => {
                    let done = results.pop().expect("erased let body");
                    results.push(done.successor());
                }
                Task::Unary(op) => {
                    let done = results.pop().expect("unary value");
                    results.push(self.unary(op, done)?);
                }
                Task::BinaryLeft(op, right, env) => {
                    let left = results.pop().expect("binary left value");
                    pending.push(Task::BinaryRight(op, left));
                    pending.push(Task::Eval(right, env));
                }
                Task::BinaryRight(op, left) => {
                    let right = results.pop().expect("binary right value");
                    results.push(self.binary(op, left, right)?);
                }
                Task::LetValue(bind, body, mut env) => {
                    let value = results.pop().expect("let initializer");
                    env.bind(bind, value.value);
                    pending.push(Task::Body(value));
                    pending.push(Task::Eval(body, env));
                }
                Task::Body(prefix) => {
                    let body = results.pop().expect("body value");
                    let value = body.value;
                    results.push(self.sequence(prefix, body, value));
                }
                Task::Guard(yes, no, env) => {
                    let guard = results.pop().expect("if condition");
                    let Value::Bool(value) = self.values.get(guard.value) else {
                        return Err(Error::NeedBool);
                    };
                    let body = if *value { yes } else { no };
                    pending.push(Task::Body(guard));
                    pending.push(Task::Eval(body, env));
                }
                Task::Unpair(left, right, body, mut env) => {
                    let pair = results.pop().expect("unpair value");
                    let Value::Pair(left_value, right_value) = self.values.get(pair.value) else {
                        return Err(Error::NeedPair);
                    };
                    env.bind(left, *left_value);
                    env.bind(right, *right_value);
                    pending.push(Task::Body(pair));
                    pending.push(Task::Eval(body, env));
                }
                Task::Case(left, yes, right, no, mut env) => {
                    let value = results.pop().expect("case value");
                    let body = match self.values.get(value.value) {
                        Value::Inl(payload) => {
                            env.bind(left, *payload);
                            yes
                        }
                        Value::Inr(payload) => {
                            env.bind(right, *payload);
                            no
                        }
                        _ => return Err(Error::NeedSum),
                    };
                    pending.push(Task::Body(value));
                    pending.push(Task::Eval(body, env));
                }
                Task::Vector(vector) => {
                    if let Some(child) = vector.children.get(vector.index) {
                        let child = *child;
                        let env = vector.env.clone();
                        pending.push(Task::VectorValue(vector));
                        pending.push(Task::Eval(child, env));
                    } else {
                        results.push(Done {
                            value: self.values.push(Value::Vec(vector.values.into())),
                            trace: vector.trace,
                            steps: vector.steps,
                            work: vector.work,
                        });
                    }
                }
                Task::VectorValue(mut vector) => {
                    let item = results.pop().expect("vector element");
                    vector.values.push(item.value);
                    vector.trace = self.traces.cat(vector.trace, item.trace);
                    vector.steps += item.steps + 1;
                    vector.work += item.work + 1;
                    vector.index += 1;
                    pending.push(Task::Vector(vector));
                }
                Task::Sequence(capacity, elem, count) => {
                    let mut active = results.pop().expect("sequence elements");
                    let Value::Vec(items) = self.values.get(active.value).clone() else {
                        return Err(Error::NeedSequence);
                    };
                    let empty = self
                        .values
                        .zero(self.types, elem)
                        .ok_or(Error::NeedSequence)?;
                    let mut full = vec![empty; capacity.get() as usize];
                    full[..count].copy_from_slice(&items);
                    let vector = self.values.push(Value::Vec(full.into()));
                    let length = self.values.integer(count);
                    active.value = self.values.push(Value::Pair(length, vector));
                    let extra = BigInt::from(capacity.get() as usize - count + 1);
                    active.steps += &extra;
                    active.work += extra;
                    results.push(active);
                }
                Task::FoldVector(seed, fold, env) => {
                    let vector = results.pop().expect("fold vector");
                    pending.push(Task::FoldSeed(vector, fold, env.clone()));
                    pending.push(Task::Eval(seed, env));
                }
                Task::FoldSeed(vector, fold, env) => {
                    let seed = results.pop().expect("fold seed");
                    let (items, used) = match self.values.get(vector.value).clone() {
                        Value::Vec(items) => {
                            let used = items.len();
                            (items, used)
                        }
                        Value::Pair(length, vector) => {
                            let (Value::Int(length), Value::Vec(items)) = (
                                self.values.get(length).clone(),
                                self.values.get(vector).clone(),
                            ) else {
                                return Err(Error::NeedVector);
                            };
                            if length.is_negative() || *length > BigInt::from(items.len()) {
                                return Err(Error::NeedVector);
                            }
                            (
                                items,
                                length.to_usize().expect("bounded fold sequence count"),
                            )
                        }
                        _ => return Err(Error::NeedVector),
                    };
                    let value = seed.value;
                    let done = self.sequence(vector, seed, value);
                    pending.push(Task::FoldStep(Folding {
                        items,
                        used,
                        index: 0,
                        done,
                        env,
                        fold,
                    }));
                }
                Task::FoldStep(folding) => {
                    if folding.index == folding.used {
                        results.push(folding.done);
                    } else {
                        let mut env = folding.env.clone();
                        env.bind(folding.fold.item, folding.items[folding.index]);
                        env.bind(folding.fold.state, folding.done.value);
                        let body = folding.fold.body;
                        pending.push(Task::FoldBody(folding));
                        pending.push(Task::Eval(body, env));
                    }
                }
                Task::FoldBody(mut folding) => {
                    let body = results.pop().expect("fold body");
                    folding.done.value = body.value;
                    folding.done.trace = self.traces.cat(folding.done.trace, body.trace);
                    folding.done.steps += body.steps + 1;
                    folding.done.work += body.work + 1;
                    folding.index += 1;
                    pending.push(Task::FoldStep(folding));
                }
            }
        }
        Ok(results.pop().expect("evaluation result"))
    }
}
