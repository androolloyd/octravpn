// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach continuation lowering. Static typing and machine layout remain
//! independent gates, including erased lets and unsupported encrypted steps.
use super::super::{
    rule::{Field, LOCAL},
    term::{Bind, Fold, Term, TermId, Terms},
    types::{Multiplicity, Type, Types},
};
use super::{CodeId, Codes, Literal, Operation as Op, Shape, ShapeId, Shapes};
use num_bigint::BigInt;
use std::sync::Arc;
type Env = Arc<Vec<Bind>>;
fn extend(env: &Env, binds: &[Bind]) -> Env {
    let mut next = env.as_ref().clone();
    next.extend_from_slice(binds);
    Arc::new(next)
}
enum Task {
    Build(TermId, Env, CodeId),
    BinaryLeft(TermId, Env),
    Vector(Arc<[TermId]>, usize, Env),
    Scope(TermId, Env, Bind, Option<Bind>, CodeId),
    Effect(super::super::Atom, CodeId),
    CheckedUnary(Unary, CodeId),
    BranchNo {
        guard: TermId,
        no: TermId,
        env: Env,
        left: Option<Bind>,
        right: Option<Bind>,
        rest: CodeId,
    },
    BranchFinish {
        guard: TermId,
        yes: CodeId,
        env: Env,
        left: Option<Bind>,
        right: Option<Bind>,
        rest: CodeId,
    },
    FoldVector {
        seed: TermId,
        fold: Fold,
        env: Env,
        rest: CodeId,
    },
    FoldBody {
        vector: CodeId,
        seed: TermId,
        fold: Fold,
        env: Env,
        sequence: bool,
        count: super::super::Natural,
        state_shape: ShapeId,
        rest: CodeId,
    },
    FoldSeed(CodeId),
}
enum Unary {
    Close,
    Left(ShapeId),
    Right(ShapeId),
}
impl Codes {
    pub fn lower(
        &mut self,
        shapes: &mut Shapes,
        types: &Types,
        terms: &Terms,
        inputs: &[Bind],
        root: TermId,
    ) -> Option<CodeId> {
        let done = self.done();
        let mut pending = vec![Task::Build(
            root,
            Arc::new(inputs.iter().rev().copied().collect()),
            done,
        )];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            let (term, env, rest) = match task {
                Task::Build(term, env, rest) => (term, env, rest),
                Task::BinaryLeft(left, env) => {
                    pending.push(Task::Build(
                        left,
                        env,
                        out.pop().expect("machine binary right"),
                    ));
                    continue;
                }
                Task::Vector(items, remaining, env) => {
                    if remaining > 0 {
                        let rest = out.pop().expect("machine vector continuation");
                        let item = items[remaining - 1];
                        pending.push(Task::Vector(items, remaining - 1, env.clone()));
                        pending.push(Task::Build(item, env, rest));
                    }
                    continue;
                }
                Task::Scope(value, env, left, right, rest) => {
                    let body = out.pop().expect("machine scope body");
                    let op = if let Some(right) = right {
                        Op::Scope2(left, right, body)
                    } else {
                        Op::Scope(left, body)
                    };
                    let rest = self.next(op, rest);
                    pending.push(Task::Build(value, env, rest));
                    continue;
                }
                Task::Effect(atom, rest) => {
                    let body = out.pop().expect("machine effect body");
                    out.push(self.next(
                        Op::Effect {
                            index: -1,
                            atom,
                            body,
                        },
                        rest,
                    ));
                    continue;
                }
                Task::CheckedUnary(kind, rest) => {
                    let value = out.pop().expect("machine checked unary");
                    let shape = self.one_shape(shapes, types, value)?;
                    let op = match kind {
                        Unary::Close => {
                            let Shape::Cap(kind) = shapes.get(shape) else {
                                return None;
                            };
                            Op::Close(*kind)
                        }
                        Unary::Left(expected) if expected == shape => Op::Left,
                        Unary::Right(expected) if expected == shape => Op::Right,
                        _ => return None,
                    };
                    let rest = self.next(op, rest);
                    out.push(self.continue_with(value, rest));
                    continue;
                }
                Task::BranchNo {
                    guard,
                    no,
                    env,
                    left,
                    right,
                    rest,
                } => {
                    let yes = out.pop().expect("machine branch yes");
                    let no_env = right.map_or_else(|| env.clone(), |bind| extend(&env, &[bind]));
                    pending.push(Task::BranchFinish {
                        guard,
                        yes,
                        env,
                        left,
                        right,
                        rest,
                    });
                    let done = self.done();
                    pending.push(Task::Build(no, no_env, done));
                    continue;
                }
                Task::BranchFinish {
                    guard,
                    yes,
                    env,
                    left,
                    right,
                    rest,
                } => {
                    let no = out.pop().expect("machine branch no");
                    let shape = self.one_shape(shapes, types, yes)?;
                    if self.one_shape(shapes, types, no)? != shape {
                        return None;
                    }
                    let op = match (left, right) {
                        (Some(left), Some(right)) => Op::Choice {
                            left,
                            yes,
                            right,
                            no,
                            shape,
                        },
                        (None, None) => Op::Fork { shape, yes, no },
                        _ => unreachable!("machine paired branch binds"),
                    };
                    let rest = self.next(op, rest);
                    pending.push(Task::Build(guard, env, rest));
                    continue;
                }
                Task::FoldVector {
                    seed,
                    fold,
                    env,
                    rest,
                } => {
                    let vector = out.pop().expect("machine fold vector");
                    let shape = self.one_shape(shapes, types, vector)?;
                    let (sequence, count, elem) = match shapes.get(shape) {
                        Shape::Vec(count, elem) => (false, *count, *elem),
                        Shape::Pair(length, vector)
                            if matches!(shapes.get(*length), Shape::Atom) =>
                        {
                            let Shape::Vec(count, elem) = shapes.get(*vector) else {
                                return None;
                            };
                            (true, *count, *elem)
                        }
                        _ => return None,
                    };
                    if shapes.from_type(types, fold.item.typ)? != elem {
                        return None;
                    }
                    let state_shape = shapes.from_type(types, fold.state.typ)?;
                    let body_env = extend(&env, &[fold.item, fold.state]);
                    pending.push(Task::FoldBody {
                        vector,
                        seed,
                        fold,
                        env,
                        sequence,
                        count,
                        state_shape,
                        rest,
                    });
                    let done = self.done();
                    pending.push(Task::Build(fold.body, body_env, done));
                    continue;
                }
                Task::FoldBody {
                    vector,
                    seed,
                    fold,
                    env,
                    sequence,
                    count,
                    state_shape,
                    rest,
                } => {
                    let body = out.pop().expect("machine fold body");
                    if self.one_shape(shapes, types, body)? != state_shape {
                        return None;
                    }
                    let rest = self.next(
                        Op::Iter {
                            sequence,
                            count,
                            item: fold.item,
                            state: fold.state,
                            body,
                        },
                        rest,
                    );
                    pending.push(Task::FoldSeed(vector));
                    pending.push(Task::Build(seed, env, rest));
                    continue;
                }
                Task::FoldSeed(vector) => {
                    let seed = out.pop().expect("machine fold seed");
                    out.push(self.continue_with(vector, seed));
                    continue;
                }
            };
            let node = terms.get(term);
            let unary = match node {
                Term::Fst(value) | Term::Length(value) => Some((*value, Op::First)),
                Term::Snd(value) => Some((*value, Op::Second)),
                Term::Neg(value) => Some((*value, Op::Negate)),
                Term::Abs(value) => Some((*value, Op::Absolute)),
                Term::Fit(typ, value) => Some((*value, Op::Fit(*typ))),
                Term::Wide(value) => Some((*value, Op::Wide)),
                Term::Take(length, value) => Some((*value, Op::Clip(*length))),
                Term::Drop(length, value) => Some((*value, Op::Skip(*length))),
                Term::At(index, value) => Some((*value, Op::Pick(*index))),
                Term::Uncons(value) => Some((*value, Op::Unhead)),
                _ => None,
            };
            if let Some((value, op)) = unary {
                let rest = self.next(op, rest);
                pending.push(Task::Build(value, env, rest));
                continue;
            }
            let binary = match node {
                Term::Pair(left, right) => Some((*left, *right, Op::Duo)),
                Term::Add(left, right) => Some((*left, *right, Op::Plus)),
                Term::Sub(left, right) => Some((*left, *right, Op::Minus)),
                Term::Mul(left, right) => Some((*left, *right, Op::Times)),
                Term::Div(left, right) => Some((*left, *right, Op::Quot)),
                Term::Mod(left, right) => Some((*left, *right, Op::Rem)),
                Term::Cmp(rel, left, right) => Some((*left, *right, Op::Order(*rel))),
                Term::Cat(left, right) => Some((*left, *right, Op::Join)),
                Term::Vcat(left, right) => Some((*left, *right, Op::Append)),
                Term::Eq(typ, left, right) => {
                    let different = if matches!(types.get(*typ), Type::Bool)
                        && matches!(terms.get(*right), Term::Bool(false))
                    {
                        match terms.get(*left) {
                            Term::Eq(inner, lhs, rhs) if matches!(types.get(*inner), Type::Int) => {
                                Some((*lhs, *rhs))
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    if let Some((left, right)) = different {
                        Some((left, right, Op::Different))
                    } else {
                        let shape = shapes.from_type(types, *typ)?;
                        if matches!(shapes.get(shape), Shape::Atom) {
                            Some((*left, *right, Op::Same))
                        } else {
                            return None;
                        }
                    }
                }
                _ => None,
            };
            if let Some((left, right, op)) = binary {
                let rest = self.next(op, rest);
                pending.push(Task::BinaryLeft(left, env.clone()));
                pending.push(Task::Build(right, env, rest));
                continue;
            }
            match node {
                Term::Unit => out.push(self.next(Op::Void, rest)),
                Term::Bool(value) => out.push(self.next(Op::Push(Literal::Bool(*value)), rest)),
                Term::Int(value) => {
                    out.push(self.next(Op::Push(Literal::Int(Arc::new(value.clone()))), rest));
                }
                Term::Narrow(typ, value) if types.admits(*typ, value) => {
                    out.push(self.next(Op::Push(Literal::Int(Arc::new(value.clone()))), rest));
                }
                Term::Bytes(value) => {
                    out.push(self.next(Op::Push(Literal::Bytes(value.as_slice().into())), rest));
                }
                Term::Vec(elem, items) | Term::Seq(_, elem, items) => {
                    let shape = shapes.from_type(types, *elem)?;
                    let mut rest = if let Term::Seq(capacity, elem, _) = node {
                        self.next(Op::Pack(*capacity, *elem), rest)
                    } else {
                        rest
                    };
                    for _ in items {
                        rest = self.next(Op::Cons, rest);
                    }
                    rest = self.next(Op::Empty(shape), rest);
                    out.push(rest);
                    pending.push(Task::Vector(items.as_slice().into(), items.len(), env));
                }
                Term::Var(id) => {
                    let bind = env.iter().rev().find(|bind| bind.id == *id)?;
                    let shape = shapes.from_type(types, bind.typ)?;
                    out.push(self.next(Op::Get(*id, shape), rest));
                }
                Term::Let(bind, value, body) => {
                    let body_env = extend(&env, &[*bind]);
                    if bind.multiplicity == Multiplicity::Zero {
                        pending.push(Task::Build(*body, body_env, rest));
                    } else {
                        pending.push(Task::Scope(*value, env, *bind, None, rest));
                        let done = self.done();
                        pending.push(Task::Build(*body, body_env, done));
                    }
                }
                Term::Unpair(value, left, right, body) => {
                    let body_env = extend(&env, &[*left, *right]);
                    pending.push(Task::Scope(*value, env, *left, Some(*right), rest));
                    let done = self.done();
                    pending.push(Task::Build(*body, body_env, done));
                }
                Term::If(guard, yes, no) => {
                    pending.push(Task::BranchNo {
                        guard: *guard,
                        no: *no,
                        env: env.clone(),
                        left: None,
                        right: None,
                        rest,
                    });
                    let done = self.done();
                    pending.push(Task::Build(*yes, env, done));
                }
                Term::Case(guard, left, yes, right, no) => {
                    if left.multiplicity == Multiplicity::Zero
                        || right.multiplicity == Multiplicity::Zero
                    {
                        return None;
                    }
                    let yes_env = extend(&env, &[*left]);
                    pending.push(Task::BranchNo {
                        guard: *guard,
                        no: *no,
                        env,
                        left: Some(*left),
                        right: Some(*right),
                        rest,
                    });
                    let done = self.done();
                    pending.push(Task::Build(*yes, yes_env, done));
                }
                Term::Act(atom, body) => {
                    pending.push(Task::Effect(*atom, rest));
                    let done = self.done();
                    pending.push(Task::Build(*body, env, done));
                }
                Term::Close(value) => {
                    pending.push(Task::CheckedUnary(Unary::Close, rest));
                    let done = self.done();
                    pending.push(Task::Build(*value, env, done));
                }
                Term::Inl(value, typ) | Term::Inr(typ, value) => {
                    let shape = shapes.from_type(types, *typ)?;
                    let kind = if matches!(node, Term::Inl(..)) {
                        Unary::Left(shape)
                    } else {
                        Unary::Right(shape)
                    };
                    pending.push(Task::CheckedUnary(kind, rest));
                    let done = self.done();
                    pending.push(Task::Build(*value, env, done));
                }
                Term::Vfold(vector, seed, fold) => {
                    if fold.item.multiplicity == Multiplicity::Zero
                        || fold.state.multiplicity == Multiplicity::Zero
                    {
                        return None;
                    }
                    pending.push(Task::FoldVector {
                        seed: *seed,
                        fold: *fold,
                        env: env.clone(),
                        rest,
                    });
                    let done = self.done();
                    pending.push(Task::Build(*vector, env, done));
                }
                // Unary/binary nodes were handled above; Narrow may fail its guard.
                _ => return None,
            }
        }
        let root = out.pop().expect("lowered machine root");
        if self.size(root) > BigInt::from(LOCAL.get(Field::Fuel)) {
            return None;
        }
        Some(self.index_effects(root))
    }
}
