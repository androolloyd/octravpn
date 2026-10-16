// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_check evaluation order with explicit continuations and located failures.
use super::{
    Arc, Atom, BigInt, Bind, Checker, Env, Error, Failure, Fold, Info, Limit, Multiplicity,
    Natural, Result, Term, TermId, Type, TypeId,
};
#[derive(Clone, Copy)]
pub(super) enum Binary {
    Pair,
    Arithmetic,
    Compare,
    Equal(TypeId),
    Cat,
    Vcat,
    Step,
}
#[derive(Clone, Copy)]
pub(super) enum Unary {
    Fst,
    Snd,
    Inl(TypeId),
    Inr(TypeId),
    Act(Atom),
    Negate,
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
    elem: TypeId,
    typ: TypeId,
    pad: Option<Natural>,
    elements: Arc<Vec<TermId>>,
    index: usize,
    infos: Vec<Info>,
}
enum Kind {
    Infer(Env),
    Unary(Unary),
    BinaryLeft(Binary, TermId),
    BinaryRight(Binary, Info),
    LetValue(Bind, TermId, Env),
    LetBody(Bind, Info),
    IfGuard(TermId, TermId),
    IfYes(Info, Env, TermId),
    IfNo(Info, Info, Env),
    UnpairValue(Bind, Bind, TermId),
    UnpairBody(Info, Bind, Bind),
    CaseValue(Bind, TermId, Bind, TermId),
    CaseYes(Info, Env, Bind, Bind, TermId),
    CaseNo(Info, Info, Env, Bind),
    FoldVector(TermId, Fold),
    FoldSeed(Natural, Info, Fold),
    FoldBody(Natural, Info, Info, Env, Fold),
    Vector(Vector, Env),
    VectorValue(Vector),
}
struct Task {
    owner: TermId,
    kind: Kind,
}
impl Task {
    fn after(owner: TermId, kind: Kind) -> Self {
        Self { owner, kind }
    }
    fn infer(id: TermId, env: Env) -> Self {
        Self::after(id, Kind::Infer(env))
    }
}
fn size(value: usize) -> Result<Natural> {
    u32::try_from(value)
        .ok()
        .and_then(Natural::from_u32)
        .ok_or(Error::Size)
}
impl Checker<'_> {
    pub(super) fn infer(
        &mut self,
        env: Env,
        root: TermId,
    ) -> std::result::Result<(Info, Env), Failure> {
        let mut tasks = vec![Task::infer(root, env)];
        let mut values: Vec<(Info, Env)> = vec![];
        while let Some(Task { owner, kind }) = tasks.pop() {
            let result: Result<()> = (|| {
                match kind {
                    Kind::Infer(mut env) => {
                        let term = self.terms.get(owner).clone();
                        match term {
                            Term::Unit => {
                                let typ = self.unit();
                                values.push((self.leaf(typ), env));
                            }
                            Term::Bool(_) => {
                                let typ = self.boolean();
                                values.push((self.leaf(typ), env));
                            }
                            Term::Int(_) => {
                                let typ = self.integer();
                                values.push((self.leaf(typ), env));
                            }
                            Term::Narrow(typ, value) => {
                                if !matches!(self.types.get(typ), Type::Num(..))
                                    || !self.types.valid(typ)
                                    || !self.types.admits(typ, &value)
                                {
                                    return Err(Error::RangeType(typ));
                                }
                                values.push((self.leaf(typ), env));
                            }
                            Term::Bytes(value) => {
                                let length = size(value.len())?;
                                let typ = self.types.intern(Type::Bytes(length));
                                let resources = Limit::make(BigInt::from(length.get())).successor();
                                values.push((self.item(typ, resources), env));
                            }
                            Term::Vec(elem, elements) => {
                                self.valid(elem)?;
                                let length = size(elements.len())?;
                                let typ = self.types.intern(Type::Vec(length, elem));
                                tasks.push(Task::after(
                                    owner,
                                    Kind::Vector(
                                        Vector {
                                            elem,
                                            typ,
                                            pad: None,
                                            elements: Arc::new(elements),
                                            index: 0,
                                            infos: vec![],
                                        },
                                        env,
                                    ),
                                ));
                            }
                            Term::Seq(capacity, elem, elements) => {
                                let typ = self.types.intern(Type::Seq(capacity, elem));
                                self.valid(typ)?;
                                let length = size(elements.len())?;
                                if length > capacity {
                                    return Err(Error::SeqSize(length, capacity));
                                }
                                let pad = capacity
                                    .checked_sub(length)
                                    .ok_or(Error::SeqSize(length, capacity))?;
                                tasks.push(Task::after(
                                    owner,
                                    Kind::Vector(
                                        Vector {
                                            elem,
                                            typ,
                                            pad: Some(pad),
                                            elements: Arc::new(elements),
                                            index: 0,
                                            infos: vec![],
                                        },
                                        env,
                                    ),
                                ));
                            }
                            Term::Var(id) => {
                                let typ = env.use_value(id)?;
                                values.push((self.leaf(typ), env));
                            }
                            Term::Let(bind, value, body) => {
                                self.valid(bind.typ)?;
                                tasks.push(Task::after(
                                    owner,
                                    Kind::LetValue(bind, body, env.clone()),
                                ));
                                tasks.push(Task::infer(value, env));
                            }
                            Term::If(guard, yes, no) => {
                                tasks.push(Task::after(owner, Kind::IfGuard(yes, no)));
                                tasks.push(Task::infer(guard, env));
                            }
                            Term::Unpair(value, left, right, body) => {
                                tasks
                                    .push(Task::after(owner, Kind::UnpairValue(left, right, body)));
                                tasks.push(Task::infer(value, env));
                            }
                            Term::Case(value, left, yes, right, no) => {
                                tasks.push(Task::after(
                                    owner,
                                    Kind::CaseValue(left, yes, right, no),
                                ));
                                tasks.push(Task::infer(value, env));
                            }
                            Term::Vfold(vector, seed, fold) => {
                                tasks.push(Task::after(owner, Kind::FoldVector(seed, fold)));
                                tasks.push(Task::infer(vector, env));
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
                                let binary = match self.terms.get(owner) {
                                    Term::Pair(..) => Binary::Pair,
                                    Term::Eq(typ, ..) => Binary::Equal(*typ),
                                    Term::Cmp(..) => Binary::Compare,
                                    Term::Cat(..) => Binary::Cat,
                                    Term::Vcat(..) => Binary::Vcat,
                                    Term::Step(..) => Binary::Step,
                                    _ => Binary::Arithmetic,
                                };
                                tasks.push(Task::after(owner, Kind::BinaryLeft(binary, right)));
                                tasks.push(Task::infer(left, env));
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
                                let unary = match self.terms.get(owner) {
                                    Term::Fst(_) => Unary::Fst,
                                    Term::Snd(_) => Unary::Snd,
                                    Term::Inl(_, typ) => {
                                        self.valid(*typ)?;
                                        Unary::Inl(*typ)
                                    }
                                    Term::Inr(typ, _) => {
                                        self.valid(*typ)?;
                                        Unary::Inr(*typ)
                                    }
                                    Term::Act(atom, _) => Unary::Act(*atom),
                                    Term::Neg(_) | Term::Abs(_) => Unary::Negate,
                                    Term::Fit(typ, _) => {
                                        if !matches!(self.types.get(*typ), Type::Num(..))
                                            || !self.types.valid(*typ)
                                        {
                                            return Err(Error::RangeType(*typ));
                                        }
                                        Unary::Fit(*typ)
                                    }
                                    Term::Wide(_) => Unary::Wide,
                                    Term::Length(_) => Unary::Length,
                                    Term::Take(length, _) => Unary::Take(*length),
                                    Term::Drop(length, _) => Unary::Drop(*length),
                                    Term::At(index, _) => Unary::At(*index),
                                    Term::Uncons(_) => Unary::Uncons,
                                    Term::Close(_) => Unary::Close,
                                    _ => unreachable!("unary term"),
                                };
                                tasks.push(Task::after(owner, Kind::Unary(unary)));
                                tasks.push(Task::infer(value, env));
                            }
                        }
                    }
                    Kind::Unary(unary) => {
                        let (info, env) = values.pop().expect("unary analysis");
                        values.push((self.unary(unary, info)?, env));
                    }
                    Kind::BinaryLeft(binary, right) => {
                        let (info, env) = values.pop().expect("binary left analysis");
                        if matches!(binary, Binary::Arithmetic | Binary::Compare) {
                            let integer = self.integer();
                            self.need(integer, info.typ)?;
                        }
                        tasks.push(Task::after(owner, Kind::BinaryRight(binary, info)));
                        tasks.push(Task::infer(right, env));
                    }
                    Kind::BinaryRight(binary, left) => {
                        let (right, env) = values.pop().expect("binary right analysis");
                        values.push((self.binary(binary, left, right)?, env));
                    }
                    Kind::LetValue(bind, body, original) => {
                        let (info, value_env) = values.pop().expect("let initializer analysis");
                        self.need(bind.typ, info.typ)?;
                        let mut body_env = if bind.multiplicity == Multiplicity::Zero {
                            if !info.effects.is_empty() {
                                return Err(Error::Impure(bind.id));
                            }
                            if original != value_env {
                                return Err(Error::Erase(original.difference(&value_env)));
                            }
                            original
                        } else {
                            value_env
                        };
                        body_env.open(self.types, bind)?;
                        tasks.push(Task::after(owner, Kind::LetBody(bind, info)));
                        tasks.push(Task::infer(body, body_env));
                    }
                    Kind::LetBody(bind, value) => {
                        let (mut body, mut env) = values.pop().expect("let body analysis");
                        env.close(bind)?;
                        if bind.multiplicity == Multiplicity::Zero {
                            body.flow = self.flows.sequence(value.flow, body.flow);
                            body.resources = body.resources.successor();
                            values.push((body, env));
                        } else {
                            let typ = body.typ;
                            values.push((self.sequence(typ, value, body), env));
                        }
                    }
                    Kind::IfGuard(yes, no) => {
                        let (guard, env) = values.pop().expect("if guard analysis");
                        let boolean = self.boolean();
                        self.need(boolean, guard.typ)?;
                        tasks.push(Task::after(owner, Kind::IfYes(guard, env.clone(), no)));
                        tasks.push(Task::infer(yes, env));
                    }
                    Kind::IfYes(guard, guard_env, no) => {
                        let (yes, yes_env) = values.pop().expect("if yes analysis");
                        tasks.push(Task::after(owner, Kind::IfNo(guard, yes, yes_env)));
                        tasks.push(Task::infer(no, guard_env));
                    }
                    Kind::IfNo(guard, yes, yes_env) => {
                        let (no, no_env) = values.pop().expect("if no analysis");
                        self.need(yes.typ, no.typ)?;
                        if yes_env != no_env {
                            return Err(Error::Split(yes_env.difference(&no_env)));
                        }
                        values.push((self.join(yes.typ, guard, yes, no), yes_env));
                    }
                    Kind::UnpairValue(left, right, body) => {
                        let (pair, mut env) = values.pop().expect("unpair input analysis");
                        let Type::Pair(left_type, right_type) = self.types.get(pair.typ).clone()
                        else {
                            return Err(Error::Need(self.unit_pair(), pair.typ));
                        };
                        self.need(left_type, left.typ)?;
                        self.need(right_type, right.typ)?;
                        env.open(self.types, left)?;
                        env.open(self.types, right)?;
                        tasks.push(Task::after(owner, Kind::UnpairBody(pair, left, right)));
                        tasks.push(Task::infer(body, env));
                    }
                    Kind::UnpairBody(pair, left, right) => {
                        let (body, mut env) = values.pop().expect("unpair body analysis");
                        env.close(right)?;
                        env.close(left)?;
                        values.push((self.sequence(body.typ, pair, body), env));
                    }
                    Kind::CaseValue(left, yes, right, no) => {
                        let (value, env) = values.pop().expect("case input analysis");
                        let Type::Sum(left_type, right_type) = self.types.get(value.typ).clone()
                        else {
                            return Err(Error::Need(self.unit_sum(), value.typ));
                        };
                        self.need(left_type, left.typ)?;
                        self.need(right_type, right.typ)?;
                        let mut yes_env = env.clone();
                        yes_env.open(self.types, left)?;
                        tasks.push(Task::after(
                            owner,
                            Kind::CaseYes(value, env, left, right, no),
                        ));
                        tasks.push(Task::infer(yes, yes_env));
                    }
                    Kind::CaseYes(value, original, left, right, no) => {
                        let (yes, mut yes_env) = values.pop().expect("case yes analysis");
                        yes_env.close(left)?;
                        let mut no_env = original;
                        no_env.open(self.types, right)?;
                        tasks.push(Task::after(owner, Kind::CaseNo(value, yes, yes_env, right)));
                        tasks.push(Task::infer(no, no_env));
                    }
                    Kind::CaseNo(value, yes, yes_env, right) => {
                        let (no, mut no_env) = values.pop().expect("case no analysis");
                        no_env.close(right)?;
                        self.need(yes.typ, no.typ)?;
                        if yes_env != no_env {
                            return Err(Error::Split(yes_env.difference(&no_env)));
                        }
                        values.push((self.join(yes.typ, value, yes, no), yes_env));
                    }
                    Kind::FoldVector(seed, fold) => {
                        let (vector, env) = values.pop().expect("fold vector analysis");
                        let (length, element) = match self.types.get(vector.typ) {
                            Type::Vec(length, element) | Type::Seq(length, element) => {
                                (*length, *element)
                            }
                            _ => return Err(Error::Need(self.empty_vector(), vector.typ)),
                        };
                        self.need(element, fold.item.typ)?;
                        tasks.push(Task::after(owner, Kind::FoldSeed(length, vector, fold)));
                        tasks.push(Task::infer(seed, env));
                    }
                    Kind::FoldSeed(length, vector, fold) => {
                        let (seed, seed_env) = values.pop().expect("fold seed analysis");
                        self.need(seed.typ, fold.state.typ)?;
                        let mut body_env = seed_env.clone();
                        body_env.open(self.types, fold.item)?;
                        body_env.open(self.types, fold.state)?;
                        tasks.push(Task::after(
                            owner,
                            Kind::FoldBody(length, vector, seed, seed_env, fold),
                        ));
                        tasks.push(Task::infer(fold.body, body_env));
                    }
                    Kind::FoldBody(length, vector, seed, seed_env, fold) => {
                        let (body, mut body_env) = values.pop().expect("fold body analysis");
                        self.need(seed.typ, body.typ)?;
                        body_env.close(fold.state)?;
                        body_env.close(fold.item)?;
                        if seed_env != body_env {
                            return Err(Error::Repeat(seed_env.difference(&body_env)));
                        }
                        values.push((self.fold_info(length, vector, seed, body), seed_env));
                    }
                    Kind::Vector(vector, env) => {
                        if let Some(child) = vector.elements.get(vector.index) {
                            let child = *child;
                            tasks.push(Task::after(owner, Kind::VectorValue(vector)));
                            tasks.push(Task::infer(child, env));
                        } else {
                            let mut info = self.item(vector.typ, Limit::one());
                            for item in vector.infos.into_iter().rev() {
                                info.effects.extend(item.effects);
                                info.resources = item.resources.add(&info.resources).successor();
                                info.flow = self.flows.sequence(item.flow, info.flow);
                            }
                            if let Some(pad) = vector.pad {
                                info.resources = info
                                    .resources
                                    .add(&Limit::make(BigInt::from(pad.get()) + 1));
                            }
                            values.push((info, env));
                        }
                    }
                    Kind::VectorValue(mut vector) => {
                        let (info, env) = values.pop().expect("vector element analysis");
                        self.need(vector.elem, info.typ)?;
                        vector.infos.push(info);
                        vector.index += 1;
                        tasks.push(Task::after(owner, Kind::Vector(vector, env)));
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                return Err(Failure {
                    error,
                    term: Some(owner),
                });
            }
        }
        Ok(values.pop().expect("core analysis root"))
    }
}
