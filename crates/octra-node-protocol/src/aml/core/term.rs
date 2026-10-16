// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_term syntax in a flat arena. Constructing a term is separate from checking
//! linear use, effects, cost or its lowering into proof-bound instructions.
use super::{
    rule::{Field, LOCAL},
    types::{Multiplicity, TypeId},
    Atom, Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bind {
    pub id: Natural,
    pub multiplicity: Multiplicity,
    pub typ: TypeId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Lt,
    Le,
    Gt,
    Ge,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TermId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fold {
    pub item: Bind,
    pub state: Bind,
    pub body: TermId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Unit,
    Bool(bool),
    Int(BigInt),
    Narrow(TypeId, BigInt),
    Bytes(Vec<u8>),
    Vec(TypeId, Vec<TermId>),
    Seq(Natural, TypeId, Vec<TermId>),
    Var(Natural),
    Let(Bind, TermId, TermId),
    If(TermId, TermId, TermId),
    Pair(TermId, TermId),
    Unpair(TermId, Bind, Bind, TermId),
    Fst(TermId),
    Snd(TermId),
    Inl(TermId, TypeId),
    Inr(TypeId, TermId),
    Case(TermId, Bind, TermId, Bind, TermId),
    Act(Atom, TermId),
    Add(TermId, TermId),
    Sub(TermId, TermId),
    Mul(TermId, TermId),
    Div(TermId, TermId),
    Mod(TermId, TermId),
    Neg(TermId),
    Abs(TermId),
    Fit(TypeId, TermId),
    Wide(TermId),
    Length(TermId),
    Eq(TypeId, TermId, TermId),
    Cmp(Relation, TermId, TermId),
    Cat(TermId, TermId),
    Take(Natural, TermId),
    Drop(Natural, TermId),
    Vcat(TermId, TermId),
    At(Natural, TermId),
    Uncons(TermId),
    Vfold(TermId, TermId, Fold),
    Step(TermId, TermId),
    Close(TermId),
}
impl Term {
    pub(crate) fn map_terms(mut self, mut map: impl FnMut(TermId) -> TermId) -> Self {
        match &mut self {
            Self::Vec(_, values) | Self::Seq(_, _, values) => {
                for value in values {
                    *value = map(*value);
                }
            }
            Self::Let(_, left, right)
            | Self::Pair(left, right)
            | Self::Unpair(left, _, _, right)
            | Self::Add(left, right)
            | Self::Sub(left, right)
            | Self::Mul(left, right)
            | Self::Div(left, right)
            | Self::Mod(left, right)
            | Self::Eq(_, left, right)
            | Self::Cmp(_, left, right)
            | Self::Cat(left, right)
            | Self::Vcat(left, right)
            | Self::Step(left, right) => {
                *left = map(*left);
                *right = map(*right);
            }
            Self::If(guard, yes, no) | Self::Case(guard, _, yes, _, no) => {
                *guard = map(*guard);
                *yes = map(*yes);
                *no = map(*no);
            }
            Self::Fst(value)
            | Self::Snd(value)
            | Self::Inl(value, _)
            | Self::Inr(_, value)
            | Self::Act(_, value)
            | Self::Neg(value)
            | Self::Abs(value)
            | Self::Fit(_, value)
            | Self::Wide(value)
            | Self::Length(value)
            | Self::Take(_, value)
            | Self::Drop(_, value)
            | Self::At(_, value)
            | Self::Uncons(value)
            | Self::Close(value) => *value = map(*value),
            Self::Vfold(vector, seed, fold) => {
                *vector = map(*vector);
                *seed = map(*seed);
                fold.body = map(fold.body);
            }
            _ => (),
        }
        self
    }
    /// Source order; shape traversal applies native Vec/Seq reversal separately.
    pub fn children(&self) -> Vec<TermId> {
        match self {
            Self::Unit
            | Self::Bool(_)
            | Self::Int(_)
            | Self::Narrow(..)
            | Self::Bytes(_)
            | Self::Var(_) => vec![],
            Self::Vec(_, values) | Self::Seq(_, _, values) => values.clone(),
            Self::Let(_, left, right)
            | Self::Pair(left, right)
            | Self::Unpair(left, _, _, right)
            | Self::Add(left, right)
            | Self::Sub(left, right)
            | Self::Mul(left, right)
            | Self::Div(left, right)
            | Self::Mod(left, right)
            | Self::Eq(_, left, right)
            | Self::Cmp(_, left, right)
            | Self::Cat(left, right)
            | Self::Vcat(left, right)
            | Self::Step(left, right) => vec![*left, *right],
            Self::If(guard, yes, no) | Self::Case(guard, _, yes, _, no) => vec![*guard, *yes, *no],
            Self::Fst(value)
            | Self::Snd(value)
            | Self::Inl(value, _)
            | Self::Inr(_, value)
            | Self::Act(_, value)
            | Self::Neg(value)
            | Self::Abs(value)
            | Self::Fit(_, value)
            | Self::Wide(value)
            | Self::Length(value)
            | Self::Take(_, value)
            | Self::Drop(_, value)
            | Self::At(_, value)
            | Self::Uncons(value)
            | Self::Close(value) => vec![*value],
            Self::Vfold(vector, seed, fold) => vec![*vector, *seed, fold.body],
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Terms {
    items: Vec<Term>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    Depth(usize, usize),
    Nodes(usize, usize),
}
impl Terms {
    /// IDs must refer to this term arena and the supplied type arena (or their
    /// clones). Native semantic checks remain at the checking boundary.
    pub fn insert(
        &mut self,
        types: &super::types::Types,
        term: Term,
    ) -> Result<TermId, super::arena::Reference> {
        for child in term.children() {
            if self.try_get(child).is_none() {
                return Err(super::arena::Reference {
                    kind: super::arena::Kind::Term,
                    index: child.0,
                    length: self.items.len(),
                });
            }
        }
        let refs = match &term {
            Term::Narrow(typ, _)
            | Term::Vec(typ, _)
            | Term::Seq(_, typ, _)
            | Term::Inl(_, typ)
            | Term::Inr(typ, _)
            | Term::Fit(typ, _)
            | Term::Eq(typ, _, _) => vec![*typ],
            Term::Let(bind, _, _) => vec![bind.typ],
            Term::Unpair(_, left, right, _) | Term::Case(_, left, _, right, _) => {
                vec![left.typ, right.typ]
            }
            Term::Vfold(_, _, fold) => vec![fold.item.typ, fold.state.typ],
            _ => Vec::new(),
        };
        for typ in refs {
            types.require(typ)?;
        }
        Ok(self.push(term))
    }
    pub fn try_get(&self, id: TermId) -> Option<&Term> {
        self.items.get(id.0)
    }
    pub fn get(&self, id: TermId) -> &Term {
        &self.items[id.0]
    }
    pub(crate) fn push(&mut self, term: Term) -> TermId {
        for child in term.children() {
            assert!(
                child.0 < self.items.len(),
                "core term child precedes parent"
            );
        }
        let id = TermId(self.items.len());
        self.items.push(term);
        id
    }
    pub fn shape(&self, root: TermId) -> Result<(), Shape> {
        let max_depth = LOCAL.get(Field::TermDepth) as usize;
        let max_nodes = LOCAL.get(Field::TermNodes) as usize;
        let mut count = 0;
        let mut pending = vec![(0, root)];
        while let Some((depth, id)) = pending.pop() {
            if depth > max_depth {
                return Err(Shape::Depth(max_depth, depth));
            }
            if count >= max_nodes {
                return Err(Shape::Nodes(max_nodes, count + 1));
            }
            let term = self.get(id);
            let children = term.children();
            if matches!(term, Term::Vec(..) | Term::Seq(..)) {
                pending.extend(children.into_iter().map(|child| (depth + 1, child)));
            } else {
                pending.extend(children.into_iter().rev().map(|child| (depth + 1, child)));
            }
            count += 1;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub inputs: Vec<Bind>,
    pub term: TermId,
}
