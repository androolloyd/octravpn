// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Named C_syn syntax before natural/type checking and binder numbering.
use super::{
    rule::{Field, LOCAL},
    term::Relation,
    types::{Multiplicity, Sign},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name(Vec<u8>);
impl Name {
    pub fn new(value: &[u8]) -> Option<Self> {
        let first = |byte: u8| byte.is_ascii_alphabetic() || byte == b'_';
        if value.is_empty()
            || value.len() > LOCAL.get(Field::Name) as usize
            || !first(value[0])
            || !value[1..]
                .iter()
                .all(|byte| first(*byte) || byte.is_ascii_digit())
        {
            return None;
        }
        Some(Self(value.to_vec()))
    }
    pub fn slot(id: Natural) -> Self {
        Self(format!("${}", id.get()).into_bytes())
    }
    pub fn dslot(id: Natural) -> Self {
        Self(format!("$d{}", id.get()).into_bytes())
    }
    pub fn text(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Unit,
    Bool,
    Int,
    Num(Sign, BigInt),
    Bytes(BigInt),
    Vec(BigInt, TypeId),
    Seq(BigInt, TypeId),
    Cap(BigInt),
    Pair(TypeId, TypeId),
    Sum(TypeId, TypeId),
}
impl Type {
    pub fn children(&self) -> Vec<TypeId> {
        match self {
            Self::Vec(_, child) | Self::Seq(_, child) => vec![*child],
            Self::Pair(left, right) | Self::Sum(left, right) => vec![*left, *right],
            _ => vec![],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Atom {
    Read(BigInt),
    Write(BigInt),
    Emit(BigInt),
    Fail(BigInt),
    Close(BigInt),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    pub name: Name,
    pub multiplicity: Multiplicity,
    pub typ: TypeId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TermId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
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
    Bytes(Vec<u8>),
    Vec(TypeId, Vec<TermId>),
    Seq(Natural, TypeId, Vec<TermId>),
    Var(Name),
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
    Take(BigInt, TermId),
    Drop(BigInt, TermId),
    Vcat(TermId, TermId),
    At(BigInt, TermId),
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
            Self::Unit | Self::Bool(_) | Self::Int(_) | Self::Bytes(_) | Self::Var(_) => (),
        }
        self
    }
    pub fn children(&self) -> Vec<TermId> {
        match self {
            Self::Unit | Self::Bool(_) | Self::Int(_) | Self::Bytes(_) | Self::Var(_) => vec![],
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
    pub fn bindings(&self) -> Vec<&Name> {
        match self {
            Self::Let(bind, ..) => vec![&bind.name],
            Self::Unpair(_, left, right, _) | Self::Case(_, left, _, right, _) => {
                vec![&left.name, &right.name]
            }
            Self::Vfold(_, _, fold) => vec![&fold.item.name, &fold.state.name],
            _ => vec![],
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Syntax {
    types: Vec<Type>,
    terms: Vec<Term>,
}
impl Syntax {
    pub fn insert_type(&mut self, typ: Type) -> Result<TypeId, super::arena::Reference> {
        for child in typ.children() {
            self.require_type(child)?;
        }
        Ok(self.add_type(typ))
    }
    /// Raw numbers retain native lowering behavior; only local references are
    /// checked here. IDs must belong to this arena (or its unchanged clone).
    pub fn insert_term(&mut self, term: Term) -> Result<TermId, super::arena::Reference> {
        for child in term.children() {
            if self.try_term(child).is_none() {
                return Err(super::arena::Reference {
                    kind: super::arena::Kind::SyntaxTerm,
                    index: child.0,
                    length: self.terms.len(),
                });
            }
        }
        let refs = match &term {
            Term::Vec(typ, _)
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
            self.require_type(typ)?;
        }
        Ok(self.add_term(term))
    }
    pub fn try_type(&self, id: TypeId) -> Option<&Type> {
        self.types.get(id.0)
    }
    pub fn try_term(&self, id: TermId) -> Option<&Term> {
        self.terms.get(id.0)
    }
    pub(crate) fn require_type(&self, id: TypeId) -> Result<(), super::arena::Reference> {
        self.try_type(id)
            .map(|_| ())
            .ok_or(super::arena::Reference {
                kind: super::arena::Kind::SyntaxType,
                index: id.0,
                length: self.types.len(),
            })
    }
    pub(crate) fn require_term(&self, id: TermId) -> Result<(), super::arena::Reference> {
        self.try_term(id)
            .map(|_| ())
            .ok_or(super::arena::Reference {
                kind: super::arena::Kind::SyntaxTerm,
                index: id.0,
                length: self.terms.len(),
            })
    }
    pub fn same_type(&self, left: TypeId, right: TypeId) -> bool {
        let mut pending = vec![(left, right)];
        let mut seen = std::collections::BTreeSet::new();
        while let Some((left, right)) = pending.pop() {
            if left == right || !seen.insert((left, right)) {
                continue;
            }
            match (self.typ(left), self.typ(right)) {
                (Type::Unit, Type::Unit) | (Type::Bool, Type::Bool) | (Type::Int, Type::Int) => (),
                (Type::Num(a, x), Type::Num(b, y)) if a == b && x == y => (),
                (Type::Bytes(a), Type::Bytes(b)) | (Type::Cap(a), Type::Cap(b)) if a == b => (),
                (Type::Vec(a, x), Type::Vec(b, y)) | (Type::Seq(a, x), Type::Seq(b, y))
                    if a == b =>
                {
                    pending.push((*x, *y));
                }
                (Type::Pair(a, b), Type::Pair(x, y)) | (Type::Sum(a, b), Type::Sum(x, y)) => {
                    pending.push((*b, *y));
                    pending.push((*a, *x));
                }
                _ => return false,
            }
        }
        true
    }
    pub fn typ(&self, id: TypeId) -> &Type {
        &self.types[id.0]
    }
    pub fn term(&self, id: TermId) -> &Term {
        &self.terms[id.0]
    }
    pub(crate) fn add_type(&mut self, typ: Type) -> TypeId {
        for child in typ.children() {
            assert!(
                child.0 < self.types.len(),
                "named type child precedes parent"
            );
        }
        let id = TypeId(self.types.len());
        self.types.push(typ);
        id
    }
    pub(crate) fn add_term(&mut self, term: Term) -> TermId {
        for child in term.children() {
            assert!(
                child.0 < self.terms.len(),
                "named term child precedes parent"
            );
        }
        let id = TermId(self.terms.len());
        self.terms.push(term);
        id
    }
    pub fn has(&self, name: &Name, root: TermId) -> bool {
        let mut pending = vec![root];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let term = self.term(id);
            if matches!(term, Term::Var(value) if value == name) || term.bindings().contains(&name)
            {
                return true;
            }
            pending.extend(term.children());
        }
        false
    }
}
