// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_data tagged declarations, constructor injection and exhaustive ordered
//! matching over named syntax. A declaration grants no execution authority.
use super::{
    check, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, Type, TypeId},
    term::{Program, Terms},
    types::{Kind, Multiplicity, Types},
    Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeSet;
pub const TAG_LEN: usize = LOCAL.get(Field::Tag) as usize;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constructor {
    pub name: Name,
    pub arg: TypeId,
}
impl Constructor {
    pub fn new(name: Name, arg: TypeId) -> Self {
        Self { name, arg }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm {
    pub name: Name,
    pub bind: Bind,
    pub body: TermId,
}
impl Arm {
    pub fn new(name: Name, bind: Bind, body: TermId) -> Self {
        Self { name, bind, body }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decl {
    bits: Vec<bool>,
    tag: TypeId,
    mark: TermId,
    name: Name,
    ctors: Vec<Constructor>,
    sums: Vec<TypeId>,
    typ: TypeId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Empty,
    Tag(usize, usize),
    Count(usize, usize),
    Dup(Vec<u8>),
    Ctor(Vec<u8>),
    Arms(usize, usize),
    Order(Vec<u8>, Vec<u8>),
    Type(Vec<u8>),
    Mode(Vec<u8>, Multiplicity, Multiplicity),
    Id,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Empty => b"data constructors empty".to_vec(),
            Self::Tag(expected, actual) => {
                format!("data tag bits expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Count(maximum, actual) => {
                format!("constructor count max = {maximum} actual = {actual}").into_bytes()
            }
            Self::Dup(name) => [b"duplicate constructor = ".as_slice(), name].concat(),
            Self::Ctor(name) => [b"unknown constructor = ".as_slice(), name].concat(),
            Self::Arms(expected, actual) => {
                format!("match arms expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Order(expected, actual) => [
                b"match arm expected = ".as_slice(),
                expected,
                b" actual = ",
                actual,
            ]
            .concat(),
            Self::Type(name) => [b"match payload type changed = ".as_slice(), name].concat(),
            Self::Mode(name, expected, actual) => [
                b"match payload mode name = ".as_slice(),
                name,
                b" expected = ",
                expected.text(),
                b" actual = ",
                actual.text(),
            ]
            .concat(),
            Self::Id => b"match binder id outside profile".to_vec(),
        }
    }
}

pub(crate) fn needed(types: &Types, typ: super::types::TypeId) -> Multiplicity {
    match types.kind(typ) {
        Kind::Data => Multiplicity::Many,
        Kind::Resource => Multiplicity::One,
    }
}
fn validate(syntax: &Syntax, typ: TypeId) -> Result<()> {
    lower::typ(syntax, &mut Types::default(), typ).map_err(Error::Low)?;
    Ok(())
}
fn tag(syntax: &mut Syntax, bits: &[bool]) -> (TypeId, TermId) {
    let mut typ = syntax.add_type(Type::Bytes(BigInt::from(0)));
    let mut value = syntax.add_term(Term::Bytes(vec![]));
    for bit in bits.iter().rev() {
        let (head_type, head_value) = if *bit {
            (
                syntax.add_type(Type::Bool),
                syntax.add_term(Term::Bool(true)),
            )
        } else {
            (syntax.add_type(Type::Unit), syntax.add_term(Term::Unit))
        };
        typ = syntax.add_type(Type::Pair(head_type, typ));
        value = syntax.add_term(Term::Pair(head_value, value));
    }
    (typ, value)
}
impl Decl {
    pub fn new(
        syntax: &mut Syntax,
        bits: &[bool],
        name: Name,
        ctors: Vec<Constructor>,
    ) -> Result<Self> {
        if ctors.is_empty() {
            return Err(Error::Empty);
        }
        if bits.len() != TAG_LEN {
            return Err(Error::Tag(TAG_LEN, bits.len()));
        }
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if ctors.len() > maximum {
            return Err(Error::Count(maximum, ctors.len()));
        }
        let mut names = BTreeSet::new();
        for ctor in &ctors {
            if !names.insert(ctor.name.clone()) {
                return Err(Error::Dup(ctor.name.text().to_vec()));
            }
        }
        for ctor in &ctors {
            validate(syntax, ctor.arg)?;
        }
        // Native sums associate to the right. Store each suffix once; later
        // traversals still count every occurrence of its named syntax subtree.
        let mut sums = Vec::with_capacity(ctors.len());
        let mut suffix = None;
        for ctor in ctors.iter().rev() {
            let typ = match suffix {
                None => ctor.arg,
                Some(right) => syntax.add_type(Type::Sum(ctor.arg, right)),
            };
            sums.push(typ);
            suffix = Some(typ);
        }
        sums.reverse();
        let (tag, mark) = tag(syntax, bits);
        let typ = syntax.add_type(Type::Pair(tag, sums[0]));
        validate(syntax, typ)?;
        Ok(Self {
            bits: bits.to_vec(),
            tag,
            mark,
            name,
            ctors,
            sums,
            typ,
        })
    }
    pub fn name(&self) -> &Name {
        &self.name
    }
    pub fn bits(&self) -> &[bool] {
        &self.bits
    }
    pub fn constructors(&self) -> &[Constructor] {
        &self.ctors
    }
    pub fn ctors(&self) -> Vec<(Name, TypeId)> {
        self.ctors
            .iter()
            .map(|ctor| (ctor.name.clone(), ctor.arg))
            .collect()
    }
    pub fn typ(&self) -> TypeId {
        self.typ
    }

    pub fn make(&self, syntax: &mut Syntax, name: &Name, mut value: TermId) -> Result<TermId> {
        let position = self
            .ctors
            .iter()
            .position(|ctor| &ctor.name == name)
            .ok_or_else(|| Error::Ctor(name.text().to_vec()))?;
        if position + 1 < self.ctors.len() {
            value = syntax.add_term(Term::Inl(value, self.sums[position + 1]));
        }
        for ctor in self.ctors[..position].iter().rev() {
            value = syntax.add_term(Term::Inr(ctor.arg, value));
        }
        Ok(syntax.add_term(Term::Pair(self.mark, value)))
    }
    fn arms(&self, syntax: &Syntax, values: &[Arm]) -> Result<()> {
        if self.ctors.len() != values.len() {
            return Err(Error::Arms(self.ctors.len(), values.len()));
        }
        let mut types = Types::default();
        for (ctor, arm) in self.ctors.iter().zip(values) {
            if ctor.name != arm.name {
                return Err(Error::Order(
                    ctor.name.text().to_vec(),
                    arm.name.text().to_vec(),
                ));
            }
            let arg = lower::typ(syntax, &mut types, ctor.arg).map_err(Error::Low)?;
            let bind = lower::typ(syntax, &mut types, arm.bind.typ).map_err(Error::Low)?;
            if arg != bind {
                return Err(Error::Type(ctor.name.text().to_vec()));
            }
            let mode = needed(&types, arg);
            if arm.bind.multiplicity != mode {
                return Err(Error::Mode(
                    ctor.name.text().to_vec(),
                    mode,
                    arm.bind.multiplicity,
                ));
            }
        }
        Ok(())
    }
    pub fn case(&self, syntax: &mut Syntax, value: TermId, values: &[Arm]) -> Result<TermId> {
        self.arms(syntax, values)?;
        let zero = Natural::from_u32(0).expect("natural zero");
        let one = Natural::from_u32(1).expect("natural one");
        let mut seed = one.checked_add(one).ok_or(Error::Id)?;
        let tag = Bind {
            name: Name::dslot(zero),
            multiplicity: Multiplicity::Many,
            typ: self.tag,
        };
        let sum = Bind {
            name: Name::dslot(one),
            multiplicity: Multiplicity::One,
            typ: self.sums[0],
        };
        let mut current = syntax.add_term(Term::Var(sum.name.clone()));
        let mut frames = Vec::with_capacity(values.len() - 1);
        for (index, arm) in values[..values.len() - 1].iter().enumerate() {
            let next = seed.checked_add(one).ok_or(Error::Id)?;
            let bind = Bind {
                name: Name::dslot(seed),
                multiplicity: Multiplicity::One,
                typ: self.sums[index + 1],
            };
            let child = syntax.add_term(Term::Var(bind.name.clone()));
            frames.push((current, arm.bind.clone(), arm.body, bind));
            current = child;
            seed = next;
        }
        let arm = values.last().expect("nonempty declared constructor arms");
        let mut body = syntax.add_term(Term::Let(arm.bind.clone(), current, arm.body));
        for (value, yes_bind, yes_body, no_bind) in frames.into_iter().rev() {
            body = syntax.add_term(Term::Case(value, yes_bind, yes_body, no_bind, body));
        }
        Ok(syntax.add_term(Term::Unpair(value, tag, sum, body)))
    }
    pub fn lower(
        &self,
        syntax: &mut Syntax,
        types: &mut Types,
        terms: &mut Terms,
        inputs: &[Bind],
        value: TermId,
        values: &[Arm],
    ) -> Result<Program> {
        let body = self.case(syntax, value, values)?;
        lower::program(syntax, types, terms, inputs, body).map_err(Error::Low)
    }
    pub fn check(
        &self,
        syntax: &mut Syntax,
        types: &mut Types,
        terms: &mut Terms,
        inputs: &[Bind],
        value: TermId,
        values: &[Arm],
    ) -> Result<check::Checked> {
        let program = self.lower(syntax, types, terms, inputs, value, values)?;
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)
    }
}
