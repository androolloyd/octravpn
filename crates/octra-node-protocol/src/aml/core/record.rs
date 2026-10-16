// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_rec record/shape declarations. Records use a single tagged data
//! constructor containing a right-associated product, with ordered field access.
use super::{
    check,
    data::{self, Arm, Constructor},
    lower,
    rule::{Field as LimitField, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, Type as SyntaxType, TypeId},
    term::{Program, Terms},
    types::{Multiplicity, Types},
    Natural,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: Name,
    pub typ: TypeId,
}
impl Field {
    pub fn new(name: Name, typ: TypeId) -> Self {
        Self { name, typ }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub name: Name,
    pub value: TermId,
}
impl Item {
    pub fn new(name: Name, value: TermId) -> Self {
        Self { name, value }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pick {
    pub name: Name,
    pub bind: Bind,
}
impl Pick {
    pub fn new(name: Name, bind: Bind) -> Self {
        Self { name, bind }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decl {
    name: Name,
    fields: Vec<Field>,
    products: Vec<TypeId>,
    data: data::Decl,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Data(data::Error),
    Low(lower::Error),
    Check(check::Error),
    Empty,
    Count(usize, usize),
    Dup(Vec<u8>),
    BindDup(Vec<u8>),
    Items(usize, usize),
    Order(Vec<u8>, Vec<u8>),
    Type(Vec<u8>),
    Mode(Vec<u8>, Multiplicity, Multiplicity),
    Id,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Data(error) => error.text(types),
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Empty => b"shape fields empty".to_vec(),
            Self::Count(maximum, actual) => {
                format!("shape field count max = {maximum} actual = {actual}").into_bytes()
            }
            Self::Dup(name) => [b"duplicate shape field = ".as_slice(), name].concat(),
            Self::BindDup(name) => [b"duplicate shape binder = ".as_slice(), name].concat(),
            Self::Items(expected, actual) => {
                format!("shape fields expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Order(expected, actual) => [
                b"shape field expected = ".as_slice(),
                expected,
                b" actual = ",
                actual,
            ]
            .concat(),
            Self::Type(name) => [b"shape field type changed = ".as_slice(), name].concat(),
            Self::Mode(name, expected, actual) => [
                b"shape field mode name = ".as_slice(),
                name,
                b" expected = ",
                expected.text(),
                b" actual = ",
                actual.text(),
            ]
            .concat(),
            Self::Id => b"shape binder id outside profile".to_vec(),
        }
    }
}
fn next(seed: Natural) -> Result<Natural> {
    seed.checked_add(Natural::from_u32(1).expect("natural one"))
        .ok_or(Error::Id)
}
fn order<T>(fields: &[Field], values: &[T], name: impl Fn(&T) -> &Name) -> Result<()> {
    if fields.len() != values.len() {
        return Err(Error::Items(fields.len(), values.len()));
    }
    for (field, value) in fields.iter().zip(values) {
        let actual = name(value);
        if &field.name != actual {
            return Err(Error::Order(
                field.name.text().to_vec(),
                actual.text().to_vec(),
            ));
        }
    }
    Ok(())
}
impl Decl {
    pub fn new(syntax: &mut Syntax, bits: &[bool], name: Name, fields: Vec<Field>) -> Result<Self> {
        if fields.is_empty() {
            return Err(Error::Empty);
        }
        let maximum = LOCAL.get(LimitField::Inputs) as usize;
        if fields.len() > maximum {
            return Err(Error::Count(maximum, fields.len()));
        }
        let mut names = BTreeSet::new();
        for field in &fields {
            if !names.insert(field.name.clone()) {
                return Err(Error::Dup(field.name.text().to_vec()));
            }
        }
        let mut products = Vec::with_capacity(fields.len());
        let mut suffix = None;
        for field in fields.iter().rev() {
            let typ = match suffix {
                None => field.typ,
                Some(right) => syntax.add_type(SyntaxType::Pair(field.typ, right)),
            };
            products.push(typ);
            suffix = Some(typ);
        }
        products.reverse();
        let data = data::Decl::new(
            syntax,
            bits,
            name.clone(),
            vec![Constructor::new(name.clone(), products[0])],
        )
        .map_err(Error::Data)?;
        Ok(Self {
            name,
            fields,
            products,
            data,
        })
    }
    pub fn name(&self) -> &Name {
        &self.name
    }
    pub fn bits(&self) -> &[bool] {
        self.data.bits()
    }
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    pub fn typ(&self) -> TypeId {
        self.data.typ()
    }

    pub fn make(&self, syntax: &mut Syntax, items: &[Item]) -> Result<TermId> {
        order(&self.fields, items, |item| &item.name)?;
        let mut reversed = items.iter().rev();
        let mut value = reversed.next().ok_or(Error::Empty)?.value;
        for item in reversed {
            value = syntax.add_term(Term::Pair(item.value, value));
        }
        self.data
            .make(syntax, &self.name, value)
            .map_err(Error::Data)
    }
    fn picks(&self, syntax: &Syntax, values: &[Pick]) -> Result<()> {
        order(&self.fields, values, |item| &item.name)?;
        let mut names = BTreeSet::new();
        for item in values {
            if !names.insert(item.bind.name.clone()) {
                return Err(Error::BindDup(item.bind.name.text().to_vec()));
            }
        }
        let mut types = Types::default();
        for (field, item) in self.fields.iter().zip(values) {
            let expected = lower::typ(syntax, &mut types, field.typ).map_err(Error::Low)?;
            let actual = lower::typ(syntax, &mut types, item.bind.typ).map_err(Error::Low)?;
            if expected != actual {
                return Err(Error::Type(field.name.text().to_vec()));
            }
            let mode = data::needed(&types, expected);
            if item.bind.multiplicity != mode {
                return Err(Error::Mode(
                    field.name.text().to_vec(),
                    mode,
                    item.bind.multiplicity,
                ));
            }
        }
        Ok(())
    }
    pub fn split(
        &self,
        syntax: &mut Syntax,
        value: TermId,
        values: &[Pick],
        body: TermId,
    ) -> Result<TermId> {
        self.picks(syntax, values)?;
        let mut types = Types::default();
        let prod = lower::typ(syntax, &mut types, self.products[0]).map_err(Error::Low)?;
        let two = next(Natural::from_u32(1).expect("natural one"))?;
        let mut seed = next(two)?;
        let payload = Bind {
            name: Name::dslot(two),
            multiplicity: data::needed(&types, prod),
            typ: self.products[0],
        };
        let mut current = syntax.add_term(Term::Var(payload.name.clone()));
        let mut frames = Vec::with_capacity(values.len() - 1);
        for (index, item) in values[..values.len() - 1].iter().enumerate() {
            let right = self.products[index + 1];
            let right_core = lower::typ(syntax, &mut types, right).map_err(Error::Low)?;
            let bind = Bind {
                name: Name::dslot(seed),
                multiplicity: data::needed(&types, right_core),
                typ: right,
            };
            seed = next(seed)?;
            let child = syntax.add_term(Term::Var(bind.name.clone()));
            frames.push((current, item.bind.clone(), bind));
            current = child;
        }
        let last = values.last().ok_or(Error::Empty)?;
        let mut body = syntax.add_term(Term::Let(last.bind.clone(), current, body));
        for (value, left, right) in frames.into_iter().rev() {
            body = syntax.add_term(Term::Unpair(value, left, right, body));
        }
        self.data
            .case(syntax, value, &[Arm::new(self.name.clone(), payload, body)])
            .map_err(Error::Data)
    }
    pub fn lower(
        &self,
        syntax: &mut Syntax,
        types: &mut Types,
        terms: &mut Terms,
        inputs: &[Bind],
        value: TermId,
        values: &[Pick],
        body: TermId,
    ) -> Result<Program> {
        let root = self.split(syntax, value, values, body)?;
        lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)
    }
    pub fn check(
        &self,
        syntax: &mut Syntax,
        types: &mut Types,
        terms: &mut Terms,
        inputs: &[Bind],
        value: TermId,
        values: &[Pick],
        body: TermId,
    ) -> Result<check::Checked> {
        let program = self.lower(syntax, types, terms, inputs, value, values, body)?;
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)
    }
}
