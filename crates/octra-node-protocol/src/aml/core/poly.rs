// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_poly kind specialization. Type substitution covers every raw expression
//! before C_spec size specialization and checked C_fun elaboration.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    declaration::{self, Type as Declaration, TypeId},
    functions,
    index::{Env, IndexId},
    lower,
    parse::ast::{Ast, Bind, ExprId, Form},
    rule::{Field, LOCAL},
    spec,
    syntax::Name,
    term::Terms,
    types::{self, Types},
    Natural,
};
use std::{cmp::Ordering, collections::BTreeSet};
mod order;
mod substitute;
pub use super::parse::ast::Kind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    name: Name,
    kind: Kind,
}
impl Parameter {
    pub fn new(name: Name, kind: Kind) -> Self {
        Self { name, kind }
    }
    pub fn name(&self) -> &Name {
        &self.name
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actual {
    typ: types::TypeId,
    raw: TypeId,
}
impl Actual {
    pub fn typ(&self) -> types::TypeId {
        self.typ
    }
    pub fn raw(&self) -> TypeId {
        self.raw
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    parameters: Vec<Parameter>,
    base: spec::Function,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Duplicate(Vec<u8>),
    Count(usize, usize),
    Arity(Vec<u8>, usize, usize),
    Kind(Vec<u8>, Kind, types::Kind),
    Name(Vec<u8>),
    Declaration(declaration::Error),
    Raw(Vec<u8>),
    Spec(spec::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
fn kind_text(kind: Kind) -> &'static [u8] {
    match kind {
        Kind::Data => b"data",
        Kind::Resource => b"res",
    }
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Duplicate(name) => [b"duplicate form kind binder = ".as_slice(), name].concat(),
            Self::Count(limit, actual) => {
                format!("form kind count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Arity(name, expected, actual) => [
                b"form kind arity name = ".as_slice(),
                name,
                format!(" expected = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::Kind(name, expected, actual) => [
                b"form kind mismatch name = ".as_slice(),
                name,
                b" expected = ",
                kind_text(*expected),
                b" actual = ",
                kind_text(match actual {
                    types::Kind::Data => Kind::Data,
                    types::Kind::Resource => Kind::Resource,
                }),
            ]
            .concat(),
            Self::Name(name) => [b"unknown form kind binder = ".as_slice(), name].concat(),
            Self::Declaration(error) => error.text(),
            Self::Raw(error) => error.clone(),
            Self::Spec(error) => error.text(types),
        }
    }
}
impl Function {
    pub fn new(parameters: Vec<Parameter>, base: spec::Function) -> Result<Self> {
        let limit = LOCAL.get(Field::Inputs) as usize;
        if parameters.len() > limit {
            return Err(Error::Count(limit, parameters.len()));
        }
        let mut seen = BTreeSet::new();
        for name in parameters
            .iter()
            .map(|parameter| &parameter.name)
            .chain(base.parameters.iter())
            .chain(base.arrow.captures.iter().map(|bind| &bind.name))
            .chain(std::iter::once(&base.arrow.argument.name))
        {
            if !seen.insert(name) {
                return Err(Error::Duplicate(name.text().to_vec()));
            }
        }
        Ok(Self { parameters, base })
    }
    pub fn from_form(form: &Form) -> Result<Self> {
        let base = spec::Function::from_form(form).map_err(Error::Spec)?;
        let parameters = form
            .kinds
            .iter()
            .map(|(name, kind)| Parameter::new(name.clone(), *kind))
            .collect();
        Self::new(parameters, base)
    }
    pub fn name(&self) -> &Name {
        &self.base.name
    }
    pub fn parameters(&self) -> &[Parameter] {
        &self.parameters
    }
    pub fn base(&self) -> &spec::Function {
        &self.base
    }
}
pub fn actuals(
    ast: &mut Ast,
    types: &mut Types,
    base: &Env,
    parameters: &[Parameter],
    values: &[TypeId],
) -> Result<Vec<Actual>> {
    if parameters.len() != values.len() {
        return Err(Error::Arity(
            b"kind".to_vec(),
            parameters.len(),
            values.len(),
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for (parameter, raw) in parameters.iter().zip(values) {
        let named = ast
            .declarations
            .typ_in(base, &ast.indices, &mut ast.syntax, *raw)
            .map_err(Error::Declaration)?;
        let typ = lower::typ(&ast.syntax, types, named)
            .map_err(|error| Error::Declaration(declaration::Error::Low(error)))?;
        let got = types.kind(typ);
        if parameter.kind
            != match got {
                types::Kind::Data => Kind::Data,
                types::Kind::Resource => Kind::Resource,
            }
        {
            return Err(Error::Kind(
                parameter.name.text().to_vec(),
                parameter.kind,
                got,
            ));
        }
        let raw = ast.declarations.push(Declaration::Exact(named));
        out.push(Actual { typ, raw });
    }
    Ok(out)
}
pub fn compare_actuals(types: &Types, left: &[Actual], right: &[Actual]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let order = order::typ(types, left.typ, right.typ);
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}
/// Substitution values belong to the same declaration arena as the source.
/// Lookup selects the first matching binding, as in native C_poly.find.
pub fn subst(
    ast: &mut Ast,
    environment: &[(Name, TypeId)],
    base: &spec::Function,
) -> Result<spec::Function> {
    let mut captures = Vec::with_capacity(base.arrow.captures.len());
    for bind in &base.arrow.captures {
        captures.push(substitute::bind(ast, environment, bind)?);
    }
    let argument = substitute::bind(ast, environment, &base.arrow.argument)?;
    let output = substitute::typ(&mut ast.declarations, environment, base.arrow.output)?;
    let body = substitute::term(ast, environment, base.body)?;
    let arrow = spec::Arrow {
        multiplicity: base.arrow.multiplicity,
        captures,
        argument,
        output,
        effects: base.arrow.effects.clone(),
        limit: base.arrow.limit.clone(),
    };
    let item = spec::Function::new(base.name.clone(), base.parameters.clone(), arrow, body)
        .map_err(Error::Spec)?;
    Ok(item.require(base.laws.clone()))
}
pub fn mono(
    ast: &mut Ast,
    types: &mut Types,
    terms: &mut Terms,
    size_environment: &Env,
    name: Name,
    item: &Function,
    actuals: &[Actual],
    sizes: &[Natural],
    elaborator: &mut impl spec::Elaborator,
) -> Result<functions::Function> {
    if item.parameters.len() != actuals.len() {
        return Err(Error::Arity(
            item.name().text().to_vec(),
            item.parameters.len(),
            actuals.len(),
        ));
    }
    let environment = item
        .parameters
        .iter()
        .zip(actuals)
        .map(|(parameter, value)| (parameter.name.clone(), value.raw))
        .collect::<Vec<_>>();
    let specialized = subst(ast, &environment, &item.base)?;
    spec::mono(
        ast,
        types,
        terms,
        size_environment,
        name,
        &specialized,
        sizes,
        elaborator,
    )
    .map_err(Error::Spec)
}
pub fn inst(
    ast: &mut Ast,
    types: &mut Types,
    terms: &mut Terms,
    base: &Env,
    name: Name,
    item: &Function,
    raw_types: &[TypeId],
    raw_sizes: &[IndexId],
    elaborator: &mut impl spec::Elaborator,
) -> Result<(Vec<Actual>, Vec<Natural>, functions::Function)> {
    let actuals = actuals(ast, types, base, &item.parameters, raw_types)?;
    let sizes = spec::args(ast, base, raw_sizes).map_err(Error::Spec)?;
    let function = mono(
        ast, types, terms, base, name, item, &actuals, &sizes, elaborator,
    )?;
    Ok((actuals, sizes, function))
}
