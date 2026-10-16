// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_spec size specialization. Raw expansion is a required compiler dependency;
//! successful specialization always validates the resulting C_fun definition.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    declaration::{self, TypeId},
    functions,
    index::{self, Env, IndexId},
    limit::Limit,
    parse::ast::{Ast, Bind, ExprId, Form, Law},
    rule::{Field, LOCAL},
    syntax::{self, Name},
    term::Terms,
    types::{Multiplicity, Types},
    Effects, Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Laws(Vec<Law>);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LawError {
    Count(usize, usize),
    Index(index::Error),
}
impl LawError {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Count(limit, actual) => {
                format!("form law count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Index(error) => error.text(),
        }
    }
}
impl Laws {
    pub fn new(items: Vec<Law>) -> std::result::Result<Self, LawError> {
        let limit = LOCAL.get(Field::Inputs) as usize;
        if items.len() > limit {
            Err(LawError::Count(limit, items.len()))
        } else {
            Ok(Self(items))
        }
    }
    pub fn items(&self) -> &[Law] {
        &self.0
    }
    pub fn hold(&self, ast: &Ast, environment: &Env) -> std::result::Result<(), LawError> {
        for law in &self.0 {
            ast.indices
                .hold(environment, law.relation, law.left, law.right)
                .map_err(LawError::Index)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrow {
    pub multiplicity: Multiplicity,
    pub captures: Vec<Bind>,
    pub argument: Bind,
    pub output: TypeId,
    pub effects: Effects,
    pub limit: Option<Limit>,
}
impl Arrow {
    pub fn new(
        multiplicity: Multiplicity,
        captures: Vec<Bind>,
        argument: Bind,
        output: TypeId,
    ) -> Self {
        Self {
            multiplicity,
            captures,
            argument,
            output,
            effects: Effects::new(),
            limit: None,
        }
    }
    pub fn marks(mut self, effects: Effects) -> Self {
        self.effects = effects;
        self
    }
    pub fn under(mut self, limit: Limit) -> Self {
        self.limit = Some(limit);
        self
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub name: Name,
    pub parameters: Vec<Name>,
    pub laws: Laws,
    pub arrow: Arrow,
    pub body: ExprId,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Duplicate(Vec<u8>),
    Count(usize, usize),
    Arity(Vec<u8>, usize, usize),
    Index(index::Error),
    Law(LawError),
    Declaration(declaration::Error),
    Raw(Vec<u8>),
    Function(functions::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Duplicate(name) => [b"duplicate form binder = ".as_slice(), name].concat(),
            Self::Count(limit, actual) => {
                format!("form size count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Arity(name, expected, actual) => [
                b"form size arity name = ".as_slice(),
                name,
                format!(" expected = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::Index(error) => error.text(),
            Self::Law(error) => error.text(),
            Self::Declaration(error) => error.text(),
            Self::Raw(error) => error.clone(),
            Self::Function(error) => error.text(types),
        }
    }
}
impl Function {
    pub fn new(name: Name, parameters: Vec<Name>, arrow: Arrow, body: ExprId) -> Result<Self> {
        let item = Self {
            name,
            parameters,
            laws: Laws::default(),
            arrow,
            body,
        };
        item.valid()?;
        Ok(item)
    }
    pub fn require(mut self, laws: Laws) -> Self {
        self.laws = laws;
        self
    }
    /// Kind parameters are handled by C_poly before this size-specialized base.
    pub fn from_form(form: &Form) -> Result<Self> {
        let arrow = Arrow {
            multiplicity: form.multiplicity,
            captures: form.captures.clone(),
            argument: form.argument.clone(),
            output: form.output,
            effects: form.effects.clone(),
            limit: form.limit.clone(),
        };
        let item = Self::new(form.name.clone(), form.sizes.clone(), arrow, form.body)?;
        Ok(item.require(Laws::new(form.laws.clone()).map_err(Error::Law)?))
    }
    pub fn valid(&self) -> Result<()> {
        let limit = LOCAL.get(Field::Inputs) as usize;
        if self.parameters.len() > limit {
            return Err(Error::Count(limit, self.parameters.len()));
        }
        let mut seen = BTreeSet::new();
        for name in self
            .parameters
            .iter()
            .chain(self.arrow.captures.iter().map(|bind| &bind.name))
            .chain(std::iter::once(&self.arrow.argument.name))
        {
            if !seen.insert(name) {
                return Err(Error::Duplicate(name.text().to_vec()));
            }
        }
        Ok(())
    }
}

/// C_raw elaboration must expand every extended raw construct into this same
/// Ast's named syntax arena. Returning raw Expr IDs cannot satisfy this API.
/// The callback supplies native C_raw diagnostics at their semantic boundary.
pub trait Elaborator {
    fn elaborate(
        &mut self,
        ast: &mut Ast,
        environment: &Env,
        body: ExprId,
    ) -> std::result::Result<syntax::TermId, Vec<u8>>;
}
impl<F> Elaborator for F
where
    F: FnMut(&mut Ast, &Env, ExprId) -> std::result::Result<syntax::TermId, Vec<u8>>,
{
    fn elaborate(
        &mut self,
        ast: &mut Ast,
        environment: &Env,
        body: ExprId,
    ) -> std::result::Result<syntax::TermId, Vec<u8>> {
        self(ast, environment, body)
    }
}
pub fn args(ast: &Ast, environment: &Env, actuals: &[IndexId]) -> Result<Vec<Natural>> {
    actuals
        .iter()
        .map(|value| ast.indices.eval(environment, *value).map_err(Error::Index))
        .collect()
}
fn environment(ast: &mut Ast, base: &Env, parameters: &[Name], values: &[Natural]) -> Result<Env> {
    let mut out = base.clone();
    let mut index = 0;
    while index < parameters.len() && index < values.len() {
        let raw = BigInt::from(values[index].get());
        let value = ast
            .indices
            .lit(&raw)
            .ok_or(Error::Index(index::Error::Nat(raw)))?;
        out = out
            .put(&ast.indices, parameters[index].clone(), value)
            .map_err(Error::Index)?;
        index += 1;
    }
    if index != parameters.len() || index != values.len() {
        return Err(Error::Count(parameters.len() - index, values.len() - index));
    }
    Ok(out)
}
fn bind(ast: &mut Ast, environment: &Env, value: &Bind) -> Result<syntax::Bind> {
    let typ = ast
        .declarations
        .typ_in(environment, &ast.indices, &mut ast.syntax, value.typ)
        .map_err(Error::Declaration)?;
    Ok(syntax::Bind {
        name: value.name.clone(),
        multiplicity: value.multiplicity,
        typ,
    })
}
pub fn mono(
    ast: &mut Ast,
    types: &mut Types,
    terms: &mut Terms,
    base: &Env,
    name: Name,
    item: &Function,
    values: &[Natural],
    elaborator: &mut impl Elaborator,
) -> Result<functions::Function> {
    item.valid()?;
    if item.parameters.len() != values.len() {
        return Err(Error::Arity(
            item.name.text().to_vec(),
            item.parameters.len(),
            values.len(),
        ));
    }
    let environment = environment(ast, base, &item.parameters, values)?;
    item.laws.hold(ast, &environment).map_err(Error::Law)?;
    let mut captures = Vec::with_capacity(item.arrow.captures.len());
    for value in &item.arrow.captures {
        captures.push(bind(ast, &environment, value)?);
    }
    let argument = bind(ast, &environment, &item.arrow.argument)?;
    let output = ast
        .declarations
        .typ_in(
            &environment,
            &ast.indices,
            &mut ast.syntax,
            item.arrow.output,
        )
        .map_err(Error::Declaration)?;
    let body = elaborator
        .elaborate(ast, &environment, item.body)
        .map_err(Error::Raw)?;
    let arrow = functions::Arrow {
        multiplicity: item.arrow.multiplicity,
        caps: captures,
        arg: argument,
        out: output,
        effects: item.arrow.effects.clone(),
        limit: item.arrow.limit.clone(),
    };
    let function = functions::Function { name, arrow, body };
    functions::valid(&ast.syntax, types, terms, &function).map_err(Error::Function)?;
    Ok(function)
}
pub fn inst(
    ast: &mut Ast,
    types: &mut Types,
    terms: &mut Terms,
    base: &Env,
    name: Name,
    item: &Function,
    actuals: &[IndexId],
    elaborator: &mut impl Elaborator,
) -> Result<(Vec<Natural>, functions::Function)> {
    let values = args(ast, base, actuals)?;
    let function = mono(ast, types, terms, base, name, item, &values, elaborator)?;
    Ok((values, function))
}
