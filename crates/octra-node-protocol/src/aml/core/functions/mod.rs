// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_fun validation and hygienic expansion into named core syntax.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    check, effects_text,
    limit::Limit,
    lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, TypeId},
    term::{Program, Terms},
    types::{Kind, Multiplicity, Types},
    Effects, Natural,
};
use std::collections::BTreeSet;
mod error;
mod rename;
mod shape;
pub use error::Error;
pub use rename::rename;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrow {
    pub multiplicity: Multiplicity,
    pub caps: Vec<Bind>,
    pub arg: Bind,
    pub out: TypeId,
    pub effects: Effects,
    pub limit: Option<Limit>,
}
impl Arrow {
    pub fn new(multiplicity: Multiplicity, caps: Vec<Bind>, arg: Bind, out: TypeId) -> Self {
        Self {
            multiplicity,
            caps,
            arg,
            out,
            effects: Effects::new(),
            limit: None,
        }
    }
    pub fn values(&self) -> Vec<Bind> {
        let mut values = self.caps.clone();
        values.push(self.arg.clone());
        values
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
    pub arrow: Arrow,
    pub body: TermId,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Ret(TermId),
    Let(Bind, TermId, BodyId),
    If(TermId, BodyId, BodyId),
    Call(Bind, Name, Vec<TermId>, TermId, BodyId),
}
#[derive(Clone, Debug, Default)]
pub struct Bodies(Vec<Body>);
impl Bodies {
    pub fn try_get(&self, id: BodyId) -> Option<&Body> {
        self.0.get(id.0)
    }
    pub fn insert(
        &mut self,
        syntax: &Syntax,
        body: Body,
    ) -> std::result::Result<BodyId, super::arena::Reference> {
        let mut refs = Vec::new();
        match &body {
            Body::Ret(value) => syntax.require_term(*value)?,
            Body::Let(bind, value, rest) => {
                syntax.require_type(bind.typ)?;
                syntax.require_term(*value)?;
                refs.push(*rest);
            }
            Body::If(guard, yes, no) => {
                syntax.require_term(*guard)?;
                refs.extend([*yes, *no]);
            }
            Body::Call(bind, _, captures, argument, rest) => {
                syntax.require_type(bind.typ)?;
                for value in captures {
                    syntax.require_term(*value)?;
                }
                syntax.require_term(*argument)?;
                refs.push(*rest);
            }
        }
        for child in refs {
            if self.try_get(child).is_none() {
                return Err(super::arena::Reference {
                    kind: super::arena::Kind::FunctionBody,
                    index: child.0,
                    length: self.0.len(),
                });
            }
        }
        Ok(self.add(body))
    }
    pub fn get(&self, id: BodyId) -> &Body {
        &self.0[id.0]
    }
    pub(crate) fn add(&mut self, body: Body) -> BodyId {
        let children: &[BodyId] = match &body {
            Body::Ret(_) | Body::If(..) => &[],
            Body::Let(_, _, child) | Body::Call(_, _, _, _, child) => std::slice::from_ref(child),
        };
        assert!(
            children.iter().all(|id| id.0 < self.0.len()),
            "function body child precedes parent"
        );
        if let Body::If(_, yes, no) = &body {
            assert!(
                yes.0 < self.0.len() && no.0 < self.0.len(),
                "function branches precede parent"
            );
        }
        let id = BodyId(self.0.len());
        self.0.push(body);
        id
    }
}
pub fn find<'a>(functions: &'a [Function], name: &Name) -> Option<&'a Function> {
    functions.iter().find(|item| &item.name == name)
}
pub fn mode(caps: &[Bind]) -> Result<Multiplicity> {
    let mut linear = false;
    for cap in caps {
        match cap.multiplicity {
            Multiplicity::Zero => return Err(Error::Mode(cap.name.clone())),
            Multiplicity::One => linear = true,
            Multiplicity::Many => (),
        }
    }
    Ok(if linear {
        Multiplicity::One
    } else {
        Multiplicity::Many
    })
}
pub fn valid(syntax: &Syntax, types: &mut Types, terms: &mut Terms, item: &Function) -> Result<()> {
    let values = item.arrow.values();
    if mode(&item.arrow.caps)? != item.arrow.multiplicity {
        return Err(Error::Mode(item.name.clone()));
    }
    // Effect atoms contain private, checked Naturals; invalid atom IDs cannot be constructed.
    if item
        .arrow
        .limit
        .as_ref()
        .is_some_and(|limit| !limit.valid())
    {
        return Err(Error::Limit(item.name.clone()));
    }
    let mut seen = BTreeSet::new();
    for value in &values {
        if !seen.insert(&value.name) {
            return Err(Error::Duplicate(value.name.clone()));
        }
    }
    let out = lower::typ(syntax, types, item.arrow.out).map_err(Error::Low)?;
    let program = lower::program(syntax, types, terms, &values, item.body).map_err(Error::Low)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let info = checked.info();
    if info.typ() != out {
        return Err(Error::Out(item.name.clone()));
    }
    if !info.effects().is_subset(&item.arrow.effects) {
        return Err(Error::Mark(
            item.name.clone(),
            item.arrow.effects.clone(),
            info.effects().clone(),
        ));
    }
    if let Some(limit) = &item.arrow.limit {
        if !info.resources().le(limit) {
            return Err(Error::Over(
                item.name.clone(),
                limit.clone(),
                info.resources().clone(),
            ));
        }
    }
    Ok(())
}
pub fn definitions(
    syntax: &Syntax,
    types: &mut Types,
    terms: &mut Terms,
    functions: &[Function],
) -> Result<()> {
    let maximum = LOCAL.get(Field::Inputs) as usize;
    if functions.len() > maximum {
        return Err(Error::Functions(maximum, maximum + 1));
    }
    let mut seen = BTreeSet::new();
    for item in functions {
        if !seen.insert(&item.name) {
            return Err(Error::Duplicate(item.name.clone()));
        }
        valid(syntax, types, terms, item)?;
    }
    Ok(())
}
fn aliases(values: &[Bind]) -> Result<Vec<Bind>> {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let index = u32::try_from(index)
                .ok()
                .and_then(Natural::from_u32)
                .ok_or(Error::Low(lower::Error::Count))?;
            Ok(Bind {
                name: Name::slot(index),
                ..value.clone()
            })
        })
        .collect()
}
fn call(syntax: &mut Syntax, item: &Function, actuals: &[TermId]) -> Result<TermId> {
    let formals = item.arrow.values();
    let aliases = aliases(&formals)?;
    let env: Vec<_> = formals
        .iter()
        .zip(&aliases)
        .map(|(formal, alias)| (formal.name.clone(), alias.name.clone()))
        .collect();
    let mut body = rename(syntax, &env, item.body);
    for (formal, actual) in aliases.into_iter().zip(actuals).rev() {
        body = syntax.add_term(Term::Let(formal, *actual, body));
    }
    Ok(body)
}
pub fn direct(syntax: &Syntax, types: &mut Types, item: &Function) -> bool {
    item.arrow.effects.is_empty()
        && lower::typ(syntax, types, item.arrow.out).is_ok_and(|out| types.kind(out) == Kind::Data)
        && item
            .arrow
            .caps
            .iter()
            .chain(std::iter::once(&item.arrow.arg))
            .all(|value| value.multiplicity == Multiplicity::Many)
}
pub fn apply(syntax: &mut Syntax, item: &Function, actuals: &[TermId]) -> Result<TermId> {
    let expected = item.arrow.caps.len() + 1;
    if actuals.len() != expected {
        return Err(Error::Arity(item.name.clone(), expected, actuals.len()));
    }
    call(syntax, item, actuals)
}
fn same_type(syntax: &Syntax, types: &mut Types, left: TypeId, right: TypeId) -> bool {
    let left = lower::typ(syntax, types, left);
    let right = lower::typ(syntax, types, right);
    matches!((left, right), (Ok(left), Ok(right)) if left == right)
}
fn target<'a>(
    syntax: &Syntax,
    types: &mut Types,
    functions: &'a [Function],
    result: &Bind,
    name: &Name,
    caps: &[TermId],
) -> Result<&'a Function> {
    let item = find(functions, name).ok_or_else(|| Error::Function(name.clone()))?;
    let expected = item.arrow.caps.len();
    if expected != caps.len() {
        return Err(Error::Arity(name.clone(), expected, caps.len()));
    }
    if !same_type(syntax, types, result.typ, item.arrow.out) {
        return Err(Error::Out(name.clone()));
    }
    Ok(item)
}
fn expand(
    syntax: &mut Syntax,
    types: &mut Types,
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<TermId> {
    enum Task {
        Visit(BodyId),
        Let(Bind, TermId),
        If(TermId),
        Call(Bind, usize, Vec<TermId>),
    }
    let mut pending = vec![Task::Visit(root)];
    let mut values = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Task::Visit(id) => match bodies.get(id) {
                Body::Ret(term) => values.push(*term),
                Body::Let(bind, value, body) => {
                    pending.push(Task::Let(bind.clone(), *value));
                    pending.push(Task::Visit(*body));
                }
                Body::If(guard, yes, no) => {
                    pending.push(Task::If(*guard));
                    pending.push(Task::Visit(*no));
                    pending.push(Task::Visit(*yes));
                }
                Body::Call(result, name, caps, arg, rest) => {
                    let item = target(syntax, types, functions, result, name, caps)?;
                    let index = functions
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, item))
                        .expect("selected function");
                    let mut actuals = caps.clone();
                    actuals.push(*arg);
                    pending.push(Task::Call(result.clone(), index, actuals));
                    pending.push(Task::Visit(*rest));
                }
            },
            Task::Let(bind, value) => {
                let body = values.pop().expect("expanded function body");
                values.push(syntax.add_term(Term::Let(bind, value, body)));
            }
            Task::If(guard) => {
                let no = values.pop().expect("expanded no branch");
                let yes = values.pop().expect("expanded yes branch");
                values.push(syntax.add_term(Term::If(guard, yes, no)));
            }
            Task::Call(result, index, actuals) => {
                let rest = values.pop().expect("expanded call continuation");
                let value = call(syntax, &functions[index], &actuals)?;
                values.push(syntax.add_term(Term::Let(result, value, rest)));
            }
        }
    }
    Ok(values.pop().expect("expanded function root"))
}
pub fn resolve(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<TermId> {
    definitions(syntax, types, terms, functions)?;
    shape::shape(syntax, types, bodies, functions, root)?;
    expand(syntax, types, bodies, functions, root)
}
pub fn names(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<Vec<(Natural, Vec<u8>)>> {
    let body = resolve(syntax, types, terms, bodies, functions, root)?;
    lower::names(syntax, inputs, body).ok_or(Error::Low(lower::Error::Count))
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<Program> {
    let body = resolve(syntax, types, terms, bodies, functions, root)?;
    lower::program(syntax, types, terms, inputs, body).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, bodies, functions, root)?;
    check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)
}
