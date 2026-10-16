// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_weave bounded vector mapping. Body checking and full expansion bounds
//! precede generated-name selection and allocation of the mapped elements.
use super::{
    check, finite, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, Type, TypeId},
    term::{Program, Terms},
    types::{self, Kind, Multiplicity, Types},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Need(types::TypeId, types::TypeId),
    Data(types::TypeId),
    Fresh,
    Nodes(BigInt),
    Depth(usize),
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<finite::Error> for Error {
    fn from(error: finite::Error) -> Self {
        match error {
            finite::Error::Nodes(value) => Self::Nodes(value),
            finite::Error::Depth(value) => Self::Depth(value),
        }
    }
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Need(expected, actual) => [
                b"weave type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Data(typ) => [
                b"weave data type expected actual = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Fresh => b"weave private name space exhausted".to_vec(),
            Self::Nodes(actual) => format!(
                "weave node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "weave depth limit = {} actual = {actual}",
                LOCAL.get(Field::TermDepth)
            )
            .into_bytes(),
        }
    }
}
fn body_check(
    syntax: &Syntax,
    types: &mut Types,
    terms: &mut Terms,
    out: TypeId,
    item: &Bind,
    body: TermId,
) -> Result<()> {
    let item_typ = lower::typ(syntax, types, item.typ).map_err(Error::Low)?;
    let out_typ = lower::typ(syntax, types, out).map_err(Error::Low)?;
    if types.kind(item_typ) != Kind::Data {
        return Err(Error::Data(item_typ));
    }
    if types.kind(out_typ) != Kind::Data {
        return Err(Error::Data(out_typ));
    }
    let program = lower::program(syntax, types, terms, std::slice::from_ref(item), body)
        .map_err(Error::Low)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let actual = checked.info().typ();
    if actual == out_typ {
        Ok(())
    } else {
        Err(Error::Need(out_typ, actual))
    }
}
fn prep(
    syntax: &Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<()> {
    body_check(syntax, types, terms, out, item, body)?;
    let source = finite::stat(syntax, source)?;
    let body = finite::stat(syntax, body)?;
    let nodes =
        BigInt::from(source.nodes + 2) + BigInt::from(count.get()) * BigInt::from(body.nodes + 3);
    let depth = if count.get() == 0 {
        1 + source.depth
    } else {
        (1 + source.depth).max(4.max(3 + body.depth))
    };
    finite::fit(&nodes, depth).map_err(Error::from)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn term(
    syntax: &mut Syntax,
    source_name: Name,
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> TermId {
    let source_type = syntax.add_type(Type::Vec(BigInt::from(count.get()), item.typ));
    let source_bind = Bind {
        name: source_name.clone(),
        multiplicity: Multiplicity::Many,
        typ: source_type,
    };
    let mut values = Vec::with_capacity(count.get() as usize);
    for index in 0..count.get() {
        let source = syntax.add_term(Term::Var(source_name.clone()));
        let value = syntax.add_term(Term::At(BigInt::from(index), source));
        values.push(syntax.add_term(Term::Let(item.clone(), value, body)));
    }
    let values = syntax.add_term(Term::Vec(out, values));
    syntax.add_term(Term::Let(source_bind, source, values))
}
pub fn build(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    source_name: Name,
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(syntax, types, terms, count, out, source, item, body)?;
    if !finite::clear(
        syntax,
        &[],
        std::slice::from_ref(item),
        &[source, body],
        &source_name,
    ) {
        return Err(Error::Fresh);
    }
    Ok(term(syntax, source_name, count, out, source, item, body))
}
pub fn make(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(syntax, types, terms, count, out, source, item, body)?;
    let name = finite::pick(syntax, &[], std::slice::from_ref(item), &[source, body])
        .ok_or(Error::Fresh)?;
    Ok(term(syntax, name, count, out, source, item, body))
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<Program> {
    let term = make(syntax, types, terms, count, out, source, item, body)?;
    lower::program(syntax, types, terms, inputs, term).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, count, out, source, item, body)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let out_typ = lower::typ(syntax, types, out).map_err(Error::Low)?;
    let expected = types.intern(types::Type::Vec(count, out_typ));
    let actual = checked.info().typ();
    if expected == actual {
        Ok(checked)
    } else {
        Err(Error::Need(expected, actual))
    }
}
