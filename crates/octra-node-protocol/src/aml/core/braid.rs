// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_braid bounded pairwise vector mapping over two evaluated sources.
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
                b"braid type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Data(typ) => [
                b"braid data type expected actual = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Fresh => b"braid private name space exhausted".to_vec(),
            Self::Nodes(actual) => format!(
                "braid node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "braid depth limit = {} actual = {actual}",
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
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<()> {
    let first_typ = lower::typ(syntax, types, first.typ).map_err(Error::Low)?;
    let second_typ = lower::typ(syntax, types, second.typ).map_err(Error::Low)?;
    let out_typ = lower::typ(syntax, types, out).map_err(Error::Low)?;
    for typ in [first_typ, second_typ, out_typ] {
        if types.kind(typ) != Kind::Data {
            return Err(Error::Data(typ));
        }
    }
    let program = lower::program(syntax, types, terms, &[first.clone(), second.clone()], body)
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
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<()> {
    body_check(syntax, types, terms, out, first, second, body)?;
    let left = finite::stat(syntax, left)?;
    let right = finite::stat(syntax, right)?;
    let body = finite::stat(syntax, body)?;
    let base = left.nodes + right.nodes + 3;
    let nodes = BigInt::from(base) + BigInt::from(count.get()) * BigInt::from(body.nodes + 6);
    let source_depth = (1 + left.depth).max(2 + right.depth);
    let depth = if count.get() == 0 {
        source_depth.max(2)
    } else {
        source_depth.max(6.max(5 + body.depth))
    };
    finite::fit(&nodes, depth).map_err(Error::from)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn term(
    syntax: &mut Syntax,
    left_name: Name,
    right_name: Name,
    count: Natural,
    out: TypeId,
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> TermId {
    let left_type = syntax.add_type(Type::Vec(BigInt::from(count.get()), first.typ));
    let left_bind = Bind {
        name: left_name.clone(),
        multiplicity: Multiplicity::Many,
        typ: left_type,
    };
    let right_type = syntax.add_type(Type::Vec(BigInt::from(count.get()), second.typ));
    let right_bind = Bind {
        name: right_name.clone(),
        multiplicity: Multiplicity::Many,
        typ: right_type,
    };
    let mut values = Vec::with_capacity(count.get() as usize);
    for index in 0..count.get() {
        let left = syntax.add_term(Term::Var(left_name.clone()));
        let first_value = syntax.add_term(Term::At(BigInt::from(index), left));
        let right = syntax.add_term(Term::Var(right_name.clone()));
        let second_value = syntax.add_term(Term::At(BigInt::from(index), right));
        let next = syntax.add_term(Term::Let(second.clone(), second_value, body));
        values.push(syntax.add_term(Term::Let(first.clone(), first_value, next)));
    }
    let values = syntax.add_term(Term::Vec(out, values));
    let right = syntax.add_term(Term::Let(right_bind, right, values));
    syntax.add_term(Term::Let(left_bind, left, right))
}
pub fn build(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    left_name: Name,
    right_name: Name,
    count: Natural,
    out: TypeId,
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(
        syntax, types, terms, count, out, left, right, first, second, body,
    )?;
    let binds = [first.clone(), second.clone()];
    let values = [left, right, body];
    if !finite::clear(
        syntax,
        std::slice::from_ref(&right_name),
        &binds,
        &values,
        &left_name,
    ) || !finite::clear(
        syntax,
        std::slice::from_ref(&left_name),
        &binds,
        &values,
        &right_name,
    ) {
        return Err(Error::Fresh);
    }
    Ok(term(
        syntax, left_name, right_name, count, out, left, right, first, second, body,
    ))
}
pub fn make(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    out: TypeId,
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(
        syntax, types, terms, count, out, left, right, first, second, body,
    )?;
    let binds = [first.clone(), second.clone()];
    let values = [left, right, body];
    let left_name = finite::pick(syntax, &[], &binds, &values).ok_or(Error::Fresh)?;
    let right_name = finite::pick(syntax, std::slice::from_ref(&left_name), &binds, &values)
        .ok_or(Error::Fresh)?;
    Ok(term(
        syntax, left_name, right_name, count, out, left, right, first, second, body,
    ))
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<Program> {
    let root = make(
        syntax, types, terms, count, out, left, right, first, second, body,
    )?;
    lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    left: TermId,
    right: TermId,
    first: &Bind,
    second: &Bind,
    body: TermId,
) -> Result<check::Checked> {
    let program = lower(
        syntax, types, terms, inputs, count, out, left, right, first, second, body,
    )?;
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
