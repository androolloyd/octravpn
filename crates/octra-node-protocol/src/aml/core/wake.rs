// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_wake finite state trajectory expansion, retaining each updated state.
use super::{
    check, finite, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId},
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
                b"wake type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Data(typ) => [
                b"wake data type expected actual = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Fresh => b"wake private name space exhausted".to_vec(),
            Self::Nodes(actual) => format!(
                "wake node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "wake depth limit = {} actual = {actual}",
                LOCAL.get(Field::TermDepth)
            )
            .into_bytes(),
        }
    }
}
fn prep(
    syntax: &Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<()> {
    let state_typ = lower::typ(syntax, types, item.typ).map_err(Error::Low)?;
    if types.kind(state_typ) != Kind::Data {
        return Err(Error::Data(state_typ));
    }
    let program = lower::program(syntax, types, terms, std::slice::from_ref(item), body)
        .map_err(Error::Low)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let actual = checked.info().typ();
    if actual != state_typ {
        return Err(Error::Need(state_typ, actual));
    }
    let seed = finite::stat(syntax, seed)?;
    let body = finite::stat(syntax, body)?;
    let (nodes, depth) = if count.get() == 0 {
        (BigInt::from(seed.nodes + 2), seed.depth + 1)
    } else {
        (
            BigInt::from(seed.nodes) + BigInt::from(count.get()) * BigInt::from(body.nodes + 6),
            (seed.depth + 2).max(2 * count.get() as usize + body.depth.max(1)),
        )
    };
    finite::fit(&nodes, depth).map_err(Error::from)
}
fn term(
    syntax: &mut Syntax,
    keep: Name,
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> TermId {
    let mut remainder = syntax.add_term(Term::Vec(item.typ, vec![]));
    if count.get() == 0 {
        return syntax.add_term(Term::Let(
            Bind {
                name: keep,
                multiplicity: Multiplicity::Zero,
                typ: item.typ,
            },
            seed,
            remainder,
        ));
    }
    let kept = syntax.add_term(Term::Var(keep.clone()));
    let head = syntax.add_term(Term::Vec(item.typ, vec![kept]));
    let bind = Bind {
        name: keep,
        multiplicity: Multiplicity::Many,
        typ: item.typ,
    };
    for index in (0..count.get()).rev() {
        let source = if index == 0 { seed } else { kept };
        let next = syntax.add_term(Term::Let(item.clone(), source, body));
        let joined = syntax.add_term(Term::Vcat(head, remainder));
        remainder = syntax.add_term(Term::Let(bind.clone(), next, joined));
    }
    remainder
}
pub fn build(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    keep: Name,
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(syntax, types, terms, count, seed, item, body)?;
    if !finite::clear(
        syntax,
        &[],
        std::slice::from_ref(item),
        &[seed, body],
        &keep,
    ) {
        return Err(Error::Fresh);
    }
    Ok(term(syntax, keep, count, seed, item, body))
}
pub fn make(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    prep(syntax, types, terms, count, seed, item, body)?;
    let keep =
        finite::pick(syntax, &[], std::slice::from_ref(item), &[seed, body]).ok_or(Error::Fresh)?;
    Ok(term(syntax, keep, count, seed, item, body))
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<Program> {
    let root = make(syntax, types, terms, count, seed, item, body)?;
    lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, count, seed, item, body)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let state_typ = lower::typ(syntax, types, item.typ).map_err(Error::Low)?;
    let expected = types.intern(types::Type::Vec(count, state_typ));
    let actual = checked.info().typ();
    if expected == actual {
        Ok(checked)
    } else {
        Err(Error::Need(expected, actual))
    }
}
