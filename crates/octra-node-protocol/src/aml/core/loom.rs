// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_loom indexed finite vector construction from a checked integer binder.
use super::{
    check, finite, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Syntax, Term, TermId, TypeId},
    term::{Program, Terms},
    types::{self, Kind, Types},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Need(types::TypeId, types::TypeId),
    Data(types::TypeId),
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
                b"loom type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Data(typ) => [
                b"loom data type expected actual = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Nodes(actual) => format!(
                "loom node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "loom depth limit = {} actual = {actual}",
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
    let integer = types.intern(types::Type::Int);
    if item_typ != integer {
        return Err(Error::Need(integer, item_typ));
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
pub fn make(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    out: TypeId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    body_check(syntax, types, terms, out, item, body)?;
    let stat = finite::stat(syntax, body)?;
    let nodes = BigInt::from(1) + BigInt::from(count.get()) * BigInt::from(stat.nodes + 2);
    let depth = if count.get() == 0 {
        0
    } else {
        2.max(2 + stat.depth)
    };
    finite::fit(&nodes, depth)?;
    let mut values = Vec::with_capacity(count.get() as usize);
    for index in 0..count.get() {
        let index = syntax.add_term(Term::Int(BigInt::from(index)));
        values.push(syntax.add_term(Term::Let(item.clone(), index, body)));
    }
    Ok(syntax.add_term(Term::Vec(out, values)))
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    item: &Bind,
    body: TermId,
) -> Result<Program> {
    let root = make(syntax, types, terms, count, out, item, body)?;
    lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    count: Natural,
    out: TypeId,
    item: &Bind,
    body: TermId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, count, out, item, body)?;
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
