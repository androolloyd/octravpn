// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_orbit finite unrolling. Bounds are checked before allocating loop copies.
use super::{
    check, finite, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, Type},
    term::{Program, Relation, Terms},
    types::{Multiplicity, TypeId, Types},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Need(TypeId, TypeId),
    Fresh,
    Nodes(BigInt),
    Depth(usize),
}
impl From<finite::Error> for Error {
    fn from(error: finite::Error) -> Self {
        match error {
            finite::Error::Nodes(actual) => Self::Nodes(actual),
            finite::Error::Depth(actual) => Self::Depth(actual),
        }
    }
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Need(expected, actual) => [
                b"orbit type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Fresh => b"orbit private name space exhausted".to_vec(),
            Self::Nodes(actual) => format!(
                "orbit node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "orbit depth limit = {} actual = {actual}",
                LOCAL.get(Field::TermDepth)
            )
            .into_bytes(),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;
fn body_check(
    syntax: &Syntax,
    types: &mut Types,
    terms: &mut Terms,
    item: &Bind,
    body: TermId,
) -> Result<TypeId> {
    let expected = lower::typ(syntax, types, item.typ).map_err(Error::Low)?;
    let program = lower::program(syntax, types, terms, std::slice::from_ref(item), body)
        .map_err(Error::Low)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let actual = checked.info().typ();
    if expected == actual {
        Ok(expected)
    } else {
        Err(Error::Need(expected, actual))
    }
}
fn fit(syntax: &Syntax, count: Natural, seed: TermId, body: TermId) -> Result<()> {
    let seed = finite::stat(syntax, seed)?;
    let body = finite::stat(syntax, body)?;
    let count = count.get();
    let (nodes, depth) = if count == 0 {
        (BigInt::from(seed.nodes + 2), seed.depth + 1)
    } else {
        (
            BigInt::from(seed.nodes) + BigInt::from(count) * BigInt::from(body.nodes + 1),
            count as usize + seed.depth.max(body.depth),
        )
    };
    finite::fit(&nodes, depth).map_err(Error::from)
}
fn seed_as(syntax: &mut Syntax, item: &Bind, seed: TermId) -> TermId {
    let bind = Bind {
        multiplicity: Multiplicity::One,
        ..item.clone()
    };
    let value = syntax.add_term(Term::Var(bind.name.clone()));
    syntax.add_term(Term::Let(bind, seed, value))
}
fn term(syntax: &mut Syntax, count: Natural, seed: TermId, item: &Bind, body: TermId) -> TermId {
    if count.get() == 0 {
        return seed_as(syntax, item, seed);
    }
    let mut out = seed;
    for _ in 0..count.get() {
        out = syntax.add_term(Term::Let(item.clone(), out, body));
    }
    out
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
    // Natural is private and already validates the native count profile.
    body_check(syntax, types, terms, item, body)?;
    fit(syntax, count, seed, body)?;
    Ok(term(syntax, count, seed, item, body))
}
fn guard(syntax: &mut Syntax, index: u32, name: &Name) -> TermId {
    let index = syntax.add_term(Term::Int(BigInt::from(index)));
    let turns = syntax.add_term(Term::Var(name.clone()));
    syntax.add_term(Term::Cmp(Relation::Lt, index, turns))
}
fn fit_upto(
    syntax: &Syntax,
    count: Natural,
    turns: TermId,
    seed: TermId,
    body: TermId,
    guard: TermId,
) -> Result<()> {
    let turns = finite::stat(syntax, turns)?;
    let seed = finite::stat(syntax, seed)?;
    let body = finite::stat(syntax, body)?;
    let guard = finite::stat(syntax, guard)?;
    let step_nodes = BigInt::from(guard.nodes + body.nodes + 3);
    let loop_nodes = if count.get() == 0 {
        BigInt::from(seed.nodes + 2)
    } else {
        BigInt::from(seed.nodes) + BigInt::from(count.get()) * step_nodes
    };
    let nodes = BigInt::from(1) + BigInt::from(turns.nodes) + loop_nodes;
    let branch_depth = 1 + guard.depth.max(body.depth);
    let loop_depth = if count.get() == 0 {
        seed.depth + 1
    } else {
        count.get() as usize + seed.depth.max(branch_depth)
    };
    finite::fit(&nodes, 1 + turns.depth.max(loop_depth)).map_err(Error::from)
}
pub fn upto(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    count: Natural,
    turns: TermId,
    seed: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    body_check(syntax, types, terms, item, body)?;
    let name = finite::pick(
        syntax,
        &[],
        std::slice::from_ref(item),
        &[turns, seed, body],
    )
    .ok_or(Error::Fresh)?;
    let integer = syntax.add_type(Type::Int);
    let turn_bind = Bind {
        name,
        multiplicity: Multiplicity::Many,
        typ: integer,
    };
    let first_guard = guard(syntax, 0, &turn_bind.name);
    fit_upto(syntax, count, turns, seed, body, first_guard)?;
    let mut out = if count.get() == 0 {
        seed_as(syntax, item, seed)
    } else {
        seed
    };
    for index in 0..count.get() {
        let condition = if index == 0 {
            first_guard
        } else {
            guard(syntax, index, &turn_bind.name)
        };
        let unchanged = syntax.add_term(Term::Var(item.name.clone()));
        let next = syntax.add_term(Term::If(condition, body, unchanged));
        out = syntax.add_term(Term::Let(item.clone(), out, next));
    }
    let out = syntax.add_term(Term::Let(turn_bind, turns, out));
    finite::stat(syntax, out)?;
    Ok(out)
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
    let expected = lower::typ(syntax, types, item.typ).map_err(Error::Low)?;
    let actual = checked.info().typ();
    if actual == expected {
        Ok(checked)
    } else {
        Err(Error::Need(expected, actual))
    }
}
