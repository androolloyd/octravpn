// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_quant predicate and aggregation expansion into a vector fold.
use super::{
    check, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Fold, Name, Syntax, Term, TermId, Type},
    term::{Program, Terms},
    types::{Multiplicity, Types},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Every,
    Any,
    Count,
    Sum,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Fresh,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Fresh => b"vector predicate names exhausted".to_vec(),
        }
    }
}
fn clear(syntax: &Syntax, name: &Name, source: TermId, item: &Bind, body: TermId) -> bool {
    name != &item.name && !syntax.has(name, source) && !syntax.has(name, body)
}
pub fn expand(
    syntax: &mut Syntax,
    state: Name,
    mark: Name,
    mode: Mode,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    if state == mark
        || !clear(syntax, &state, source, item, body)
        || !clear(syntax, &mark, source, item, body)
    {
        return Err(Error::Fresh);
    }
    let state_typ = syntax.add_type(match mode {
        Mode::Every | Mode::Any => Type::Bool,
        Mode::Count | Mode::Sum => Type::Int,
    });
    let mark_typ = syntax.add_type(match mode {
        Mode::Every | Mode::Any | Mode::Count => Type::Bool,
        Mode::Sum => Type::Int,
    });
    let state_bind = Bind {
        name: state.clone(),
        multiplicity: Multiplicity::Many,
        typ: state_typ,
    };
    let mark_bind = Bind {
        name: mark.clone(),
        multiplicity: Multiplicity::Many,
        typ: mark_typ,
    };
    let state_var = syntax.add_term(Term::Var(state));
    let mark_var = syntax.add_term(Term::Var(mark));
    let branch = match mode {
        Mode::Every => {
            let no = syntax.add_term(Term::Bool(false));
            syntax.add_term(Term::If(state_var, mark_var, no))
        }
        Mode::Any => {
            let yes = syntax.add_term(Term::Bool(true));
            syntax.add_term(Term::If(state_var, yes, mark_var))
        }
        Mode::Count => {
            let one = syntax.add_term(Term::Int(BigInt::from(1)));
            let yes = syntax.add_term(Term::Add(state_var, one));
            syntax.add_term(Term::If(mark_var, yes, state_var))
        }
        Mode::Sum => syntax.add_term(Term::Add(state_var, mark_var)),
    };
    let term = syntax.add_term(Term::Let(mark_bind, body, branch));
    let seed = syntax.add_term(match mode {
        Mode::Every => Term::Bool(true),
        Mode::Any => Term::Bool(false),
        Mode::Count | Mode::Sum => Term::Int(BigInt::from(0)),
    });
    Ok(syntax.add_term(Term::Vfold(
        source,
        seed,
        Fold {
            item: item.clone(),
            state: state_bind,
            body: term,
        },
    )))
}
pub fn make(
    syntax: &mut Syntax,
    mode: Mode,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<TermId> {
    let maximum = LOCAL.get(Field::Inputs) as u32;
    let mut index = 0;
    while index + 1 < maximum {
        let left = Natural::from_u32(index).ok_or(Error::Fresh)?;
        let right = Natural::from_u32(index + 1).ok_or(Error::Fresh)?;
        match expand(
            syntax,
            Name::dslot(left),
            Name::dslot(right),
            mode,
            source,
            item,
            body,
        ) {
            Ok(value) => return Ok(value),
            Err(Error::Fresh) => index += 2,
            Err(error) => return Err(error),
        }
    }
    Err(Error::Fresh)
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    mode: Mode,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<Program> {
    let term = make(syntax, mode, source, item, body)?;
    lower::program(syntax, types, terms, inputs, term).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    mode: Mode,
    source: TermId,
    item: &Bind,
    body: TermId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, mode, source, item, body)?;
    check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)
}
