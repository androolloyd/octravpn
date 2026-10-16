// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_rift finite vector splitting, preserving resource-sensitive head and
//! remainder multiplicities while validating the complete private-name path.
use super::{
    check, data, finite, lower,
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId, Type, TypeId},
    term::{Program, Terms},
    types::{self, Types},
    Natural,
};
use num_bigint::BigInt;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    head: Name,
    remainder: Name,
}
impl Step {
    pub fn new(head: Name, remainder: Name) -> Self {
        Self { head, remainder }
    }
    pub fn head(&self) -> &Name {
        &self.head
    }
    pub fn remainder(&self) -> &Name {
        &self.remainder
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    source: Name,
    steps: Vec<Step>,
}
impl Path {
    pub fn new(source: Name, steps: Vec<Step>) -> Self {
        Self { source, steps }
    }
    pub fn source(&self) -> &Name {
        &self.source
    }
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
    fn names(&self) -> Vec<Name> {
        let mut names = Vec::with_capacity(1 + 2 * self.steps.len());
        names.push(self.source.clone());
        for step in &self.steps {
            names.push(step.head.clone());
            names.push(step.remainder.clone());
        }
        names
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Need(types::TypeId, types::TypeId),
    Path(usize, usize),
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
                b"rift type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Path(expected, actual) => {
                format!("rift path expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Fresh => b"rift private name space exhausted".to_vec(),
            Self::Nodes(actual) => format!(
                "rift node limit = {} actual = {actual}",
                LOCAL.get(Field::TermNodes)
            )
            .into_bytes(),
            Self::Depth(actual) => format!(
                "rift depth limit = {} actual = {actual}",
                LOCAL.get(Field::TermDepth)
            )
            .into_bytes(),
        }
    }
}
struct Spec {
    elem: types::TypeId,
    total: Natural,
}
fn prep(
    syntax: &Syntax,
    types: &mut Types,
    cut: Natural,
    rest: Natural,
    elem: TypeId,
    source: TermId,
) -> Result<Spec> {
    let elem = lower::typ(syntax, types, elem).map_err(Error::Low)?;
    let total = cut.checked_add(rest).ok_or_else(|| {
        Error::Low(lower::Error::Natural(
            BigInt::from(cut.get()) + BigInt::from(rest.get()),
        ))
    })?;
    let stat = finite::stat(syntax, source)?;
    let nodes = BigInt::from(stat.nodes + 4) + BigInt::from(4) * BigInt::from(cut.get());
    let body_depth = if cut.get() == 0 {
        1
    } else {
        cut.get() as usize + 2
    };
    finite::fit(&nodes, 1 + stat.depth.max(body_depth))?;
    Ok(Spec { elem, total })
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn term(
    syntax: &mut Syntax,
    types: &mut Types,
    path: &Path,
    spec: Spec,
    elem: TypeId,
    source: TermId,
) -> Result<TermId> {
    let source_core = types.intern(types::Type::Vec(spec.total, spec.elem));
    let source_type = syntax.add_type(Type::Vec(BigInt::from(spec.total.get()), elem));
    let source_bind = Bind {
        name: path.source.clone(),
        multiplicity: data::needed(types, source_core),
        typ: source_type,
    };
    let mut left = spec.total;
    let mut current = path.source.clone();
    let mut frames = Vec::with_capacity(path.steps.len());
    for step in &path.steps {
        let remainder = left
            .checked_sub(Natural::from_u32(1).expect("natural one"))
            .ok_or_else(|| Error::Low(lower::Error::Natural(BigInt::from(left.get()))))?;
        let remainder_core = types.intern(types::Type::Vec(remainder, spec.elem));
        let remainder_type = syntax.add_type(Type::Vec(BigInt::from(remainder.get()), elem));
        let head = Bind {
            name: step.head.clone(),
            multiplicity: data::needed(types, spec.elem),
            typ: elem,
        };
        let tail = Bind {
            name: step.remainder.clone(),
            multiplicity: data::needed(types, remainder_core),
            typ: remainder_type,
        };
        let value = syntax.add_term(Term::Var(current));
        let value = syntax.add_term(Term::Uncons(value));
        frames.push((value, head, tail));
        left = remainder;
        current = step.remainder.clone();
    }
    let held = path
        .steps
        .iter()
        .map(|step| syntax.add_term(Term::Var(step.head.clone())))
        .collect();
    let held = syntax.add_term(Term::Vec(elem, held));
    let current = syntax.add_term(Term::Var(current));
    let mut body = syntax.add_term(Term::Pair(held, current));
    for (value, head, remainder) in frames.into_iter().rev() {
        body = syntax.add_term(Term::Unpair(value, head, remainder, body));
    }
    Ok(syntax.add_term(Term::Let(source_bind, source, body)))
}
pub fn build(
    syntax: &mut Syntax,
    types: &mut Types,
    _terms: &mut Terms,
    path: &Path,
    cut: Natural,
    rest: Natural,
    elem: TypeId,
    source: TermId,
) -> Result<TermId> {
    let spec = prep(syntax, types, cut, rest, elem, source)?;
    let expected = cut.get() as usize;
    if path.steps.len() != expected {
        return Err(Error::Path(expected, path.steps.len()));
    }
    if !finite::clear_all(syntax, &[], &[], &[source], &path.names()) {
        return Err(Error::Fresh);
    }
    term(syntax, types, path, spec, elem, source)
}
pub fn make(
    syntax: &mut Syntax,
    types: &mut Types,
    _terms: &mut Terms,
    cut: Natural,
    rest: Natural,
    elem: TypeId,
    source: TermId,
) -> Result<TermId> {
    let spec = prep(syntax, types, cut, rest, elem, source)?;
    let count = 1 + 2 * i64::from(cut.get());
    let mut names = finite::pick_many(count, syntax, &[], &[], &[source])
        .ok_or(Error::Fresh)?
        .into_iter();
    let source_name = names.next().ok_or(Error::Fresh)?;
    let mut steps = Vec::with_capacity(cut.get() as usize);
    while let Some(head) = names.next() {
        steps.push(Step::new(head, names.next().ok_or(Error::Fresh)?));
    }
    term(
        syntax,
        types,
        &Path::new(source_name, steps),
        spec,
        elem,
        source,
    )
}
pub fn lower(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    cut: Natural,
    rest: Natural,
    elem: TypeId,
    source: TermId,
) -> Result<Program> {
    let root = make(syntax, types, terms, cut, rest, elem, source)?;
    lower::program(syntax, types, terms, inputs, root).map_err(Error::Low)
}
pub fn check(
    syntax: &mut Syntax,
    types: &mut Types,
    terms: &mut Terms,
    inputs: &[Bind],
    cut: Natural,
    rest: Natural,
    elem: TypeId,
    source: TermId,
) -> Result<check::Checked> {
    let program = lower(syntax, types, terms, inputs, cut, rest, elem, source)?;
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    let elem = lower::typ(syntax, types, elem).map_err(Error::Low)?;
    let left = types.intern(types::Type::Vec(cut, elem));
    let right = types.intern(types::Type::Vec(rest, elem));
    let expected = types.intern(types::Type::Pair(left, right));
    let actual = checked.info().typ();
    if expected == actual {
        Ok(checked)
    } else {
        Err(Error::Need(expected, actual))
    }
}
