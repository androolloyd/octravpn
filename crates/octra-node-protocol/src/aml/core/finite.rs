// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_fin structural limits and collision-free generated names.
use super::{
    rule::{Field, LOCAL},
    syntax::{Bind, Name, Syntax, Term, TermId},
    Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Nodes(BigInt),
    Depth(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub nodes: usize,
    pub depth: usize,
}
pub fn stat(syntax: &Syntax, root: TermId) -> Result<Stat, Error> {
    let maximum_depth = LOCAL.get(Field::TermDepth) as usize;
    let maximum_nodes = LOCAL.get(Field::TermNodes) as usize;
    let mut pending = vec![(0, root)];
    let mut nodes = 0;
    let mut high = 0;
    while let Some((depth, id)) = pending.pop() {
        if depth > maximum_depth {
            return Err(Error::Depth(depth));
        }
        if nodes >= maximum_nodes {
            return Err(Error::Nodes(BigInt::from(nodes + 1)));
        }
        let term = syntax.term(id);
        let children = term.children();
        if matches!(term, Term::Vec(..) | Term::Seq(..)) {
            pending.extend(children.into_iter().map(|child| (depth + 1, child)));
        } else {
            pending.extend(children.into_iter().rev().map(|child| (depth + 1, child)));
        }
        nodes += 1;
        high = high.max(depth);
    }
    Ok(Stat { nodes, depth: high })
}
pub fn fit(nodes: &BigInt, depth: usize) -> Result<(), Error> {
    if nodes > &BigInt::from(LOCAL.get(Field::TermNodes)) {
        Err(Error::Nodes(nodes.clone()))
    } else if depth > LOCAL.get(Field::TermDepth) as usize {
        Err(Error::Depth(depth))
    } else {
        Ok(())
    }
}
fn occupied(syntax: &Syntax, used: &[Name], binds: &[Bind], terms: &[TermId]) -> BTreeSet<Name> {
    let mut names: BTreeSet<_> = used.iter().cloned().collect();
    names.extend(binds.iter().map(|bind| bind.name.clone()));
    let mut pending = terms.to_vec();
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let term = syntax.term(id);
        if let Term::Var(name) = term {
            names.insert(name.clone());
        }
        names.extend(term.bindings().into_iter().cloned());
        pending.extend(term.children());
    }
    names
}
pub fn clear(
    syntax: &Syntax,
    used: &[Name],
    binds: &[Bind],
    terms: &[TermId],
    name: &Name,
) -> bool {
    !occupied(syntax, used, binds, terms).contains(name)
}
pub fn clear_all(
    syntax: &Syntax,
    used: &[Name],
    binds: &[Bind],
    terms: &[TermId],
    names: &[Name],
) -> bool {
    let mut blocked = occupied(syntax, used, binds, terms);
    names.iter().all(|name| blocked.insert(name.clone()))
}
pub fn pick_many(
    count: i64,
    syntax: &Syntax,
    used: &[Name],
    binds: &[Bind],
    terms: &[TermId],
) -> Option<Vec<Name>> {
    let count = usize::try_from(count).ok()?;
    let blocked = occupied(syntax, used, binds, terms);
    let mut out = vec![];
    for index in 0..LOCAL.get(Field::Inputs) as u32 {
        if out.len() == count {
            return Some(out);
        }
        let name = Name::dslot(Natural::from_u32(index)?);
        if !blocked.contains(&name) {
            out.push(name);
        }
    }
    (out.len() == count).then_some(out)
}
pub fn pick(syntax: &Syntax, used: &[Name], binds: &[Bind], terms: &[TermId]) -> Option<Name> {
    pick_many(1, syntax, used, binds, terms)?.pop()
}
