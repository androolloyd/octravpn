// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent C_low conversion from named syntax to numbered core terms.
use super::{
    rule::{Field, LOCAL},
    syntax as syn, term as core, types as core_types, Atom, Natural,
};
use num_bigint::BigInt;
use std::sync::Arc;
mod terms;
mod types;
pub use self::types::typ;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Natural(BigInt),
    Free(syn::Name),
    Duplicate(syn::Name),
    Type,
    Count,
    Depth(usize, usize),
    Nodes(usize, usize),
    Inputs(usize, usize),
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Natural(value) => format!("natural outside profile = {value}").into_bytes(),
            Self::Free(name) => [b"free name = ".as_slice(), name.text()].concat(),
            Self::Duplicate(name) => [b"duplicate name = ".as_slice(), name.text()].concat(),
            Self::Type => b"type outside profile".to_vec(),
            Self::Count => b"binder count outside profile".to_vec(),
            Self::Depth(limit, actual) => {
                format!("term depth max = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("term nodes max = {limit} actual = {actual}").into_bytes()
            }
            Self::Inputs(limit, actual) => {
                format!("input count max = {limit} actual = {actual}").into_bytes()
            }
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn natural(value: &BigInt) -> Result<Natural> {
    Natural::new(value).ok_or_else(|| Error::Natural(value.clone()))
}
fn shape(syntax: &syn::Syntax, root: syn::TermId) -> Result<()> {
    let max_depth = LOCAL.get(Field::TermDepth) as usize;
    let max_nodes = LOCAL.get(Field::TermNodes) as usize;
    let mut pending = vec![(0, root)];
    let mut nodes = 0;
    while let Some((depth, id)) = pending.pop() {
        if depth > max_depth {
            return Err(Error::Depth(max_depth, depth));
        }
        if nodes >= max_nodes {
            return Err(Error::Nodes(max_nodes, nodes + 1));
        }
        let term = syntax.term(id);
        let children = term.children();
        if matches!(term, syn::Term::Vec(..) | syn::Term::Seq(..)) {
            pending.extend(children.into_iter().map(|child| (depth + 1, child)));
        } else {
            pending.extend(children.into_iter().rev().map(|child| (depth + 1, child)));
        }
        nodes += 1;
    }
    Ok(())
}
#[derive(Clone, Default)]
struct Env(Arc<Vec<(syn::Name, Natural)>>);
impl Env {
    fn find(&self, name: &syn::Name) -> Option<Natural> {
        self.0
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, id)| *id)
    }
    fn put(&mut self, name: syn::Name, id: Natural) {
        Arc::make_mut(&mut self.0).push((name, id));
    }
}
struct Lowerer<'a> {
    syntax: &'a syn::Syntax,
    types: &'a mut core_types::Types,
    terms: &'a mut core::Terms,
    next: Natural,
}
impl Lowerer<'_> {
    fn bind(&mut self, binding: &syn::Bind) -> Result<core::Bind> {
        let typ = typ(self.syntax, self.types, binding.typ)?;
        let id = self.next;
        self.next = id
            .checked_add(Natural::from_u32(1).expect("native one"))
            .ok_or(Error::Count)?;
        Ok(core::Bind {
            id,
            multiplicity: binding.multiplicity,
            typ,
        })
    }
    fn distinct(left: &syn::Bind, right: &syn::Bind) -> Result<()> {
        if left.name == right.name {
            Err(Error::Duplicate(left.name.clone()))
        } else {
            Ok(())
        }
    }
}
pub fn term(
    syntax: &syn::Syntax,
    types: &mut core_types::Types,
    terms: &mut core::Terms,
    root: syn::TermId,
) -> Result<core::TermId> {
    shape(syntax, root)?;
    Lowerer {
        syntax,
        types,
        terms,
        next: Natural::from_u32(0).expect("native zero"),
    }
    .lower(Env::default(), root)
}
pub fn program(
    syntax: &syn::Syntax,
    types: &mut core_types::Types,
    terms: &mut core::Terms,
    inputs: &[syn::Bind],
    root: syn::TermId,
) -> Result<core::Program> {
    let max_inputs = LOCAL.get(Field::Inputs) as usize;
    if inputs.len() > max_inputs {
        return Err(Error::Inputs(max_inputs, max_inputs + 1));
    }
    shape(syntax, root)?;
    let mut lowerer = Lowerer {
        syntax,
        types,
        terms,
        next: Natural::from_u32(0).expect("native zero"),
    };
    let mut env = Env::default();
    let mut binds = Vec::with_capacity(inputs.len());
    for input in inputs {
        if env.find(&input.name).is_some() {
            return Err(Error::Duplicate(input.name.clone()));
        }
        let binding = lowerer.bind(input)?;
        env.put(input.name.clone(), binding.id);
        binds.push(binding);
    }
    let term = lowerer.lower(env, root)?;
    Ok(core::Program {
        inputs: binds,
        term,
    })
}
// Traversal appends further names to this collected mutable vector.
#[allow(clippy::needless_collect)]
pub fn names(
    syntax: &syn::Syntax,
    inputs: &[syn::Bind],
    root: syn::TermId,
) -> Option<Vec<(Natural, Vec<u8>)>> {
    enum Task<'a> {
        Term(syn::TermId),
        Name(&'a syn::Name),
    }
    let mut ordered: Vec<_> = inputs.iter().map(|bind| &bind.name).collect();
    let mut pending = vec![Task::Term(root)];
    while let Some(task) = pending.pop() {
        let term = match task {
            Task::Name(name) => {
                ordered.push(name);
                continue;
            }
            Task::Term(id) => syntax.term(id),
        };
        match term {
            syn::Term::Let(bind, value, body) => {
                pending.push(Task::Term(*body));
                pending.push(Task::Name(&bind.name));
                pending.push(Task::Term(*value));
            }
            syn::Term::Unpair(pair, left, right, body) => {
                pending.push(Task::Term(*body));
                pending.push(Task::Name(&right.name));
                pending.push(Task::Name(&left.name));
                pending.push(Task::Term(*pair));
            }
            syn::Term::Case(value, left, yes, right, no) => {
                pending.push(Task::Term(*no));
                pending.push(Task::Name(&right.name));
                pending.push(Task::Term(*yes));
                pending.push(Task::Name(&left.name));
                pending.push(Task::Term(*value));
            }
            syn::Term::Vfold(vector, seed, fold) => {
                pending.push(Task::Term(fold.body));
                pending.push(Task::Name(&fold.state.name));
                pending.push(Task::Name(&fold.item.name));
                pending.push(Task::Term(*seed));
                pending.push(Task::Term(*vector));
            }
            _ => pending.extend(term.children().into_iter().rev().map(Task::Term)),
        }
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            let id = Natural::from_u32(u32::try_from(index).ok()?)?;
            Some((id, name.text().to_vec()))
        })
        .collect()
}
