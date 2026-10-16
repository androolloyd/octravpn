// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent C_check analysis. A checked term is not deployment authority;
//! evidence construction must bind this analysis to independently lowered code.
use super::{
    flow::{FlowId, Flows, Location, Origin, Site},
    limit::Limit,
    rule::{self, Field, LOCAL},
    term::{Bind, Fold, Term, TermId, Terms},
    types::{Kind, Multiplicity, Type, TypeId, Types},
    Atom, Effects, Natural,
};
use num_bigint::BigInt;
use std::sync::Arc;
mod combine;
mod env;
mod error;
mod infer;
mod operations;
use env::Env;
pub use error::Error;
type Result<T> = std::result::Result<T, Error>;
pub const MAX_DEPTH: usize = LOCAL.get(Field::TermDepth) as usize;
pub const MAX_NODES: usize = LOCAL.get(Field::TermNodes) as usize;
pub const MAX_INPUTS: usize = LOCAL.get(Field::Inputs) as usize;
#[derive(Clone, Debug)]
pub struct Info {
    typ: TypeId,
    effects: Effects,
    resources: Limit,
    flow: FlowId,
}
impl Info {
    pub fn typ(&self) -> TypeId {
        self.typ
    }
    pub fn effects(&self) -> &Effects {
        &self.effects
    }
    pub fn resources(&self) -> &Limit {
        &self.resources
    }
    pub fn flow(&self) -> FlowId {
        self.flow
    }
}
#[derive(Clone, Debug)]
pub struct Checked {
    info: Info,
    flows: Flows,
}
impl Checked {
    pub(crate) fn raise_resources(&mut self, bound: &Limit) {
        self.info.resources = self.info.resources.maximum(bound);
    }
    pub fn info(&self) -> &Info {
        &self.info
    }
    pub fn flows(&self) -> &Flows {
        &self.flows
    }
    pub fn locations(&self) -> Vec<Location> {
        self.flows.locations(self.info.flow)
    }
    pub fn sites(&self) -> Vec<Site> {
        self.locations()
            .into_iter()
            .map(|location| location.site())
            .collect()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub error: Error,
    pub term: Option<TermId>,
}
struct Checker<'a> {
    types: &'a mut Types,
    terms: &'a Terms,
    flows: Flows,
}
impl Checker<'_> {
    fn need(&self, expected: TypeId, actual: TypeId) -> Result<()> {
        if !self.types.valid(expected) {
            Err(Error::Bad(expected))
        } else if !self.types.valid(actual) {
            Err(Error::Bad(actual))
        } else if expected == actual {
            Ok(())
        } else {
            Err(Error::Need(expected, actual))
        }
    }
    fn valid(&self, typ: TypeId) -> Result<()> {
        if self.types.valid(typ) {
            Ok(())
        } else {
            Err(Error::Bad(typ))
        }
    }
    fn integer(&mut self) -> TypeId {
        self.types.intern(Type::Int)
    }
    fn boolean(&mut self) -> TypeId {
        self.types.intern(Type::Bool)
    }
    fn unit(&mut self) -> TypeId {
        self.types.intern(Type::Unit)
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    fn zero(&self) -> Natural {
        Natural::from_u32(0).expect("native zero")
    }
    fn unit_pair(&mut self) -> TypeId {
        let unit = self.unit();
        self.types.intern(Type::Pair(unit, unit))
    }
    fn unit_sum(&mut self) -> TypeId {
        let unit = self.unit();
        self.types.intern(Type::Sum(unit, unit))
    }
    fn empty_vector(&mut self) -> TypeId {
        let unit = self.unit();
        let zero = self.zero();
        self.types.intern(Type::Vec(zero, unit))
    }
    fn empty_bytes(&mut self) -> TypeId {
        let zero = self.zero();
        self.types.intern(Type::Bytes(zero))
    }
    fn empty_sequence(&mut self) -> TypeId {
        let unit = self.unit();
        let zero = self.zero();
        self.types.intern(Type::Seq(zero, unit))
    }
    fn empty_capability(&mut self) -> TypeId {
        let zero = self.zero();
        self.types.intern(Type::Cap(zero))
    }
}
fn binding_term(terms: &Terms, root: TermId, id: Natural) -> Option<TermId> {
    let mut pending = vec![root];
    while let Some(current) = pending.pop() {
        let term = terms.get(current);
        let found = match term {
            Term::Let(bind, _, _) => bind.id == id,
            Term::Unpair(_, left, right, _) | Term::Case(_, left, _, right, _) => {
                left.id == id || right.id == id
            }
            Term::Vfold(_, _, fold) => fold.item.id == id || fold.state.id == id,
            _ => false,
        };
        if found {
            return Some(current);
        }
        pending.extend(term.children().into_iter().rev());
    }
    None
}
pub fn check_in_located(
    types: &mut Types,
    terms: &Terms,
    binds: &[Bind],
    root: TermId,
) -> std::result::Result<Checked, Failure> {
    let max_inputs = LOCAL.get(Field::Inputs) as usize;
    if binds.len() > max_inputs {
        return Err(Failure {
            error: Error::Inputs(max_inputs, max_inputs + 1),
            term: None,
        });
    }
    if let Err(shape) = terms.shape(root) {
        let error = match shape {
            super::term::Shape::Depth(limit, actual) => Error::Depth(limit, actual),
            super::term::Shape::Nodes(limit, actual) => Error::Nodes(limit, actual),
        };
        return Err(Failure {
            error,
            term: Some(root),
        });
    }
    let mut env = Env::default();
    for bind in binds {
        env.open(types, *bind)
            .map_err(|error| Failure { error, term: None })?;
    }
    let mut checker = Checker {
        types,
        terms,
        flows: Flows::default(),
    };
    let (info, env) = checker.infer(env, root)?;
    if let Some(id) = env.pending() {
        return Err(Failure {
            error: Error::Unused(id),
            term: binding_term(terms, root, id),
        });
    }
    Ok(Checked {
        info,
        flows: checker.flows,
    })
}
pub fn check_in(types: &mut Types, terms: &Terms, binds: &[Bind], root: TermId) -> Result<Checked> {
    check_in_located(types, terms, binds, root).map_err(|failure| failure.error)
}
pub fn check(types: &mut Types, terms: &Terms, root: TermId) -> Result<Checked> {
    check_in(types, terms, &[], root)
}
#[derive(Clone, Debug)]
pub struct Selected {
    rule: rule::Id,
    checked: Checked,
}
impl Selected {
    pub fn rule(&self) -> &rule::Id {
        &self.rule
    }
    pub fn checked(&self) -> &Checked {
        &self.checked
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    Rule(rule::Error),
    Check(Error),
}
pub fn check_in_at(
    schedule: &rule::Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &Terms,
    binds: &[Bind],
    root: TermId,
) -> std::result::Result<Selected, RuleError> {
    let rule = schedule
        .select(epoch)
        .map_err(RuleError::Rule)?
        .id()
        .clone();
    let checked = check_in(types, terms, binds, root).map_err(RuleError::Check)?;
    Ok(Selected { rule, checked })
}
pub fn check_at(
    schedule: &rule::Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &Terms,
    root: TermId,
) -> std::result::Result<Selected, RuleError> {
    check_in_at(schedule, epoch, types, terms, &[], root)
}
