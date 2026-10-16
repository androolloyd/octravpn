// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Static Aml_effect host binding and checked-site sealing. Sealing here binds
//! core analysis to host declarations; bytecode evidence remains a later stage.
use super::{
    ast,
    core::{
        self,
        check::{self, Checked},
        flow::{Location, Origin, Site},
        term::{Program, Terms},
        types::{Type, TypeId, Types},
        Atom, Natural,
    },
};
use num_bigint::BigInt;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
mod error;
mod lower;
mod plan;
mod restore;
mod trace;
pub use error::Error;
pub use lower::{Block, Charge, Rollback};
pub use plan::{Host, Item, Plan, Prepared, Scalar};
pub(crate) use restore::RestoreError;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    State(Vec<u8>),
    Event(Vec<u8>),
    Fault(Vec<u8>),
}
impl Target {
    fn text(&self) -> Vec<u8> {
        match self {
            Self::State(name) => [b"state:".as_slice(), name].concat(),
            Self::Event(name) => [b"event:".as_slice(), name].concat(),
            Self::Fault(name) => [b"error:".as_slice(), name].concat(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Bind {
    atom: Atom,
    target: Target,
}
impl Bind {
    pub fn new(atom: Atom, target: Target) -> Self {
        Self { atom, target }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostType {
    Int,
    Bool,
    Bytes32,
}
impl HostType {
    fn from_ast(typ: &ast::Type) -> Option<Self> {
        match typ {
            ast::Type::Int => Some(Self::Int),
            ast::Type::Bool => Some(Self::Bool),
            ast::Type::Bytes32 => Some(Self::Bytes32),
            _ => None,
        }
    }
    fn core(self, types: &mut Types) -> TypeId {
        types.intern(match self {
            Self::Int => Type::Int,
            Self::Bool => Type::Bool,
            Self::Bytes32 => Type::Bytes(Natural::from_u32(32).expect("native bytes32 width")),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    State(Vec<u8>, HostType),
    Event(Vec<u8>, Vec<HostType>),
    Fault(Vec<u8>, i64, Vec<u8>),
}
#[derive(Clone, Debug)]
pub struct Registry {
    entries: Vec<(Atom, Entry)>,
}
fn target_kind(atom: Atom, target: &Target) -> bool {
    matches!(
        (atom, target),
        (Atom::Read(_) | Atom::Write(_), Target::State(_))
            | (Atom::Emit(_), Target::Event(_))
            | (Atom::Fail(_), Target::Fault(_))
    )
}
fn unique<'a, T>(target: &Target, mut items: impl Iterator<Item = &'a T>) -> Result<&'a T>
where
    T: 'a,
{
    let first = items
        .next()
        .ok_or_else(|| Error::TargetAbsent(target.clone()))?;
    if items.next().is_some() {
        Err(Error::TargetRepeated(target.clone()))
    } else {
        Ok(first)
    }
}
impl Registry {
    pub fn make(ast: &ast::Ast, binds: &[Bind]) -> Result<Self> {
        if ast.contract.declaration != ast::Declaration::Program {
            return Err(Error::Program);
        }
        let limit = core::rule::LOCAL.get(core::rule::Field::TermNodes) as usize;
        if binds.len() > limit {
            return Err(Error::BindLimit(binds.len()));
        }
        let mut entries = Vec::with_capacity(binds.len());
        let mut seen = BTreeSet::new();
        for bind in binds {
            if !seen.insert(bind.atom) {
                return Err(Error::AtomRepeated(bind.atom));
            }
            if !target_kind(bind.atom, &bind.target) {
                return Err(Error::TargetKind(bind.atom, bind.target.clone()));
            }
            let entry = match &bind.target {
                Target::State(name) => {
                    let field = unique(
                        &bind.target,
                        ast.contract
                            .state
                            .iter()
                            .filter(|field| field.name == *name),
                    )?;
                    let typ = HostType::from_ast(ast.nodes.typ(field.typ)).ok_or_else(|| {
                        Error::TargetType(
                            bind.target.clone(),
                            ast.nodes.typ(field.typ).name().to_vec(),
                        )
                    })?;
                    Entry::State(name.clone(), typ)
                }
                Target::Event(name) => {
                    let event = unique(
                        &bind.target,
                        ast.contract
                            .events
                            .iter()
                            .filter(|event| event.name == *name),
                    )?;
                    if event.fields.len() > 64 {
                        return Err(Error::HostLimit(bind.atom, event.fields.len()));
                    }
                    let mut types = Vec::with_capacity(event.fields.len());
                    for (_, typ, _) in &event.fields {
                        types.push(HostType::from_ast(ast.nodes.typ(*typ)).ok_or_else(|| {
                            Error::TargetType(
                                bind.target.clone(),
                                ast.nodes.typ(*typ).name().to_vec(),
                            )
                        })?);
                    }
                    Entry::Event(name.clone(), types)
                }
                Target::Fault(name) => {
                    let fault = unique(
                        &bind.target,
                        ast.contract
                            .errors
                            .iter()
                            .filter(|fault| fault.name == *name),
                    )?;
                    Entry::Fault(name.clone(), fault.code, fault.message.clone())
                }
            };
            entries.push((bind.atom, entry));
        }
        Ok(Self { entries })
    }
    pub fn entries(&self) -> &[(Atom, Entry)] {
        &self.entries
    }
    fn find(&self, atom: Atom) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|(found, _)| *found == atom)
            .map(|(_, entry)| entry)
    }
    fn check_site(&self, types: &mut Types, site: Site) -> Result<()> {
        match (site.atom(), site.origin()) {
            (Atom::Read(_) | Atom::Write(_) | Atom::Emit(_) | Atom::Fail(_), Origin::Direct) => (),
            (Atom::Write(kind) | Atom::Close(kind), Origin::Held(actual)) if kind == actual => (),
            (atom, origin) => return Err(Error::SiteOrigin(atom, origin)),
        }
        let entry = self
            .find(site.atom())
            .ok_or(Error::BindingAbsent(site.atom()))?;
        let expected = match entry {
            Entry::State(_, typ) => typ.core(types),
            Entry::Event(_, host_types) => {
                let mut reversed = host_types.iter().rev();
                let mut typ = match reversed.next() {
                    None => types.intern(Type::Unit),
                    Some(typ) => typ.core(types),
                };
                for host in reversed {
                    let head = host.core(types);
                    typ = types.intern(Type::Pair(head, typ));
                }
                typ
            }
            Entry::Fault(..) => {
                if fault_type(types, site.payload()) {
                    return Ok(());
                }
                return Err(Error::SitePayload(site.atom(), site.payload()));
            }
        };
        if expected == site.payload() {
            Ok(())
        } else {
            Err(Error::SiteType(site.atom(), expected, site.payload()))
        }
    }
    pub fn seal(&self, types: &mut Types, terms: &Terms, program: &Program) -> Result<Sealed> {
        let checked =
            check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Static)?;
        let locations = checked.locations();
        let mut quotas: BTreeMap<(Atom, Origin), Quota> = BTreeMap::new();
        for location in &locations {
            let site = location.site();
            self.check_site(types, site)?;
            match quotas.entry((site.atom(), site.origin())) {
                std::collections::btree_map::Entry::Occupied(mut quota) => {
                    quota.get_mut().left += location.count();
                }
                std::collections::btree_map::Entry::Vacant(quota) => {
                    quota.insert(Quota {
                        site,
                        left: location.count().clone(),
                    });
                }
            }
        }
        Ok(Sealed {
            registry: self.clone(),
            types: Arc::new(types.clone()),
            terms: Arc::new(terms.clone()),
            program: program.clone(),
            checked,
            locations,
            quotas,
        })
    }
}
fn fault_type(types: &Types, root: TypeId) -> bool {
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(typ) = pending.pop() {
        if !seen.insert(typ) {
            continue;
        }
        match types.get(typ) {
            Type::Unit | Type::Bool | Type::Int | Type::Num(..) | Type::Bytes(_) => (),
            Type::Pair(left, right) => {
                pending.push(*right);
                pending.push(*left);
            }
            _ => return false,
        }
    }
    true
}
#[derive(Clone, Debug)]
pub(crate) struct Quota {
    pub(crate) site: Site,
    pub(crate) left: BigInt,
}
#[derive(Clone, Debug)]
pub struct Sealed {
    registry: Registry,
    types: Arc<Types>,
    terms: Arc<Terms>,
    program: Program,
    checked: Checked,
    locations: Vec<Location>,
    quotas: BTreeMap<(Atom, Origin), Quota>,
}
impl Sealed {
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    pub fn types(&self) -> &Types {
        &self.types
    }
    pub fn terms(&self) -> &Terms {
        &self.terms
    }
    pub fn program(&self) -> &Program {
        &self.program
    }
    pub fn typ(&self) -> TypeId {
        self.checked.info().typ()
    }
    pub fn checked(&self) -> &Checked {
        &self.checked
    }
    pub fn locations(&self) -> &[Location] {
        &self.locations
    }
}
