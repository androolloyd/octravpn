// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_fhe static depth/work validation and checked host plans. These plans do
//! not perform encryption or replace the native cryptographic backend.
use super::{
    parse::ast::{Ast, Fhe, FheId},
    rule::{Field as RuleField, LOCAL},
    syntax::Name,
    Natural,
};
use num_bigint::BigInt;
use std::collections::{BTreeMap, BTreeSet};
mod host;
mod run;
pub use host::{Host, Instruction};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Key,
    Depth,
    AddWork,
    MulWork,
    RecryptWork,
    ParameterId,
    ParameterCapacity,
}
impl Field {
    fn text(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Depth => "depth",
            Self::AddWork => "add work",
            Self::MulWork => "mul work",
            Self::RecryptWork => "recrypt work",
            Self::ParameterId => "parameter id",
            Self::ParameterCapacity => "parameter capacity",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    Steps,
    Work,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enc {
    key: Natural,
    remaining: Natural,
}
impl Enc {
    pub fn key(self) -> Natural {
        self.key
    }
    pub fn remaining(self) -> Natural {
        self.remaining
    }
    pub fn text(self) -> Vec<u8> {
        format!("enc[{},{}]", self.key.get(), self.remaining.get()).into_bytes()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    full: Natural,
    add: Natural,
    multiply: Natural,
    recrypt: Natural,
}
impl Config {
    pub fn new(depth: &BigInt, add: &BigInt, multiply: &BigInt, recrypt: &BigInt) -> Result<Self> {
        let full = nat(Field::Depth, depth)?;
        let add = positive(Field::AddWork, add)?;
        let multiply = positive(Field::MulWork, multiply)?;
        let recrypt = positive(Field::RecryptWork, recrypt)?;
        Ok(Self {
            full,
            add,
            multiply,
            recrypt,
        })
    }
    pub fn full(self) -> Natural {
        self.full
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Profile(BTreeMap<Natural, Config>);
impl Profile {
    pub fn new(values: &[(BigInt, Config)]) -> Result<Self> {
        let mut out = BTreeMap::new();
        let limit = LOCAL.get(RuleField::Inputs) as usize;
        for (count, (raw, config)) in values.iter().enumerate() {
            if count == limit {
                return Err(Error::ProfileCount(limit, limit + 1));
            }
            let key = nat(Field::Key, raw)?;
            if out.insert(key, *config).is_some() {
                return Err(Error::ProfileDuplicate(key));
            }
        }
        Ok(Self(out))
    }
    fn config(&self, key: Natural) -> Result<Config> {
        self.0.get(&key).copied().ok_or(Error::NoKey(key))
    }
    pub fn full(&self, key: Natural) -> Result<Natural> {
        Ok(self.config(key)?.full)
    }
    fn legal(&self, typ: Enc) -> Result<Config> {
        let config = self.config(typ.key)?;
        if typ.remaining <= config.full {
            Ok(config)
        } else {
            Err(Error::InputDepth(typ.key, typ.remaining, config.full))
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameter {
    id: Natural,
    key: Natural,
    capacity: Natural,
}
impl Parameter {
    pub fn new(id: &BigInt, key: &BigInt, capacity: &BigInt) -> Result<Self> {
        Ok(Self {
            id: nat(Field::ParameterId, id)?,
            key: nat(Field::Key, key)?,
            capacity: nat(Field::ParameterCapacity, capacity)?,
        })
    }
    pub fn id(self) -> Natural {
        self.id
    }
    pub fn key(self) -> Natural {
        self.key
    }
    pub fn capacity(self) -> Natural {
        self.capacity
    }
    pub fn text(self) -> Vec<u8> {
        format!(
            "param[{},{},{}]",
            self.id.get(),
            self.key.get(),
            self.capacity.get()
        )
        .into_bytes()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Catalog {
    keys: BTreeMap<Natural, BTreeMap<Natural, Parameter>>,
}
impl Catalog {
    pub fn new(values: &[Parameter]) -> Result<Self> {
        let mut ids = BTreeSet::new();
        let mut keys: BTreeMap<Natural, BTreeMap<Natural, Parameter>> = BTreeMap::new();
        let limit = LOCAL.get(RuleField::Inputs) as usize;
        for (count, value) in values.iter().enumerate() {
            if count == limit {
                return Err(Error::CatalogCount(limit, limit + 1));
            }
            if !ids.insert(value.id) {
                return Err(Error::CatalogDuplicateId(value.id));
            }
            if keys
                .entry(value.key)
                .or_default()
                .insert(value.capacity, *value)
                .is_some()
            {
                return Err(Error::CatalogDuplicateCapacity(value.key, value.capacity));
            }
        }
        Ok(Self { keys })
    }
    pub fn select(&self, key: Natural, need: Natural) -> Result<Parameter> {
        self.keys
            .get(&key)
            .and_then(|values| values.range(need..).next())
            .map(|(_, value)| *value)
            .ok_or(Error::NoParameter(key, need))
    }
    pub fn params(&self, info: &Info) -> Result<Parameter> {
        self.select(info.typ.key, info.peak)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    name: Name,
    key: BigInt,
    remaining: BigInt,
}
impl Input {
    pub fn new(name: Name, key: BigInt, remaining: BigInt) -> Self {
        Self {
            name,
            key,
            remaining,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Environment(BTreeMap<Name, Enc>);
impl Environment {
    pub fn new(profile: &Profile, values: &[Input]) -> Result<Self> {
        let mut out = BTreeMap::new();
        let limit = LOCAL.get(RuleField::Inputs) as usize;
        for (count, value) in values.iter().enumerate() {
            if count == limit {
                return Err(Error::InputCount(limit, limit + 1));
            }
            if out.contains_key(&value.name) {
                return Err(Error::InputDuplicate(value.name.text().to_vec()));
            }
            let typ = Enc {
                key: nat(Field::Key, &value.key)?,
                remaining: nat(Field::Depth, &value.remaining)?,
            };
            profile.legal(typ)?;
            out.insert(value.name.clone(), typ);
        }
        Ok(Self(out))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TermId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Var(Name),
    Trim(BigInt, TermId),
    Add(TermId, TermId),
    Mul(TermId, TermId),
    Recrypt(TermId),
}
impl Term {
    fn children(&self) -> Vec<TermId> {
        match self {
            Self::Var(_) => Vec::new(),
            Self::Trim(_, value) | Self::Recrypt(value) => vec![*value],
            Self::Add(left, right) | Self::Mul(left, right) => vec![*left, *right],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Terms(Vec<Term>);
impl Terms {
    pub fn try_get(&self, id: TermId) -> Option<&Term> {
        self.0.get(id.0)
    }
    pub fn insert(&mut self, term: Term) -> std::result::Result<TermId, super::arena::Reference> {
        for child in term.children() {
            if self.try_get(child).is_none() {
                return Err(super::arena::Reference {
                    kind: super::arena::Kind::Fhe,
                    index: child.0,
                    length: self.0.len(),
                });
            }
        }
        Ok(self.push(term))
    }
    pub fn get(&self, id: TermId) -> &Term {
        &self.0[id.0]
    }
    pub fn push(&mut self, term: Term) -> TermId {
        assert!(
            term.children().iter().all(|id| id.0 < self.0.len()),
            "FHE child precedes parent"
        );
        let id = TermId(self.0.len());
        self.0.push(term);
        id
    }
    pub fn from_ast(ast: &Ast, root: FheId) -> (Self, TermId) {
        let mut out = Self::default();
        let mut mapped = BTreeMap::new();
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            if mapped.contains_key(&id) {
                continue;
            }
            let term = &ast.private(id).value;
            if !finish {
                pending.push((id, true));
                match term {
                    Fhe::Var(_) => (),
                    Fhe::Trim(_, value) | Fhe::Renew(value) => pending.push((*value, false)),
                    Fhe::Add(left, right) | Fhe::Mul(left, right) => {
                        pending.push((*right, false));
                        pending.push((*left, false));
                    }
                }
                continue;
            }
            let term = match term {
                Fhe::Var(name) => Term::Var(name.clone()),
                Fhe::Trim(rem, value) => Term::Trim(rem.clone(), mapped[value]),
                Fhe::Renew(value) => Term::Recrypt(mapped[value]),
                Fhe::Add(left, right) => Term::Add(mapped[left], mapped[right]),
                Fhe::Mul(left, right) => Term::Mul(mapped[left], mapped[right]),
            };
            let term = out.push(term);
            mapped.insert(id, term);
        }
        let root = mapped[&root];
        (out, root)
    }
    pub fn shape(&self, root: TermId) -> Result<()> {
        let max_depth = LOCAL.get(RuleField::TermDepth) as usize;
        let max_nodes = LOCAL.get(RuleField::TermNodes) as usize;
        let mut nodes = 0;
        let mut pending = vec![(0, root)];
        while let Some((depth, id)) = pending.pop() {
            if depth > max_depth {
                return Err(Error::Depth(max_depth, depth));
            }
            if nodes >= max_nodes {
                return Err(Error::Nodes(max_nodes, nodes + 1));
            }
            nodes += 1;
            pending.extend(
                self.get(id)
                    .children()
                    .into_iter()
                    .rev()
                    .map(|child| (depth + 1, child)),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Multiply(Natural),
    Recrypt(Natural),
}
impl Operation {
    pub fn text(self) -> Vec<u8> {
        match self {
            Self::Multiply(key) => format!("fhe_mul<{}>", key.get()).into_bytes(),
            Self::Recrypt(key) => format!("recrypt<{}>", key.get()).into_bytes(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    typ: Enc,
    steps: Natural,
    work: Natural,
    peak: Natural,
    plan: Vec<Operation>,
}
impl Info {
    pub fn typ(&self) -> Enc {
        self.typ
    }
    pub fn steps(&self) -> Natural {
        self.steps
    }
    pub fn work(&self) -> Natural {
        self.work
    }
    pub fn peak(&self) -> Natural {
        self.peak
    }
    pub fn plan(&self) -> &[Operation] {
        &self.plan
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Natural(Field, BigInt),
    Zero(Field),
    ProfileDuplicate(Natural),
    ProfileCount(usize, usize),
    CatalogDuplicateId(Natural),
    CatalogDuplicateCapacity(Natural, Natural),
    CatalogCount(usize, usize),
    NoParameter(Natural, Natural),
    NoKey(Natural),
    InputDuplicate(Vec<u8>),
    InputCount(usize, usize),
    InputDepth(Natural, Natural, Natural),
    Free(Vec<u8>),
    Need(Enc, Enc),
    MultiplyZero(Natural),
    RecryptNeed(Natural, Natural),
    Depth(usize, usize),
    Nodes(usize, usize),
    Statistic(Axis, BigInt),
}
pub type Result<T> = std::result::Result<T, Error>;
fn nat(field: Field, value: &BigInt) -> Result<Natural> {
    Natural::new(value).ok_or_else(|| Error::Natural(field, value.clone()))
}
fn positive(field: Field, value: &BigInt) -> Result<Natural> {
    let value = nat(field, value)?;
    if value.get() == 0 {
        Err(Error::Zero(field))
    } else {
        Ok(value)
    }
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let raw = match self {
            Self::Natural(field, value) => format!(
                "fhe natural outside profile field = {} value = {value}",
                field.text()
            )
            .into_bytes(),
            Self::Zero(field) => format!("fhe cost is zero field = {}", field.text()).into_bytes(),
            Self::ProfileDuplicate(key) => {
                format!("duplicate fhe key profile = {}", key.get()).into_bytes()
            }
            Self::ProfileCount(limit, actual) => {
                format!("fhe profile count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::CatalogDuplicateId(id) => {
                format!("duplicate fhe parameter id = {}", id.get()).into_bytes()
            }
            Self::CatalogDuplicateCapacity(key, cap) => format!(
                "duplicate fhe parameter capacity key = {} capacity = {}",
                key.get(),
                cap.get()
            )
            .into_bytes(),
            Self::CatalogCount(limit, actual) => {
                format!("fhe parameter count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::NoParameter(key, need) => format!(
                "fhe parameter unavailable key = {} required = {}",
                key.get(),
                need.get()
            )
            .into_bytes(),
            Self::NoKey(key) => format!("fhe key profile absent = {}", key.get()).into_bytes(),
            Self::InputDuplicate(name) => [b"duplicate fhe input = ".as_slice(), name].concat(),
            Self::InputCount(limit, actual) => {
                format!("fhe input count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::InputDepth(key, rem, full) => format!(
                "fhe depth exceeds allowance key = {} remaining = {} allowance = {}",
                key.get(),
                rem.get(),
                full.get()
            )
            .into_bytes(),
            Self::Free(name) => [b"fhe input is free = ".as_slice(), name].concat(),
            Self::Need(left, right) => [
                b"fhe operand type mismatch left = ".as_slice(),
                &left.text(),
                b" right = ",
                &right.text(),
            ]
            .concat(),
            Self::MultiplyZero(key) => {
                format!("fhe multiplication has no depth key = {}", key.get()).into_bytes()
            }
            Self::RecryptNeed(key, rem) => format!(
                "recrypt requires zero remaining depth key = {} remaining = {}",
                key.get(),
                rem.get()
            )
            .into_bytes(),
            Self::Depth(limit, actual) => {
                format!("fhe term depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("fhe term nodes limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Statistic(axis, value) => format!(
                "fhe static {} outside profile = {value}",
                match axis {
                    Axis::Steps => "steps",
                    Axis::Work => "work",
                }
            )
            .into_bytes(),
        };
        super::text::clip(&raw)
    }
}
pub fn check(
    profile: &Profile,
    environment: &Environment,
    terms: &Terms,
    root: TermId,
) -> Result<Info> {
    Ok(run::run(profile, environment, terms, root)?.0)
}
pub fn host(
    profile: &Profile,
    environment: &Environment,
    terms: &Terms,
    root: TermId,
) -> Result<Host> {
    Ok(run::run(profile, environment, terms, root)?.1)
}
