// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_idx natural indices and ordered parameter environments. The flat arena
//! preserves native occurrence limits without recursive host-stack ownership.
use super::{
    rule::{Field, LOCAL},
    syntax::Name,
    Natural,
};
use num_bigint::BigInt;
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexId(usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Index {
    Lit(Natural),
    Var(Name),
    Add(IndexId, IndexId),
    Mul(IndexId, IndexId),
    Max(IndexId, IndexId),
    Sub(IndexId, IndexId),
}
#[derive(Clone, Debug, Default)]
pub struct Indices {
    items: Vec<Index>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env(Arc<Vec<(Name, Natural)>>);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Eq,
    Le,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Free(Vec<u8>),
    Dup(Vec<u8>),
    Nat(BigInt),
    Depth(usize, usize),
    Nodes(usize, usize),
    Vars(usize, usize),
    False(Relation, Natural, Natural),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// C_idx diagnostics are not clipped here. C_decl/C_parse apply their own
    /// native diagnostic clipping at the surrounding boundary.
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Free(name) => [b"index parameter is free = ".as_slice(), name].concat(),
            Self::Dup(name) => [b"duplicate index parameter = ".as_slice(), name].concat(),
            Self::Nat(value) => format!("index natural outside profile = {value}").into_bytes(),
            Self::Depth(limit, actual) => {
                format!("index depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("index nodes limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Vars(limit, actual) => {
                format!("index parameter count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::False(relation, left, right) => {
                let relation = match relation {
                    Relation::Eq => "=",
                    Relation::Le => "<=",
                };
                format!(
                    "index law is false relation = {relation} left = {} right = {}",
                    left.get(),
                    right.get()
                )
                .into_bytes()
            }
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}

impl Env {
    pub fn from_values(values: &[(Name, BigInt)]) -> Result<Self> {
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if values.len() > maximum {
            return Err(Error::Vars(maximum, values.len()));
        }
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(values.len());
        for (name, raw) in values {
            if !seen.insert(name.clone()) {
                return Err(Error::Dup(name.text().to_vec()));
            }
            let value = Natural::new(raw).ok_or_else(|| Error::Nat(raw.clone()))?;
            out.push((name.clone(), value));
        }
        Ok(Self(Arc::new(out)))
    }
    pub fn values(&self) -> &[(Name, Natural)] {
        &self.0
    }
    pub fn find(&self, name: &Name) -> Option<Natural> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| *value)
    }
    pub fn put(&self, indices: &Indices, name: Name, term: IndexId) -> Result<Self> {
        if self.find(&name).is_some() {
            return Err(Error::Dup(name.text().to_vec()));
        }
        let count = self.0.len() + 1;
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if count > maximum {
            return Err(Error::Vars(maximum, count));
        }
        let value = indices.eval(self, term)?;
        let mut out = Vec::with_capacity(count);
        out.push((name, value));
        out.extend(self.0.iter().cloned());
        Ok(Self(Arc::new(out)))
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Add,
    Mul,
    Max,
    Sub,
}
enum Task {
    Visit(IndexId),
    Apply(Operation),
}

impl Indices {
    pub fn try_get(&self, id: IndexId) -> Option<&Index> {
        self.items.get(id.0)
    }
    pub(crate) fn require(&self, id: IndexId) -> std::result::Result<(), super::arena::Reference> {
        self.try_get(id).map(|_| ()).ok_or(super::arena::Reference {
            kind: super::arena::Kind::Index,
            index: id.0,
            length: self.items.len(),
        })
    }
    pub fn insert(
        &mut self,
        value: Index,
    ) -> std::result::Result<IndexId, super::arena::Reference> {
        if let Index::Add(left, right)
        | Index::Mul(left, right)
        | Index::Max(left, right)
        | Index::Sub(left, right) = &value
        {
            self.require(*left)?;
            self.require(*right)?;
        }
        Ok(self.push(value))
    }
    pub fn get(&self, id: IndexId) -> &Index {
        &self.items[id.0]
    }
    pub fn push(&mut self, value: Index) -> IndexId {
        if let Index::Add(left, right)
        | Index::Mul(left, right)
        | Index::Max(left, right)
        | Index::Sub(left, right) = &value
        {
            assert!(
                left.0 < self.items.len() && right.0 < self.items.len(),
                "index children precede parent"
            );
        }
        let id = IndexId(self.items.len());
        self.items.push(value);
        id
    }
    pub fn lit(&mut self, value: &BigInt) -> Option<IndexId> {
        Natural::new(value).map(|value| self.exact(value))
    }
    pub fn exact(&mut self, value: Natural) -> IndexId {
        self.push(Index::Lit(value))
    }
    pub fn var(&mut self, name: Name) -> IndexId {
        self.push(Index::Var(name))
    }
    pub fn add(&mut self, left: IndexId, right: IndexId) -> IndexId {
        self.push(Index::Add(left, right))
    }
    pub fn mul(&mut self, left: IndexId, right: IndexId) -> IndexId {
        self.push(Index::Mul(left, right))
    }
    pub fn max(&mut self, left: IndexId, right: IndexId) -> IndexId {
        self.push(Index::Max(left, right))
    }
    pub fn sub(&mut self, left: IndexId, right: IndexId) -> IndexId {
        self.push(Index::Sub(left, right))
    }

    pub fn shape(&self, root: IndexId) -> Result<()> {
        let maximum_depth = LOCAL.get(Field::TermDepth) as usize;
        let maximum_nodes = LOCAL.get(Field::TermNodes) as usize;
        let mut pending = vec![(0, root)];
        let mut nodes = 0;
        while let Some((depth, id)) = pending.pop() {
            // Native depth refusal takes precedence when both limits fail.
            if depth > maximum_depth {
                return Err(Error::Depth(maximum_depth, depth));
            }
            if nodes >= maximum_nodes {
                return Err(Error::Nodes(maximum_nodes, nodes + 1));
            }
            match self.get(id) {
                Index::Lit(_) | Index::Var(_) => (),
                Index::Add(left, right)
                | Index::Mul(left, right)
                | Index::Max(left, right)
                | Index::Sub(left, right) => {
                    pending.push((depth + 1, *right));
                    pending.push((depth + 1, *left));
                }
            }
            nodes += 1;
        }
        Ok(())
    }
    pub fn eval(&self, environment: &Env, root: IndexId) -> Result<Natural> {
        self.shape(root)?;
        let mut tasks = vec![Task::Visit(root)];
        let mut values = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Visit(id) => {
                    let (left, right, operation) = match self.get(id) {
                        Index::Lit(value) => {
                            values.push(*value);
                            continue;
                        }
                        Index::Var(name) => {
                            values.push(
                                environment
                                    .find(name)
                                    .ok_or_else(|| Error::Free(name.text().to_vec()))?,
                            );
                            continue;
                        }
                        Index::Add(left, right) => (*left, *right, Operation::Add),
                        Index::Mul(left, right) => (*left, *right, Operation::Mul),
                        Index::Max(left, right) => (*left, *right, Operation::Max),
                        Index::Sub(left, right) => (*left, *right, Operation::Sub),
                    };
                    tasks.push(Task::Apply(operation));
                    tasks.push(Task::Visit(right));
                    tasks.push(Task::Visit(left));
                }
                Task::Apply(operation) => {
                    let right = values.pop().expect("evaluated right index");
                    let left = values.pop().expect("evaluated left index");
                    let value = match operation {
                        Operation::Max => left.max(right),
                        Operation::Sub if left <= right => {
                            Natural::from_u32(0).expect("natural zero")
                        }
                        Operation::Add | Operation::Mul | Operation::Sub => {
                            let left = BigInt::from(left.get());
                            let right = BigInt::from(right.get());
                            let raw = match operation {
                                Operation::Add => left + right,
                                Operation::Mul => left * right,
                                Operation::Sub => left - right,
                                Operation::Max => unreachable!("maximum handled before arithmetic"),
                            };
                            Natural::new(&raw).ok_or(Error::Nat(raw))?
                        }
                    };
                    values.push(value);
                }
            }
        }
        Ok(values.pop().expect("index root result"))
    }
    pub fn eq(&self, environment: &Env, left: IndexId, right: IndexId) -> Result<bool> {
        let left = self.eval(environment, left)?;
        let right = self.eval(environment, right)?;
        Ok(left == right)
    }
    pub fn le(&self, environment: &Env, left: IndexId, right: IndexId) -> Result<bool> {
        let left = self.eval(environment, left)?;
        let right = self.eval(environment, right)?;
        Ok(left <= right)
    }
    pub fn hold(
        &self,
        environment: &Env,
        relation: Relation,
        left: IndexId,
        right: IndexId,
    ) -> Result<()> {
        let left = self.eval(environment, left)?;
        let right = self.eval(environment, right)?;
        let accepted = match relation {
            Relation::Eq => left == right,
            Relation::Le => left <= right,
        };
        if accepted {
            Ok(())
        } else {
            Err(Error::False(relation, left, right))
        }
    }
}
