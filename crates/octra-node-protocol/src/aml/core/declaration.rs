// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_decl indexed declarations. Declaration shape, index evaluation, C_low
//! type validity and resource input modes remain separate ordered checks.
use super::{
    index::{self, IndexId, Indices},
    lower,
    rule::{Field, LOCAL},
    syntax::{self, Name, Syntax},
    term,
    types::{self, Multiplicity, Sign},
    Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    Unit,
    Bool,
    Int,
    Num(Sign, IndexId),
    Var(Name),
    Bytes(IndexId),
    Vec(IndexId, TypeId),
    Seq(IndexId, TypeId),
    Cap(BigInt),
    Pair(TypeId, TypeId),
    Result(TypeId, TypeId),
    Exact(syntax::TypeId),
}
#[derive(Clone, Debug, Default)]
pub struct Declarations {
    items: Vec<Type>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub name: Vec<u8>,
    pub multiplicity: Multiplicity,
    pub typ: TypeId,
}
impl Input {
    pub fn new(name: impl AsRef<[u8]>, multiplicity: Multiplicity, typ: TypeId) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            multiplicity,
            typ,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Name(Vec<u8>),
    Dup(Vec<u8>),
    Nat(BigInt),
    Depth(usize, usize),
    Nodes(usize, usize),
    Mode(Vec<u8>, Multiplicity),
    Count(usize, usize),
    Idx(index::Error),
    Low(lower::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let raw = match self {
            Self::Name(name) => [b"invalid input name = ".as_slice(), name].concat(),
            Self::Dup(name) => [b"duplicate input name = ".as_slice(), name].concat(),
            Self::Nat(value) => format!("natural outside profile = {value}").into_bytes(),
            Self::Depth(limit, actual) => {
                format!("type depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("type nodes limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Mode(name, multiplicity) => [
                b"resource input mode name = ".as_slice(),
                name,
                b" mode = ",
                multiplicity.text(),
            ]
            .concat(),
            Self::Count(limit, actual) => {
                format!("input count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Idx(error) => error.text(),
            Self::Low(error) => error.text(),
        };
        super::text::clip(&raw)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn natural(value: &BigInt) -> Result<Natural> {
    Natural::new(value).ok_or_else(|| Error::Nat(value.clone()))
}
enum Task {
    Visit(TypeId),
    Finish(TypeId, Option<BigInt>),
}
impl Declarations {
    pub fn try_get(&self, id: TypeId) -> Option<&Type> {
        self.items.get(id.0)
    }
    pub(crate) fn require(&self, id: TypeId) -> std::result::Result<(), super::arena::Reference> {
        self.try_get(id).map(|_| ()).ok_or(super::arena::Reference {
            kind: super::arena::Kind::Declaration,
            index: id.0,
            length: self.items.len(),
        })
    }
    pub fn insert(
        &mut self,
        indices: &Indices,
        syntax: &Syntax,
        typ: Type,
    ) -> std::result::Result<TypeId, super::arena::Reference> {
        match &typ {
            Type::Vec(index, child) | Type::Seq(index, child) => {
                indices.require(*index)?;
                self.require(*child)?;
            }
            Type::Pair(left, right) | Type::Result(left, right) => {
                self.require(*left)?;
                self.require(*right)?;
            }
            Type::Num(_, index) | Type::Bytes(index) => indices.require(*index)?,
            Type::Exact(id) => syntax.require_type(*id)?,
            _ => (),
        }
        Ok(self.push(typ))
    }
    pub fn get(&self, id: TypeId) -> &Type {
        &self.items[id.0]
    }
    pub fn push(&mut self, typ: Type) -> TypeId {
        match &typ {
            Type::Vec(_, child) | Type::Seq(_, child) => {
                assert!(
                    child.0 < self.items.len(),
                    "declaration child precedes parent"
                );
            }
            Type::Pair(left, right) | Type::Result(left, right) => {
                assert!(
                    left.0 < self.items.len() && right.0 < self.items.len(),
                    "declaration children precede parent"
                );
            }
            _ => (),
        }
        let id = TypeId(self.items.len());
        self.items.push(typ);
        id
    }
    pub fn shape(&self, root: TypeId) -> Result<()> {
        let maximum_depth = types::MAX_DEPTH;
        let maximum_nodes = types::MAX_NODES;
        let mut pending = vec![(0, root)];
        let mut nodes = 0;
        while let Some((depth, id)) = pending.pop() {
            if depth > maximum_depth {
                return Err(Error::Depth(maximum_depth, depth));
            }
            if nodes >= maximum_nodes {
                return Err(Error::Nodes(maximum_nodes, nodes + 1));
            }
            match self.get(id) {
                Type::Cap(kind) => {
                    natural(kind)?;
                }
                Type::Vec(_, child) | Type::Seq(_, child) => pending.push((depth + 1, *child)),
                Type::Pair(left, right) | Type::Result(left, right) => {
                    pending.push((depth + 1, *right));
                    pending.push((depth + 1, *left));
                }
                Type::Unit
                | Type::Bool
                | Type::Int
                | Type::Var(_)
                | Type::Exact(_)
                | Type::Num(_, _)
                | Type::Bytes(_) => (),
            }
            nodes += 1;
        }
        Ok(())
    }
    fn lower(
        &self,
        environment: &index::Env,
        indices: &Indices,
        syntax: &mut Syntax,
        root: TypeId,
    ) -> Result<syntax::TypeId> {
        let mut tasks = vec![Task::Visit(root)];
        let mut values = vec![];
        while let Some(task) = tasks.pop() {
            let typ = match task {
                Task::Visit(id) => match self.get(id) {
                    Type::Unit => syntax::Type::Unit,
                    Type::Bool => syntax::Type::Bool,
                    Type::Int => syntax::Type::Int,
                    Type::Num(sign, index) => syntax::Type::Num(
                        *sign,
                        BigInt::from(indices.eval(environment, *index).map_err(Error::Idx)?.get()),
                    ),
                    Type::Var(name) => return Err(Error::Name(name.text().to_vec())),
                    Type::Bytes(index) => syntax::Type::Bytes(BigInt::from(
                        indices.eval(environment, *index).map_err(Error::Idx)?.get(),
                    )),
                    Type::Vec(index, child) | Type::Seq(index, child) => {
                        let length = indices.eval(environment, *index).map_err(Error::Idx)?;
                        tasks.push(Task::Finish(id, Some(BigInt::from(length.get()))));
                        tasks.push(Task::Visit(*child));
                        continue;
                    }
                    Type::Cap(kind) => syntax::Type::Cap(BigInt::from(natural(kind)?.get())),
                    Type::Pair(left, right) | Type::Result(left, right) => {
                        tasks.push(Task::Finish(id, None));
                        tasks.push(Task::Visit(*right));
                        tasks.push(Task::Visit(*left));
                        continue;
                    }
                    Type::Exact(typ) => {
                        values.push(*typ);
                        continue;
                    }
                },
                Task::Finish(id, length) => match self.get(id) {
                    Type::Vec(_, _) => syntax::Type::Vec(
                        length.expect("evaluated vector length"),
                        values.pop().expect("vector element type"),
                    ),
                    Type::Seq(_, _) => syntax::Type::Seq(
                        length.expect("evaluated sequence capacity"),
                        values.pop().expect("sequence element type"),
                    ),
                    Type::Pair(_, _) | Type::Result(_, _) => {
                        let right = values.pop().expect("right declaration type");
                        let left = values.pop().expect("left declaration type");
                        match self.get(id) {
                            Type::Pair(_, _) => syntax::Type::Pair(left, right),
                            Type::Result(_, _) => syntax::Type::Sum(left, right),
                            _ => unreachable!("binary declaration finish"),
                        }
                    }
                    _ => unreachable!("composite declaration finish"),
                },
            };
            values.push(syntax.add_type(typ));
        }
        Ok(values.pop().expect("lowered declaration root"))
    }

    pub fn typ_in(
        &self,
        environment: &index::Env,
        indices: &Indices,
        syntax: &mut Syntax,
        root: TypeId,
    ) -> Result<syntax::TypeId> {
        self.shape(root)?;
        let root = self.lower(environment, indices, syntax, root)?;
        // Native C_decl returns named syntax after independently validating it
        // through C_low. Numbered core types are temporary at this boundary.
        lower::typ(syntax, &mut types::Types::default(), root).map_err(Error::Low)?;
        Ok(root)
    }
    pub fn typ(
        &self,
        indices: &Indices,
        syntax: &mut Syntax,
        root: TypeId,
    ) -> Result<syntax::TypeId> {
        self.typ_in(&index::Env::default(), indices, syntax, root)
    }
    pub fn binds_in(
        &self,
        environment: &index::Env,
        indices: &Indices,
        syntax: &mut Syntax,
        inputs: &[Input],
    ) -> Result<Vec<syntax::Bind>> {
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if inputs.len() > maximum {
            return Err(Error::Count(maximum, inputs.len()));
        }
        let mut names = BTreeSet::new();
        let mut out = Vec::with_capacity(inputs.len());
        for input in inputs {
            let name = Name::new(&input.name).ok_or_else(|| Error::Name(input.name.clone()))?;
            if names.contains(&input.name) {
                return Err(Error::Dup(input.name.clone()));
            }
            let typ = self.typ_in(environment, indices, syntax, input.typ)?;
            if resource(syntax, typ) && input.multiplicity != Multiplicity::One {
                return Err(Error::Mode(input.name.clone(), input.multiplicity));
            }
            names.insert(input.name.clone());
            out.push(syntax::Bind {
                name,
                multiplicity: input.multiplicity,
                typ,
            });
        }
        Ok(out)
    }
    pub fn binds(
        &self,
        indices: &Indices,
        syntax: &mut Syntax,
        inputs: &[Input],
    ) -> Result<Vec<syntax::Bind>> {
        self.binds_in(&index::Env::default(), indices, syntax, inputs)
    }
    pub fn prog_in(
        &self,
        environment: &index::Env,
        indices: &Indices,
        syntax: &mut Syntax,
        types: &mut types::Types,
        terms: &mut term::Terms,
        inputs: &[Input],
        body: syntax::TermId,
    ) -> Result<term::Program> {
        let inputs = self.binds_in(environment, indices, syntax, inputs)?;
        lower::program(syntax, types, terms, &inputs, body).map_err(Error::Low)
    }
    pub fn prog(
        &self,
        indices: &Indices,
        syntax: &mut Syntax,
        types: &mut types::Types,
        terms: &mut term::Terms,
        inputs: &[Input],
        body: syntax::TermId,
    ) -> Result<term::Program> {
        self.prog_in(
            &index::Env::default(),
            indices,
            syntax,
            types,
            terms,
            inputs,
            body,
        )
    }
}

fn resource(syntax: &Syntax, root: syntax::TypeId) -> bool {
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        match syntax.typ(id) {
            syntax::Type::Cap(_) => return true,
            syntax::Type::Vec(length, _) if length == &BigInt::from(0) => (),
            syntax::Type::Vec(_, child) | syntax::Type::Seq(_, child) => pending.push(*child),
            syntax::Type::Pair(left, right) | syntax::Type::Sum(left, right) => {
                pending.push(*right);
                pending.push(*left);
            }
            syntax::Type::Unit
            | syntax::Type::Bool
            | syntax::Type::Int
            | syntax::Type::Num(_, _)
            | syntax::Type::Bytes(_) => (),
        }
    }
    false
}
