// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_proj ordered source dependencies, root outputs and exact rule identity.
//! A project describes source artifacts; construction does not execute them.
use super::rule::{self, Field, Id, LOCAL};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Octb1,
    Ocps1,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    path: Vec<u8>,
    body: Vec<u8>,
    deps: Vec<Vec<u8>>,
}
impl Source {
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn deps(&self) -> &[Vec<u8>] {
        &self.deps
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    path: Vec<u8>,
    name: Vec<u8>,
    feed: Vec<u8>,
}
impl Root {
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    pub fn feed(&self) -> &[u8] {
        &self.feed
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    sources: Vec<Source>,
    roots: Vec<Root>,
    rule: Id,
    target: Target,
}
impl Project {
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }
    pub fn roots(&self) -> &[Root] {
        &self.roots
    }
    pub fn rule(&self) -> &Id {
        &self.rule
    }
    pub fn target(&self) -> Target {
        self.target
    }
    pub fn outs(&self) -> Vec<Vec<u8>> {
        self.roots
            .iter()
            .map(|root| out(self.target, root))
            .collect()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Sources,
    Roots,
    Deps,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Count(Part, usize, usize),
    Size(usize, usize),
    Path(Vec<u8>),
    Body(Vec<u8>, usize, usize),
    DuplicateSource(Vec<u8>),
    DuplicateDependency(Vec<u8>, Vec<u8>),
    MissingDependency(Vec<u8>, Vec<u8>),
    MissingRoot(Vec<u8>),
    DuplicateRoot(Vec<u8>),
    Name(Vec<u8>),
    DuplicateName(Vec<u8>),
    Rule(Id),
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let pair = |prefix: &[u8], owner: &[u8], value: &[u8]| {
            [prefix, owner, b" dependency = ", value].concat()
        };
        match self {
            Self::Count(part, limit, actual) => {
                let part = match part {
                    Part::Sources => "sources",
                    Part::Roots => "roots",
                    Part::Deps => "dependencies",
                };
                format!("project {part} count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Size(limit, actual) => {
                format!("project size limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Path(path) => [b"project path is invalid path = ".as_slice(), path].concat(),
            Self::Body(path, limit, actual) => [
                b"project source size path = ".as_slice(),
                path,
                format!(" limit = {limit} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::DuplicateSource(path) => {
                [b"project source repeats path = ".as_slice(), path].concat()
            }
            Self::DuplicateDependency(path, dep) => {
                pair(b"project dependency repeats path = ", path, dep)
            }
            Self::MissingDependency(path, dep) => {
                pair(b"project dependency is not earlier path = ", path, dep)
            }
            Self::MissingRoot(path) => {
                [b"project root is absent path = ".as_slice(), path].concat()
            }
            Self::DuplicateRoot(path) => {
                [b"project root repeats path = ".as_slice(), path].concat()
            }
            Self::Name(name) => {
                [b"project output name is invalid name = ".as_slice(), name].concat()
            }
            Self::DuplicateName(name) => {
                [b"project output name repeats name = ".as_slice(), name].concat()
            }
            Self::Rule(rule) => {
                format!("project rule is unsupported id = {}", rule.text()).into_bytes()
            }
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}

pub fn source(path: &[u8], body: &[u8], deps: Vec<Vec<u8>>) -> Source {
    Source {
        path: path.to_vec(),
        body: body.to_vec(),
        deps,
    }
}
pub fn root(path: &[u8], name: &[u8]) -> Root {
    root_feed(path, name, &[])
}
pub fn root_feed(path: &[u8], name: &[u8], feed: &[u8]) -> Root {
    Root {
        path: path.to_vec(),
        name: name.to_vec(),
        feed: feed.to_vec(),
    }
}
fn alpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}
pub fn path_ok(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > LOCAL.get(Field::Text) as usize {
        return false;
    }
    value.split(|byte| *byte == b'/').all(|segment| {
        !(segment.is_empty() || segment.len() <= 2 && segment.iter().all(|byte| *byte == b'.'))
            && segment
                .iter()
                .all(|byte| alpha(*byte) || byte.is_ascii_digit() || matches!(*byte, b'-' | b'.'))
    })
}
pub fn name_ok(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= LOCAL.get(Field::Name) as usize
        && value
            .iter()
            .all(|byte| alpha(*byte) || byte.is_ascii_digit() || *byte == b'-')
}
fn count(part: Part, values: usize) -> Result<usize, Error> {
    let limit = LOCAL.get(Field::Inputs) as usize;
    if values > limit {
        Err(Error::Count(part, limit, limit + 1))
    } else {
        Ok(values)
    }
}
fn add(total: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let limit = LOCAL.get(Field::Str) as usize;
    if bytes.len() > limit - *total {
        return Err(Error::Size(limit, *total + bytes.len()));
    }
    *total += bytes.len();
    Ok(())
}
pub fn make(
    rule: Id,
    target: Target,
    sources: Vec<Source>,
    roots: Vec<Root>,
) -> Result<Project, Error> {
    let source_count = count(Part::Sources, sources.len())?;
    let root_count = count(Part::Roots, roots.len())?;
    let limit = LOCAL.get(Field::Inputs) as usize;
    if source_count == 0 {
        return Err(Error::Count(Part::Sources, limit, 0));
    }
    if root_count == 0 {
        return Err(Error::Count(Part::Roots, limit, 0));
    }
    let mut total = 0;
    for source in &sources {
        add(&mut total, &source.path)?;
        add(&mut total, &source.body)?;
        for dep in &source.deps {
            add(&mut total, dep)?;
        }
    }
    for root in &roots {
        add(&mut total, &root.path)?;
        add(&mut total, &root.name)?;
        add(&mut total, &root.feed)?;
    }
    if rule.version() <= 0 || rule.limits() != rule::LOCAL {
        return Err(Error::Rule(rule));
    }
    let mut seen = BTreeSet::new();
    for source in &sources {
        if !path_ok(&source.path) {
            return Err(Error::Path(source.path.clone()));
        }
        let limit = LOCAL.get(Field::Str) as usize;
        if source.body.len() > limit {
            return Err(Error::Body(source.path.clone(), limit, source.body.len()));
        }
        if seen.contains(&source.path) {
            return Err(Error::DuplicateSource(source.path.clone()));
        }
        count(Part::Deps, source.deps.len())?;
        let mut used = BTreeSet::new();
        for dep in &source.deps {
            if !path_ok(dep) {
                return Err(Error::Path(dep.clone()));
            }
            if !used.insert(dep) {
                return Err(Error::DuplicateDependency(source.path.clone(), dep.clone()));
            }
            if !seen.contains(dep) {
                return Err(Error::MissingDependency(source.path.clone(), dep.clone()));
            }
        }
        seen.insert(source.path.clone());
    }
    let mut used = BTreeSet::new();
    let mut names = BTreeSet::new();
    for root in &roots {
        if !seen.contains(&root.path) {
            return Err(Error::MissingRoot(root.path.clone()));
        }
        if !name_ok(&root.name) {
            return Err(Error::Name(root.name.clone()));
        }
        if !used.insert(&root.path) {
            return Err(Error::DuplicateRoot(root.path.clone()));
        }
        if !names.insert(&root.name) {
            return Err(Error::DuplicateName(root.name.clone()));
        }
    }
    Ok(Project {
        sources,
        roots,
        rule,
        target,
    })
}
pub fn out(target: Target, root: &Root) -> Vec<u8> {
    [
        root.name.as_slice(),
        match target {
            Target::Octb1 => b".octb".as_slice(),
            Target::Ocps1 => b".ocps",
        },
    ]
    .concat()
}
