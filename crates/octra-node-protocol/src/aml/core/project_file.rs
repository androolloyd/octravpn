// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_pfile manifests bind ordered source/feed bodies to a project and schedule.
//! This parser performs no filesystem reads and preserves byte diagnostics.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    declaration,
    eval::Values,
    feed, lexer, parse,
    project::{self, Project, Target},
    rule::{self, Rule, Schedule, LOCAL},
    types::Types,
    Natural,
};
use num_bigint::BigInt;

#[derive(Clone, Debug)]
struct Source {
    path: Vec<u8>,
    deps: Vec<Vec<u8>>,
}
#[derive(Clone, Debug)]
struct Root {
    path: Vec<u8>,
    name: Vec<u8>,
    feed_path: Option<Vec<u8>>,
}
#[derive(Clone, Debug)]
pub struct ProjectFile {
    version: i64,
    target: Target,
    sources: Vec<Source>,
    roots: Vec<Root>,
}
impl ProjectFile {
    pub fn paths(&self) -> Vec<Vec<u8>> {
        self.sources
            .iter()
            .map(|source| source.path.clone())
            .chain(self.roots.iter().filter_map(|root| root.feed_path.clone()))
            .collect()
    }
}
#[derive(Clone, Debug)]
pub struct Image {
    project: Project,
    rules: Schedule,
}
impl Image {
    pub fn project(&self) -> &Project {
        &self.project
    }
    pub fn rules(&self) -> &Schedule {
        &self.rules
    }
    pub fn into_parts(self) -> (Project, Schedule) {
        (self.project, self.rules)
    }
}
#[derive(Clone, Debug)]
pub enum Error {
    Header,
    Line(usize),
    Character(usize, usize, u8),
    Comment(lexer::Span),
    Roots(usize, usize),
    Version(Vec<u8>),
    Bodies(usize, usize),
    Source(Vec<u8>, parse::Error),
    Binds(Vec<u8>, declaration::Error),
    Feed {
        path: Vec<u8>,
        error: feed::Error,
        types: Types,
    },
    Rule(rule::Error),
    Project(project::Error),
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Header => b"project file header is invalid".to_vec(),
            Self::Line(line) => format!("project file line is invalid line = {line}").into_bytes(),
            Self::Character(line, column, byte) => format!(
                "project file character is invalid line = {line} column = {column} byte = {byte}"
            )
            .into_bytes(),
            Self::Comment(span) => super::comments::text(*span),
            Self::Roots(expected, actual) => {
                format!("project root count expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Version(value) => [
                b"project rule version is invalid value = ".as_slice(),
                value,
            ]
            .concat(),
            Self::Bodies(expected, actual) => {
                format!("project source count expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Source(path, error) => [
                b"project root source refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(),
            ]
            .concat(),
            Self::Binds(path, error) => [
                b"project root input refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(),
            ]
            .concat(),
            Self::Feed { path, error, types } => [
                b"project root feed refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(types),
            ]
            .concat(),
            Self::Rule(error) => error.to_string().into_bytes(),
            Self::Project(error) => error.text(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn version(raw: &[u8]) -> Result<i64, Error> {
    let number = BigInt::parse_bytes(raw, 10).ok_or_else(|| Error::Version(raw.to_vec()))?;
    if number <= BigInt::from(0) || number.to_string().as_bytes() != raw {
        return Err(Error::Version(raw.to_vec()));
    }
    Natural::new(&number)
        .map(|number| i64::from(number.get()))
        .ok_or_else(|| Error::Version(raw.to_vec()))
}
fn trim(mut raw: &[u8]) -> &[u8] {
    let space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 12);
    while raw.first().is_some_and(|byte| space(*byte)) {
        raw = &raw[1..];
    }
    while raw.last().is_some_and(|byte| space(*byte)) {
        raw = &raw[..raw.len() - 1];
    }
    raw
}
#[derive(Clone, Copy)]
enum Stage {
    Rule,
    Target,
    Sources,
    Roots,
}
pub fn parse(input: &[u8]) -> Result<ProjectFile, Error> {
    let input = lexer::erase_comments(input).map_err(Error::Comment)?;
    let (mut line, mut column) = (1, 1);
    for byte in &input {
        if matches!(*byte, b'\r' | b'\t') {
            return Err(Error::Character(line, column, *byte));
        }
        if *byte == b'\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    let mut lines = input
        .split(|byte| *byte == b'\n')
        .enumerate()
        .map(|(line, value)| (line + 1, trim(value)))
        .filter(|(_, value)| !value.is_empty());
    if !matches!(lines.next(), Some((_, b"folio 1"))) {
        return Err(Error::Header);
    }
    let mut stage = Stage::Rule;
    let mut rule_version = 0;
    let mut target = Target::Octb1;
    let mut sources = Vec::new();
    let mut roots = Vec::new();
    for (line, value) in lines {
        let words = value
            .split(|byte| *byte == b' ')
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>();
        match (stage, words.as_slice()) {
            (Stage::Rule, [b"rule", raw]) => {
                rule_version = version(raw)?;
                stage = Stage::Target;
            }
            (Stage::Target, [b"target", b"octb"]) => {
                target = Target::Octb1;
                stage = Stage::Sources;
            }
            (Stage::Target, [b"target", b"ocps"]) => {
                target = Target::Ocps1;
                stage = Stage::Sources;
            }
            (Stage::Sources, [b"source", path, deps @ ..])
                if project::path_ok(path) && deps.iter().all(|dep| project::path_ok(dep)) =>
            {
                sources.push(Source {
                    path: path.to_vec(),
                    deps: deps.iter().map(|dep| dep.to_vec()).collect(),
                });
            }
            (Stage::Sources | Stage::Roots, [b"root", path, name])
                if !sources.is_empty() && project::path_ok(path) && project::name_ok(name) =>
            {
                roots.push(Root {
                    path: path.to_vec(),
                    name: name.to_vec(),
                    feed_path: None,
                });
                stage = Stage::Roots;
            }
            (Stage::Sources | Stage::Roots, [b"root", path, name, feed])
                if !sources.is_empty()
                    && project::path_ok(path)
                    && project::name_ok(name)
                    && project::path_ok(feed) =>
            {
                roots.push(Root {
                    path: path.to_vec(),
                    name: name.to_vec(),
                    feed_path: Some(feed.to_vec()),
                });
                stage = Stage::Roots;
            }
            _ => return Err(Error::Line(line)),
        }
    }
    match stage {
        Stage::Roots => Ok(ProjectFile {
            version: rule_version,
            target,
            sources,
            roots,
        }),
        Stage::Sources if !sources.is_empty() => Err(Error::Roots(1, 0)),
        _ => Err(Error::Header),
    }
}
fn feed_body(path: &[u8], body: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut parsed = parse::parse(body).map_err(|error| Error::Source(path.to_vec(), error))?;
    let binds = parsed
        .binds()
        .map_err(|error| Error::Binds(path.to_vec(), error))?;
    let mut types = Types::default();
    let specs = feed::specs(&parsed.parsed().ast.syntax, &mut types, &binds).map_err(|error| {
        Error::Feed {
            path: path.to_vec(),
            error,
            types: types.clone(),
        }
    })?;
    let mut values = Values::default();
    let feed = feed::parse(&types, &mut values, &specs, input).map_err(|error| Error::Feed {
        path: path.to_vec(),
        error,
        types,
    })?;
    Ok(feed.encode().to_vec())
}
pub fn make(value: &ProjectFile, bodies: &[Vec<u8>]) -> Result<Image, Error> {
    let feeds = value
        .roots
        .iter()
        .filter(|root| root.feed_path.is_some())
        .count();
    let expected = value.sources.len() + feeds;
    if expected != bodies.len() {
        return Err(Error::Bodies(expected, bodies.len()));
    }
    let rule = Rule::new(value.version, 0.into(), LOCAL).map_err(Error::Rule)?;
    let rules = Schedule::new([rule.clone()]).map_err(Error::Rule)?;
    let (source_bodies, feed_bodies) = bodies.split_at(value.sources.len());
    let sources = value
        .sources
        .iter()
        .zip(source_bodies)
        .map(|(source, body)| project::source(&source.path, body, source.deps.clone()))
        .collect::<Vec<_>>();
    let mut feed_bodies = feed_bodies.iter();
    let mut roots = Vec::new();
    for root in &value.roots {
        let feed = if root.feed_path.is_some() {
            let input = feed_bodies.next().ok_or(Error::Bodies(1, 0))?;
            let source = sources
                .iter()
                .find(|source| source.path() == root.path)
                .ok_or_else(|| Error::Project(project::Error::MissingRoot(root.path.clone())))?;
            feed_body(&root.path, source.body(), input)?
        } else {
            Vec::new()
        };
        roots.push(project::root_feed(&root.path, &root.name, &feed));
    }
    let project =
        project::make(rule.id().clone(), value.target, sources, roots).map_err(Error::Project)?;
    Ok(Image { project, rules })
}
