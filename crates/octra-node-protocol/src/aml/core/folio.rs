// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_folio project images retain exact OCTB, source seals and source/live maps.
//! Structural decoding is distinct from source recompilation in `verify`.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    bin::Bits,
    eval::Values,
    feed::{self, Feed},
    lexer::Span,
    maps::{LiveMap, Slot, SourceMap},
    octb,
    project::{Project, Root, Source, Target},
    project_image,
    rule::{self, Field, Rule, Schedule, LOCAL},
    seal,
    types::Types,
};
use num_bigint::BigInt;
use std::sync::Arc;
mod wire;
pub use wire::{decode, encode, file, of_file};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    path: Vec<u8>,
    name: Vec<u8>,
    octb: Vec<u8>,
    seal: Bits,
    map: Bits,
    live: Bits,
}
impl Part {
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    pub fn octb(&self) -> &[u8] {
        &self.octb
    }
    pub fn seal(&self) -> &[bool] {
        &self.seal
    }
    pub fn map(&self) -> &[bool] {
        &self.map
    }
    pub fn live(&self) -> &[bool] {
        &self.live
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folio {
    project: Project,
    epoch: BigInt,
    parts: Vec<Part>,
}
impl Folio {
    pub fn project(&self) -> &Project {
        &self.project
    }
    pub fn epoch(&self) -> &BigInt {
        &self.epoch
    }
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }
}
#[derive(Clone, Debug)]
pub struct Origin {
    src: Source,
    root: Root,
    part: Part,
    input: Option<Feed>,
    values: Values,
    spans: Vec<Span>,
    rows: Vec<Arc<[Slot]>>,
}
impl Origin {
    pub fn source(&self) -> &Source {
        &self.src
    }
    pub fn root(&self) -> &Root {
        &self.root
    }
    pub fn part(&self) -> &Part {
        &self.part
    }
    pub fn input(&self) -> Option<&Feed> {
        self.input.as_ref()
    }
    /// An origin feed's ValueIds are owned by this retained arena.
    pub fn values(&self) -> &Values {
        &self.values
    }
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }
    pub fn rows(&self) -> &[Arc<[Slot]>] {
        &self.rows
    }
}
#[derive(Clone, Debug)]
pub enum Error {
    Target,
    Rule(rule::Error),
    RuleId,
    Root(Vec<u8>),
    Feed(Vec<u8>, feed::Error),
    Octb(Vec<u8>, octb::SourceFailure),
    Seal(Vec<u8>, seal::SourceFailure),
    Image,
    Header,
    Size(usize, usize),
    Epoch(BigInt),
    Form,
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Target => b"project target is not OCTB".to_vec(),
            Self::Rule(error) => error.to_string().into_bytes(),
            Self::RuleId => b"project rule differs from selected rule".to_vec(),
            Self::Root(path) => {
                [b"project root source is absent path = ".as_slice(), path].concat()
            }
            Self::Feed(path, error) => [
                b"project root feed refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(&Types::default()),
            ]
            .concat(),
            Self::Octb(path, error) => [
                b"project root OCTB refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(),
            ]
            .concat(),
            Self::Seal(path, error) => [
                b"project root seal refusal path = ".as_slice(),
                path,
                b" reason = ",
                &error.text(),
            ]
            .concat(),
            Self::Image => b"project folio encoding failed".to_vec(),
            Self::Header => b"project folio header is invalid".to_vec(),
            Self::Size(expected, actual) => {
                format!("project folio size expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Epoch(value) => format!(
                "project folio epoch is invalid value = {value} maximum = {}",
                epoch_max()
            )
            .into_bytes(),
            Self::Form => b"project folio form is invalid".to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}

pub fn epoch_max() -> BigInt {
    BigInt::from(i64::MAX)
}
pub fn epoch_valid(value: &BigInt) -> bool {
    value >= &BigInt::from(0) && value <= &epoch_max()
}
pub fn part(path: &[u8], name: &[u8], octb: &[u8], seal: Bits, map: Bits, live: Bits) -> Part {
    Part {
        path: path.to_vec(),
        name: name.to_vec(),
        octb: octb.to_vec(),
        seal,
        map,
        live,
    }
}
fn valid_part(value: &Part) -> bool {
    !value.octb.is_empty()
        && value.octb.len() <= LOCAL.get(Field::Str) as usize
        && seal::decode(&value.seal).is_some()
        && SourceMap::decode(&value.map).is_some()
        && LiveMap::decode(&value.live).is_some()
}
fn valid(value: &Folio) -> bool {
    epoch_valid(&value.epoch)
        && project_image::valid(&value.project)
        && value.project.target() == Target::Octb1
        && value.project.roots().len() == value.parts.len()
        && value
            .project
            .roots()
            .iter()
            .zip(&value.parts)
            .all(|(root, part)| {
                root.path() == part.path && root.name() == part.name && valid_part(part)
            })
}
pub fn form(project: Project, epoch: BigInt, parts: Vec<Part>) -> Option<Folio> {
    let value = Folio {
        project,
        epoch,
        parts,
    };
    valid(&value).then_some(value)
}
pub fn origins(value: &Folio) -> Option<Vec<Origin>> {
    if value.project.roots().len() != value.parts.len() {
        return None;
    }
    value
        .project
        .roots()
        .iter()
        .zip(&value.parts)
        .map(|(root, part)| {
            if root.path() != part.path || root.name() != part.name {
                return None;
            }
            let src = value
                .project
                .sources()
                .iter()
                .find(|src| src.path() == root.path())?;
            let mut values = Values::default();
            let input = if root.feed().is_empty() {
                None
            } else {
                Some(Feed::decode(&mut values, root.feed()).ok()?)
            };
            let map = SourceMap::decode(&part.map)?;
            let live = LiveMap::decode(&part.live)?;
            Some(Origin {
                src: src.clone(),
                root: root.clone(),
                part: part.clone(),
                input,
                values,
                spans: map.spans().to_vec(),
                rows: live.rows().to_vec(),
            })
        })
        .collect()
}
fn one(schedule: &Schedule, epoch: &BigInt, project: &Project, root: &Root) -> Result<Part, Error> {
    let source = project
        .sources()
        .iter()
        .find(|source| source.path() == root.path())
        .ok_or_else(|| Error::Root(root.path().to_vec()))?;
    let image = if root.feed().is_empty() {
        octb::compile(source.body())
    } else {
        let mut values = Values::default();
        let feed = Feed::decode(&mut values, root.feed())
            .map_err(|error| Error::Feed(root.path().to_vec(), error))?;
        octb::compile_feed(source.body(), &feed)
    }
    .map_err(|error| Error::Octb(root.path().to_vec(), error))?;
    let seal = seal::make(schedule, epoch, source.body())
        .map_err(|error| Error::Seal(root.path().to_vec(), error))?;
    Ok(part(
        root.path(),
        root.name(),
        image.image.octb(),
        seal,
        image.image.source_map().encode().to_vec(),
        image.image.live_map().encode().to_vec(),
    ))
}
pub fn make(schedule: &Schedule, epoch: &BigInt, project: &Project) -> Result<Folio, Error> {
    if !epoch_valid(epoch) {
        return Err(Error::Epoch(epoch.clone()));
    }
    if project.target() != Target::Octb1 {
        return Err(Error::Target);
    }
    let selected = schedule.select(epoch).map_err(Error::Rule)?;
    if selected.id() != project.rule() {
        return Err(Error::RuleId);
    }
    let parts = project
        .roots()
        .iter()
        .map(|root| one(schedule, epoch, project, root))
        .collect::<Result<Vec<_>, _>>()?;
    let value = Folio {
        project: project.clone(),
        epoch: epoch.clone(),
        parts,
    };
    if encode(&value).is_some() {
        Ok(value)
    } else {
        Err(Error::Image)
    }
}
pub fn verify(input: &[u8]) -> Result<Folio, Error> {
    let value = of_file(input)?;
    let id = value.project.rule();
    let rule = Rule::new(id.version(), 0.into(), id.limits()).map_err(Error::Rule)?;
    let schedule = Schedule::new([rule]).map_err(Error::Rule)?;
    let rebuilt = make(&schedule, &value.epoch, &value.project)?;
    if file(&rebuilt).is_some_and(|exact| exact == input) {
        Ok(rebuilt)
    } else {
        Err(Error::Form)
    }
}
