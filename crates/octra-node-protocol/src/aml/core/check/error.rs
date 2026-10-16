// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_check diagnostics retain bounded byte text and native named-use overrides.
use super::super::text::{self, Text};
use super::{Multiplicity, Natural, RuleError, TypeId, Types};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unknown(Natural),
    Used(Natural),
    Ghost(Natural),
    Shadow(Natural),
    Need(TypeId, TypeId),
    Bad(TypeId),
    ByteIndex(Natural, Natural),
    VecIndex(Natural, Natural),
    SeqSize(Natural, Natural),
    RangeType(TypeId),
    Size,
    Mode(Natural, Multiplicity),
    Split(Vec<Natural>),
    Repeat(Vec<Natural>),
    Erase(Vec<Natural>),
    Unused(Natural),
    Impure(Natural),
    Access(TypeId),
    DropResource(TypeId),
    Depth(usize, usize),
    Nodes(usize, usize),
    Inputs(usize, usize),
}
fn ids_text(ids: &[Natural]) -> Vec<u8> {
    let mut out = Text::default();
    for (index, id) in ids.iter().enumerate() {
        if out.full() {
            break;
        }
        if index > 0 {
            out.add(b",");
        }
        out.add(id.get().to_string().as_bytes());
    }
    out.finish()
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        let raw = match self {
            Self::Unknown(id) => format!("unknown id = {}", id.get()).into_bytes(),
            Self::Used(id) => format!("used id = {}", id.get()).into_bytes(),
            Self::Ghost(id) => format!("ghost id = {}", id.get()).into_bytes(),
            Self::Shadow(id) => format!("shadow id = {}", id.get()).into_bytes(),
            Self::Need(expected, actual) => [
                b"type expected = ".as_slice(),
                &types.text(*expected),
                b" actual = ",
                &types.text(*actual),
            ]
            .concat(),
            Self::Bad(typ) => [b"invalid type = ".as_slice(), &types.text(*typ)].concat(),
            Self::ByteIndex(index, total) => {
                format!("byte index = {} size = {}", index.get(), total.get()).into_bytes()
            }
            Self::VecIndex(index, total) => {
                format!("vec index = {} size = {}", index.get(), total.get()).into_bytes()
            }
            Self::SeqSize(actual, capacity) => format!(
                "sequence size = {} capacity = {}",
                actual.get(),
                capacity.get()
            )
            .into_bytes(),
            Self::RangeType(typ) => {
                [b"range type invalid = ".as_slice(), &types.text(*typ)].concat()
            }
            Self::Size => b"byte size overflow".to_vec(),
            Self::Mode(id, mode) => [
                format!("resource mode id = {} mode = ", id.get()).as_bytes(),
                mode.text(),
            ]
            .concat(),
            Self::Split(ids) => [b"split ids = ".as_slice(), &ids_text(ids)].concat(),
            Self::Repeat(ids) => {
                [b"fold captures linear ids = ".as_slice(), &ids_text(ids)].concat()
            }
            Self::Erase(ids) => [
                b"erased value captures linear ids = ".as_slice(),
                &ids_text(ids),
            ]
            .concat(),
            Self::Unused(id) => format!("unused id = {}", id.get()).into_bytes(),
            Self::Impure(id) => format!("zero binding has effects id = {}", id.get()).into_bytes(),
            Self::Access(typ) => [
                b"data access expected type = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::DropResource(typ) => [
                b"resource component would be dropped type = ".as_slice(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Depth(limit, actual) => {
                format!("term depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Nodes(limit, actual) => {
                format!("term node limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Inputs(limit, actual) => {
                format!("input limit = {limit} actual = {actual}").into_bytes()
            }
        };
        text::clip(&raw)
    }
    pub fn text_named(
        &self,
        types: &Types,
        mut find: impl FnMut(Natural) -> Option<Vec<u8>>,
    ) -> Vec<u8> {
        match self {
            Self::Used(id) => match find(*id) {
                Some(name) => [
                    b"linear value used more than once name = ".as_slice(),
                    &name,
                ]
                .concat(),
                None => self.text(types),
            },
            Self::Unused(id) => match find(*id) {
                Some(name) => [b"linear value is not consumed name = ".as_slice(), &name].concat(),
                None => self.text(types),
            },
            _ => self.text(types),
        }
    }
}
impl RuleError {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Rule(error) => text::clip(error.to_string().as_bytes()),
            Self::Check(error) => error.text(types),
        }
    }
}
