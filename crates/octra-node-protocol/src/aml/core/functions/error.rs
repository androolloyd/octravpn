// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{check, effects_text, lower, Effects, Limit, Name, Types};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Low(lower::Error),
    Check(check::Error),
    Duplicate(Name),
    Function(Name),
    Direct(Name),
    Mode(Name),
    Arity(Name, usize, usize),
    Out(Name),
    Atom(Name),
    Mark(Name, Effects, Effects),
    Limit(Name),
    Over(Name, Limit, Limit),
    Functions(usize, usize),
    Depth(usize, usize),
    Nodes(usize, usize),
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        let named = |prefix: &[u8], name: &Name| [prefix, name.text()].concat();
        match self {
            Self::Low(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Duplicate(name) => named(b"duplicate name = ", name),
            Self::Function(name) => named(b"unknown function = ", name),
            Self::Direct(name) => named(b"function requires explicit use = ", name),
            Self::Mode(name) => named(b"function mode invalid = ", name),
            Self::Arity(name, expected, actual) => [
                b"function arity name = ".as_slice(),
                name.text(),
                format!(" expected = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::Out(name) => named(b"function result type changed = ", name),
            Self::Atom(name) => named(b"function mark atom invalid = ", name),
            Self::Mark(name, expected, actual) => [
                b"function marks exceeded name = ".as_slice(),
                name.text(),
                b" declared = ",
                &effects_text(expected),
                b" actual = ",
                &effects_text(actual),
            ]
            .concat(),
            Self::Limit(name) => named(b"function under invalid = ", name),
            Self::Over(name, expected, actual) => [
                b"function under exceeded name = ".as_slice(),
                name.text(),
                format!(" declared = {expected} actual = {actual}").as_bytes(),
            ]
            .concat(),
            Self::Functions(maximum, actual) => {
                format!("function count max = {maximum} actual = {actual}").into_bytes()
            }
            Self::Depth(maximum, actual) => {
                format!("function depth max = {maximum} actual = {actual}").into_bytes()
            }
            Self::Nodes(maximum, actual) => {
                format!("function nodes max = {maximum} actual = {actual}").into_bytes()
            }
        }
    }
}
