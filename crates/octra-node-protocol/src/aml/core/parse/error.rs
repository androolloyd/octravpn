// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_parse diagnostics preserve byte names and the original token range.
use super::super::{lexer, text};
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Index,
    Declaration,
    Function,
    Instance,
    Polymorphic,
    Data,
    Record,
    Quantifier,
    Weave,
    Braid,
    Loom,
    Orbit,
    Wake,
    Rift,
    Fhe,
    Hfhe,
    Hpar,
    Permission,
    Lower,
    Check,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    Unavailable(Vec<u8>),
    Lex(lexer::Error),
    Held(lexer::Hold),
    Need(Vec<lexer::Form>, lexer::Form),
    Name(Vec<u8>),
    SizeName(Vec<u8>),
    SizeDuplicate(Vec<u8>),
    Word(Vec<u8>, Vec<u8>),
    VeilDuplicate(Vec<u8>),
    DataName(Vec<u8>),
    DataDuplicate(Vec<u8>),
    ShapeName(Vec<u8>),
    ShapeDuplicate(Vec<u8>),
    Tag(BigInt),
    TagDuplicate(BigInt),
    MarkNatural(BigInt),
    MarkDuplicate(Vec<u8>),
    UnderNatural(BigInt),
    Empty,
    Private,
    Depth(usize, usize),
    Nodes(usize, usize),
    Semantic(Stage, Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub cause: Cause,
    pub span: lexer::Span,
}
impl Error {
    pub fn is_operational(&self) -> bool {
        matches!(self.cause, Cause::Unavailable(_))
    }
    pub fn text(&self) -> Vec<u8> {
        if let Cause::Unavailable(reason) = &self.cause {
            return reason.clone();
        }
        if let Cause::Lex(error) = &self.cause {
            return error.text();
        }
        let named = |prefix: &[u8], name: &[u8]| [prefix, name].concat();
        let detail = match &self.cause {
            Cause::Unavailable(reason) => reason.clone(),
            Cause::Lex(_) => Vec::new(),
            Cause::Held(value) => named(b"source form held by profile = ", value.text()),
            Cause::Need(expected, actual) => {
                let mut value = b"expected = ".to_vec();
                for (at, form) in expected.iter().enumerate() {
                    if at > 0 {
                        value.extend_from_slice(b" or ");
                    }
                    value.extend_from_slice(form.text());
                }
                value.extend_from_slice(b" actual = ");
                value.extend_from_slice(actual.text());
                value
            }
            Cause::Name(name) => named(b"invalid name = ", name),
            Cause::SizeName(name) => named(b"invalid size name = ", name),
            Cause::SizeDuplicate(name) => named(b"duplicate size name = ", name),
            Cause::Word(expected, actual) => [
                b"expected word = ",
                expected.as_slice(),
                b" actual = ",
                actual,
            ]
            .concat(),
            Cause::VeilDuplicate(name) => named(b"duplicate veil = ", name),
            Cause::DataName(name) => named(b"unknown data type = ", name),
            Cause::DataDuplicate(name) => named(b"duplicate data type = ", name),
            Cause::ShapeName(name) => named(b"unknown shape type = ", name),
            Cause::ShapeDuplicate(name) => named(b"duplicate shape type = ", name),
            Cause::Tag(value) => format!(
                "type tag outside {}-bit range = {value}",
                super::super::rule::LOCAL.get(super::super::rule::Field::Tag)
            )
            .into_bytes(),
            Cause::TagDuplicate(value) => format!("duplicate type tag = {value}").into_bytes(),
            Cause::MarkNatural(value) => {
                format!("function mark outside profile = {value}").into_bytes()
            }
            Cause::MarkDuplicate(value) => named(b"duplicate function mark = ", value),
            Cause::UnderNatural(value) => {
                format!("function under outside profile = {value}").into_bytes()
            }
            Cause::Empty => b"program body is empty".to_vec(),
            Cause::Private => b"private name space exhausted".to_vec(),
            Cause::Depth(limit, actual) => {
                format!("syntax depth limit = {limit} actual = {actual}").into_bytes()
            }
            Cause::Nodes(limit, actual) => {
                format!("syntax nodes limit = {limit} actual = {actual}").into_bytes()
            }
            Cause::Semantic(_, detail) => detail.clone(),
        };
        text::clip(
            &[
                format!(
                    "line = {} col = {} ",
                    self.span.first.line, self.span.first.column
                )
                .as_bytes(),
                &detail,
            ]
            .concat(),
        )
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
