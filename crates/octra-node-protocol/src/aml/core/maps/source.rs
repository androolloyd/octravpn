// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::lexer::{Position, Span};
use super::{bin, natural, tagged, Code, CodeId, Codes, Field, LOCAL, MAX_ROWS};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct SourceMap {
    spans: Arc<[Span]>,
    bits: Arc<[bool]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    Size(usize),
    Point(usize),
    Span(usize),
    Bits,
}
fn point_valid(value: Position) -> bool {
    let maximum = LOCAL.get(Field::Str) as usize;
    value.offset <= maximum
        && value.line > 0
        && value.line <= maximum + 1
        && value.column > 0
        && value.column <= maximum + 1
}
fn span_valid(value: Span) -> bool {
    value.first.offset <= value.last.offset
        && (value.first.line < value.last.line
            || value.first.line == value.last.line && value.first.column <= value.last.column)
}
fn point_code(codes: &mut Codes, value: Position) -> CodeId {
    let off = codes.num(value.offset);
    let line = codes.num(value.line);
    let column = codes.num(value.column);
    let fields = codes.list(&[off, line, column]);
    codes.tag(0, fields)
}
fn span_code(codes: &mut Codes, value: Span) -> CodeId {
    let first = point_code(codes, value.first);
    let last = point_code(codes, value.last);
    let fields = codes.list(&[first, last]);
    codes.tag(1, fields)
}
// Native construction uses source-string bounds, while decoding applies the
// smaller C_nat.make bound to every coordinate. Do not merge these two gates.
fn point_get(codes: &Codes, id: CodeId) -> Option<Position> {
    let fields = codes.list_get(tagged(codes, id, 0)?)?;
    let [offset, line, column] = fields.as_slice() else {
        return None;
    };
    Some(Position {
        offset: natural(codes, *offset)?.get() as usize,
        line: natural(codes, *line)?.get() as usize,
        column: natural(codes, *column)?.get() as usize,
    })
}
fn span_get(codes: &Codes, id: CodeId) -> Option<Span> {
    let fields = codes.list_get(tagged(codes, id, 1)?)?;
    let [first, last] = fields.as_slice() else {
        return None;
    };
    Some(Span {
        first: point_get(codes, *first)?,
        last: point_get(codes, *last)?,
    })
}
impl SourceMap {
    pub fn make(spans: &[Span]) -> Result<Self, Error> {
        if spans.is_empty() {
            return Err(Error::Empty);
        }
        if spans.len() > MAX_ROWS {
            return Err(Error::Size(spans.len()));
        }
        for (index, span) in spans.iter().enumerate() {
            if !point_valid(span.first) || !point_valid(span.last) {
                return Err(Error::Point(index));
            }
            if !span_valid(*span) {
                return Err(Error::Span(index));
            }
        }
        let mut codes = Codes::default();
        let rows = spans
            .iter()
            .map(|span| span_code(&mut codes, *span))
            .collect::<Vec<_>>();
        let body = codes.list(&rows);
        let root = codes.tag(2, body);
        let bits = bin::encode(&codes, root).ok_or(Error::Bits)?;
        Ok(Self {
            spans: spans.into(),
            bits: bits.into(),
        })
    }
    pub fn decode(bits: &[bool]) -> Option<Self> {
        let decoded = bin::decode(bits)?;
        let mut body = tagged(&decoded.codes, decoded.root, 2)?;
        let mut spans = vec![];
        loop {
            match decoded.codes.get(body) {
                Code::Nil => break,
                Code::Cons(first, rest) if spans.len() < MAX_ROWS => {
                    spans.push(span_get(&decoded.codes, *first)?);
                    body = *rest;
                }
                _ => return None,
            }
        }
        let map = Self::make(&spans).ok()?;
        (map.encode() == bits).then_some(map)
    }
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }
    pub fn encode(&self) -> &[bool] {
        &self.bits
    }
    pub fn equal(&self, right: &Self) -> bool {
        self.bits == right.bits
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("source map is empty"),
            Self::Size(size) => write!(f, "source map size = {size} maximum = {MAX_ROWS}"),
            Self::Point(at) => write!(f, "source map point is invalid index = {at}"),
            Self::Span(at) => write!(f, "source map span is invalid index = {at}"),
            Self::Bits => f.write_str("source map bit image exceeds the local limit"),
        }
    }
}
impl std::error::Error for Error {}
