// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_lex byte tokens and comment masking for the core language and typed feeds.
use super::{
    rule::{Field, LOCAL},
    text,
};
use num_bigint::BigInt;
macro_rules! words {
    ($($variant:ident => $text:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Word { $($variant),* }
        impl Word {
            pub fn parse(value: &[u8]) -> Option<Self> { Some(match value { $($text => Self::$variant,)* _ => return None }) }
            pub fn text(self) -> &'static [u8] { match self { $(Self::$variant => $text),* } }
        }
    };
}
words! {
    Program => b"program", Size => b"size", Measure => b"measure", Law => b"law", Input => b"input", Term => b"term",
    Form => b"form", Kind => b"kind", Marks => b"marks", Under => b"under", Steps => b"steps", Depth => b"depth", Work => b"work",
    Use => b"use", Data => b"data", Shape => b"shape", Permit => b"permit", Tag => b"tag", Make => b"make", Erase => b"erase",
    Once => b"once", Many => b"many", Unit => b"unit", Bool => b"bool", Int => b"int", Sint => b"sint", Uint => b"uint",
    Bytes => b"bytes", Vec => b"vec", Seq => b"seq", Cap => b"cap", Result => b"result", Res => b"res", Let => b"let", In => b"in",
    Split => b"split", As => b"as", If => b"if", Then => b"then", Else => b"else", True => b"true", False => b"false",
    Good => b"ok", Bad => b"err", Case => b"case", Of => b"of", Fst => b"fst", Snd => b"snd", Equal => b"equal",
    Fit => b"fit", Wide => b"wide", Length => b"length", Read => b"read", Write => b"write", Emit => b"emit", Fail => b"fail",
    Cat => b"cat", Take => b"take", Drop => b"drop", Vcat => b"vcat", At => b"at", Uncons => b"uncons", Fold => b"fold",
    Every => b"every", Any => b"some", Count => b"count", Total => b"total", Weave => b"weave", Braid => b"braid", Loom => b"loom",
    Orbit => b"orbit", Wake => b"wake", Rift => b"rift", From => b"from", With => b"with", Step => b"step", Close => b"close", Max => b"max", Abs => b"abs",
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    Recur,
    Store,
    Closure,
    Raise,
    Depend,
    Polymark,
}
impl Hold {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Recur => b"recur",
            Self::Store => b"store",
            Self::Closure => b"closure",
            Self::Raise => b"raise",
            Self::Depend => b"dependent",
            Self::Polymark => b"polymark",
        }
    }
    fn parse(value: &[u8]) -> Option<Self> {
        Some(match value {
            b"recur" => Self::Recur,
            b"store" => Self::Store,
            b"closure" => Self::Closure,
            b"raise" => Self::Raise,
            b"dependent" => Self::Depend,
            b"polymark" => Self::Polymark,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symbol {
    Lbrace,
    Rbrace,
    Lparen,
    Rparen,
    Lbrack,
    Rbrack,
    Colon,
    Comma,
    Eq,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Arrow,
    Thin,
    Bar,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
}
impl Symbol {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Lbrace => b"{",
            Self::Rbrace => b"}",
            Self::Lparen => b"(",
            Self::Rparen => b")",
            Self::Lbrack => b"[",
            Self::Rbrack => b"]",
            Self::Colon => b":",
            Self::Comma => b",",
            Self::Eq => b"=",
            Self::EqEq => b"==",
            Self::Ne => b"!=",
            Self::Lt => b"<",
            Self::Le => b"<=",
            Self::Gt => b">",
            Self::Ge => b">=",
            Self::Arrow => b"=>",
            Self::Thin => b"->",
            Self::Bar => b"|",
            Self::Plus => b"+",
            Self::Minus => b"-",
            Self::Star => b"*",
            Self::Slash => b"/",
            Self::Percent => b"%",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Word(Word),
    Symbol(Symbol),
    Ident(Vec<u8>),
    Natural(BigInt),
    Hex(Vec<u8>),
    Hold(Hold),
    Eof,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    Word(Word),
    Symbol(Symbol),
    Ident,
    Natural,
    Hex,
    Hold(Hold),
    Eof,
}
impl Form {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Word(word) => word.text(),
            Self::Symbol(symbol) => symbol.text(),
            Self::Ident => b"name",
            Self::Natural => b"number",
            Self::Hex => b"hex",
            Self::Hold(hold) => hold.text(),
            Self::Eof => b"end",
        }
    }
}
impl Token {
    pub fn form(&self) -> Form {
        match self {
            Self::Word(word) => Form::Word(*word),
            Self::Symbol(symbol) => Form::Symbol(*symbol),
            Self::Ident(_) => Form::Ident,
            Self::Natural(_) => Form::Natural,
            Self::Hex(_) => Form::Hex,
            Self::Hold(hold) => Form::Hold(*hold),
            Self::Eof => Form::Eof,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}
const ZERO: Position = Position {
    offset: 0,
    line: 1,
    column: 1,
};
impl Position {
    fn advance(&mut self, byte: u8) {
        self.offset += 1;
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub first: Position,
    pub last: Position,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub token: Token,
    pub span: Span,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    Source(usize, usize),
    Tokens(usize, usize),
    Name(usize, usize),
    Number,
    Hex,
    Comment,
    Nest(usize, usize),
    Byte(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub cause: Cause,
    pub span: Span,
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        let detail = match self.cause {
            Cause::Source(limit, actual) => {
                format!("source size limit = {limit} actual = {actual}")
            }
            Cause::Tokens(limit, actual) => {
                format!("token count limit = {limit} actual = {actual}")
            }
            Cause::Name(limit, actual) => format!("name size limit = {limit} actual = {actual}"),
            Cause::Number => "invalid number".to_owned(),
            Cause::Hex => "invalid hex".to_owned(),
            Cause::Comment => "comment is not closed".to_owned(),
            Cause::Nest(limit, actual) => format!("syntax depth limit = {limit} actual = {actual}"),
            Cause::Byte(byte) => format!("invalid source byte = {byte}"),
        };
        text::clip(
            format!(
                "line = {} col = {} {detail}",
                self.span.first.line, self.span.first.column
            )
            .as_bytes(),
        )
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
/// C_comments.erase runs over the whole source before tokenization, preserving
/// every byte position and newline while masking nested comments with spaces.
pub fn erase_comments(source: &[u8]) -> Result<Vec<u8>, Span> {
    let mut out = source.to_vec();
    let mut pos = ZERO;
    while pos.offset < source.len() {
        let pair = source.get(pos.offset..pos.offset + 2);
        if matches!(pair, Some(b"//")) {
            while pos.offset < source.len() && source[pos.offset] != b'\n' {
                out[pos.offset] = b' ';
                pos.advance(source[pos.offset]);
            }
        } else if matches!(pair, Some(b"/*")) {
            let first = pos;
            let mut depth = 1;
            out[pos.offset..pos.offset + 2].fill(b' ');
            pos.advance(b'/');
            pos.advance(b'*');
            while depth > 0 {
                if pos.offset == source.len() {
                    return Err(Span { first, last: pos });
                }
                let pair = source.get(pos.offset..pos.offset + 2);
                if matches!(pair, Some(b"/*" | b"*/")) {
                    let close = pair == Some(b"*/".as_slice());
                    depth = if close { depth - 1 } else { depth + 1 };
                    let first = source[pos.offset];
                    let second = source[pos.offset + 1];
                    out[pos.offset..pos.offset + 2].fill(b' ');
                    pos.advance(first);
                    pos.advance(second);
                } else {
                    let byte = source[pos.offset];
                    out[pos.offset] = if byte == b'\n' { b'\n' } else { b' ' };
                    pos.advance(byte);
                }
            }
        } else {
            pos.advance(source[pos.offset]);
        }
    }
    Ok(out)
}
fn alpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}
fn error(cause: Cause, first: Position, last: Position) -> Error {
    Error {
        cause,
        span: Span { first, last },
    }
}
pub fn scan(source: &[u8]) -> Result<Vec<Item>, Error> {
    let maximum = LOCAL.get(Field::Str) as usize;
    if source.len() > maximum {
        return Err(error(Cause::Source(maximum, source.len()), ZERO, ZERO));
    }
    let source = erase_comments(source).map_err(|span| Error {
        cause: Cause::Comment,
        span,
    })?;
    let mut pos = ZERO;
    let mut depth = 0usize;
    let mut out = vec![];
    loop {
        while source
            .get(pos.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            pos.advance(source[pos.offset]);
        }
        let first = pos;
        let (token, delta) = match source.get(pos.offset).copied() {
            None => (Token::Eof, 0),
            Some(b'0') if source.get(pos.offset + 1) == Some(&b'x') => {
                pos.advance(b'0');
                pos.advance(b'x');
                let body = pos.offset;
                while source.get(pos.offset).is_some_and(u8::is_ascii_hexdigit) {
                    pos.advance(source[pos.offset]);
                }
                let raw = &source[body..pos.offset];
                if raw.len() % 2 != 0 {
                    return Err(error(Cause::Hex, first, pos));
                }
                (
                    Token::Hex(hex::decode(raw).expect("even hexadecimal digits")),
                    0,
                )
            }
            Some(byte) if byte.is_ascii_digit() => {
                let mut digits = 0;
                let mut under = false;
                while let Some(byte) = source.get(pos.offset).copied() {
                    if byte.is_ascii_digit() {
                        digits += 1;
                        under = false;
                        pos.advance(byte);
                    } else if byte == b'_' && digits > 0 && !under {
                        under = true;
                        pos.advance(byte);
                    } else {
                        break;
                    }
                }
                if under || digits == 0 || digits > LOCAL.get(Field::Text) as usize {
                    return Err(error(Cause::Number, first, pos));
                }
                let raw: Vec<_> = source[first.offset..pos.offset]
                    .iter()
                    .copied()
                    .filter(|byte| *byte != b'_')
                    .collect();
                let value = BigInt::parse_bytes(&raw, 10)
                    .ok_or_else(|| error(Cause::Number, first, pos))?;
                (Token::Natural(value), 0)
            }
            Some(byte) if alpha(byte) => {
                while source
                    .get(pos.offset)
                    .is_some_and(|byte| alpha(*byte) || byte.is_ascii_digit())
                {
                    pos.advance(source[pos.offset]);
                }
                let name = &source[first.offset..pos.offset];
                let maximum = LOCAL.get(Field::Name) as usize;
                if name.len() > maximum {
                    return Err(error(Cause::Name(maximum, name.len()), first, pos));
                }
                let token = if let Some(word) = Word::parse(name) {
                    Token::Word(word)
                } else if let Some(hold) = Hold::parse(name) {
                    Token::Hold(hold)
                } else {
                    Token::Ident(name.to_vec())
                };
                (token, 0)
            }
            Some(byte) => {
                let next = source.get(pos.offset + 1).copied();
                let (symbol, count, delta) = match (byte, next) {
                    (b'{', _) => (Symbol::Lbrace, 1, 1),
                    (b'}', _) => (Symbol::Rbrace, 1, -1),
                    (b'(', _) => (Symbol::Lparen, 1, 1),
                    (b')', _) => (Symbol::Rparen, 1, -1),
                    (b'[', _) => (Symbol::Lbrack, 1, 1),
                    (b']', _) => (Symbol::Rbrack, 1, -1),
                    (b':', _) => (Symbol::Colon, 1, 0),
                    (b',', _) => (Symbol::Comma, 1, 0),
                    (b'|', _) => (Symbol::Bar, 1, 0),
                    (b'+', _) => (Symbol::Plus, 1, 0),
                    (b'-', Some(b'>')) => (Symbol::Thin, 2, 0),
                    (b'-', _) => (Symbol::Minus, 1, 0),
                    (b'*', _) => (Symbol::Star, 1, 0),
                    (b'/', _) => (Symbol::Slash, 1, 0),
                    (b'%', _) => (Symbol::Percent, 1, 0),
                    (b'!', Some(b'=')) => (Symbol::Ne, 2, 0),
                    (b'<', Some(b'=')) => (Symbol::Le, 2, 0),
                    (b'<', _) => (Symbol::Lt, 1, 0),
                    (b'>', Some(b'=')) => (Symbol::Ge, 2, 0),
                    (b'>', _) => (Symbol::Gt, 1, 0),
                    (b'=', Some(b'>')) => (Symbol::Arrow, 2, 0),
                    (b'=', Some(b'=')) => (Symbol::EqEq, 2, 0),
                    (b'=', _) => (Symbol::Eq, 1, 0),
                    _ => {
                        pos.advance(byte);
                        return Err(error(Cause::Byte(byte), first, pos));
                    }
                };
                for _ in 0..count {
                    pos.advance(source[pos.offset]);
                }
                (Token::Symbol(symbol), delta)
            }
        };
        depth = if delta < 0 {
            depth.saturating_sub(1)
        } else {
            depth + delta as usize
        };
        let maximum_depth = LOCAL.get(Field::TermDepth) as usize;
        if depth > maximum_depth {
            return Err(error(Cause::Nest(maximum_depth, depth), first, pos));
        }
        let maximum_tokens = LOCAL.get(Field::TermNodes) as usize;
        if out.len() == maximum_tokens {
            return Err(error(
                Cause::Tokens(maximum_tokens, maximum_tokens + 1),
                first,
                pos,
            ));
        }
        let end = token == Token::Eof;
        out.push(Item {
            token,
            span: Span { first, last: pos },
        });
        if end {
            return Ok(out);
        }
    }
}
