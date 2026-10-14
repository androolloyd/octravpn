// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Byte-preserving Yojson input semantics. The flat arena keeps parsing and drop
//! iterative even for deeply nested untrusted values. Duplicate object keys stay
//! ordered because native transaction decoding selects the first occurrence.
use crate::transaction::Nonce;
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(Nonce),
    IntLiteral(Vec<u8>),
    Float(f64),
    String(Vec<u8>),
    List(Vec<usize>),
    Object(Vec<(Vec<u8>, usize)>),
}
#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    nodes: Vec<Value>,
    root: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid native JSON at byte {0}")]
    Syntax(usize),
    #[error("native JSON allocation unavailable")]
    Allocation,
}
fn push<T>(items: &mut Vec<T>, item: T) -> Result<(), Error> {
    items.try_reserve(1).map_err(|_| Error::Allocation)?;
    items.push(item);
    Ok(())
}
fn extend(items: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    items
        .try_reserve(bytes.len())
        .map_err(|_| Error::Allocation)?;
    items.extend_from_slice(bytes);
    Ok(())
}
#[derive(Clone, Copy)]
enum State {
    FirstList,
    ListValue,
    ListSeparator,
    FirstObject,
    ObjectKey,
    ObjectSeparator,
}
struct Parser<'a> {
    raw: &'a [u8],
    at: usize,
    nodes: Vec<Value>,
    frames: Vec<(usize, State)>,
}
impl Document {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let mut parser = Parser {
            raw,
            at: 0,
            nodes: Vec::new(),
            frames: Vec::new(),
        };
        let root = parser.value()?;
        while let Some(&(id, state)) = parser.frames.last() {
            parser.space()?;
            match state {
                State::FirstList | State::ListValue => {
                    if matches!(state, State::FirstList) && parser.consume(b']') {
                        parser.frames.pop();
                        continue;
                    }
                    parser.frames.last_mut().expect("frame").1 = State::ListSeparator;
                    let child = parser.value()?;
                    let Value::List(items) = &mut parser.nodes[id] else {
                        unreachable!()
                    };
                    push(items, child)?;
                }
                State::FirstObject | State::ObjectKey => {
                    if matches!(state, State::FirstObject) && parser.consume(b'}') {
                        parser.frames.pop();
                        continue;
                    }
                    let key = parser.key()?;
                    parser.space()?;
                    parser.require(b':')?;
                    parser.frames.last_mut().expect("frame").1 = State::ObjectSeparator;
                    let child = parser.value()?;
                    let Value::Object(fields) = &mut parser.nodes[id] else {
                        unreachable!()
                    };
                    push(fields, (key, child))?;
                }
                State::ListSeparator => {
                    if parser.consume(b']') {
                        parser.frames.pop();
                    } else {
                        parser.require(b',')?;
                        parser.frames.last_mut().expect("frame").1 = State::ListValue;
                    }
                }
                State::ObjectSeparator => {
                    if parser.consume(b'}') {
                        parser.frames.pop();
                    } else {
                        parser.require(b',')?;
                        parser.frames.last_mut().expect("frame").1 = State::ObjectKey;
                    }
                }
            }
        }
        parser.space()?;
        if parser.at != raw.len() {
            return Err(Error::Syntax(parser.at));
        }
        Ok(Self {
            nodes: parser.nodes,
            root,
        })
    }
    pub fn root(&self) -> &Value {
        &self.nodes[self.root]
    }
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.nodes.get(index)
    }
    pub fn field(&self, object: &Value, name: &[u8]) -> Option<&Value> {
        let Value::Object(fields) = object else {
            return None;
        };
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, index)| &self.nodes[*index])
    }
}
impl Parser<'_> {
    fn consume(&mut self, byte: u8) -> bool {
        if self.raw.get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn require(&mut self, byte: u8) -> Result<(), Error> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(Error::Syntax(self.at))
        }
    }
    fn space(&mut self) -> Result<(), Error> {
        loop {
            while self
                .raw
                .get(self.at)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                self.at += 1;
            }
            if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"//") {
                self.at += 2;
                while self.raw.get(self.at).is_some_and(|b| *b != b'\n') {
                    self.at += 1;
                }
            } else if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"/*") {
                self.at += 2;
                loop {
                    if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"*/") {
                        self.at += 2;
                        break;
                    }
                    if self.at >= self.raw.len() {
                        return Err(Error::Syntax(self.at));
                    }
                    self.at += 1;
                }
            } else {
                return Ok(());
            }
        }
    }
    fn key(&mut self) -> Result<Vec<u8>, Error> {
        if self.raw.get(self.at) == Some(&b'"') {
            return self.string();
        }
        let start = self.at;
        if !self
            .raw
            .get(self.at)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            return Err(Error::Syntax(self.at));
        }
        self.at += 1;
        while self
            .raw
            .get(self.at)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            self.at += 1;
        }
        let mut key = Vec::new();
        extend(&mut key, &self.raw[start..self.at])?;
        Ok(key)
    }
    fn value(&mut self) -> Result<usize, Error> {
        self.space()?;
        let mut frame = None;
        let value = match self.raw.get(self.at).copied() {
            Some(b'[') => {
                self.at += 1;
                frame = Some(State::FirstList);
                Value::List(Vec::new())
            }
            Some(b'{') => {
                self.at += 1;
                frame = Some(State::FirstObject);
                Value::Object(Vec::new())
            }
            Some(b'"') => Value::String(self.string()?),
            Some(b'n') => {
                self.literal(b"null")?;
                Value::Null
            }
            Some(b't') => {
                self.literal(b"true")?;
                Value::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Value::Bool(false)
            }
            Some(b'N') => {
                self.literal(b"NaN")?;
                Value::Float(f64::NAN)
            }
            Some(b'I') => {
                self.literal(b"Infinity")?;
                Value::Float(f64::INFINITY)
            }
            Some(b'-') if self.raw[self.at..].starts_with(b"-Infinity") => {
                self.at += 9;
                Value::Float(f64::NEG_INFINITY)
            }
            Some(b'-' | b'0'..=b'9') => self.number()?,
            _ => return Err(Error::Syntax(self.at)),
        };
        let id = self.nodes.len();
        push(&mut self.nodes, value)?;
        if let Some(state) = frame {
            push(&mut self.frames, (id, state))?;
        }
        Ok(id)
    }
    fn literal(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.raw[self.at..].starts_with(bytes) {
            self.at += bytes.len();
            Ok(())
        } else {
            Err(Error::Syntax(self.at))
        }
    }
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.at;
        self.consume(b'-');
        match self.raw.get(self.at) {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.at += 1;
                while self.raw.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
            }
            _ => return Err(Error::Syntax(self.at)),
        }
        let mut float = false;
        if self.raw.get(self.at) == Some(&b'.')
            && self.raw.get(self.at + 1).is_some_and(u8::is_ascii_digit)
        {
            float = true;
            self.at += 2;
            while self.raw.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
        }
        if self
            .raw
            .get(self.at)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            float = true;
            self.at += 1;
            if self
                .raw
                .get(self.at)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                self.at += 1;
            }
            if !self.raw.get(self.at).is_some_and(u8::is_ascii_digit) {
                return Err(Error::Syntax(self.at));
            }
            while self.raw.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
        }
        let bytes = &self.raw[start..self.at];
        let text = std::str::from_utf8(bytes).expect("numeric ASCII");
        if float {
            return text
                .parse()
                .map(Value::Float)
                .map_err(|_| Error::Syntax(start));
        }
        if let Ok(value) = text.parse::<i64>() {
            if let Ok(value) = Nonce::new(value) {
                return Ok(Value::Int(value));
            }
        }
        let mut raw = Vec::new();
        extend(&mut raw, bytes)?;
        Ok(Value::IntLiteral(raw))
    }
    fn hex4(&mut self) -> Result<u32, Error> {
        let mut value = 0;
        for _ in 0..4 {
            let Some(byte) = self.raw.get(self.at).copied() else {
                return Err(Error::Syntax(self.at));
            };
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(Error::Syntax(self.at)),
            };
            value = value * 16 + u32::from(digit);
            self.at += 1;
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<Vec<u8>, Error> {
        self.require(b'"')?;
        let mut bytes = Vec::new();
        loop {
            let Some(byte) = self.raw.get(self.at).copied() else {
                return Err(Error::Syntax(self.at));
            };
            self.at += 1;
            match byte {
                b'"' => return Ok(bytes),
                b'\\' => {
                    let Some(escaped) = self.raw.get(self.at).copied() else {
                        return Err(Error::Syntax(self.at));
                    };
                    self.at += 1;
                    let single = match escaped {
                        b'"' | b'\\' | b'/' => Some(escaped),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => return Err(Error::Syntax(self.at - 1)),
                    };
                    if let Some(byte) = single {
                        push(&mut bytes, byte)?;
                    } else {
                        let mut code = self.hex4()?;
                        if (0xd800..=0xdbff).contains(&code) {
                            self.require(b'\\')?;
                            self.require(b'u')?;
                            let low = self.hex4()?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(Error::Syntax(self.at - 4));
                            }
                            code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                        }
                        // Yojson encodes an unpaired low surrogate as its three
                        // UTF-8-like bytes; String cannot represent that value.
                        let encoded = if code <= 0x7f {
                            vec![code as u8]
                        } else if code <= 0x7ff {
                            vec![0xc0 | (code >> 6) as u8, 0x80 | (code & 63) as u8]
                        } else if code <= 0xffff {
                            vec![
                                0xe0 | (code >> 12) as u8,
                                0x80 | ((code >> 6) & 63) as u8,
                                0x80 | (code & 63) as u8,
                            ]
                        } else {
                            vec![
                                0xf0 | (code >> 18) as u8,
                                0x80 | ((code >> 12) & 63) as u8,
                                0x80 | ((code >> 6) & 63) as u8,
                                0x80 | (code & 63) as u8,
                            ]
                        };
                        extend(&mut bytes, &encoded)?;
                    }
                }
                _ => push(&mut bytes, byte)?,
            }
        }
    }
}
