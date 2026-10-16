// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Byte-preserving Yojson input semantics. The flat arena keeps parsing and drop
//! iterative even for deeply nested untrusted values. Duplicate object keys stay
//! ordered because native transaction decoding selects the first occurrence.
use crate::transaction::Nonce;
use std::sync::Arc;
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
    nodes: Arc<Vec<Value>>,
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
    mode: ReadMode,
    line: usize,
    bol: usize,
    fault: Option<Vec<u8>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    Tree,
    Plain,
    Safe,
}
/// Only a classified native JSON failure may become a consensus refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    Json { offset: usize, message: Vec<u8> },
    Unavailable(Error),
}
impl ReadError {
    pub fn exception(&self) -> Option<Vec<u8>> {
        match self {
            Self::Json { message, .. } => Some(crate::native_exception::string_argument(
                b"Yojson__Common.Json_error",
                message,
            )),
            Self::Unavailable(_) => None,
        }
    }
    pub fn legacy(self) -> Error {
        match self {
            Self::Json { offset, .. } => Error::Syntax(offset),
            Self::Unavailable(error) => error,
        }
    }
}
impl Document {
    /// Native Json_tree.measure without serializing a potentially oversized
    /// response. Iterator frames grow with nesting, rather than container width.
    pub fn measure(&self, value: &Value, limit: usize) -> Result<Option<usize>, Error> {
        enum Part<'a> {
            Value(&'a Value),
            List(std::slice::Iter<'a, usize>),
            Fields(std::slice::Iter<'a, (Vec<u8>, usize)>),
        }
        fn take(left: &mut usize, size: usize) -> bool {
            if size > *left {
                false
            } else {
                *left -= size;
                true
            }
        }
        fn string(left: &mut usize, raw: &[u8]) -> bool {
            if !take(left, 2) || raw.len() > *left {
                return false;
            }
            raw.iter().all(|byte| {
                take(
                    left,
                    match byte {
                        b'"' | b'\\' | 8 | 12 | b'\n' | b'\r' | b'\t' => 2,
                        0..=31 | 127 => 6,
                        _ => 1,
                    },
                )
            })
        }
        let mut left = limit;
        let mut pending = vec![Part::Value(value)];
        while let Some(part) = pending.pop() {
            let within = match part {
                Part::List(mut values) => match values.next() {
                    None => true,
                    Some(id) => {
                        let comma = values.len() > 0;
                        push(&mut pending, Part::List(values))?;
                        push(
                            &mut pending,
                            Part::Value(self.get(*id).ok_or(Error::Syntax(*id))?),
                        )?;
                        !comma || take(&mut left, 1)
                    }
                },
                Part::Fields(mut fields) => match fields.next() {
                    None => true,
                    Some((name, id)) => {
                        let count = if fields.len() == 0 { 1 } else { 2 };
                        push(&mut pending, Part::Fields(fields))?;
                        push(
                            &mut pending,
                            Part::Value(self.get(*id).ok_or(Error::Syntax(*id))?),
                        )?;
                        string(&mut left, name) && take(&mut left, count)
                    }
                },
                Part::Value(value) => match value {
                    Value::Null => take(&mut left, 4),
                    Value::Bool(value) => take(&mut left, if *value { 4 } else { 5 }),
                    Value::Int(value) => take(&mut left, value.get().to_string().len()),
                    Value::IntLiteral(raw) => take(&mut left, raw.len()),
                    Value::String(raw) => string(&mut left, raw),
                    Value::Float(value) => {
                        let size = if value.is_nan() {
                            3
                        } else if *value == f64::INFINITY {
                            8
                        } else if *value == f64::NEG_INFINITY {
                            9
                        } else {
                            crate::transaction::native_float(*value)
                                .map_err(|_| Error::Syntax(0))?
                                .len()
                        };
                        take(&mut left, size)
                    }
                    Value::List(values) => {
                        push(&mut pending, Part::List(values.iter()))?;
                        take(&mut left, 2)
                    }
                    Value::Object(fields) => {
                        push(&mut pending, Part::Fields(fields.iter()))?;
                        take(&mut left, 2)
                    }
                },
            };
            if !within {
                return Ok(None);
            }
        }
        Ok(Some(limit - left))
    }
    /// Native Json_tree.write: iterative traversal, stable bytewise object-key
    /// sorting, and preservation of duplicate keys and integer literals.
    pub fn write(&self, value: &Value, sort: bool) -> Result<Vec<u8>, Error> {
        enum Output<'a> {
            Value(&'a Value),
            Byte(u8),
            Key(&'a [u8]),
        }
        let mut output = Vec::new();
        let mut pending = vec![Output::Value(value)];
        while let Some(next) = pending.pop() {
            match next {
                Output::Byte(byte) => push(&mut output, byte)?,
                Output::Key(raw) => crate::transaction::json_string(&mut output, raw),
                Output::Value(value) => match value {
                    Value::Null => extend(&mut output, b"null")?,
                    Value::Bool(v) => extend(&mut output, if *v { b"true" } else { b"false" })?,
                    Value::Int(v) => extend(&mut output, v.get().to_string().as_bytes())?,
                    Value::IntLiteral(v) => extend(&mut output, v)?,
                    Value::Float(v) => {
                        let raw = if v.is_nan() {
                            "NaN".into()
                        } else if *v == f64::INFINITY {
                            "Infinity".into()
                        } else if *v == f64::NEG_INFINITY {
                            "-Infinity".into()
                        } else {
                            crate::transaction::native_float(*v).map_err(|_| Error::Syntax(0))?
                        };
                        extend(&mut output, raw.as_bytes())?;
                    }
                    Value::String(v) => crate::transaction::json_string(&mut output, v),
                    Value::List(values) => {
                        push(&mut output, b'[')?;
                        push(&mut pending, Output::Byte(b']'))?;
                        for (index, id) in values.iter().enumerate().rev() {
                            push(
                                &mut pending,
                                Output::Value(self.get(*id).ok_or(Error::Syntax(*id))?),
                            )?;
                            if index > 0 {
                                push(&mut pending, Output::Byte(b','))?;
                            }
                        }
                    }
                    Value::Object(values) => {
                        let mut fields = values.iter().collect::<Vec<_>>();
                        if sort {
                            fields.sort_by(|a, b| a.0.cmp(&b.0));
                        }
                        push(&mut output, b'{')?;
                        push(&mut pending, Output::Byte(b'}'))?;
                        for (index, (name, id)) in fields.into_iter().enumerate().rev() {
                            push(
                                &mut pending,
                                Output::Value(self.get(*id).ok_or(Error::Syntax(*id))?),
                            )?;
                            push(&mut pending, Output::Byte(b':'))?;
                            push(&mut pending, Output::Key(name))?;
                            if index > 0 {
                                push(&mut pending, Output::Byte(b','))?;
                            }
                        }
                    }
                },
            }
        }
        Ok(output)
    }
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        Self::parse_native(raw, ReadMode::Tree).map_err(ReadError::legacy)
    }
    /// Native Json_tree.read/read_plain and Yojson.Safe.from_string differ in
    /// their plain-container guard and trailing-junk diagnostics.
    pub fn parse_native(raw: &[u8], mode: ReadMode) -> Result<Self, ReadError> {
        let mut parser = Parser {
            raw,
            at: 0,
            nodes: Vec::new(),
            frames: Vec::new(),
            mode,
            line: 1,
            bol: 0,
            fault: None,
        };
        match parser.document() {
            Ok(root) => Ok(Self {
                nodes: Arc::new(parser.nodes),
                root,
            }),
            Err(error @ Error::Syntax(offset)) => match parser.fault {
                Some(message) => Err(ReadError::Json { offset, message }),
                None => Err(ReadError::Unavailable(error)),
            },
            Err(error @ Error::Allocation) => Err(ReadError::Unavailable(error)),
        }
    }
    pub fn root(&self) -> &Value {
        &self.nodes[self.root]
    }
    /// Select an existing arena value without copying its strings or rewriting
    /// native integer/float tokens through another JSON serialization.
    pub fn rooted(&self, index: usize) -> Option<Self> {
        (index < self.nodes.len()).then(|| Self {
            nodes: self.nodes.clone(),
            root: index,
        })
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
    fn document(&mut self) -> Result<usize, Error> {
        self.space()?;
        if self.at == self.raw.len() {
            return Err(self.message(self.at, b"Blank input data"));
        }
        let root = self.value()?;
        while let Some(&(id, state)) = self.frames.last() {
            self.space()?;
            match state {
                State::FirstList | State::ListValue => {
                    if matches!(state, State::FirstList) && self.consume(b']') {
                        self.frames.pop();
                        continue;
                    }
                    self.frames.last_mut().expect("frame").1 = State::ListSeparator;
                    let child = self.value()?;
                    let Value::List(items) = &mut self.nodes[id] else {
                        unreachable!()
                    };
                    push(items, child)?;
                }
                State::FirstObject | State::ObjectKey => {
                    if matches!(state, State::FirstObject) && self.consume(b'}') {
                        self.frames.pop();
                        continue;
                    }
                    let key = self.key()?;
                    self.space()?;
                    self.expect(b':', b"Expected ':' but found")?;
                    self.frames.last_mut().expect("frame").1 = State::ObjectSeparator;
                    let child = self.value()?;
                    let Value::Object(fields) = &mut self.nodes[id] else {
                        unreachable!()
                    };
                    push(fields, (key, child))?;
                }
                State::ListSeparator => {
                    if self.consume(b']') {
                        self.frames.pop();
                    } else {
                        self.expect(b',', b"Expected ',' or ']' but found")?;
                        self.frames.last_mut().expect("frame").1 = State::ListValue;
                    }
                }
                State::ObjectSeparator => {
                    if self.consume(b'}') {
                        self.frames.pop();
                    } else {
                        self.expect(b',', b"Expected ',' or '}' but found")?;
                        self.frames.last_mut().expect("frame").1 = State::ObjectKey;
                    }
                }
            }
        }
        self.space()?;
        if self.at != self.raw.len() {
            let start = self.at;
            if self.mode == ReadMode::Safe {
                return Err(self.long_error(b"Junk after end of JSON value:", start, 0));
            }
            let count = (self.raw.len() - start).min(32);
            let first = start - self.bol;
            let last = start + (self.raw.len() - start).min(33) - self.bol;
            let mut description = b"Junk after end of JSON value: '".to_vec();
            description.extend_from_slice(&self.raw[start..start + count]);
            description.push(b'\'');
            return Err(self.located(start, first as i64, last as i64, &description));
        }
        Ok(root)
    }
    fn message(&mut self, offset: usize, message: &[u8]) -> Error {
        self.fault = Some(message.to_vec());
        Error::Syntax(offset)
    }
    fn located(&mut self, offset: usize, first: i64, last: i64, description: &[u8]) -> Error {
        let location = if first == last {
            format!("byte {first}")
        } else {
            format!("bytes {first}-{last}")
        };
        let mut message = format!("Line {}, {location}:\n", self.line).into_bytes();
        message.extend_from_slice(description);
        self.message(offset, &message)
    }
    fn eof(&mut self) -> Error {
        let at = self.at as i64 - self.bol as i64;
        self.located(self.at, at - 1, at, b"Unexpected end of input")
    }
    fn long_error(&mut self, description: &[u8], start: usize, token: usize) -> Error {
        let end = start
            .saturating_add(token)
            .saturating_add(33)
            .min(self.raw.len());
        let snippet_end = start
            .saturating_add(token)
            .saturating_add(32)
            .min(self.raw.len());
        let mut message = description.to_vec();
        message.extend_from_slice(b" '");
        // Lexer_utils.read_junk consumes one more byte when its counter has
        // reached zero. That byte affects the range but not the snippet.
        message.extend_from_slice(&self.raw[start..snippet_end]);
        message.push(b'\'');
        self.located(
            start,
            start as i64 - self.bol as i64,
            end as i64 - self.bol as i64,
            &message,
        )
    }
    fn expect(&mut self, byte: u8, description: &[u8]) -> Result<(), Error> {
        if self.consume(byte) {
            Ok(())
        } else if self.at == self.raw.len() {
            Err(self.eof())
        } else {
            Err(self.long_error(description, self.at, 1))
        }
    }
    fn consume(&mut self, byte: u8) -> bool {
        if self.raw.get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn space(&mut self) -> Result<(), Error> {
        loop {
            while self
                .raw
                .get(self.at)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
            {
                let newline = self.raw[self.at] == b'\n';
                self.at += 1;
                if newline {
                    self.line += 1;
                    self.bol = self.at;
                }
            }
            if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"//") {
                self.at += 2;
                while self.raw.get(self.at).is_some_and(|b| *b != b'\n') {
                    self.at += 1;
                }
                if self.raw.get(self.at) == Some(&b'\n') {
                    self.at += 1;
                }
                // read_space counts the EOF-terminated line comment too.
                self.line += 1;
                self.bol = self.at;
            } else if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"/*") {
                self.at += 2;
                loop {
                    if self.raw.get(self.at..self.at.saturating_add(2)) == Some(b"*/") {
                        self.at += 2;
                        break;
                    }
                    if self.at >= self.raw.len() {
                        return Err(self.long_error(b"Unterminated comment", self.at, 0));
                    }
                    let newline = self.raw[self.at] == b'\n';
                    self.at += 1;
                    if newline {
                        self.line += 1;
                        self.bol = self.at;
                    }
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
            return Err(if self.at == self.raw.len() {
                self.eof()
            } else {
                self.long_error(b"Expected string or identifier but found", self.at, 1)
            });
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
        if self.mode == ReadMode::Plain && matches!(self.raw.get(self.at), Some(b'(' | b'<')) {
            return Err(self.message(self.at, b"JSON container is invalid"));
        }
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
            _ => {
                return Err(if self.at == self.raw.len() {
                    self.eof()
                } else {
                    self.long_error(b"Invalid token", self.at, 1)
                })
            }
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
            Err(self.long_error(b"Invalid token", self.at, 1))
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
            _ => {
                self.at = start;
                return Err(self.long_error(b"Invalid token", start, 1));
            }
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
            let mut exponent = self.at + 1;
            if self
                .raw
                .get(exponent)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                exponent += 1;
            }
            // ocamllex chooses the longest complete token. An incomplete
            // exponent leaves `e` for the enclosing separator/junk reader.
            if self.raw.get(exponent).is_some_and(u8::is_ascii_digit) {
                float = true;
                self.at = exponent + 1;
                while self.raw.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
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
    fn hex4(&self, at: usize) -> Option<u32> {
        let mut value = 0;
        for &byte in self.raw.get(at..at.checked_add(4)?)? {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return None,
            };
            value = value * 16 + u32::from(digit);
        }
        Some(value)
    }
    fn string(&mut self) -> Result<Vec<u8>, Error> {
        self.expect(b'"', b"Expected string or identifier but found")?;
        let mut bytes = Vec::new();
        loop {
            let Some(byte) = self.raw.get(self.at).copied() else {
                return Err(self.eof());
            };
            self.at += 1;
            match byte {
                b'"' => return Ok(bytes),
                b'\\' => {
                    let Some(escaped) = self.raw.get(self.at).copied() else {
                        return Err(self.eof());
                    };
                    let escape_start = self.at;
                    self.at += 1;
                    let single = match escaped {
                        b'"' | b'\\' | b'/' => Some(escaped),
                        b'b' => Some(8),
                        b'f' => Some(12),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => {
                            return Err(self.long_error(
                                b"Invalid escape sequence",
                                escape_start,
                                1,
                            ))
                        }
                    };
                    if let Some(byte) = single {
                        push(&mut bytes, byte)?;
                    } else {
                        let Some(mut code) = self.hex4(self.at) else {
                            return Err(self.long_error(
                                b"Invalid escape sequence",
                                escape_start,
                                1,
                            ));
                        };
                        self.at += 4;
                        if (0xd800..=0xdbff).contains(&code) {
                            let start = self.at;
                            if start == self.raw.len() {
                                return Err(self.eof());
                            }
                            let low = if self.raw.get(start..start + 2) == Some(b"\\u") {
                                self.hex4(start + 2)
                            } else {
                                None
                            };
                            let Some(low) = low else {
                                return Err(self.long_error(b"Missing escape sequence representing low surrogate for code point beyond U+FFFF", start, 1));
                            };
                            self.at += 6;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(self.long_error(
                                    b"Invalid low surrogate for code point beyond U+FFFF",
                                    start,
                                    6,
                                ));
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
