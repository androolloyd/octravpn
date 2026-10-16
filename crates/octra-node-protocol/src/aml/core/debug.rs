// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_dbg canonical debugger configuration and resumable session transport.
//! Digests bind caller-supplied identities; decoding does not execute code.
use super::{
    bin::{self, Code, CodeId, Codes},
    eval::Values,
    machine::Literal,
    result::Record,
    rule::{Field, LOCAL},
    types::Types,
    Natural,
};
use crate::native_integer::parse_integer;
use num_traits::ToPrimitive;
use std::sync::Arc;

const MAX_NATURAL: i64 = LOCAL.get(Field::Nat);
const MAX_STRING: usize = LOCAL.get(Field::Str) as usize;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Point {
    Pc(i64),
    Line(i64),
}
#[derive(Clone, Debug)]
pub struct Config {
    cap: i64,
    points: Vec<Point>,
    expect: Option<Literal>,
    types: Types,
    values: Values,
}
impl Config {
    pub fn cap(&self) -> i64 {
        self.cap
    }
    pub fn points(&self) -> &[Point] {
        &self.points
    }
    pub fn expect(&self) -> Option<&Literal> {
        self.expect.as_ref()
    }
    pub fn types(&self) -> &Types {
        &self.types
    }
    pub fn values(&self) -> &Values {
        &self.values
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Step,
    Pause,
    Limit,
}
#[derive(Clone, Debug)]
pub struct Session {
    source: Vec<u8>,
    code: Vec<u8>,
    config: Config,
    seen: i64,
    trace: Vec<u8>,
    form: Vec<u8>,
}
impl Session {
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    pub fn code(&self) -> &[u8] {
        &self.code
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn seen(&self) -> i64 {
        self.seen
    }
    pub fn trace(&self) -> &[u8] {
        &self.trace
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Cap,
    Point,
    Form,
    Digest,
    Seen,
    Expect,
}
impl Error {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Cap => b"step cap is invalid",
            Self::Point => b"breakpoint is invalid",
            Self::Form => b"debug session form is invalid",
            Self::Digest => b"debug session digest is invalid",
            Self::Seen => b"debug session step is invalid",
            Self::Expect => b"expected result is invalid",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(std::str::from_utf8(self.text()).expect("ASCII diagnostic"))
    }
}
impl std::error::Error for Error {}
fn valid_literal(value: &Literal) -> bool {
    match value {
        Literal::Bytes(raw) => raw.len() <= MAX_NATURAL as usize,
        _ => true,
    }
}
fn rehome(types: &mut Types, values: &mut Values, value: Literal) -> Option<Literal> {
    match value {
        Literal::Data(record) => Some(Literal::Data(
            Record::decode(types, values, record.encode()).ok()?,
        )),
        value => Some(value),
    }
}
pub fn make(cap: i64, mut points: Vec<Point>, expect: Option<Literal>) -> Result<Config, Error> {
    if !(1..=MAX_NATURAL).contains(&cap) {
        return Err(Error::Cap);
    }
    if !points.iter().all(|point| match point {
        Point::Pc(value) | Point::Line(value) => (0..=MAX_NATURAL).contains(value),
    }) {
        return Err(Error::Point);
    }
    if expect.as_ref().is_some_and(|value| !valid_literal(value)) {
        return Err(Error::Expect);
    }
    points.sort();
    points.dedup();
    if points.len() > MAX_NATURAL as usize {
        return Err(Error::Point);
    }
    let mut types = Types::default();
    let mut values = Values::default();
    let expect = match expect {
        None => None,
        Some(value) => Some(rehome(&mut types, &mut values, value).ok_or(Error::Expect)?),
    };
    Ok(Config {
        cap,
        points,
        expect,
        types,
        values,
    })
}
pub fn decide(config: &Config, skip: Option<i64>, seen: i64, pc: i64, line: i64) -> Choice {
    if seen >= config.cap {
        Choice::Limit
    } else if skip.is_some_and(|past| seen <= past) {
        Choice::Step
    } else if config.points.iter().any(|point| match point {
        Point::Pc(value) => *value == pc,
        Point::Line(value) => *value == line,
    }) {
        Choice::Pause
    } else {
        Choice::Step
    }
}
pub fn check(config: &Config, actual: &Literal) -> bool {
    config
        .expect
        .as_ref()
        .is_none_or(|wanted| wanted.equal(actual))
}
// Preserve the native remainder guard and zero-divisor short-circuit order.
#[allow(clippy::manual_is_multiple_of)]
fn unhex(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() % 2 != 0
        || !raw
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    hex::decode(raw).ok()
}
pub fn lit_text(value: &Literal) -> Vec<u8> {
    match value {
        Literal::Bool(false) => b"b:0".to_vec(),
        Literal::Bool(true) => b"b:1".to_vec(),
        Literal::Int(value) => format!("i:{value}").into_bytes(),
        Literal::Bytes(value) => format!("x:{}", hex::encode(value)).into_bytes(),
        Literal::Data(value) => format!("d:{}", hex::encode(value.encode())).into_bytes(),
        Literal::Cap(kind, id) => format!("c:{}:{}", kind.get(), id.get()).into_bytes(),
    }
}
/// Data literals are decoded into the caller's retained arenas. Capability
/// integers follow native Zarith input rules; integer literals are canonical.
pub fn lit(types: &mut Types, values: &mut Values, raw: &[u8]) -> Option<Literal> {
    if raw == b"b:0" {
        return Some(Literal::Bool(false));
    }
    if raw == b"b:1" {
        return Some(Literal::Bool(true));
    }
    if let Some(raw) = raw.strip_prefix(b"i:") {
        let value = parse_integer(raw)?;
        return (value.to_string().as_bytes() == raw).then(|| Literal::Int(Arc::new(value)));
    }
    if let Some(raw) = raw.strip_prefix(b"x:") {
        return Some(Literal::Bytes(unhex(raw)?.into()));
    }
    if let Some(raw) = raw.strip_prefix(b"d:") {
        return Some(Literal::Data(
            Record::decode(types, values, &unhex(raw)?).ok()?,
        ));
    }
    if raw.starts_with(b"c:") {
        let pieces = raw.split(|byte| *byte == b':').collect::<Vec<_>>();
        let [prefix, kind, id] = pieces.as_slice() else {
            return None;
        };
        if *prefix != b"c" {
            return None;
        }
        return Some(Literal::Cap(
            Natural::new(&parse_integer(kind)?)?,
            Natural::new(&parse_integer(id)?)?,
        ));
    }
    None
}
fn natural(codes: &Codes, root: CodeId) -> Option<Natural> {
    let Code::Num(value) = codes.get(root) else {
        return None;
    };
    Natural::new(value)
}
fn tagged(codes: &Codes, root: CodeId, expected: u32) -> Option<CodeId> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    (tag.to_u32()? == expected).then_some(*body)
}
fn point_code(codes: &mut Codes, point: Point) -> CodeId {
    let (tag, value) = match point {
        Point::Pc(value) => (0, value),
        Point::Line(value) => (1, value),
    };
    let value = codes.num(value);
    codes.tag(tag, value)
}
fn point_get(codes: &Codes, root: CodeId) -> Option<Point> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    let value = i64::from(natural(codes, *body)?.get());
    match tag.to_u8()? {
        0 => Some(Point::Pc(value)),
        1 => Some(Point::Line(value)),
        _ => None,
    }
}
fn literal_code(codes: &mut Codes, value: &Literal) -> CodeId {
    let (tag, body) = match value {
        Literal::Bool(value) => (0, codes.num(u8::from(*value))),
        Literal::Int(value) => (1, codes.integer((**value).clone())),
        Literal::Bytes(raw) => (2, codes.bytes_code(raw)),
        Literal::Data(value) => (3, codes.bytes_code(value.encode())),
        Literal::Cap(kind, id) => {
            let kind = codes.num(kind.get());
            let id = codes.num(id.get());
            (4, codes.list(&[kind, id]))
        }
    };
    codes.tag(tag, body)
}
fn literal_get(
    codes: &Codes,
    types: &mut Types,
    values: &mut Values,
    root: CodeId,
) -> Option<Literal> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    match tag.to_u8()? {
        0 => {
            let Code::Num(value) = codes.get(*body) else {
                return None;
            };
            match value.to_u8()? {
                0 => Some(Literal::Bool(false)),
                1 => Some(Literal::Bool(true)),
                _ => None,
            }
        }
        1 => {
            let Code::Int(value) = codes.get(*body) else {
                return None;
            };
            Some(Literal::Int(value.clone()))
        }
        2 => {
            let value = Literal::Bytes(codes.bytes_get(*body)?.into());
            valid_literal(&value).then_some(value)
        }
        3 => Some(Literal::Data(
            Record::decode(types, values, &codes.bytes_get(*body)?).ok()?,
        )),
        4 => {
            let [kind, id] = codes.fields::<2>(*body)?;
            Some(Literal::Cap(natural(codes, kind)?, natural(codes, id)?))
        }
        _ => None,
    }
}
fn config_code(codes: &mut Codes, config: &Config) -> CodeId {
    let cap = codes.num(config.cap);
    let points = config
        .points
        .iter()
        .map(|point| point_code(codes, *point))
        .collect::<Vec<_>>();
    let points = codes.list(&points);
    let expect = match &config.expect {
        None => codes.tag(0, codes.nil()),
        Some(value) => {
            let literal = literal_code(codes, value);
            codes.tag(1, literal)
        }
    };
    let fields = codes.list(&[cap, points, expect]);
    codes.tag(3, fields)
}
fn config_get(codes: &Codes, root: CodeId) -> Option<Config> {
    let [cap, points, expect] = codes.fields::<3>(tagged(codes, root, 3)?)?;
    let cap = i64::from(natural(codes, cap)?.get());
    let points = codes
        .list_get(points)?
        .into_iter()
        .map(|point| point_get(codes, point))
        .collect::<Option<Vec<_>>>()?;
    let Code::Tag(tag, body) = codes.get(expect) else {
        return None;
    };
    let expect = match tag.to_u8()? {
        0 if matches!(codes.get(*body), Code::Nil) => None,
        1 => {
            let mut types = Types::default();
            let mut values = Values::default();
            Some(literal_get(codes, &mut types, &mut values, *body)?)
        }
        _ => return None,
    };
    make(cap, points, expect).ok()
}
fn state_form(session: &Session) -> Option<Vec<u8>> {
    let mut codes = Codes::default();
    let source = codes.bytes_code(&session.source);
    let code = codes.bytes_code(&session.code);
    let config = config_code(&mut codes, &session.config);
    let seen = codes.num(session.seen);
    let trace = codes.bytes_code(&session.trace);
    let fields = codes.list(&[source, code, config, seen, trace]);
    let root = codes.tag(4, fields);
    let bits = bin::encode(&codes, root)?;
    let mut raw = b"CD1\n".to_vec();
    raw.extend(bits.into_iter().map(|bit| if bit { b'1' } else { b'0' }));
    (raw.len() <= MAX_STRING).then_some(raw)
}
fn digest(raw: &[u8]) -> bool {
    raw.len() == 64
        && raw
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
pub fn session(
    source: &[u8],
    code: &[u8],
    config: &Config,
    seen: i64,
    trace: &[u8],
) -> Result<Session, Error> {
    if !(digest(source) && digest(code) && digest(trace)) {
        return Err(Error::Digest);
    }
    if seen < 0 || seen >= config.cap {
        return Err(Error::Seen);
    }
    let mut value = Session {
        source: source.to_vec(),
        code: code.to_vec(),
        config: config.clone(),
        seen,
        trace: trace.to_vec(),
        form: Vec::new(),
    };
    value.form = state_form(&value).ok_or(Error::Form)?;
    Ok(value)
}
pub fn encode(value: &Session) -> &[u8] {
    &value.form
}
fn state_get(codes: &Codes, root: CodeId) -> Option<Session> {
    let [source, code, config, seen, trace] = codes.fields::<5>(tagged(codes, root, 4)?)?;
    session(
        &codes.bytes_get(source)?,
        &codes.bytes_get(code)?,
        &config_get(codes, config)?,
        i64::from(natural(codes, seen)?.get()),
        &codes.bytes_get(trace)?,
    )
    .ok()
}
pub fn decode(raw: &[u8]) -> Result<Session, Error> {
    if raw.len() > MAX_STRING {
        return Err(Error::Form);
    }
    let body = raw.strip_prefix(b"CD1\n").ok_or(Error::Form)?;
    if !body.iter().all(|byte| matches!(byte, b'0' | b'1')) {
        return Err(Error::Form);
    }
    let bits = body.iter().map(|byte| *byte == b'1').collect::<Vec<_>>();
    let decoded = bin::decode(&bits).ok_or(Error::Form)?;
    let value = state_get(&decoded.codes, decoded.root).ok_or(Error::Form)?;
    if encode(&value) != raw {
        return Err(Error::Form);
    }
    Ok(value)
}
