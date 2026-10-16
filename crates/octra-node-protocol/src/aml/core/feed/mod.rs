// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_feed AF1 transport and typed attachment. A feed and its value IDs belong to
//! one request's value arena; successful decoding does not authorize execution.
use super::{
    bin::{self, Codes},
    eval::{ShapeError, ValueId, Values},
    lower,
    rule::{Field, LOCAL},
    syntax,
    term::{Bind, TermId, Terms},
    types::{TypeId, Types},
    Natural,
};
mod parse;
mod projection;
pub use parse::{parse, parse_value};
pub use projection::{substitute, term_of};
#[derive(Clone, Debug)]
pub struct Spec {
    pub name: Vec<u8>,
    pub typ: TypeId,
}
impl Spec {
    pub fn new(name: impl AsRef<[u8]>, typ: TypeId) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            typ,
        }
    }
}
pub fn typed(types: &Types, values: &mut Values, typ: TypeId, value: ValueId) -> bool {
    values.typed(types, typ, value)
}
pub fn shaped(values: &Values, value: ValueId) -> bool {
    values.shape(&[value]).is_ok()
}
#[derive(Clone, Debug)]
pub struct Feed {
    values: Vec<ValueId>,
    raw: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Bits,
    Size(usize, usize),
    Form,
    Count(usize, usize),
    Capability(Natural, Natural),
    Spec(Vec<u8>),
    Inputs(usize, usize),
    Input(Natural, TypeId),
    Machine(Natural, TypeId),
    Lex(super::lexer::Error),
    Need(super::lexer::Form, super::lexer::Form, super::lexer::Span),
    Name(Vec<u8>, Vec<u8>, super::lexer::Span),
    Natural(num_bigint::BigInt, super::lexer::Span),
    Type(Vec<u8>, TypeId, super::lexer::Span),
}
type Result<T> = std::result::Result<T, Error>;
pub fn specs(
    syntax: &syntax::Syntax,
    types: &mut Types,
    binds: &[syntax::Bind],
) -> Result<Vec<Spec>> {
    binds
        .iter()
        .map(|bind| {
            let typ = lower::typ(syntax, types, bind.typ)
                .map_err(|_| Error::Spec(bind.name.text().to_vec()))?;
            Ok(Spec {
                name: bind.name.text().to_vec(),
                typ,
            })
        })
        .collect()
}
fn raw(values: &Values, roots: &[ValueId]) -> Option<Vec<u8>> {
    let mut codes = Codes::default();
    let roots: Vec<_> = roots
        .iter()
        .map(|root| codes.value_code(values, *root))
        .collect();
    let root = codes.list(&roots);
    let bits = bin::encode(&codes, root)?;
    let mut raw = b"AF1\n".to_vec();
    raw.extend(bits.into_iter().map(|bit| if bit { b'1' } else { b'0' }));
    (raw.len() <= LOCAL.get(Field::Str) as usize).then_some(raw)
}
impl Feed {
    pub fn make(values: &Values, roots: &[ValueId]) -> Result<Self> {
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if roots.len() > maximum {
            return Err(Error::Count(maximum, roots.len()));
        }
        if !roots
            .iter()
            .all(|root| bin::encode_value(values, *root).is_some())
        {
            return Err(Error::Form);
        }
        values.shape(roots).map_err(|error| match error {
            ShapeError::Form => Error::Form,
            ShapeError::Capability(kind, id) => Error::Capability(kind, id),
        })?;
        let raw = raw(values, roots).ok_or(Error::Form)?;
        Ok(Self {
            values: roots.to_vec(),
            raw,
        })
    }
    pub fn decode(values: &mut Values, input: &[u8]) -> Result<Self> {
        let maximum = LOCAL.get(Field::Str) as usize;
        if input.len() > maximum {
            return Err(Error::Size(maximum, input.len()));
        }
        let Some(body) = input.strip_prefix(b"AF1\n") else {
            return Err(Error::Header);
        };
        if !body.iter().all(|byte| matches!(byte, b'0' | b'1')) {
            return Err(Error::Bits);
        }
        let bits: Vec<_> = body.iter().map(|byte| *byte == b'1').collect();
        let decoded = bin::decode(&bits).ok_or(Error::Form)?;
        let roots = decoded.codes.list_get(decoded.root).ok_or(Error::Form)?;
        let roots: Vec<_> = roots
            .into_iter()
            .map(|root| decoded.codes.value_get(values, root))
            .collect::<Option<_>>()
            .ok_or(Error::Form)?;
        let feed = Self::make(values, &roots)?;
        if feed.raw != input {
            return Err(Error::Form);
        }
        Ok(feed)
    }
    pub fn values(&self) -> &[ValueId] {
        &self.values
    }
    pub fn encode(&self) -> &[u8] {
        &self.raw
    }
    pub fn attach(
        &self,
        types: &Types,
        values: &mut Values,
        binds: &[Bind],
    ) -> Result<Vec<(Bind, ValueId)>> {
        if binds.len() != self.values.len() {
            return Err(Error::Inputs(binds.len(), self.values.len()));
        }
        let mut out = Vec::with_capacity(binds.len());
        for (bind, value) in binds.iter().zip(&self.values) {
            if !values.typed(types, bind.typ, *value) {
                return Err(Error::Input(bind.id, bind.typ));
            }
            out.push((*bind, *value));
        }
        Ok(out)
    }
    pub fn close(
        &self,
        types: &Types,
        values: &mut Values,
        terms: &mut Terms,
        binds: &[Bind],
        root: TermId,
    ) -> Result<TermId> {
        let pairs = self.attach(types, values, binds)?;
        let mut replacements = Vec::with_capacity(pairs.len());
        for (bind, value) in pairs {
            if bind.multiplicity == super::types::Multiplicity::Zero {
                continue;
            }
            let term = term_of(types, values, terms, bind.typ, value)
                .ok_or(Error::Machine(bind.id, bind.typ))?;
            replacements.push((bind.id, term));
        }
        Ok(substitute(terms, &replacements, root))
    }
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Header => b"feed header is not AF1".to_vec(),
            Self::Bits => b"feed body contains a non-bit octet".to_vec(),
            Self::Size(limit, actual) => {
                format!("feed size max = {limit} actual = {actual}").into_bytes()
            }
            Self::Form => b"feed form is invalid".to_vec(),
            Self::Count(limit, actual) => {
                format!("feed value count max = {limit} actual = {actual}").into_bytes()
            }
            Self::Capability(kind, id) => format!(
                "feed capability is repeated kind = {} id = {}",
                kind.get(),
                id.get()
            )
            .into_bytes(),
            Self::Spec(name) => {
                [b"feed input type is unavailable name = ".as_slice(), name].concat()
            }
            Self::Inputs(expected, actual) => {
                format!("feed input count expected = {expected} actual = {actual}").into_bytes()
            }
            Self::Input(id, typ) => [
                format!("feed input differs id = {} type = ", id.get()).as_bytes(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Machine(id, typ) => [
                format!(
                    "feed input is outside the machine data profile id = {} type = ",
                    id.get()
                )
                .as_bytes(),
                &types.text(*typ),
            ]
            .concat(),
            Self::Lex(error) => error.text(),
            Self::Need(wanted, actual, span) => [
                b"feed token expected = ".as_slice(),
                wanted.text(),
                b" actual = ",
                actual.text(),
                format!(" at = {}:{}", span.first.line, span.first.column).as_bytes(),
            ]
            .concat(),
            Self::Name(wanted, actual, span) => [
                b"feed name expected = ".as_slice(),
                wanted,
                b" actual = ",
                actual,
                format!(" at = {}:{}", span.first.line, span.first.column).as_bytes(),
            ]
            .concat(),
            Self::Natural(value, span) => format!(
                "feed natural outside profile = {value} at = {}:{}",
                span.first.line, span.first.column
            )
            .into_bytes(),
            Self::Type(name, typ, span) => [
                b"feed value differs name = ".as_slice(),
                name,
                b" type = ",
                &types.text(*typ),
                format!(" at = {}:{}", span.first.line, span.first.column).as_bytes(),
            ]
            .concat(),
        }
    }
}
