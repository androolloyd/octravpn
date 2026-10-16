// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_seal binds source checking resources to an epoch-selected core certificate.
//! Decoding a seal alone does not verify either its source or its certificate.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    bin::{self, Bits, Code, Codes},
    certificate,
    limit::Limit,
    parse,
    rule::Schedule,
    types::Types,
};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub core: Bits,
    pub resources: Limit,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Source(parse::Error),
    Cert(certificate::Error),
    Encode,
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Source(error) => error.text(),
            Self::Cert(error) => error.text(types),
            Self::Encode => b"source artifact encoding failed".to_vec(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct SourceFailure {
    pub error: Error,
    pub types: Types,
}
impl SourceFailure {
    pub fn text(&self) -> Vec<u8> {
        self.error.text(&self.types)
    }
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for SourceFailure {}

pub fn encode(item: &Item) -> Option<Bits> {
    let mut codes = Codes::default();
    let bits = item
        .core
        .iter()
        .map(|bit| codes.tag(u8::from(*bit), codes.nil()))
        .collect::<Vec<_>>();
    let bits = codes.list(&bits);
    let resources = codes.resources_code(&item.resources)?;
    let fields = codes.list(&[bits, resources]);
    let root = codes.tag(0, fields);
    bin::encode(&codes, root)
}
pub fn decode(input: &[bool]) -> Option<Item> {
    let decoded = bin::decode(input)?;
    let codes = &decoded.codes;
    let Code::Tag(tag, fields) = codes.get(decoded.root) else {
        return None;
    };
    if !tag.is_zero() {
        return None;
    }
    let [core, resources] = codes.fields::<2>(*fields)?;
    let core = codes
        .list_get(core)?
        .into_iter()
        .map(|id| {
            let Code::Tag(tag, body) = codes.get(id) else {
                return None;
            };
            if !matches!(codes.get(*body), Code::Nil) {
                return None;
            }
            match tag.to_u8()? {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()?;
    let resources = codes.resources_get(resources)?;
    let item = Item { core, resources };
    (encode(&item)?.as_slice() == input).then_some(item)
}
pub fn make(schedule: &Schedule, epoch: &BigInt, source: &[u8]) -> Result<Bits, SourceFailure> {
    let parse::Compiled {
        lowered:
            parse::Lowered {
                program,
                mut types,
                terms,
            },
        checked,
        ..
    } = parse::parse(source)
        .and_then(parse::Program::into_compiled)
        .map_err(|error| SourceFailure {
            error: Error::Source(error),
            types: Types::default(),
        })?;
    let resources = checked.info().resources().clone();
    let result = certificate::issue(schedule, epoch, &mut types, &terms, &program)
        .map_err(Error::Cert)
        .and_then(|core| encode(&Item { core, resources }).ok_or(Error::Encode));
    result.map_err(|error| SourceFailure { error, types })
}
pub fn accept(schedule: &Schedule, epoch: &BigInt, source: &[u8], input: &[bool]) -> bool {
    make(schedule, epoch, source).is_ok_and(|exact| exact.as_slice() == input)
}
