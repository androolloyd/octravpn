// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_rval structured plain-data result records. These are not execution proofs.
use super::{
    bin::{self, Code, Codes},
    eval::{ValueId, Values},
    rule::{Field, LOCAL},
    types::{Type, TypeId, Types},
};
use num_traits::Zero;
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct Record {
    typ: TypeId,
    value: ValueId,
    raw: Arc<[u8]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Bits,
    Size(usize, usize),
    Form,
}
type Result<T> = std::result::Result<T, Error>;
fn valid(types: &Types, values: &mut Values, typ: TypeId, value: ValueId) -> bool {
    matches!(
        types.get(typ),
        Type::Unit | Type::Vec(..) | Type::Seq(..) | Type::Pair(..) | Type::Sum(..)
    ) && types.plain(typ)
        && types.valid(typ)
        && values.typed(types, typ, value)
        && values.shape(&[value]).is_ok()
}
fn raw(types: &Types, values: &Values, typ: TypeId, value: ValueId) -> Option<Vec<u8>> {
    let mut codes = Codes::default();
    let typ = codes.type_code(types, typ);
    let value = codes.value_code(values, value);
    let body = codes.list(&[typ, value]);
    let root = codes.tag(0, body);
    let bits = bin::encode(&codes, root)?;
    let mut raw = b"AR1\n".to_vec();
    raw.extend(bits.into_iter().map(|bit| if bit { b'1' } else { b'0' }));
    (raw.len() <= LOCAL.get(Field::Str) as usize).then_some(raw)
}
impl Record {
    pub fn make(types: &Types, values: &mut Values, typ: TypeId, value: ValueId) -> Result<Self> {
        if !valid(types, values, typ, value) {
            return Err(Error::Form);
        }
        Ok(Self {
            typ,
            value,
            raw: raw(types, values, typ, value).ok_or(Error::Form)?.into(),
        })
    }
    pub fn decode(types: &mut Types, values: &mut Values, input: &[u8]) -> Result<Self> {
        let maximum = LOCAL.get(Field::Str) as usize;
        if input.len() > maximum {
            return Err(Error::Size(maximum, input.len()));
        }
        let body = input.strip_prefix(b"AR1\n").ok_or(Error::Header)?;
        if !body.iter().all(|byte| matches!(byte, b'0' | b'1')) {
            return Err(Error::Bits);
        }
        let bits: Vec<_> = body.iter().map(|byte| *byte == b'1').collect();
        let decoded = bin::decode(&bits).ok_or(Error::Form)?;
        let Code::Tag(tag, body) = decoded.codes.get(decoded.root) else {
            return Err(Error::Form);
        };
        if !tag.is_zero() {
            return Err(Error::Form);
        }
        let fields = decoded.codes.list_get(*body).ok_or(Error::Form)?;
        let [typ, value] = fields.as_slice() else {
            return Err(Error::Form);
        };
        let typ = decoded.codes.type_get(types, *typ).ok_or(Error::Form)?;
        let value = decoded.codes.value_get(values, *value).ok_or(Error::Form)?;
        if !valid(types, values, typ, value) {
            return Err(Error::Form);
        }
        let record = Self::make(types, values, typ, value)?;
        if record.raw.as_ref() != input {
            return Err(Error::Form);
        }
        Ok(record)
    }
    pub fn typ(&self) -> TypeId {
        self.typ
    }
    pub fn value(&self) -> ValueId {
        self.value
    }
    pub fn encode(&self) -> &[u8] {
        &self.raw
    }
    /// The private constructors encode the full structural type and value in a
    /// deterministic image, allowing equality across independent request arenas.
    pub fn equal(&self, right: &Self) -> bool {
        self.raw == right.raw
    }
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Header => b"result file header is invalid".to_vec(),
            Self::Bits => b"result file bit image is invalid".to_vec(),
            Self::Size(maximum, actual) => {
                format!("result file size = {actual} maximum = {maximum}").into_bytes()
            }
            Self::Form => b"result file form is invalid".to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
