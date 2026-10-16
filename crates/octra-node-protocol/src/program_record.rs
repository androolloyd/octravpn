// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Store_chaindata Program records. These are auxiliary source metadata and
//! never confer bytecode admission, ownership, or consensus authority.
use crate::{
    native_json::{Document, ReadError, ReadMode, Value},
    transaction::json_string,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub source: Vec<u8>,
    pub abi: Vec<u8>,
    pub report: Option<Vec<u8>>,
    pub certificate: Option<Vec<u8>>,
    pub code_hash: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(Vec<u8>),
    Unavailable(crate::native_json::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "{}", String::from_utf8_lossy(reason)),
            Self::Unavailable(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {}
fn invalid(reason: impl AsRef<[u8]>) -> Error {
    Error::Invalid(reason.as_ref().to_vec())
}
pub fn valid_hash(raw: &[u8]) -> bool {
    raw.len() == 64 && raw.iter().all(u8::is_ascii_hexdigit)
}
pub fn key(address: &[u8], code_hash: Option<&[u8]>) -> Vec<u8> {
    let mut out = [b"program_record:".as_slice(), address].concat();
    if let Some(hash) = code_hash {
        out.push(b':');
        out.extend_from_slice(hash);
    }
    out
}
impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"{\"version\":1,\"source\":".to_vec();
        json_string(&mut out, &self.source);
        out.extend_from_slice(b",\"abi\":");
        json_string(&mut out, &self.abi);
        for (name, value) in [
            (b"report".as_slice(), self.report.as_deref()),
            (b"certificate", self.certificate.as_deref()),
        ] {
            out.push(b',');
            json_string(&mut out, name);
            out.push(b':');
            match value {
                Some(value) => json_string(&mut out, value),
                None => out.extend_from_slice(b"null"),
            }
        }
        out.extend_from_slice(b",\"code_hash\":");
        json_string(&mut out, &self.code_hash);
        out.push(b'}');
        out
    }
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse_native(raw, ReadMode::Safe).map_err(|error| match error {
            ReadError::Json { .. } => invalid(b"program record JSON is invalid"),
            ReadError::Unavailable(error) => Error::Unavailable(error),
        })?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(invalid(b"program record is invalid"));
        }
        if !matches!(doc.field(doc.root(), b"version"), Some(Value::Int(value)) if value.get() == 1)
        {
            return Err(invalid(b"program record version is invalid"));
        }
        let text = |name: &[u8]| match doc.field(doc.root(), name) {
            Some(Value::String(value)) => Ok(value.clone()),
            _ => Err(invalid(
                [b"program record field is invalid name = ".as_slice(), name].concat(),
            )),
        };
        let optional = |name: &[u8]| match doc.field(doc.root(), name) {
            Some(Value::String(value)) => Ok(Some(value.clone())),
            Some(Value::Null) => Ok(None),
            _ => Err(invalid(
                [b"program record field is invalid name = ".as_slice(), name].concat(),
            )),
        };
        let code_hash = text(b"code_hash")?;
        if !valid_hash(&code_hash) {
            return Err(invalid(b"program record hash is invalid"));
        }
        let certificate = optional(b"certificate")?;
        let report = optional(b"report")?;
        let abi = text(b"abi")?;
        let source = text(b"source")?;
        Ok(Self {
            source,
            abi,
            report,
            certificate,
            code_hash,
        })
    }
}
