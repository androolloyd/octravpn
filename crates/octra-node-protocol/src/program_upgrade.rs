// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Program_upgrade payload parsing. The owner and code checks belong to state.
use crate::{
    native_json::{Document, ReadError, ReadMode, Value},
    transaction::{decode_base64, json_string, Transaction},
};
use num_traits::Zero;

pub const SCHEMA: &[u8] = b"octra_program_upgrade_v1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upgrade {
    pub expected_code_hash: Vec<u8>,
    pub bytecode: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Rejected(&'static str),
    #[error("{0}")]
    Unavailable(crate::native_json::Error),
}
pub fn is_hash(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}
pub fn parse_message(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let doc = Document::parse_native(raw, ReadMode::Tree).map_err(|error| match error {
        ReadError::Json { .. } => Error::Rejected("program upgrade payload invalid"),
        ReadError::Unavailable(error) => Error::Unavailable(error),
    })?;
    let Value::Object(fields) = doc.root() else {
        return Err(Error::Rejected("program upgrade payload must be an object"));
    };
    if fields.len() != 2 {
        return Err(Error::Rejected("program upgrade payload fields invalid"));
    }
    let one = |name: &[u8]| {
        let mut fields = fields.iter().filter(|(key, _)| key == name);
        match (fields.next(), fields.next()) {
            (Some((_, id)), None) => match doc.get(*id) {
                Some(Value::String(value)) => Some(value.as_slice()),
                _ => None,
            },
            _ => None,
        }
    };
    let (Some(schema), Some(hash)) = (one(b"schema"), one(b"expected_code_hash")) else {
        return Err(Error::Rejected("program upgrade payload invalid"));
    };
    if schema != SCHEMA {
        Err(Error::Rejected("program upgrade schema mismatch"))
    } else if !is_hash(hash) {
        Err(Error::Rejected(
            "program upgrade expected code hash invalid",
        ))
    } else {
        Ok(hash.to_vec())
    }
}
pub fn parse(tx: &Transaction) -> Result<Upgrade, Error> {
    if !tx.amount.is_zero() {
        return Err(Error::Rejected("program upgrade value must be zero"));
    }
    let (Some(message), Some(encoded)) = (&tx.message, &tx.encrypted_data) else {
        return Err(Error::Rejected("program upgrade payload missing"));
    };
    let expected_code_hash = parse_message(message)?;
    let bytecode =
        decode_base64(encoded).map_err(|_| Error::Rejected("program upgrade bytecode invalid"))?;
    if bytecode.is_empty() {
        return Err(Error::Rejected("program upgrade bytecode empty"));
    }
    Ok(Upgrade {
        expected_code_hash,
        bytecode,
    })
}
pub fn message(expected_code_hash: &[u8]) -> Vec<u8> {
    let mut out = b"{\"schema\":".to_vec();
    json_string(&mut out, SCHEMA);
    out.extend_from_slice(b",\"expected_code_hash\":");
    json_string(&mut out, expected_code_hash);
    out.push(b'}');
    out
}
