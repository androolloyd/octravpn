// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native snapshot commitments. Parsing or hashing alone grants no state-import
//! authority: callers must authenticate finality, exporters and trusted network.
pub mod anchor;
pub mod checkpoint;
pub mod cycle;
pub mod head;
pub mod http;
pub mod lease;
pub mod manifest;
pub mod migration;
pub mod range_part;
pub mod readiness;
pub mod roots;

pub use crate::oce1::Error;
use crate::{
    native_integer,
    native_json::{Document, Value},
};
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn require(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}
pub(crate) fn lower_hex(value: &[u8], length: usize) -> bool {
    value.len() == length
        && value
            .iter()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
pub(crate) fn fields(value: &Value, names: &[&[u8]], context: &str) -> Result<()> {
    let Value::Object(fields) = value else {
        return Err(format!("{context} must be an object").into());
    };
    let mut actual = fields
        .iter()
        .map(|(name, _)| name.as_slice())
        .collect::<Vec<_>>();
    let mut expected = names.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    require(
        actual == expected,
        &format!(
            "unexpected {} fields",
            if context.starts_with("checkpoint") {
                "checkpoint"
            } else {
                "manifest"
            }
        ),
    )
}
pub(crate) fn field<'a>(doc: &'a Document, object: &Value, name: &[u8]) -> Result<&'a Value> {
    doc.field(object, name)
        .ok_or_else(|| Error::from(format!("missing field {}", String::from_utf8_lossy(name))))
}
pub(crate) fn text(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::String(value) => Ok(value.clone()),
        _ => Err("expected string".into()),
    }
}
pub(crate) fn optional(value: &Value) -> Result<Option<Vec<u8>>> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err("expected optional string".into()),
    }
}
pub(crate) fn int64(value: &Value) -> Result<i64> {
    match value {
        Value::Int(value) => Ok(value.get()),
        Value::String(value) | Value::IntLiteral(value) => {
            native_integer::parse_int64(value).ok_or_else(|| "Failure(\"Int64.of_string\")".into())
        }
        _ => Err("expected int64".into()),
    }
}
pub(crate) fn integer(value: &Value) -> Result<i64> {
    match value {
        Value::Int(value) => Ok(value.get()),
        Value::IntLiteral(value) => {
            native_integer::parse_int63(value).ok_or_else(|| "Failure(\"int_of_string\")".into())
        }
        _ => Err("expected integer".into()),
    }
}
pub(crate) fn list<'a>(doc: &'a Document, value: &Value) -> Result<Vec<&'a Value>> {
    let Value::List(values) = value else {
        return Err("expected list".into());
    };
    Ok(values
        .iter()
        .map(|i| doc.get(*i).expect("parsed JSON index"))
        .collect())
}
