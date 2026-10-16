// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{malformed, Result};
use crate::{
    circle_program::Refusal,
    native_integer::{parse_int63, parse_int64},
    native_json::{Document, Value},
};
pub(crate) struct Fields<'a> {
    pub doc: &'a Document,
    scope: &'static str,
}
impl<'a> Fields<'a> {
    pub(crate) fn new(doc: &'a Document, scope: &'static str) -> Result<Self> {
        Self::object(
            doc,
            scope,
            &format!("{scope} payload must be a json object"),
        )
    }
    pub(crate) fn object(doc: &'a Document, scope: &'static str, error: &str) -> Result<Self> {
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(malformed(error.as_bytes()));
        }
        Ok(Self { doc, scope })
    }
    pub(crate) fn get(&self, name: &str) -> Option<&'a Value> {
        self.doc.field(self.doc.root(), name.as_bytes())
    }
    fn invalid(&self, name: &str, missing: bool) -> Refusal {
        malformed(
            format!(
                "{} {} field: {name}",
                if missing { "missing" } else { "invalid" },
                self.scope
            )
            .into_bytes(),
        )
    }
    pub(crate) fn required(&self, name: &str) -> Result<Vec<u8>> {
        match self.get(name) {
            Some(Value::String(raw)) => Ok(raw.clone()),
            _ => Err(self.invalid(name, true)),
        }
    }
    pub(crate) fn text(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.get(name) {
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            None | Some(Value::Null) => Ok(None),
            _ => Err(self.invalid(name, false)),
        }
    }
    pub(crate) fn flag(&self, name: &str) -> Result<Option<bool>> {
        match self.get(name) {
            Some(Value::Bool(value)) => Ok(Some(*value)),
            None | Some(Value::Null) => Ok(None),
            _ => Err(self.invalid(name, false)),
        }
    }
    pub(crate) fn number(&self, name: &str, machine: bool) -> Result<Option<i64>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(value)) => Ok(Some(value.get())),
            Some(Value::String(raw) | Value::IntLiteral(raw)) => {
                let value = if machine {
                    parse_int63(raw)
                } else {
                    parse_int64(raw)
                };
                value.map(Some).ok_or_else(|| {
                    Refusal::new(
                        "malformed_transaction_exception",
                        if machine {
                            b"Failure(\"int_of_string\")".as_slice()
                        } else {
                            b"Failure(\"Int64.of_string\")"
                        },
                    )
                })
            }
            _ => Err(self.invalid(name, false)),
        }
    }
    /// Native tuple arguments are evaluated right to left before their ordinary
    /// Result errors are matched in field order. Integer exceptions escape first.
    pub(crate) fn integer_exceptions(&self, names: &[(&str, bool)]) -> Result<()> {
        for &(name, machine) in names.iter().rev() {
            if let Err(error) = self.number(name, machine) {
                if error.tag == "malformed_transaction_exception" {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn strings(&self, name: &str) -> Result<Option<Vec<Vec<u8>>>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::List(values)) => Ok(Some(
                values
                    .iter()
                    .filter_map(|id| match self.doc.get(*id) {
                        Some(Value::String(raw)) => Some(raw.clone()),
                        _ => None,
                    })
                    .collect(),
            )),
            _ => Err(self.invalid(name, false)),
        }
    }
    pub(crate) fn integers(&self, name: &str) -> Result<Option<Vec<i64>>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::List(values)) => Ok(Some(
                values
                    .iter()
                    .filter_map(|id| integer(self.doc.get(*id)?))
                    .collect(),
            )),
            _ => Err(self.invalid(name, false)),
        }
    }
    // Keep the explicit ordered native tuple/field projection at this boundary.
    #[allow(clippy::type_complexity)]
    pub(crate) fn weights(&self, name: &str) -> Result<Option<Vec<(Vec<u8>, i64)>>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Object(values)) => Ok(Some(
                values
                    .iter()
                    .filter_map(|(key, id)| Some((key.clone(), integer(self.doc.get(*id)?)?)))
                    .collect(),
            )),
            _ => Err(self.invalid(name, false)),
        }
    }
}
pub(crate) fn integer(value: &Value) -> Option<i64> {
    match value {
        Value::Int(v) => Some(v.get()),
        Value::IntLiteral(raw) | Value::String(raw) => parse_int63(raw),
        _ => None,
    }
}
