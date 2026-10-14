// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! HFHE receipt validation and exact native commitment bytes.
use super::{field, parse, reject, string, Error};
use crate::{
    native_json::{Document, Value},
    transaction::json_string,
};
use sha2::{Digest, Sha256};
pub const MAX_ENTRIES: usize = 16;
pub const MAX_VERIFIERS: usize = 2;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub method: Vec<u8>,
    pub request_hash: Vec<u8>,
    pub response_hash: Vec<u8>,
    pub result: Option<bool>,
}
pub fn verifier(method: &[u8]) -> bool {
    matches!(
        method,
        b"fhe_verify_zero" | b"fhe_verify_range" | b"fhe_verify_bound"
    )
}
pub(super) fn hex64(value: &[u8]) -> bool {
    value.len() == 64 && value.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn valid(entry: &Entry) -> bool {
    !entry.method.is_empty()
        && entry.method.len() <= 64
        && hex64(&entry.request_hash)
        && hex64(&entry.response_hash)
        && verifier(&entry.method) == entry.result.is_some()
}
pub fn validate(entries: &[Entry]) -> Result<(), Error> {
    if entries.len() > MAX_ENTRIES {
        Err(reject("circle_hfhe_transcript_limit"))
    } else if entries.iter().filter(|e| verifier(&e.method)).count() > MAX_VERIFIERS {
        Err(reject("circle_hfhe_verifier_limit"))
    } else if entries.iter().all(valid) {
        Ok(())
    } else {
        Err(reject("circle_hfhe_transcript_invalid"))
    }
}
pub fn decode(raw: &[u8]) -> Result<Vec<Entry>, Error> {
    let doc = parse(raw)?;
    decode_value(&doc, doc.root())
}
pub(crate) fn decode_value(doc: &Document, value: &Value) -> Result<Vec<Entry>, Error> {
    let Value::List(items) = value else {
        return Err(reject("circle_hfhe_entries_invalid"));
    };
    let mut entries = Vec::new();
    for id in items {
        let value = doc.get(*id).expect("native arena child");
        if !matches!(value, Value::Object(_)) {
            return Err(reject("circle_hfhe_entry_invalid"));
        }
        let read = |name: &str| {
            string(field(doc, value, name))
                .map(<[u8]>::to_vec)
                .ok_or_else(|| reject(format!("circle_hfhe_{name}_invalid")))
        };
        let method = read("method")?;
        let request_hash = read("request_hash")?;
        let response_hash = read("response_hash")?;
        let result = match field(doc, value, "result") {
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Null) => None,
            _ => return Err(reject("circle_hfhe_result_invalid")),
        };
        let entry = Entry {
            method,
            request_hash,
            response_hash,
            result,
        };
        if !valid(&entry) {
            return Err(reject("circle_hfhe_entry_invalid"));
        }
        entries.push(entry);
    }
    validate(&entries)?;
    Ok(entries)
}
pub fn entries_json(entries: &[Entry]) -> Vec<u8> {
    let mut out = vec![b'['];
    for (i, entry) in entries.iter().enumerate() {
        if i != 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"method\":");
        json_string(&mut out, &entry.method);
        out.extend_from_slice(b",\"request_hash\":");
        json_string(&mut out, &entry.request_hash);
        out.extend_from_slice(b",\"response_hash\":");
        json_string(&mut out, &entry.response_hash);
        out.extend_from_slice(b",\"result\":");
        out.extend_from_slice(match entry.result {
            Some(true) => b"true",
            Some(false) => b"false",
            None => b"null",
        });
        out.push(b'}');
    }
    out.push(b']');
    out
}
pub fn canonical(entries: &[Entry]) -> Vec<u8> {
    let mut out = b"{\"schema\":\"octra_circle_hfhe_transcript_v1\",\"entries\":".to_vec();
    out.extend_from_slice(&entries_json(entries));
    out.push(b'}');
    out
}
pub fn hash(entries: &[Entry]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"octra:circle_hfhe_transcript:v1\0");
    hash.update(canonical(entries));
    hex::encode(hash.finalize())
}
