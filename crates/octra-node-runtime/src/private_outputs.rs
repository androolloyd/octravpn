// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native stealth output records. Mutations require an active state batch;
//! admission and ownership/proof checks belong to the private transition host.
use crate::{execution::Error, state_batch::StateBatch};
use num_bigint::BigInt;
use octra_node_protocol::{
    native_integer,
    native_json::{Document, Value},
    transaction::{json_string, native_float},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub id: i64,
    pub stealth_tag: Vec<u8>,
    pub eph_pub: Vec<u8>,
    pub enc_amount: Vec<u8>,
    pub amount: Vec<u8>,
    pub epoch_id: i64,
    pub tx_hash: Vec<u8>,
    pub sender_addr: Vec<u8>,
    pub claimed: i64,
    pub claim_pub: Vec<u8>,
    pub delta_cipher_stored: Vec<u8>,
    pub amount_hash: Vec<u8>,
    pub amount_commitment: Vec<u8>,
}
fn document(raw: &[u8]) -> Result<Option<Document>, Error> {
    match Document::parse(raw) {
        Ok(doc) => Ok(Some(doc)),
        Err(octra_node_protocol::native_json::Error::Syntax(_)) => Ok(None),
        Err(error) => Err(Error(error.to_string())),
    }
}
fn field<'a>(doc: &'a Document, name: &[u8]) -> Option<&'a Value> {
    doc.field(doc.root(), name)
}
fn integer(doc: &Document, name: &[u8]) -> Option<i64> {
    match field(doc, name) {
        Some(Value::Int(value)) => Some(value.get()),
        _ => None,
    }
}
fn string<'a>(doc: &'a Document, name: &[u8]) -> Option<&'a [u8]> {
    match field(doc, name) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}
impl Output {
    pub fn parse(raw: &[u8], fallback_id: i64) -> Result<Option<Self>, Error> {
        let Some(doc) = document(raw)? else {
            return Ok(None);
        };
        let parse = || {
            Some(Self {
                id: integer(&doc, b"id").unwrap_or(fallback_id),
                stealth_tag: string(&doc, b"stealth_tag")?.to_vec(),
                eph_pub: string(&doc, b"eph_pub")?.to_vec(),
                enc_amount: string(&doc, b"enc_amount")?.to_vec(),
                amount: string(&doc, b"amount")?.to_vec(),
                epoch_id: integer(&doc, b"epoch_id")?,
                tx_hash: string(&doc, b"tx_hash")?.to_vec(),
                sender_addr: string(&doc, b"sender_addr")?.to_vec(),
                claimed: integer(&doc, b"claimed")?,
                claim_pub: string(&doc, b"claim_pub").unwrap_or_default().to_vec(),
                delta_cipher_stored: string(&doc, b"delta_cipher_stored")
                    .unwrap_or_default()
                    .to_vec(),
                amount_hash: string(&doc, b"amount_hash").unwrap_or_default().to_vec(),
                amount_commitment: string(&doc, b"amount_commitment")
                    .unwrap_or_default()
                    .to_vec(),
            })
        };
        Ok(parse())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("{{\"id\":{}", self.id).into_bytes();
        for (name, value) in [
            ("stealth_tag", &self.stealth_tag),
            ("eph_pub", &self.eph_pub),
            ("enc_amount", &self.enc_amount),
            ("amount", &self.amount),
        ] {
            text_field(&mut out, name, value);
        }
        out.extend_from_slice(format!(",\"epoch_id\":{}", self.epoch_id).as_bytes());
        text_field(&mut out, "tx_hash", &self.tx_hash);
        text_field(&mut out, "sender_addr", &self.sender_addr);
        out.extend_from_slice(format!(",\"claimed\":{}", self.claimed).as_bytes());
        for (name, value) in [
            ("claim_pub", &self.claim_pub),
            ("delta_cipher_stored", &self.delta_cipher_stored),
            ("amount_hash", &self.amount_hash),
            ("amount_commitment", &self.amount_commitment),
        ] {
            text_field(&mut out, name, value);
        }
        out.push(b'}');
        out
    }
}
fn text_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.push(b',');
    json_string(out, name.as_bytes());
    out.push(b':');
    json_string(out, value);
}
/// ID and claimed fields are assigned by storage, as in insert_stealth_output.
pub fn insert(state: &mut StateBatch, mut output: Output) -> Result<i64, Error> {
    let _ = state.save().map_err(|e| Error(e.to_string()))?;
    let id = match state.get(&[b"index", b"stealth_counter"]) {
        None => 0,
        Some(raw) => native_integer::parse_int64(raw)
            .ok_or_else(|| Error("Failure(\"Int64.of_string\")".into()))?,
    };
    let next = id.wrapping_add(1);
    state.set_stealth_counter(next);
    state
        .set(
            &[b"index", b"stealth_counter"],
            next.to_string().into_bytes(),
        )
        .map_err(|e| Error(e.to_string()))?;
    output.id = id;
    output.claimed = 0;
    state
        .set(&[b"stealth", id.to_string().as_bytes()], output.to_bytes())
        .map_err(|e| Error(e.to_string()))?;
    Ok(id)
}
pub fn get(state: &StateBatch, id: i64) -> Result<Option<Output>, Error> {
    match state.get(&[b"stealth", id.to_string().as_bytes()]) {
        Some(raw) => Output::parse(raw, id),
        None => Ok(None),
    }
}
// Standard Yojson serialization preserves unknown fields, duplicate keys and
// byte strings. Non-finite numbers fail before a claim writes the record.
fn json(doc: &Document, value: &Value) -> Result<Vec<u8>, Error> {
    enum Task<'a> {
        Value(&'a Value),
        Key(&'a [u8]),
        Byte(u8),
    }
    let mut tasks = vec![Task::Value(value)];
    let mut out = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Byte(byte) => out.push(byte),
            Task::Key(key) => json_string(&mut out, key),
            Task::Value(value) => match value {
                Value::Null => out.extend_from_slice(b"null"),
                Value::Bool(value) => {
                    out.extend_from_slice(if *value { b"true" } else { b"false" });
                }
                Value::Int(value) => out.extend_from_slice(value.get().to_string().as_bytes()),
                Value::IntLiteral(value) => out.extend_from_slice(value),
                Value::Float(value) => {
                    out.extend_from_slice(
                        native_float(*value)
                            .map_err(|e| Error(e.to_string()))?
                            .as_bytes(),
                    );
                }
                Value::String(value) => json_string(&mut out, value),
                Value::List(values) => {
                    out.push(b'[');
                    tasks.push(Task::Byte(b']'));
                    for (i, id) in values.iter().enumerate().rev() {
                        tasks.push(Task::Value(doc.get(*id).expect("JSON arena")));
                        if i > 0 {
                            tasks.push(Task::Byte(b','));
                        }
                    }
                }
                Value::Object(values) => {
                    out.push(b'{');
                    tasks.push(Task::Byte(b'}'));
                    for (i, (key, id)) in values.iter().enumerate().rev() {
                        tasks.push(Task::Value(doc.get(*id).expect("JSON arena")));
                        tasks.push(Task::Byte(b':'));
                        tasks.push(Task::Key(key));
                        if i > 0 {
                            tasks.push(Task::Byte(b','));
                        }
                    }
                }
            },
        }
    }
    Ok(out)
}
/// Native refusal strings are returned separately from local storage failures.
pub fn mark_claimed(
    state: &mut StateBatch,
    id: i64,
    hash: &[u8],
) -> Result<Result<(), &'static str>, Error> {
    let key = id.to_string();
    let path = [b"stealth".as_slice(), key.as_bytes()];
    let Some(raw) = state.get(&path) else {
        return Ok(Err("output not found"));
    };
    let Some(doc) = document(raw)? else {
        return Ok(Err("parse error"));
    };
    let Some(claimed) = integer(&doc, b"claimed") else {
        return Ok(Err("parse error"));
    };
    if claimed != 0 {
        return Ok(Err("output already claimed or not found"));
    }
    let Value::Object(fields) = doc.root() else {
        return Ok(Err("parse error"));
    };
    let mut out = vec![b'{'];
    let mut has_hash = false;
    for (i, (key, id)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        if key == b"claimed" {
            out.push(b'1');
        } else if key == b"claim_tx_hash" {
            has_hash = true;
            json_string(&mut out, hash);
        } else {
            match json(&doc, doc.get(*id).expect("JSON arena")) {
                Ok(value) => out.extend(value),
                Err(_) => return Ok(Err("parse error")),
            }
        }
    }
    if !has_hash {
        text_field(&mut out, "claim_tx_hash", hash);
    }
    out.push(b'}');
    state.set(&path, out).map_err(|e| Error(e.to_string()))?;
    Ok(Ok(()))
}
pub fn unclaimed_amount(state: &StateBatch) -> Result<BigInt, Error> {
    let snapshot = state.snapshot();
    let mut total = BigInt::from(0);
    for id in snapshot.child_names(&[b"stealth"]) {
        let Some(raw) = snapshot.get(&[b"stealth", id]) else {
            continue;
        };
        let Some(doc) = document(raw)? else { continue };
        if integer(&doc, b"claimed") == Some(0) {
            if let Some(amount) = string(&doc, b"amount").and_then(native_integer::parse_integer) {
                total += amount;
            }
        }
    }
    Ok(total)
}
pub fn claimed_hashes(state: &StateBatch) -> Result<Vec<Vec<u8>>, Error> {
    let snapshot = state.snapshot();
    let mut hashes = Vec::new();
    for id in snapshot.child_names(&[b"stealth"]) {
        let Some(raw) = snapshot.get(&[b"stealth", id]) else {
            continue;
        };
        let Some(doc) = document(raw)? else { continue };
        if integer(&doc, b"claimed").unwrap_or(0) != 0 {
            if let Some(hash) = string(&doc, b"claim_tx_hash").filter(|h| h.len() == 64) {
                hashes.push(hash.to_vec());
            }
        }
    }
    Ok(hashes)
}
/// Native legacy scan JSON. Unlike typed output reads, this projection retains
/// untyped id/claimed values and does not require an amount field.
pub fn since(state: &StateBatch, epoch: i64) -> Result<Vec<u8>, Error> {
    let snapshot = state.snapshot();
    let mut rows = Vec::new();
    for id in snapshot.child_names(&[b"stealth"]) {
        let Some(raw) = snapshot.get(&[b"stealth", id]) else {
            continue;
        };
        let Some(doc) = document(raw)? else { continue };
        let Some(found) = integer(&doc, b"epoch_id").filter(|e| *e >= epoch) else {
            continue;
        };
        let required = [
            b"stealth_tag".as_slice(),
            b"eph_pub",
            b"enc_amount",
            b"tx_hash",
            b"sender_addr",
        ];
        if required.iter().any(|name| string(&doc, name).is_none()) {
            continue;
        }
        let mut row = b"{\"id\":".to_vec();
        row.extend(json(&doc, field(&doc, b"id").unwrap_or(&Value::Null))?);
        for name in ["stealth_tag", "eph_pub", "enc_amount"] {
            text_field(
                &mut row,
                name,
                string(&doc, name.as_bytes()).expect("checked"),
            );
        }
        row.extend_from_slice(format!(",\"epoch_id\":{found}").as_bytes());
        for name in ["tx_hash", "sender_addr"] {
            text_field(
                &mut row,
                name,
                string(&doc, name.as_bytes()).expect("checked"),
            );
        }
        row.extend_from_slice(b",\"claimed\":");
        row.extend(json(&doc, field(&doc, b"claimed").unwrap_or(&Value::Null))?);
        row.extend_from_slice(b",\"claim_pub\":");
        if let Some(value) = string(&doc, b"claim_pub") {
            json_string(&mut row, value);
        } else {
            row.extend_from_slice(b"null");
        }
        for name in ["delta_cipher_stored", "amount_hash", "amount_commitment"] {
            text_field(
                &mut row,
                name,
                string(&doc, name.as_bytes()).unwrap_or_default(),
            );
        }
        row.push(b'}');
        rows.push(row);
    }
    let mut out = vec![b'['];
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(row);
    }
    out.push(b']');
    Ok(out)
}
