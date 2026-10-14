// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Complete native WASM result decoding, before storage/effect authorization.
use super::{
    boolean,
    codec::{self, Scalar},
    field, int, parse, reject, string, transcript, Error,
};
use crate::{
    circle_storage::StorageTable,
    circles::MetadataMode,
    native_integer::parse_int64,
    native_json::{Document, Value},
    transaction::decode_base64,
};
use std::collections::BTreeMap;

pub type Storage = BTreeMap<Vec<u8>, Vec<u8>>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub topic: Vec<u8>,
    pub data: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnOwner {
    Caller,
    Parent,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spawn {
    pub circle_id: Vec<u8>,
    pub owner: SpawnOwner,
    pub nonce: i64,
    pub payload_json: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub circle_id: Vec<u8>,
    pub path: Vec<u8>,
    pub content_type: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
    pub body_b64: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAsset {
    pub circle_id: Vec<u8>,
    pub path: Option<Vec<u8>>,
    pub slot_ref: Option<Vec<u8>>,
    pub state_ref: Option<Vec<u8>>,
    pub content_type: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
    pub key_id: Vec<u8>,
    pub plaintext_hash: Vec<u8>,
    pub padding_class: Option<Vec<u8>>,
    pub activate_after_epoch: Option<i64>,
    pub expire_after_epoch: Option<i64>,
    pub metadata_mode: Option<MetadataMode>,
    pub ciphertext_b64: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeTrace {
    pub root: Vec<u8>,
    pub steps: i64,
    pub operations: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub success: bool,
    pub effort_used: i64,
    pub response_status: i64,
    pub compute_trace: Option<ComputeTrace>,
    pub compute_exit: Option<i32>,
    pub compute_fault: Option<Vec<u8>>,
    pub response: Option<Scalar>,
    pub storage: StorageTable,
    pub events: Vec<Event>,
    pub spawns: Vec<Spawn>,
    pub assets: Vec<Asset>,
    pub encrypted_assets: Vec<EncryptedAsset>,
    pub transcript: Vec<transcript::Entry>,
    pub error: Option<Vec<u8>>,
}
fn b64(value: &Value, name: &str) -> Result<Vec<u8>, Error> {
    let Value::String(bytes) = value else {
        return Err(reject(format!("invalid {name} encoding")));
    };
    decode_base64(bytes).map_err(|error| {
        reject(format!(
            "invalid {name} base64: Invalid_argument(\"{error}\")"
        ))
    })
}
fn required(doc: &Document, value: &Value, name: &str, error: &str) -> Result<Vec<u8>, Error> {
    string(field(doc, value, name))
        .map(<[u8]>::to_vec)
        .ok_or_else(|| reject(error))
}
fn optional_string(doc: &Document, value: &Value, name: &str) -> Result<Option<Vec<u8>>, Error> {
    match field(doc, value, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        _ => Err(reject("invalid wasm encrypted asset effect")),
    }
}
fn optional_integer(doc: &Document, value: &Value, name: &str) -> Result<Option<i64>, Error> {
    match field(doc, value, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Int(v)) => Ok(Some(v.get())),
        Some(Value::String(v) | Value::IntLiteral(v)) => parse_int64(v)
            .map(Some)
            .ok_or_else(|| reject("invalid wasm encrypted asset effect")),
        _ => Err(reject("invalid wasm encrypted asset effect")),
    }
}
fn list<T>(
    doc: &Document,
    value: &Value,
    error: &str,
    nullable: bool,
    mut item: impl FnMut(&Value) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    match value {
        Value::Null if nullable => Ok(Vec::new()),
        Value::List(ids) => ids
            .iter()
            .map(|id| item(doc.get(*id).expect("native arena child")))
            .collect(),
        _ => Err(reject(error)),
    }
}
/// Decode the storage table exchanged with the native resumable interpreter.
pub fn decode_storage(raw: &[u8]) -> Result<StorageTable, Error> {
    let doc = parse(raw)?;
    storage(&doc, doc.root())
}
fn storage(doc: &Document, value: &Value) -> Result<StorageTable, Error> {
    let pairs = list(doc, value, "invalid wasm storage table", false, |value| {
        let (Some(key), Some(value)) =
            (field(doc, value, "key_b64"), field(doc, value, "value_b64"))
        else {
            return Err(reject("invalid wasm storage pair"));
        };
        Ok((b64(key, "storage key")?, b64(value, "storage value")?))
    })?;
    let mut table = StorageTable::new(pairs.len().max(8));
    for (key, value) in pairs {
        table.replace(key, value);
    }
    Ok(table)
}
fn events(doc: &Document, value: &Value) -> Result<Vec<Event>, Error> {
    list(doc, value, "invalid wasm events", false, |value| {
        let (Some(topic), Some(data)) = (
            field(doc, value, "topic_b64"),
            field(doc, value, "data_b64"),
        ) else {
            return Err(reject("invalid wasm event"));
        };
        Ok(Event {
            topic: b64(topic, "event topic")?,
            data: b64(data, "event data")?,
        })
    })
}
fn spawns(doc: &Document, value: &Value) -> Result<Vec<Spawn>, Error> {
    list(doc, value, "invalid wasm spawns", true, |value| {
        let error = "invalid wasm spawn effect";
        let circle_id = required(doc, value, "circle_id", error)?;
        let owner = required(doc, value, "owner_mode", error)?;
        let nonce = int(field(doc, value, "spawn_nonce")).ok_or_else(|| reject(error))?;
        let payload_json = required(doc, value, "payload_json", error)?;
        let owner = match owner.as_slice() {
            b"caller" => SpawnOwner::Caller,
            b"parent" => SpawnOwner::Parent,
            _ => return Err(reject([b"unknown spawn owner: ", &owner[..]].concat())),
        };
        Ok(Spawn {
            circle_id,
            owner,
            nonce,
            payload_json,
        })
    })
}
fn assets(doc: &Document, value: &Value) -> Result<Vec<Asset>, Error> {
    list(doc, value, "invalid wasm asset effects", true, |value| {
        let error = "invalid wasm asset effect";
        let circle_id = required(doc, value, "circle_id", error)?;
        let path = required(doc, value, "path", error)?;
        let content_type = required(doc, value, "content_type", error)?;
        let body_b64 = required(doc, value, "body_b64", error)?;
        let encoding = optional_string(doc, value, "encoding").map_err(|_| reject(error))?;
        if encoding.as_deref() == Some(b"__invalid__") {
            return Err(reject(error));
        }
        Ok(Asset {
            circle_id,
            path,
            content_type,
            encoding,
            body_b64,
        })
    })
}
fn encrypted_assets(doc: &Document, value: &Value) -> Result<Vec<EncryptedAsset>, Error> {
    list(
        doc,
        value,
        "invalid wasm encrypted asset effects",
        true,
        |value| {
            let error = "invalid wasm encrypted asset effect";
            let circle_id = required(doc, value, "circle_id", error)?;
            let path = optional_string(doc, value, "path")?;
            let slot_ref = optional_string(doc, value, "slot_ref")?;
            let state_ref = optional_string(doc, value, "state_ref")?;
            let content_type = required(doc, value, "content_type", error)?;
            let encoding = optional_string(doc, value, "encoding")?;
            let key_id = required(doc, value, "key_id", error)?;
            let plaintext_hash = required(doc, value, "plaintext_hash", error)?;
            let padding_class = optional_string(doc, value, "padding_class")?;
            let activate_after_epoch = optional_integer(doc, value, "activate_after_epoch")?;
            let expire_after_epoch = optional_integer(doc, value, "expire_after_epoch")?;
            let metadata = optional_string(doc, value, "metadata_mode")?;
            let ciphertext_b64 = required(doc, value, "ciphertext_b64", error)?;
            let metadata_mode = match metadata.as_deref() {
                None => None,
                Some(b"reveal") => Some(MetadataMode::Reveal),
                Some(b"opaque") => Some(MetadataMode::Opaque),
                Some(mode) => return Err(reject([b"unknown metadata mode: ", mode].concat())),
            };
            Ok(EncryptedAsset {
                circle_id,
                path,
                slot_ref,
                state_ref,
                content_type,
                encoding,
                key_id,
                plaintext_hash,
                padding_class,
                activate_after_epoch,
                expire_after_epoch,
                metadata_mode,
                ciphertext_b64,
            })
        },
    )
}
fn trace(doc: &Document, root: &Value) -> Result<Option<ComputeTrace>, Error> {
    match (
        field(doc, root, "compute_trace_root"),
        optional_integer(doc, root, "compute_steps"),
        optional_integer(doc, root, "compute_operations"),
    ) {
        (None | Some(Value::Null), Ok(None), Ok(None)) => Ok(None),
        (Some(Value::String(root)), Ok(Some(steps)), Ok(Some(operations)))
            if transcript::hex64(root) && steps > 0 && operations > 0 =>
        {
            Ok(Some(ComputeTrace {
                root: root.clone(),
                steps,
                operations,
            }))
        }
        _ => Err(reject("invalid wasm compute trace")),
    }
}
pub fn decode(raw: &[u8], before: &StorageTable) -> Result<Receipt, Error> {
    let doc = parse(raw)?;
    let root = doc.root();
    if let Some(reason) = string(field(&doc, root, "unavailable")) {
        return Err(Error::Unavailable(reason.to_vec()));
    }
    let (
        Some(success),
        Some(response_status),
        Some(effort_used),
        Some(response),
        Some(storage_json),
        Some(events_json),
        Some(transcript_json),
    ) = (
        boolean(field(&doc, root, "success")),
        int(field(&doc, root, "status_code")),
        int(field(&doc, root, "effort_used")),
        field(&doc, root, "response_b64"),
        field(&doc, root, "storage_pairs"),
        field(&doc, root, "events"),
        field(&doc, root, "hfhe_receipt_entries"),
    )
    else {
        return Err(reject("invalid wasm execution response"));
    };
    // Native tuple matching prioritizes errors in this exact order.
    let storage = if *storage_json == Value::Null {
        before.clone()
    } else {
        storage(&doc, storage_json)?
    };
    let events = events(&doc, events_json)?;
    let spawns = spawns(&doc, field(&doc, root, "spawns").unwrap_or(&Value::Null))?;
    let assets = assets(&doc, field(&doc, root, "assets").unwrap_or(&Value::Null))?;
    let encrypted_assets = encrypted_assets(
        &doc,
        field(&doc, root, "encrypted_assets").unwrap_or(&Value::Null),
    )?;
    let transcript = transcript::decode_value(&doc, transcript_json)?;
    let compute_trace = trace(&doc, root)?;
    let response = if *response == Value::Null {
        None
    } else {
        Some(codec::decode_response(&b64(response, "wasm response")?)?)
    };
    Ok(Receipt {
        success,
        effort_used,
        response_status,
        compute_trace,
        compute_exit: int(field(&doc, root, "compute_exit"))
            .and_then(|value| i32::try_from(value).ok()),
        compute_fault: string(field(&doc, root, "compute_fault")).map(<[u8]>::to_vec),
        error: string(field(&doc, root, "error")).map(<[u8]>::to_vec),
        response,
        storage,
        events,
        spawns,
        assets,
        encrypted_assets,
        transcript,
    })
}
