// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Head_record codec without Head_manifest's separate file-reader size bound.
use super::{Error, Head, Result};
use crate::{
    native_integer,
    native_json::{Document, Value},
    transaction::{json_optional, json_string, native_float},
};

pub(super) fn text(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::String(value) => Ok(value.clone()),
        _ => Err("expected string".into()),
    }
}
pub(super) fn integer(value: &Value) -> Result<i64> {
    match value {
        Value::Int(value) => Ok(value.get()),
        _ => Err("expected integer".into()),
    }
}
pub(super) fn read(document: &Document, value: &Value) -> Result<Head> {
    let Value::Object(rows) = value else {
        return Err("HEAD is not an object".into());
    };
    let field = |name: &[u8]| document.field(value, name).unwrap_or(&Value::Null);
    let has_version = document.field(value, b"schema_version").is_some();
    let schema_version = if has_version {
        integer(field(b"schema_version"))?
    } else {
        1
    };
    if !(1..=3).contains(&schema_version) {
        return Err("HEAD schema is unsupported".into());
    }
    let base: Vec<&[u8]> = vec![
        b"generation",
        b"epoch_id",
        b"state_root",
        b"txid_hi",
        b"txlog_seg",
        b"txlog_off",
        b"epochlog_off",
        b"commit_id",
        b"ts",
    ];
    let mut known = base.clone();
    if has_version {
        known.push(b"schema_version");
    }
    if schema_version >= 2 {
        known.push(b"irmin_commit");
    }
    if schema_version >= 3 {
        known.push(b"quorum_cert_hash");
    }
    let mut full = base;
    full.extend([
        b"schema_version".as_slice(),
        b"irmin_commit",
        b"quorum_cert_hash",
        b"ledger_state_root",
        b"epoch_index_hash",
        b"epoch_index_root",
    ]);
    let mut actual = rows
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect::<Vec<_>>();
    known.sort_unstable();
    full.sort_unstable();
    actual.sort_unstable();
    if actual != known && !(has_version && actual == full) {
        return Err("HEAD fields are missing, repeated or unknown".into());
    }
    let optional = |name: &[u8]| match field(name) {
        Value::Null => Ok(None),
        value => text(value).map(Some),
    };
    let position = |name: &[u8]| match field(name) {
        Value::Null => Ok(None),
        value => integer(value).map(Some),
    };
    #[allow(clippy::cast_precision_loss)] // Native Yojson to_number int projection.
    let ts = match field(b"ts") {
        Value::Int(value) => value.get() as f64,
        Value::Float(value) => *value,
        _ => return Err("HEAD expected timestamp".into()),
    };
    let head = Head {
        schema_version,
        generation: integer(field(b"generation"))?,
        epoch_id: integer(field(b"epoch_id"))?,
        state_root: text(field(b"state_root"))?,
        ledger_state_root: optional(b"ledger_state_root")?,
        irmin_commit: optional(b"irmin_commit")?,
        txid_hi: native_integer::parse_int64(&text(field(b"txid_hi"))?)
            .ok_or("Failure(\"Int64.of_string\")")?,
        txlog_seg: position(b"txlog_seg")?,
        txlog_off: position(b"txlog_off")?,
        epochlog_off: position(b"epochlog_off")?,
        commit_id: text(field(b"commit_id"))?,
        ts,
        quorum_cert_hash: optional(b"quorum_cert_hash")?,
        epoch_index_hash: optional(b"epoch_index_hash")?,
        epoch_index_root: optional(b"epoch_index_root")?,
    };
    head.validate()?;
    Ok(head)
}

pub fn parse_head(raw: &[u8]) -> Result<Head> {
    let document = Document::parse(raw).map_err(|error| Error::from(error.to_string()))?;
    read(&document, document.root())
}

/// Native Head_record.to_json serialization; validation remains a separate step.
pub fn encode_head(head: &Head) -> Result<Vec<u8>> {
    let mut raw = format!(
        "{{\"schema_version\":{},\"generation\":{},\"epoch_id\":{},\"state_root\":",
        head.schema_version, head.generation, head.epoch_id
    )
    .into_bytes();
    json_string(&mut raw, &head.state_root);
    for (name, value) in [
        (
            b",\"ledger_state_root\":".as_slice(),
            &head.ledger_state_root,
        ),
        (b",\"irmin_commit\":", &head.irmin_commit),
    ] {
        raw.extend_from_slice(name);
        json_optional(&mut raw, value.as_deref());
    }
    raw.extend_from_slice(b",\"txid_hi\":");
    json_string(&mut raw, head.txid_hi.to_string().as_bytes());
    for (name, value) in [
        (b",\"txlog_seg\":".as_slice(), head.txlog_seg),
        (b",\"txlog_off\":", head.txlog_off),
        (b",\"epochlog_off\":", head.epochlog_off),
    ] {
        raw.extend_from_slice(name);
        raw.extend_from_slice(
            value
                .map_or_else(|| "null".to_owned(), |value| value.to_string())
                .as_bytes(),
        );
    }
    raw.extend_from_slice(b",\"commit_id\":");
    json_string(&mut raw, &head.commit_id);
    raw.extend_from_slice(b",\"ts\":");
    let ts = if head.ts.is_nan() {
        "NaN".to_owned()
    } else if head.ts == f64::INFINITY {
        "Infinity".to_owned()
    } else if head.ts == f64::NEG_INFINITY {
        "-Infinity".to_owned()
    } else {
        native_float(head.ts).map_err(|error| Error::from(error.to_string()))?
    };
    raw.extend_from_slice(ts.as_bytes());
    for (name, value) in [
        (b",\"quorum_cert_hash\":".as_slice(), &head.quorum_cert_hash),
        (b",\"epoch_index_hash\":", &head.epoch_index_hash),
        (b",\"epoch_index_root\":", &head.epoch_index_root),
    ] {
        raw.extend_from_slice(name);
        json_optional(&mut raw, value.as_deref());
    }
    raw.push(b'}');
    Ok(raw)
}
