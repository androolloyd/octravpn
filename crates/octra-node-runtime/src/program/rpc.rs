// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Bounded Contract_rpc reads over one immutable committed tree.
use super::store::{self, Meta};
use crate::state_batch::Snapshot;
use octra_node_protocol::{
    account_pack::{self, Data},
    native_integer::parse_int63,
    native_json::{Document, Value},
    rpc::{param, param_int, require_address, require_string, Fault},
    transaction::{is_valid_address, json_string},
};
type Result<T> = std::result::Result<T, Fault>;
#[derive(Clone, Copy)]
pub enum Read {
    Info,
    List,
    Storage,
    StorageDump,
    Bytecode,
}
fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
fn not_found(reason: &[u8]) -> Fault {
    Fault::new(112, b"not found").string_data(reason)
}
fn strings(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        json_string(&mut out, value);
    }
    out.push(b'}');
    out
}
fn balance(state: &Snapshot, address: &[u8]) -> Result<String> {
    let Some(raw) = state.get(&[b"accounts", address, b"data"]) else {
        return Ok("0".into());
    };
    match account_pack::data(raw).map_err(unavailable)? {
        Data::Old(account) | Data::Parts(account, _) => Ok(account.balance.to_string()),
    }
}
fn row(state: &Snapshot, address: &[u8], meta: &Meta, info: bool) -> Result<Vec<u8>> {
    let balance = balance(state, address)?;
    Ok(if info {
        strings(&[
            (b"address", address),
            (b"version", &meta.version),
            (b"code_hash", &meta.code_hash),
            (b"balance", balance.as_bytes()),
            (b"owner", &meta.owner),
        ])
    } else {
        strings(&[
            (b"address", address),
            (b"owner", &meta.owner),
            (b"code_hash", &meta.code_hash),
            (b"version", &meta.version),
            (b"balance", balance.as_bytes()),
        ])
    })
}
fn list(state: &Snapshot, doc: &Document, params: &Value) -> Result<Vec<u8>> {
    let offset = param_int(doc, params, 0).unwrap_or(0);
    let limit = param_int(doc, params, 1).unwrap_or(128);
    if !(0..=1024).contains(&offset) {
        return Err(Fault::invalid(b"program offset outside read limit"));
    }
    if !(1..=128).contains(&limit) {
        return Err(Fault::invalid(b"program page size outside read limit"));
    }
    // Native pagination applies offset/length to raw tree names before address
    // filtering, then derives `more` before dropping malformed metadata rows.
    let addresses: Vec<_> = state
        .child_names(&[b"contracts"])
        .skip(offset as usize)
        .take(limit as usize + 1)
        .filter(|address| is_valid_address(address))
        .collect();
    let more = addresses.len() > limit as usize;
    let mut count = 0;
    let mut out = b"{\"contracts\":[".to_vec();
    for address in addresses.into_iter().take(limit as usize) {
        if let Some(meta) = store::meta(state, address).map_err(unavailable)? {
            if count > 0 {
                out.push(b',');
            }
            out.extend_from_slice(&row(state, address, &meta, false)?);
            count += 1;
        }
    }
    out.extend_from_slice(
        format!("],\"count\":{count},\"offset\":{offset},\"limit\":{limit},\"next_offset\":")
            .as_bytes(),
    );
    if more {
        out.extend_from_slice((offset + count).to_string().as_bytes());
    } else {
        out.extend_from_slice(b"null");
    }
    out.extend_from_slice(format!(",\"more\":{more}}}").as_bytes());
    Ok(out)
}
fn storage_limit(value: Option<&Value>) -> usize {
    const MAX: i64 = 4_194_304;
    let value = match value {
        Some(Value::String(value)) if value == b"full" => Some(MAX),
        Some(Value::String(value)) => parse_int63(value),
        Some(Value::Int(value)) => Some(value.get()),
        _ => None,
    };
    value.unwrap_or(4096).clamp(0, MAX) as usize
}
fn storage(state: &Snapshot, doc: &Document, params: &Value) -> Result<Vec<u8>> {
    let address = require_address(doc, params, 0, "address");
    let key = require_string(doc, params, 1, "key");
    let address = address?;
    let key = key?;
    let limit = storage_limit(param(doc, params, 2));
    let mut out = b"{\"key\":".to_vec();
    json_string(&mut out, key);
    out.extend_from_slice(b",\"value\":");
    match state.get(&[b"contracts", address, b"storage", key]) {
        Some(value) => {
            json_string(&mut out, &value[..limit.min(value.len())]);
            out.extend_from_slice(
                format!(
                    ",\"size\":{},\"truncated\":{},\"limit\":{limit}}}",
                    value.len(),
                    value.len() > limit
                )
                .as_bytes(),
            );
        }
        None => out.extend_from_slice(b"null,\"size\":0,\"truncated\":false}"),
    }
    Ok(out)
}
pub fn read(kind: Read, state: &Snapshot, doc: &Document, params: &Value) -> Result<Vec<u8>> {
    match kind {
        Read::StorageDump => {
            return Err(Fault::new(
                -32601,
                b"program storage dump is disabled; query explicit keys",
            ))
        }
        Read::Storage => return storage(state, doc, params),
        Read::List => return list(state, doc, params),
        _ => (),
    }
    let address = require_address(doc, params, 0, "address")?;
    match kind {
        Read::Info => {
            let meta = store::meta(state, address)
                .map_err(unavailable)?
                .ok_or_else(|| not_found(b"contract not found"))?;
            row(state, address, &meta, true)
        }
        Read::Bytecode => {
            let encoded = store::bytecode(state, address)
                .ok_or_else(|| not_found(b"bytecode not found for address"))?;
            let meta = store::meta(state, address).map_err(unavailable)?;
            let hash = meta
                .as_ref()
                .map_or(b"".as_slice(), |meta| meta.code_hash.as_slice());
            let mut out = strings(&[
                (b"address", address),
                (b"bytecode", encoded),
                (b"code_hash", hash),
            ]);
            out.pop();
            out.extend_from_slice(format!(",\"size\":{}}}", encoded.len()).as_bytes());
            Ok(out)
        }
        _ => unreachable!("other reads returned before address projection"),
    }
}
pub fn derived_abi(
    state: &Snapshot,
    address: &[u8],
    point_ops: bool,
    keys: &octra_node_protocol::program_trust::Keys,
) -> Result<Vec<u8>> {
    let artifact =
        super::Artifact::load(state, &super::Journal::default(), address, point_ops, keys)
            .map_err(unavailable)?
            .ok_or_else(|| not_found(b"contract not found"))?;
    let methods = crate::circle_octb::methods(artifact.admitted().code());
    let mut out = b"{\"address\":".to_vec();
    json_string(&mut out, address);
    out.extend_from_slice(b",\"methods\":[");
    for (index, method) in methods.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        json_string(&mut out, &method.name);
        out.extend_from_slice(format!(",\"view\":{}}}", method.view).as_bytes());
    }
    out.extend_from_slice(
        format!(
            "],\"instruction_count\":{}}}",
            artifact.admitted().code().len()
        )
        .as_bytes(),
    );
    Ok(out)
}
