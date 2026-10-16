// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native contracts/ metadata, bytecode, ABI and immediate storage entries.
use super::{Error, Result};
use crate::state_batch::{Snapshot, StateBatch};
use octra_node_protocol::{
    circle_storage::StorageTable,
    native_json::{Document, ReadError, ReadMode, Value},
    transaction::json_string,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub address: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub version: Vec<u8>,
    pub owner: Vec<u8>,
    pub ctype: Vec<u8>,
    pub admission: Vec<u8>,
}
fn object(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
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
impl Meta {
    pub fn encode(&self) -> Vec<u8> {
        object(&[
            (b"address", &self.address),
            (b"code_hash", &self.code_hash),
            (b"version", &self.version),
            (b"owner", &self.owner),
            (b"ctype", &self.ctype),
            (b"admission", &self.admission),
        ])
    }
    pub fn abi(&self) -> Vec<u8> {
        object(&[
            (b"contract_type", &self.ctype),
            (b"address", &self.address),
            (b"deployer", &self.owner),
            (b"version", &self.version),
        ])
    }
    pub fn parse(raw: &[u8]) -> Result<Option<Self>> {
        let doc = match Document::parse_native(raw, ReadMode::Safe) {
            Ok(doc) => doc,
            Err(ReadError::Json { .. }) => return Ok(None),
            Err(ReadError::Unavailable(error)) => return Err(Error::unavailable(error)),
        };
        let string = |key: &[u8]| match doc.field(doc.root(), key) {
            Some(Value::String(value)) => Some(value.as_slice()),
            _ => None,
        };
        let (Some(address), Some(code_hash), Some(version), Some(owner)) = (
            string(b"address"),
            string(b"code_hash"),
            string(b"version"),
            string(b"owner"),
        ) else {
            return Ok(None);
        };
        Ok(Some(Self {
            address: address.to_vec(),
            code_hash: code_hash.to_vec(),
            version: version.to_vec(),
            owner: owner.to_vec(),
            ctype: string(b"ctype").unwrap_or(b"CUSTOM").to_vec(),
            admission: string(b"admission").unwrap_or(b"binary").to_vec(),
        }))
    }
}
pub fn meta(state: &Snapshot, address: &[u8]) -> Result<Option<Meta>> {
    state
        .get(&[b"contracts", address, b"meta"])
        .map_or(Ok(None), Meta::parse)
}
pub fn exists(state: &Snapshot, address: &[u8]) -> bool {
    state.get(&[b"contracts", address, b"meta"]).is_some()
}
pub fn bytecode<'a>(state: &'a Snapshot, address: &[u8]) -> Option<&'a [u8]> {
    state.get(&[b"contracts", address, b"bytecode"])
}
pub fn storage(state: &Snapshot, address: &[u8]) -> StorageTable {
    let mut values = StorageTable::new(100);
    for (key, value) in state.entries(&[b"contracts", address, b"storage"]) {
        values.replace(key.to_vec(), value.to_vec());
    }
    values
}
pub fn save_storage(state: &mut StateBatch, address: &[u8], values: &StorageTable) -> Result<()> {
    let previous = storage(&state.snapshot(), address);
    for key in previous
        .values()
        .keys()
        .filter(|key| !values.values().contains_key(*key))
    {
        state
            .remove(&[b"contracts", address, b"storage", key])
            .map_err(Error::unavailable)?;
    }
    for (key, value) in values.values() {
        if previous.get(key) != Some(value) {
            state
                .set(&[b"contracts", address, b"storage", key], value.clone())
                .map_err(Error::unavailable)?;
        }
    }
    Ok(())
}
pub fn deploy(state: &mut StateBatch, meta: &Meta, encoded: &[u8]) -> Result<()> {
    state
        .set(&[b"contracts", &meta.address, b"meta"], meta.encode())
        .map_err(Error::unavailable)?;
    state
        .set(
            &[b"contracts", &meta.address, b"bytecode"],
            encoded.to_vec(),
        )
        .map_err(Error::unavailable)
}
pub fn save_abi(state: &mut StateBatch, meta: &Meta) -> Result<()> {
    state
        .set(&[b"contracts", &meta.address, b"abi"], meta.abi())
        .map_err(Error::unavailable)
}
pub fn upgrade(state: &mut StateBatch, next: &Meta, expected: &[u8], encoded: &[u8]) -> Result<()> {
    let current = meta(&state.snapshot(), &next.address)?
        .ok_or_else(|| Error::rejected("program not found"))?;
    if current.owner != next.owner {
        return Err(Error::rejected("program owner changed"));
    }
    if current.code_hash != expected {
        return Err(Error::rejected("program code hash changed"));
    }
    deploy(state, next, encoded)
}
