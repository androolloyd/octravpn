// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use crate::{
    native_json::{Document, Value},
    program_attestation::{field, text},
    transaction::json_string,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Int,
    Bool,
    String,
    Bytes,
    Bytes32,
    U64,
    U128,
    U256,
    Addr,
    Cipher,
    PubKey,
    Unknown,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Bool => "bool",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Bytes32 => "bytes32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::U256 => "u256",
            Self::Addr => "address",
            Self::Cipher => "cipher",
            Self::PubKey => "pubkey",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(raw: &[u8]) -> Option<Self> {
        Some(match raw {
            b"int" => Self::Int,
            b"bool" => Self::Bool,
            b"string" => Self::String,
            b"bytes" => Self::Bytes,
            b"bytes32" => Self::Bytes32,
            b"u64" => Self::U64,
            b"u128" => Self::U128,
            b"u256" => Self::U256,
            b"address" => Self::Addr,
            b"cipher" => Self::Cipher,
            b"pubkey" => Self::PubKey,
            b"unknown" => Self::Unknown,
            _ => return None,
        })
    }
    pub fn numeric(self) -> bool {
        matches!(self, Self::Int | Self::U64 | Self::U128 | Self::U256)
    }
    pub fn text(self) -> bool {
        matches!(self, Self::String | Self::Bytes | Self::Bytes32)
    }
    pub fn address(self) -> bool {
        matches!(self, Self::String | Self::Addr)
    }
    pub fn scalar(self) -> bool {
        self.numeric() || self.text() || self.address() || self == Self::Bool
    }
    pub fn same(self, other: Self) -> bool {
        self != Self::Unknown
            && other != Self::Unknown
            && (self == other || self.numeric() && other.numeric())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    View,
    StorageRead,
    StorageWrite,
    Transfer,
    Deploy,
    Fhe,
}
impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::Transfer => "transfer",
            Self::Deploy => "deploy",
            Self::Fhe => "fhe",
        }
    }
    fn parse(raw: &[u8]) -> Option<Self> {
        Some(match raw {
            b"view" => Self::View,
            b"storage_read" => Self::StorageRead,
            b"storage_write" => Self::StorageWrite,
            b"transfer" => Self::Transfer,
            b"deploy" => Self::Deploy,
            b"fhe" => Self::Fhe,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub target: i64,
    pub memory: Vec<(i64, Kind)>,
    pub effects: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub owner: i64,
    pub pc: i64,
    pub target: i64,
    pub kind: Kind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xcall {
    pub pc: i64,
    pub method: Vec<u8>,
    pub inputs: Vec<Kind>,
    pub output: Kind,
    pub capabilities: Vec<Capability>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    pub root: Vec<(i64, Kind)>,
    pub storage: Vec<(Vec<u8>, Kind)>,
    pub entries: Vec<Entry>,
    pub calls: Vec<Call>,
    pub xcalls: Vec<Xcall>,
}
fn list<T>(
    doc: &Document,
    value: &Value,
    mut read: impl FnMut(&Value) -> Option<T>,
) -> Option<Vec<T>> {
    let Value::List(values) = value else {
        return None;
    };
    values.iter().map(|id| read(doc.get(*id)?)).collect()
}
fn integer(doc: &Document, value: &Value, name: &[u8]) -> Option<i64> {
    match field(doc, value, name)? {
        Value::Int(v) => Some(v.get()),
        _ => None,
    }
}
fn kind(doc: &Document, value: &Value, name: &[u8]) -> Option<Kind> {
    Kind::parse(text(doc, value, name)?)
}
fn pairs(doc: &Document, value: &Value) -> Option<Vec<(i64, Kind)>> {
    let mut seen = BTreeSet::new();
    list(doc, value, |v| {
        let slot = integer(doc, v, b"slot")?;
        let kind = kind(doc, v, b"kind")?;
        (slot >= 0 && seen.insert(slot)).then_some((slot, kind))
    })
}
pub(super) fn strings(doc: &Document, value: &Value) -> Option<Vec<Vec<u8>>> {
    list(doc, value, |v| match v {
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    })
}
impl Facts {
    pub fn parse(doc: &Document, value: &Value) -> Option<Self> {
        let root = pairs(doc, field(doc, value, b"root")?)?;
        let mut seen = BTreeSet::new();
        let entries = list(doc, field(doc, value, b"entries")?, |v| {
            let target = integer(doc, v, b"target")?;
            if target < 0 || !seen.insert(target) {
                return None;
            }
            Some(Entry {
                target,
                memory: pairs(doc, field(doc, v, b"memory")?)?,
                effects: strings(doc, field(doc, v, b"effects")?)?,
            })
        })?;
        let mut seen = BTreeSet::new();
        let calls = list(doc, field(doc, value, b"calls")?, |v| {
            let owner = integer(doc, v, b"owner")?;
            let pc = integer(doc, v, b"pc")?;
            let target = integer(doc, v, b"target")?;
            (owner >= 0 && pc >= 0 && target >= 0 && seen.insert(pc)).then(|| {
                Some(Call {
                    owner,
                    pc,
                    target,
                    kind: kind(doc, v, b"kind")?,
                })
            })?
        })?;
        let mut seen = BTreeSet::new();
        let storage = match field(doc, value, b"storage") {
            None => vec![],
            Some(raw) => list(doc, raw, |v| {
                let key = text(doc, v, b"key")?;
                let kind = kind(doc, v, b"kind")?;
                (!key.is_empty() && kind != Kind::Unknown && seen.insert(key.to_vec()))
                    .then(|| (key.to_vec(), kind))
            })?,
        };
        let mut seen = BTreeSet::new();
        let xcalls = match field(doc, value, b"xcalls") {
            None => vec![],
            Some(raw) => list(doc, raw, |v| {
                let pc = integer(doc, v, b"pc")?;
                let method = text(doc, v, b"method")?;
                if pc < 0 || method.is_empty() || !seen.insert(pc) {
                    return None;
                }
                let inputs = list(doc, field(doc, v, b"inputs")?, |v| match v {
                    Value::String(raw) => Kind::parse(raw).filter(|k| *k != Kind::Unknown),
                    _ => None,
                })?;
                let capabilities = list(doc, field(doc, v, b"capabilities")?, |v| match v {
                    Value::String(raw) => Capability::parse(raw),
                    _ => None,
                })?;
                Some(Xcall {
                    pc,
                    method: method.to_vec(),
                    inputs,
                    output: kind(doc, v, b"output")?,
                    capabilities,
                })
            })?,
        };
        Some(Self {
            root,
            storage,
            entries,
            calls,
            xcalls,
        })
    }
    /// Exact native field/list order, distinct from sorted attestation JSON.
    pub fn canonical(&self) -> Vec<u8> {
        self.encode(true)
    }
    /// Compiler certificate projection preserves input fact order; XCALL rows
    /// are sorted in both native representations.
    pub fn json(&self) -> Vec<u8> {
        self.encode(false)
    }
    fn encode(&self, normalize: bool) -> Vec<u8> {
        fn pairs(out: &mut Vec<u8>, values: &[(i64, Kind)], normalize: bool) {
            let mut values = values.to_vec();
            if normalize {
                values.sort_by_key(|(slot, _)| *slot);
            }
            out.push(b'[');
            for (index, (slot, kind)) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(format!("{{\"slot\":{slot},\"kind\":").as_bytes());
                json_string(out, kind.name().as_bytes());
                out.push(b'}');
            }
            out.push(b']');
        }
        fn names<'a>(out: &mut Vec<u8>, names: impl IntoIterator<Item = &'a [u8]>) {
            out.push(b'[');
            for (index, name) in names.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                json_string(out, name);
            }
            out.push(b']');
        }
        let mut out = b"{".to_vec();
        if !self.storage.is_empty() {
            out.extend(b"\"storage\":[");
            let mut storage = self.storage.iter().collect::<Vec<_>>();
            if normalize {
                storage.sort_by(|a, b| a.0.cmp(&b.0));
            }
            for (index, (key, kind)) in storage.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(b"{\"key\":");
                json_string(&mut out, key);
                out.extend(b",\"kind\":");
                json_string(&mut out, kind.name().as_bytes());
                out.push(b'}');
            }
            out.extend(b"],");
        }
        out.extend(b"\"root\":");
        pairs(&mut out, &self.root, normalize);
        out.extend(b",\"entries\":[");
        let mut entries = self.entries.iter().collect::<Vec<_>>();
        if normalize {
            entries.sort_by_key(|e| e.target);
        }
        for (index, entry) in entries.into_iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend(format!("{{\"target\":{},\"memory\":", entry.target).as_bytes());
            pairs(&mut out, &entry.memory, normalize);
            out.extend(b",\"effects\":");
            names(&mut out, entry.effects.iter().map(Vec::as_slice));
            out.push(b'}');
        }
        out.extend(b"],\"calls\":[");
        let mut calls = self.calls.iter().collect::<Vec<_>>();
        if normalize {
            calls.sort_by_key(|c| c.pc);
        }
        for (index, call) in calls.into_iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend(
                format!(
                    "{{\"owner\":{},\"pc\":{},\"target\":{},\"kind\":",
                    call.owner, call.pc, call.target
                )
                .as_bytes(),
            );
            json_string(&mut out, call.kind.name().as_bytes());
            out.push(b'}');
        }
        out.extend(b"],\"xcalls\":[");
        let mut calls = self.xcalls.iter().collect::<Vec<_>>();
        calls.sort_by_key(|c| c.pc);
        for (index, call) in calls.into_iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend(format!("{{\"pc\":{},\"method\":", call.pc).as_bytes());
            json_string(&mut out, &call.method);
            out.extend(b",\"inputs\":");
            names(&mut out, call.inputs.iter().map(|k| k.name().as_bytes()));
            out.extend(b",\"output\":");
            json_string(&mut out, call.output.name().as_bytes());
            out.extend(b",\"capabilities\":");
            names(
                &mut out,
                call.capabilities.iter().map(|c| c.name().as_bytes()),
            );
            out.push(b'}');
        }
        out.extend(b"]}");
        out
    }
    pub fn hash(&self) -> Vec<u8> {
        hex::encode(Sha256::digest(self.canonical())).into_bytes()
    }
}
