// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::Zero;
use octra_node_protocol::{
    circle_wasm::codec::Scalar,
    native_integer::parse_integer,
    octb::{StorageKind, Value as Constant},
    transaction::{is_valid_address, json_string},
};
use std::{borrow::Cow, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub scope: Vec<u8>,
    pub kind: i64,
    pub id: i64,
    pub revision: i64,
}
impl Capability {
    pub fn matches(&self, kind: &BigInt) -> bool {
        self.scope.len() == 32
            && [self.kind, self.id, self.revision]
                .iter()
                .all(|v| (0..=1_000_000).contains(v))
            && *kind == BigInt::from(self.kind)
    }
}
#[derive(Clone)]
pub enum Value {
    Int(Arc<BigInt>),
    Bool(bool),
    String(Arc<[u8]>),
    Bytes(Arc<[u8]>),
    Bytes32(Arc<[u8]>),
    U64(Arc<BigInt>),
    U128(Arc<BigInt>),
    U256(Arc<BigInt>),
    Address(Arc<[u8]>),
    Capability(Capability),
    Cipher(Arc<octra_hfhe::cipher::Cipher>),
    PublicKey(Arc<octra_hfhe::keys::PublicKey>),
}
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(a), Self::Int(b))
            | (Self::U64(a), Self::U64(b))
            | (Self::U128(a), Self::U128(b))
            | (Self::U256(a), Self::U256(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::String(a), Self::String(b))
            | (Self::Bytes(a), Self::Bytes(b))
            | (Self::Bytes32(a), Self::Bytes32(b))
            | (Self::Address(a), Self::Address(b)) => a == b,
            (Self::Capability(a), Self::Capability(b)) => a == b,
            (Self::Cipher(a), Self::Cipher(b)) => Arc::ptr_eq(a, b),
            (Self::PublicKey(a), Self::PublicKey(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}
impl Eq for Value {}
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Int(_) => "Int",
            Self::Bool(_) => "Bool",
            Self::String(_) => "String",
            Self::Bytes(_) => "Bytes",
            Self::Bytes32(_) => "Bytes32",
            Self::U64(_) => "U64",
            Self::U128(_) => "U128",
            Self::U256(_) => "U256",
            Self::Address(_) => "Address",
            Self::Capability(_) => "Capability",
            Self::Cipher(_) => "Cipher",
            Self::PublicKey(_) => "PublicKey",
        };
        f.debug_tuple(kind).field(&self.text()).finish()
    }
}
impl Default for Value {
    fn default() -> Self {
        Self::int(0)
    }
}
impl Value {
    /// Native Receipt_view.return_json, preserving OCaml string bytes.
    pub fn result_json(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Bool(true) => out.extend_from_slice(b"true"),
            Self::Bool(false) => out.extend_from_slice(b"false"),
            Self::Capability(_) => out.extend_from_slice(b"null"),
            Self::Bytes(v) | Self::Bytes32(v) => {
                json_string(&mut out, STANDARD.encode(v).as_bytes());
            }
            _ => json_string(&mut out, &self.text()),
        }
        out
    }
    /// Native WASM scalar-to-VM conversion; null is an empty string.
    pub fn from_scalar(value: &Scalar) -> Option<Self> {
        Some(match value {
            Scalar::Null => Self::string(vec![]),
            Scalar::Bool(v) => Self::Bool(*v),
            Scalar::String(v) => Self::string(v.clone()),
            Scalar::Integer(v) => Self::int(parse_integer(v)?),
        })
    }
    pub fn int(v: impl Into<BigInt>) -> Self {
        Self::Int(Arc::new(v.into()))
    }
    pub fn string(v: impl Into<Vec<u8>>) -> Self {
        Self::String(v.into().into())
    }
    pub fn from_constant(value: &Constant) -> Self {
        match value {
            Constant::Int(v) => Self::Int(v.clone()),
            Constant::Bool(v) => Self::Bool(*v),
            Constant::Str(v) => Self::String(v.clone()),
            Constant::Bytes(v) => Self::Bytes(v.clone()),
            Constant::Addr(v) => Self::Address(v.clone()),
        }
    }
    pub fn numeric(&self) -> bool {
        matches!(
            self,
            Self::Int(_) | Self::U64(_) | Self::U128(_) | Self::U256(_)
        )
    }
    pub fn is_text(&self) -> bool {
        matches!(self, Self::String(_) | Self::Bytes(_) | Self::Bytes32(_))
    }
    pub fn is_address(&self) -> bool {
        matches!(self, Self::String(_) | Self::Address(_))
    }
    pub fn scalar(&self) -> bool {
        self.numeric() || self.is_text() || self.is_address() || matches!(self, Self::Bool(_))
    }
    pub fn private(&self) -> bool {
        matches!(self, Self::Cipher(_) | Self::PublicKey(_))
    }
    pub fn number(&self) -> Cow<'_, BigInt> {
        match self {
            Self::Int(v) | Self::U64(v) | Self::U128(v) | Self::U256(v) => Cow::Borrowed(v),
            Self::Bool(v) => Cow::Owned(BigInt::from(u8::from(*v))),
            Self::String(v) => Cow::Owned(parse_integer(v).unwrap_or_default()),
            _ => Cow::Owned(BigInt::zero()),
        }
    }
    pub fn truth(&self) -> bool {
        match self {
            Self::Bool(v) => *v,
            Self::Int(v) => !v.is_zero(),
            Self::String(v) => !v.is_empty(),
            _ => false,
        }
    }
    pub fn text(&self) -> Cow<'_, [u8]> {
        match self {
            Self::String(v) | Self::Bytes(v) | Self::Bytes32(v) | Self::Address(v) => {
                Cow::Borrowed(v)
            }
            Self::Int(v) | Self::U64(v) | Self::U128(v) | Self::U256(v) => {
                Cow::Owned(v.to_string().into_bytes())
            }
            Self::Bool(true) => Cow::Borrowed(b"true"),
            Self::Bool(false) => Cow::Borrowed(b"false"),
            Self::Capability(_) => Cow::Borrowed(b"<cap>"),
            Self::Cipher(_) => Cow::Borrowed(b"<cipher>"),
            Self::PublicKey(_) => Cow::Borrowed(b"<pubkey>"),
        }
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::String(v) | Self::Bytes(v) | Self::Bytes32(v) => Some(v),
            _ => None,
        }
    }
    pub fn equal(&self, right: &Self) -> bool {
        match (self, right) {
            (Self::Cipher(a), Self::Cipher(b)) => Arc::ptr_eq(a, b),
            (Self::PublicKey(a), Self::PublicKey(b)) => Arc::ptr_eq(a, b),
            (a, b) if a.private() || b.private() => false,
            _ => self.text() == right.text(),
        }
    }
    pub fn comparable(&self, right: &Self) -> bool {
        self.numeric() && right.numeric()
            || matches!(
                (self, right),
                (Self::Bool(_), Self::Bool(_))
                    | (Self::String(_), Self::String(_))
                    | (Self::Bytes(_), Self::Bytes(_))
                    | (Self::Bytes32(_), Self::Bytes32(_))
                    | (Self::Address(_), Self::Address(_))
                    | (Self::Cipher(_), Self::Cipher(_))
                    | (Self::PublicKey(_), Self::PublicKey(_))
            )
    }
    pub fn add_operand(&self, right: &Self) -> bool {
        let decimal = |v: &Self| matches!(v,Self::String(s) if parse_integer(s).is_some());
        self.numeric() && right.numeric()
            || self.numeric() && self.number().is_zero() && decimal(right)
            || decimal(self) && right.numeric() && right.number().is_zero()
    }
    pub fn matches_storage(&self, kind: StorageKind) -> bool {
        match kind {
            StorageKind::Int => self.numeric(),
            StorageKind::Bool => matches!(self, Self::Bool(_)),
            StorageKind::String => matches!(self, Self::String(_)),
            StorageKind::Bytes => matches!(self, Self::Bytes(_)),
            StorageKind::Bytes32 => matches!(self, Self::Bytes32(_)),
            StorageKind::Addr => matches!(self, Self::Address(_)),
            StorageKind::U64 | StorageKind::U128 | StorageKind::U256 => {
                self.numeric() && unsigned(&self.number(), width(kind))
            }
        }
    }
    pub fn storage_default(kind: StorageKind) -> Self {
        match kind {
            StorageKind::Int => Self::default(),
            StorageKind::Bool => Self::Bool(false),
            StorageKind::String => Self::string(vec![]),
            StorageKind::Bytes => Self::Bytes(Arc::from([])),
            StorageKind::Bytes32 => Self::Bytes32(Arc::from([0; 32])),
            StorageKind::Addr => Self::Address(Arc::from([])),
            StorageKind::U64 => Self::U64(Arc::new(BigInt::zero())),
            StorageKind::U128 => Self::U128(Arc::new(BigInt::zero())),
            StorageKind::U256 => Self::U256(Arc::new(BigInt::zero())),
        }
    }
    pub fn decode_storage(kind: StorageKind, raw: &[u8]) -> Option<Self> {
        Some(match kind {
            StorageKind::Int => Self::int(parse_integer(raw)?),
            StorageKind::Bool => match raw {
                b"true" => Self::Bool(true),
                b"false" => Self::Bool(false),
                _ => return None,
            },
            StorageKind::String => Self::String(raw.into()),
            StorageKind::Bytes => Self::Bytes(raw.into()),
            StorageKind::Bytes32 if raw.len() == 32 => Self::Bytes32(raw.into()),
            StorageKind::Addr if is_valid_address(raw) => Self::Address(raw.into()),
            StorageKind::Bytes32 | StorageKind::Addr => return None,
            StorageKind::U64 | StorageKind::U128 | StorageKind::U256 => {
                let value = parse_integer(raw)?;
                if !unsigned(&value, width(kind)) {
                    return None;
                }
                let value = Arc::new(value);
                match kind {
                    StorageKind::U64 => Self::U64(value),
                    StorageKind::U128 => Self::U128(value),
                    _ => Self::U256(value),
                }
            }
        })
    }
}
fn width(kind: StorageKind) -> u64 {
    match kind {
        StorageKind::U64 => 64,
        StorageKind::U128 => 128,
        StorageKind::U256 => 256,
        _ => unreachable!(),
    }
}
fn unsigned(value: &BigInt, bits: u64) -> bool {
    value.sign() != num_bigint::Sign::Minus && value.bits() <= bits
}
