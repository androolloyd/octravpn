// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{fields::Fields, Result, Snapshot};
use crate::{
    circle_program::Refusal, native_integer::parse_int64, native_json::Document,
    network::endpoint::native_trim,
};
#[derive(Clone, Copy, Default, Debug)]
pub struct Policy {
    pub activate: Option<i64>,
    pub expire: Option<i64>,
    pub revoked: bool,
    pub erased: bool,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Scheduled,
    Live,
    Expired,
    Revoked,
    Erased,
}
impl State {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Scheduled => b"scheduled",
            Self::Live => b"live",
            Self::Expired => b"expired",
            Self::Revoked => b"revoked",
            Self::Erased => b"erased",
        }
    }
}
#[derive(Clone, Copy)]
pub enum Operation {
    Put(Policy),
    Grant {
        activate: Option<i64>,
        expire: Option<i64>,
    },
    Extend(i64),
    Revoke,
    Erase,
}
pub struct Payload {
    pub key_id: Vec<u8>,
    pub operation: Operation,
}
fn invalid(reason: &'static [u8]) -> Refusal {
    Refusal::new("invalid_circle_key_window", reason)
}
pub fn validate_window(activate: Option<i64>, expire: Option<i64>) -> Result<()> {
    if matches!((activate, expire), (Some(a), Some(e)) if e <= a) {
        return Err(invalid(
            b"expire_after_epoch must be greater than activate_after_epoch",
        ));
    }
    Ok(())
}
impl Payload {
    pub fn parse(doc: &Document, operation: &str) -> Result<Self> {
        let scope = match operation {
            "put" => "key policy",
            "grant" => "key grant",
            "extend" => "key extend",
            "revoke" => "key revoke",
            _ => "key erase",
        };
        let fields = Fields::new(doc, scope)?;
        if matches!(operation, "put" | "grant") {
            fields.integer_exceptions(&[
                ("activate_after_epoch", false),
                ("expire_after_epoch", false),
            ])?;
        }
        let key_id = fields.required("key_id")?;
        let operation = match operation {
            "put" | "grant" => {
                let activate = fields.number("activate_after_epoch", false)?;
                let expire = fields.number("expire_after_epoch", false)?;
                if operation == "put" {
                    Operation::Put(Policy {
                        activate,
                        expire,
                        revoked: fields.flag("revoked")?.unwrap_or(false),
                        erased: fields.flag("erased")?.unwrap_or(false),
                    })
                } else {
                    Operation::Grant { activate, expire }
                }
            }
            "extend" => {
                let raw = fields.required("expire_after_epoch")?;
                let expire = parse_int64(&raw).ok_or_else(|| {
                    Refusal::new(
                        "malformed_transaction_exception",
                        b"Failure(\"Int64.of_string\")",
                    )
                })?;
                Operation::Extend(expire)
            }
            "revoke" => Operation::Revoke,
            _ => Operation::Erase,
        };
        Ok(Self { key_id, operation })
    }
}
impl Policy {
    pub fn from_stored(mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Self {
        let integer = |raw: Option<Vec<u8>>| raw.and_then(|raw| parse_int64(native_trim(&raw)));
        let flag = |raw: Option<Vec<u8>>| {
            raw.is_some_and(|raw| {
                matches!(
                    native_trim(&raw).to_ascii_lowercase().as_slice(),
                    b"1" | b"true" | b"yes"
                )
            })
        };
        Self {
            activate: integer(get(b"activate_after_epoch")),
            expire: integer(get(b"expire_after_epoch")),
            revoked: flag(get(b"revoked")),
            erased: flag(get(b"erased")),
        }
    }
    pub fn state(self, epoch: i64) -> State {
        if self.erased {
            State::Erased
        } else if self.revoked {
            State::Revoked
        } else if self.expire.is_some_and(|e| epoch >= e) {
            State::Expired
        } else if self.activate.is_some_and(|a| epoch < a) {
            State::Scheduled
        } else {
            State::Live
        }
    }
    pub fn deliverable(self, epoch: i64, deadline: i64) -> bool {
        if matches!(
            self.state(epoch),
            State::Expired | State::Revoked | State::Erased
        ) {
            return false;
        }
        let activation = self.activate.unwrap_or(epoch);
        activation < deadline && self.expire.is_none_or(|e| e > epoch && e > activation)
    }
    pub fn apply(self, operation: &Operation, epoch: i64) -> Result<Self> {
        let erased = |reason: &'static [u8]| Refusal::new("circle_key_erased", reason);
        match *operation {
            Operation::Put(policy) => {
                validate_window(policy.activate, policy.expire)?;
                Ok(policy)
            }
            Operation::Grant { activate, expire } => {
                if self.erased {
                    return Err(erased(b"erased keys cannot be granted again"));
                }
                validate_window(activate, expire)?;
                if expire.is_some_and(|e| e <= epoch) && activate.is_none_or(|a| a <= epoch) {
                    return Err(invalid(b"expire_after_epoch must be in the future"));
                }
                Ok(Self {
                    activate,
                    expire,
                    revoked: false,
                    erased: false,
                })
            }
            Operation::Extend(expire) => {
                if self.erased {
                    return Err(erased(b"erased keys cannot be extended"));
                }
                if self.revoked {
                    return Err(Refusal::new(
                        "circle_key_revoked",
                        b"revoked keys must be granted again before extension",
                    ));
                }
                if expire <= self.activate.unwrap_or(epoch) {
                    return Err(invalid(
                        b"expire_after_epoch must be greater than activation epoch",
                    ));
                }
                if expire <= epoch {
                    return Err(invalid(b"expire_after_epoch must be in the future"));
                }
                Ok(Self {
                    expire: Some(expire),
                    ..self
                })
            }
            Operation::Revoke => {
                if self.erased {
                    return Err(erased(b"erased keys cannot be revoked again"));
                }
                Ok(Self {
                    revoked: true,
                    ..self
                })
            }
            Operation::Erase => Ok(Self {
                revoked: true,
                erased: true,
                ..self
            }),
        }
    }
    pub fn snapshot(self, key: &[u8]) -> Snapshot {
        let mut out = Snapshot::default();
        let prefix = [b"key_policy:".as_slice(), key].concat();
        out.set(
            &prefix,
            b"activate_after_epoch",
            self.activate.map(|v| v.to_string().into_bytes()),
        );
        out.set(
            &prefix,
            b"expire_after_epoch",
            self.expire.map(|v| v.to_string().into_bytes()),
        );
        out.set(&prefix, b"revoked", self.revoked.then(|| b"true".to_vec()));
        out.set(&prefix, b"erased", self.erased.then(|| b"true".to_vec()));
        out
    }
}
