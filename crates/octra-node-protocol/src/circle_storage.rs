// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Circle storage authorization. Validation does not normalize stored bytes.
use crate::{native_base64, native_integer::parse_int64, transaction::is_valid_address};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub key: Vec<u8>,
    pub detail: Vec<u8>,
}
impl Error {
    fn new(code: impl Into<String>, key: &[u8], detail: &[u8]) -> Self {
        Self {
            code: code.into(),
            key: key.to_vec(),
            detail: detail.to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.code,
            String::from_utf8_lossy(&self.key),
            String::from_utf8_lossy(&self.detail)
        )
    }
}
impl std::error::Error for Error {}

fn trim(raw: &[u8]) -> &[u8] {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 12);
    let start = raw.iter().position(|b| !space(b)).unwrap_or(raw.len());
    let end = raw.iter().rposition(|b| !space(b)).map_or(start, |i| i + 1);
    &raw[start..end]
}
fn hex64(raw: &[u8]) -> bool {
    raw.len() == 64 && raw.iter().all(u8::is_ascii_hexdigit)
}
fn boolean(raw: &[u8]) -> bool {
    [b"0".as_slice(), b"1", b"false", b"true", b"no", b"yes"]
        .iter()
        .any(|v| raw.eq_ignore_ascii_case(v))
}
const RESERVED: &[&[u8]] = &[
    b"object_policy:",
    b"object_binding:",
    b"object_member:",
    b"object_transition:",
    b"balance_binding:",
    b"register_binding:",
    b"balance_cell:",
    b"balance_workflow:",
    b"register_cell:",
    b"register_workflow:",
    b"state_descriptor:",
    b"transport_policy:",
    b"hfhe_policy:",
    b"key_policy:",
    b"mailbox:",
    b"outbox:",
    b"ingress:",
];
fn reserved(key: &[u8]) -> Result<(), Error> {
    match RESERVED.iter().find(|p| key.starts_with(p)) {
        Some(prefix) => Err(Error::new(
            "circle_runtime_reserved_storage_key",
            key,
            prefix,
        )),
        None => Ok(()),
    }
}
#[derive(Clone, Copy)]
enum ValueKind {
    Text,
    Integer,
    Natural,
    Boolean,
    Hex,
    OptionalHex,
    Address,
    OptionalAddress,
    Commitment,
    Proof,
    Transition,
    StateClass,
    Hfhe,
}
impl ValueKind {
    fn accepts(self, raw: &[u8]) -> bool {
        let v = trim(raw);
        match self {
            Self::Text => !v.is_empty(),
            Self::Integer => parse_int64(v).is_some(),
            Self::Natural => parse_int64(v).is_some_and(|n| n >= 0),
            Self::Boolean => boolean(v),
            Self::Hex => hex64(v),
            Self::OptionalHex => v.is_empty() || hex64(v),
            Self::Address => is_valid_address(v),
            Self::OptionalAddress => v.is_empty() || is_valid_address(v),
            Self::Commitment => {
                !v.is_empty() && native_base64::decode(v).is_ok_and(|b| b.len() == 32)
            }
            Self::Proof => matches!(
                v,
                b"none"
                    | b"zero_receipt_v1"
                    | b"range_v1"
                    | b"range_receipt_v1"
                    | b"bound_zero_v1"
                    | b"bound_zero_receipt_v1"
            ),
            Self::Transition => matches!(v, b"open" | b"proof_required" | b"frozen"),
            Self::StateClass => matches!(
                v,
                b"opaque_cell"
                    | b"cipher_cell"
                    | b"balance_cell"
                    | b"register_cell"
                    | b"program_object"
            ),
            Self::Hfhe => matches!(
                v,
                b"none"
                    | b"ciphertext_v1"
                    | b"balance_cell_v1"
                    | b"register_cell_v1"
                    | b"commit_bound_v1"
            ),
        }
    }
}
// Keep fields grouped by their native record type for source review.
#[allow(clippy::match_same_arms)]
fn kind(prefix: &[u8], suffix: &[u8]) -> Option<ValueKind> {
    use ValueKind::{
        Address, Boolean, Commitment, Hex, Hfhe, Integer, Natural, OptionalAddress, OptionalHex,
        Proof, StateClass, Text, Transition,
    };
    Some(match (prefix, suffix) {
        (b"slot_policy" | b"state_policy", b"delivery_key_id") => Text,
        (b"slot_policy" | b"state_policy", b"activate_after_epoch" | b"expire_after_epoch") => {
            Integer
        }
        (b"slot_policy" | b"state_policy", b"tombstone" | b"revoked") => Boolean,
        (b"state_descriptor", b"state_class") => StateClass,
        (b"state_descriptor", b"codec") => Text,
        (b"state_descriptor", b"schema_hash") => OptionalHex,
        (b"state_descriptor", b"subject_addr") => OptionalAddress,
        (b"state_descriptor", b"hfhe_profile") => Hfhe,
        (b"state_descriptor", b"mutable_state") => Boolean,
        (b"object_policy", b"delivery_key_id") => Text,
        (b"object_policy", b"activate_after_epoch" | b"expire_after_epoch" | b"member_quorum") => {
            Natural
        }
        (
            b"object_policy",
            b"tombstone" | b"revoked" | b"allow_detach" | b"allow_root_state_rotation",
        ) => Boolean,
        (b"object_policy", b"transition_mode") => Transition,
        (b"object_policy", b"required_proof_kind") => Proof,
        (b"object_binding" | b"balance_binding" | b"register_binding", b"current_state_ref") => Hex,
        (b"object_binding" | b"balance_binding" | b"register_binding", b"version") => Natural,
        (b"object_binding" | b"balance_binding" | b"register_binding", b"status") => Text,
        (b"object_binding", b"last_transition_ref") => Hex,
        (b"balance_binding" | b"register_binding", b"last_workflow_ref") => Hex,
        (b"object_member", b"state_ref") => Hex,
        (b"object_member", b"member_kind" | b"state_class" | b"codec" | b"status") => Text,
        (
            b"object_transition",
            b"object_ref"
            | b"touched_members_hash"
            | b"proof_receipt_hash"
            | b"intent_id"
            | b"previous_state_ref"
            | b"next_state_ref",
        ) => Hex,
        (b"object_transition", b"proof_kind") => Proof,
        (b"object_transition", b"status") => Text,
        (b"balance_cell" | b"register_cell", b"ciphertext_commitment") => Commitment,
        (b"balance_cell", b"amount_commitment") => Commitment,
        (b"balance_cell" | b"register_cell", b"proof_kind") => Proof,
        (b"balance_cell" | b"register_cell", b"proof_receipt_hash") => Hex,
        (b"balance_workflow", b"flow_kind" | b"status") => Text,
        (b"balance_workflow", b"debit_subject_addr" | b"credit_subject_addr") => Address,
        (
            b"balance_workflow",
            b"debit_state_ref" | b"credit_state_ref" | b"proof_receipt_hash" | b"intent_id",
        ) => Hex,
        (b"balance_workflow", b"amount_commitment") => Commitment,
        (b"balance_workflow" | b"register_workflow", b"proof_kind") => Proof,
        (
            b"register_workflow",
            b"register_ref"
            | b"proof_receipt_hash"
            | b"intent_id"
            | b"previous_state_ref"
            | b"next_state_ref",
        ) => Hex,
        (b"register_workflow", b"workflow_kind" | b"status") => Text,
        _ => return None,
    })
}

pub fn validate_write(key: &[u8], value: &[u8]) -> Result<(), Error> {
    let parts: Vec<_> = key.split(|b| *b == b':').collect();
    let prefix = parts[0];
    // A bare reserved word is an ordinary application key in the native runtime.
    if parts.len() == 1
        || !matches!(
            prefix,
            b"slot_policy"
                | b"state_policy"
                | b"state_descriptor"
                | b"object_policy"
                | b"object_binding"
                | b"object_member"
                | b"object_transition"
                | b"balance_binding"
                | b"register_binding"
                | b"balance_cell"
                | b"balance_workflow"
                | b"register_cell"
                | b"register_workflow"
        )
    {
        return reserved(key);
    }
    let name = if matches!(prefix, b"slot_policy" | b"state_policy") {
        b"object_policy".as_slice()
    } else {
        prefix
    };
    let error = |what: &str, detail: &[u8]| {
        Error::new(
            format!(
                "circle_runtime_invalid_{}_{what}",
                String::from_utf8_lossy(name)
            ),
            key,
            detail,
        )
    };
    let member = prefix == b"object_member";
    if parts.len() != if member { 4 } else { 3 } {
        return Err(error("key", b"shape"));
    }
    let id = parts[1];
    let (id_ok, label): (bool, &[u8]) = match prefix {
        b"slot_policy" | b"state_policy" | b"state_descriptor" | b"balance_cell"
        | b"register_cell" => (hex64(id), b"path_key"),
        b"balance_binding" => (is_valid_address(id), b"subject_addr"),
        b"object_member" => (hex64(trim(id)) && !trim(parts[2]).is_empty(), b"shape"),
        b"object_transition" => (hex64(trim(id)), b"transition_ref"),
        b"register_binding" => (hex64(trim(id)), b"register_ref"),
        b"balance_workflow" | b"register_workflow" => (hex64(trim(id)), b"workflow_ref"),
        _ => (hex64(trim(id)), b"object_ref"),
    };
    if !id_ok {
        return Err(error("key", label));
    }
    let suffix = parts[parts.len() - 1];
    let kind = kind(prefix, suffix).ok_or_else(|| error("key", suffix))?;
    if kind.accepts(value) {
        Ok(())
    } else {
        Err(error("value", suffix))
    }
}

pub fn validate_delete(key: &[u8]) -> Result<(), Error> {
    let prefix = key.split(|b| *b == b':').next().unwrap_or_default();
    if key.contains(&b':')
        && matches!(
            prefix,
            b"slot_policy"
                | b"state_policy"
                | b"object_policy"
                | b"object_binding"
                | b"object_member"
                | b"object_transition"
                | b"balance_binding"
                | b"register_binding"
                | b"balance_cell"
                | b"balance_workflow"
                | b"register_cell"
                | b"register_workflow"
        )
    {
        Ok(())
    } else {
        reserved(key)
    }
}

pub use crate::native_table::string_hash;
pub type StorageTable = crate::native_table::Table<Vec<u8>>;
impl StorageTable {
    pub fn validate(&self) -> Result<(), Error> {
        for key in self.keys() {
            validate_write(key, &self.values()[key])?;
        }
        Ok(())
    }
}

// Sorting the union is required by the active consensus rule.
#[allow(clippy::needless_collect)]
pub fn validate_delta(
    before: &StorageTable,
    after: &StorageTable,
    proof_active: bool,
) -> Result<(), Error> {
    let validate = |key: &[u8]| {
        let previous = before.values().get(key);
        let next = after.values().get(key);
        if previous == next {
            return Ok(());
        }
        if proof_active {
            if let Some(prefix) = [b"balance_cell:".as_slice(), b"register_cell:"]
                .into_iter()
                .find(|p| key.starts_with(p))
            {
                return Err(Error::new("circle_runtime_cell_write_denied", key, prefix));
            }
        }
        match next {
            Some(value) => validate_write(key, value),
            None => validate_delete(key),
        }
    };
    if proof_active {
        for key in before
            .values()
            .keys()
            .chain(after.values().keys())
            .collect::<BTreeSet<_>>()
        {
            validate(key)?;
        }
    } else {
        let mut seen = BTreeSet::new();
        for key in before.keys().chain(after.keys()) {
            if seen.insert(key) {
                validate(key)?;
            }
        }
    }
    Ok(())
}
