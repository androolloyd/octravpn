// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{rejected, Error, Result};
use octra_node_protocol::{
    native_json::{Document, Value},
    transaction::{RuleMode, Transaction},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Migration {
    Standard,
    Rebinding,
    Public,
    Commitment,
    Zero,
    Owner,
    Cipher,
}
impl Migration {
    fn parse(raw: &[u8]) -> Result<Self> {
        Ok(match raw {
            b"standard" => Self::Standard,
            b"rejected_rebinding" => Self::Rebinding,
            b"public_history" => Self::Public,
            b"commitment_history" => Self::Commitment,
            b"verified_zero_reset" => Self::Zero,
            b"historical_owner_proof" => Self::Owner,
            b"cipher_proof" => Self::Cipher,
            _ => {
                return Err(rejected(
                    [b"unknown key_switch migration_mode = ".as_slice(), raw].concat(),
                ))
            }
        })
    }
    pub(super) fn needs_audit(self, cipher: RuleMode) -> bool {
        matches!(
            self,
            Self::Rebinding | Self::Public | Self::Commitment | Self::Owner
        ) || self == Self::Zero && cipher == RuleMode::Active
    }
}
pub(super) struct Payload {
    pub new_key: Vec<u8>,
    pub kat: Vec<u8>,
    pub migration: Migration,
    pub old_key: Option<Vec<u8>>,
    pub old_cipher: Option<Vec<u8>>,
    pub source_hash: Option<Vec<u8>>,
    pub new_cipher: Option<Vec<u8>>,
    pub old_proof: Option<Vec<u8>>,
    pub new_proof: Option<Vec<u8>>,
    pub commitment: Option<Vec<u8>>,
    pub blinding: Option<Vec<u8>>,
    pub range: Option<Vec<u8>>,
}
fn document(tx: &Transaction) -> Result<Document> {
    let raw = tx
        .encrypted_data
        .as_deref()
        .ok_or_else(|| rejected("key_switch: missing encrypted_data"))?;
    Document::parse(raw).map_err(|error| match error {
        octra_node_protocol::native_json::Error::Allocation => {
            Error::Unavailable(error.to_string())
        }
        octra_node_protocol::native_json::Error::Syntax(_) => {
            rejected("key_switch: malformed encrypted_data")
        }
    })
}
fn value<'a>(doc: &'a Document, name: &[u8], mode: RuleMode) -> Result<Option<&'a Value>> {
    let Value::Object(fields) = doc.root() else {
        return Err(rejected("encrypted_data must be a JSON object"));
    };
    if mode == RuleMode::Active && fields.iter().filter(|(key, _)| key == name).count() > 1 {
        return Err(rejected([b"duplicate ".as_slice(), name].concat()));
    }
    Ok(doc.field(doc.root(), name))
}
fn text(doc: &Document, name: &[u8], mode: RuleMode, required: bool) -> Result<Option<Vec<u8>>> {
    match value(doc, name, mode)? {
        None | Some(Value::Null) if !required => Ok(None),
        None | Some(Value::Null) => Err(rejected([b"missing ".as_slice(), name].concat())),
        Some(Value::String(raw)) => Ok(Some(raw.clone())),
        _ => Err(rejected([name, b" must be a string"].concat())),
    }
}
fn migration(doc: &Document, mode: RuleMode) -> Result<Migration> {
    let requested = text(doc, b"migration_mode", mode, false)?;
    let mut selected = Vec::new();
    for (name, kind) in [
        (b"legacy_ct_migration".as_slice(), Migration::Rebinding),
        (b"legacy_public_migration", Migration::Public),
        (b"legacy_commitment_migration", Migration::Commitment),
        (b"legacy_zero_reset", Migration::Zero),
    ] {
        match value(doc, name, mode)? {
            Some(Value::Bool(true)) => selected.push(kind),
            None | Some(Value::Null | Value::Bool(false)) => (),
            _ => return Err(rejected([name, b" must be a boolean"].concat())),
        }
    }
    if selected.len() > 1 {
        return Err(rejected(
            "key_switch migration modes are mutually exclusive",
        ));
    }
    match (requested, selected.first()) {
        (None, Some(kind)) => Ok(*kind),
        (None, None) => Ok(Migration::Standard),
        (Some(raw), None) => Migration::parse(&raw),
        (Some(_), Some(_)) => Err(rejected(
            "migration_mode cannot be mixed with legacy migration fields",
        )),
    }
}
impl Payload {
    pub(super) fn parse(tx: &Transaction, mode: RuleMode) -> Result<Self> {
        Self::parse_inner(tx, mode).map_err(|mut error| {
            if let Error::Rejected(failure) = &mut error {
                failure.user_reason =
                    b"encrypted_data must be JSON with new_pubkey and aes_kat".to_vec();
            }
            error
        })
    }
    fn parse_inner(tx: &Transaction, mode: RuleMode) -> Result<Self> {
        let doc = document(tx)?;
        let new_key = text(&doc, b"new_pubkey", mode, true)?.expect("required field");
        let kat = text(&doc, b"aes_kat", mode, true)?.expect("required field");
        let migration = migration(&doc, mode)?;
        Ok(Self {
            new_key,
            kat,
            migration,
            old_key: text(&doc, b"old_bound_pubkey", mode, false)?,
            old_cipher: text(&doc, b"old_bound_cipher", mode, false)?,
            source_hash: text(&doc, b"source_cipher_hash", mode, false)?,
            new_cipher: text(&doc, b"new_cipher", mode, false)?,
            old_proof: text(&doc, b"old_zero_proof", mode, false)?,
            new_proof: text(&doc, b"new_zero_proof", mode, false)?,
            commitment: text(&doc, b"amount_commitment", mode, false)?,
            blinding: text(&doc, b"amount_blinding", mode, false)?,
            range: if migration == Migration::Cipher {
                text(&doc, b"new_range_proof", mode, false)?
            } else {
                None
            },
        })
    }
    /// Native activation admission examines the selector before the remaining
    /// payload fields, preserving its refusal priority for disabled modes.
    pub(super) fn cipher_selected(tx: &Transaction, mode: RuleMode) -> bool {
        let selected = || {
            let doc = document(tx)?;
            text(&doc, b"new_pubkey", mode, true)?;
            text(&doc, b"aes_kat", mode, true)?;
            migration(&doc, mode)
        };
        matches!(selected(), Ok(Migration::Cipher))
    }
}
