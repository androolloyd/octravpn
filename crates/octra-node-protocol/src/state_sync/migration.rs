// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Migration entitlements are bound to the independently configured artifact
//! root. Exporter signatures alone cannot authorize a different entitlement set.
use super::{field, list, lower_hex, optional, require, text, Result};
use crate::{
    native_integer,
    native_json::{Document, Value},
    state::MAX_SUPPLY,
    transaction,
};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classifier {
    Prior,
    Capped,
    Receipt,
}
impl Classifier {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Prior => b"prior_v1",
            Self::Capped => b"capped_v1",
            Self::Receipt => b"receipt_v1",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audit {
    PublicClean,
    HiddenWitness,
    Poisoned,
}
impl Audit {
    fn name(self) -> &'static [u8] {
        match self {
            Self::PublicClean => b"public_clean",
            Self::HiddenWitness => b"hidden_witness",
            Self::Poisoned => b"poisoned",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub address: Vec<u8>,
    pub source_cipher_hash: Vec<u8>,
    pub total: i64,
    pub audit: Audit,
    pub can_public_migrate: bool,
    pub public_net: Option<BigInt>,
    pub commitment_net: Option<Vec<u8>>,
    pub blockers: Vec<Vec<u8>>,
    pub reason: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Admission {
    classifier: Option<Classifier>,
    chain_id: Vec<u8>,
    snapshot_epoch: i64,
    state_root: Vec<u8>,
    activation_epoch: i64,
    root: Vec<u8>,
    entries: BTreeMap<Vec<u8>, Entry>,
}
fn fields(value: &Value, expected: &[&[u8]], scope: &str) -> Result<()> {
    let Value::Object(rows) = value else {
        return Err(format!("migration {scope} must be an object").into());
    };
    let mut names = rows.iter().map(|(n, _)| n.as_slice()).collect::<Vec<_>>();
    names.sort_unstable();
    require(
        !names.windows(2).any(|w| w[0] == w[1]),
        &format!("duplicate migration field in {scope}"),
    )?;
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    require(
        names == expected,
        &format!("unexpected migration fields in {scope}"),
    )
}
fn integer(value: &Value) -> Result<i64> {
    match value {
        Value::Int(n) => Ok(n.get()),
        _ => Err("migration field must be integer".into()),
    }
}
fn boolean(value: &Value) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        _ => Err("migration field must be boolean".into()),
    }
}
fn schema(classifier: Option<Classifier>) -> &'static [u8] {
    if classifier.is_some() {
        b"octra_pvac_migration_entitlements_v3"
    } else {
        b"octra_pvac_migration_entitlements_v2"
    }
}
fn put(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(value.len().to_string().as_bytes());
    buffer.push(b':');
    buffer.extend_from_slice(value);
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn put_int(buffer: &mut Vec<u8>, value: impl ToString) {
    put(buffer, value.to_string().as_bytes());
}
fn put_opt(buffer: &mut Vec<u8>, value: Option<&[u8]>) {
    if let Some(value) = value {
        buffer.push(b'1');
        put(buffer, value);
    } else {
        buffer.push(b'0');
    }
}
impl Entry {
    fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(
            value,
            &[
                b"address",
                b"source_cipher_hash",
                b"total",
                b"audit_class",
                b"can_public_migrate",
                b"public_net",
                b"commitment_net",
                b"blockers",
                b"reason",
            ],
            "entry",
        )?;
        let get = |key: &[u8]| field(doc, value, key);
        let audit = match text(get(b"audit_class")?)?.as_slice() {
            b"public_clean" => Audit::PublicClean,
            b"hidden_witness" => Audit::HiddenWitness,
            b"poisoned" => Audit::Poisoned,
            _ => return Err("invalid migration audit class".into()),
        };
        let public_net = optional(get(b"public_net")?)?
            .map(|v| {
                native_integer::parse_integer(&v).ok_or_else(|| {
                    super::Error::from("migration field must be decimal or null = public_net")
                })
            })
            .transpose()?;
        Ok(Self {
            address: text(get(b"address")?)?,
            source_cipher_hash: text(get(b"source_cipher_hash")?)?,
            total: integer(get(b"total")?)?,
            audit,
            can_public_migrate: boolean(get(b"can_public_migrate")?)?,
            public_net,
            commitment_net: optional(get(b"commitment_net")?)?,
            blockers: list(doc, get(b"blockers")?)?
                .into_iter()
                .map(text)
                .collect::<Result<_>>()?,
            reason: text(get(b"reason")?)?,
        })
    }
    fn validate(
        &self,
        classifier: Option<Classifier>,
        valid_commitment: &impl Fn(&[u8]) -> bool,
    ) -> Result<()> {
        require(
            transaction::is_valid_address(&self.address),
            "invalid migration address",
        )?;
        require(
            lower_hex(&self.source_cipher_hash, 64),
            "invalid migration source hash",
        )?;
        require(self.total >= 0, "invalid migration history count")?;
        if classifier == Some(Classifier::Receipt) {
            require(
                self.audit == Audit::HiddenWitness
                    && !self.can_public_migrate
                    && self.public_net.is_none()
                    && self.commitment_net.is_some()
                    && self.blockers.is_empty(),
                "receipt admission requires a private commitment",
            )?;
        }
        if let Some(commitment) = &self.commitment_net {
            require(
                valid_commitment(commitment),
                "migration commitment has invalid encoding",
            )?;
        }
        if let Some(amount) = &self.public_net {
            require(
                amount >= &BigInt::from(0) && amount <= &BigInt::from(MAX_SUPPLY),
                "migration public_net is outside the supply envelope",
            )?;
        }
        if self.can_public_migrate {
            require(
                self.audit == Audit::PublicClean,
                "public migration admission requires public_clean audit",
            )?;
            require(
                self.public_net.is_some(),
                "public migration admission requires public_net",
            )?;
            require(
                self.blockers.is_empty(),
                "public migration admission must not contain blockers",
            )?;
        }
        Ok(())
    }
    fn encode(&self, out: &mut Vec<u8>) {
        put(out, &self.address);
        put(out, &self.source_cipher_hash);
        put_int(out, self.total);
        put(out, self.audit.name());
        out.push(if self.can_public_migrate { b'1' } else { b'0' });
        let amount = self.public_net.as_ref().map(ToString::to_string);
        put_opt(out, amount.as_ref().map(std::string::String::as_bytes));
        put_opt(out, self.commitment_net.as_deref());
        put_int(out, self.blockers.len());
        for blocker in &self.blockers {
            put(out, blocker);
        }
        put(out, &self.reason);
    }
}
impl Admission {
    pub fn parse(
        raw: &[u8],
        chain: &[u8],
        expected_root: &[u8],
        valid_commitment: impl Fn(&[u8]) -> bool,
    ) -> Result<Self> {
        require(
            raw.len() <= MAX_BYTES,
            "migration admission artifact exceeds byte limit",
        )?;
        let doc = Document::parse(raw).map_err(|e| super::Error::from(e.to_string()))?;
        let value = doc.root();
        let get = |key: &[u8]| field(&doc, value, key);
        let artifact_schema = text(get(b"schema")?)?;
        let classifier = if artifact_schema == schema(None) {
            None
        } else if artifact_schema == schema(Some(Classifier::Capped)) {
            Some(match text(get(b"classifier")?)?.as_slice() {
                b"prior_v1" => Classifier::Prior,
                b"capped_v1" => Classifier::Capped,
                b"receipt_v1" => Classifier::Receipt,
                _ => return Err("unsupported migration classifier".into()),
            })
        } else {
            return Err("unsupported migration schema".into());
        };
        let mut expected: Vec<&[u8]> = vec![
            b"schema",
            b"chain_id",
            b"snapshot_epoch",
            b"state_root",
            b"activation_epoch",
            b"root",
            b"entries",
        ];
        if classifier.is_some() {
            expected.push(b"classifier");
        }
        fields(value, &expected, "artifact")?;
        let chain_id = text(get(b"chain_id")?)?;
        require(chain_id == chain, "migration chain_id mismatch")?;
        require(!chain_id.is_empty(), "migration chain_id is empty")?;
        let snapshot_epoch = integer(get(b"snapshot_epoch")?)?;
        let activation_epoch = integer(get(b"activation_epoch")?)?;
        require(snapshot_epoch >= 0, "migration snapshot_epoch is negative")?;
        require(
            activation_epoch >= 0,
            "migration activation_epoch is negative",
        )?;
        require(
            activation_epoch > snapshot_epoch,
            "migration activation_epoch must follow snapshot_epoch",
        )?;
        let state_root = text(get(b"state_root")?)?;
        require(
            lower_hex(&state_root, 64),
            "migration state_root must be lowercase sha256 hex",
        )?;
        let root = text(get(b"root")?)?;
        require(
            root == expected_root,
            "migration artifact root does not match configured root",
        )?;
        let items = list(&doc, get(b"entries")?)?;
        require(
            items.len() <= MAX_ENTRIES,
            "migration admission entry cap exceeded",
        )?;
        let mut entries = BTreeMap::new();
        for value in items {
            let entry = Entry::parse(&doc, value)?;
            entry.validate(classifier, &valid_commitment)?;
            require(
                !entries.contains_key(&entry.address),
                "duplicate migration address",
            )?;
            entries.insert(entry.address.clone(), entry);
        }
        let admission = Self {
            classifier,
            chain_id,
            snapshot_epoch,
            state_root,
            activation_epoch,
            root,
            entries,
        };
        require(
            hex::encode(Sha256::digest(admission.payload())).as_bytes() == expected_root,
            "migration admission root mismatch",
        )?;
        Ok(admission)
    }
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, schema(self.classifier));
        if let Some(c) = self.classifier {
            put(&mut out, c.name());
        }
        put(&mut out, &self.chain_id);
        put_int(&mut out, self.snapshot_epoch);
        put(&mut out, &self.state_root);
        put_int(&mut out, self.activation_epoch);
        put_int(&mut out, self.entries.len());
        for entry in self.entries.values() {
            entry.encode(&mut out);
        }
        out
    }
    pub fn bind_floor(&self, config: &[u8], floor_config: &[u8], epoch: i64) -> Result<()> {
        require(
            config == floor_config,
            "migration floor config hash mismatch",
        )?;
        require(
            epoch >= self.activation_epoch,
            "migration floor precedes activation",
        )
    }
    pub fn bind_snapshot(&self, root: &[u8]) -> Result<()> {
        require(
            root == self.state_root,
            "migration snapshot state root mismatch",
        )
    }
    pub fn find(&self, epoch: i64, address: &[u8], cipher: &[u8]) -> Result<&Entry> {
        require(
            epoch >= self.activation_epoch,
            "migration entitlement is not active",
        )?;
        let entry = self
            .entries
            .get(address)
            .ok_or("migration entitlement not found")?;
        require(
            hex::encode(Sha256::digest(cipher)).as_bytes() == entry.source_cipher_hash,
            "migration entitlement source ciphertext mismatch",
        )?;
        Ok(entry)
    }
    pub fn snapshot_epoch(&self) -> i64 {
        self.snapshot_epoch
    }
    pub fn state_root(&self) -> &[u8] {
        &self.state_root
    }
    pub fn activation_epoch(&self) -> i64 {
        self.activation_epoch
    }
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
