// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native validator-control payload parsing. Parsing is separate from epoch,
//! bond, authority and signature checks performed by execution.
use crate::{
    consensus::{codec::Wire, evidence::VoteConflict, Validator, ValidatorSet},
    native_json::{Document, Value},
    transaction::{self, OpType},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use num_traits::{One, Signed};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Json(#[from] crate::native_json::Error),
    #[error("{0}")]
    Invalid(String),
}
fn error(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorEntry {
    pub address: Vec<u8>,
    pub public_key: Vec<u8>,
    pub weight: BigInt,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorUpdate {
    pub activate_epoch: i64,
    pub source_epoch: Option<i64>,
    pub validators: Vec<ValidatorEntry>,
    pub weighted: bool,
    pub fingerprint: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyReady {
    pub fingerprint: Vec<u8>,
    pub head_epoch: i64,
    pub state_root: Vec<u8>,
    pub extra: ReadyExtra,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReadyExtra {
    pub chain_id: Option<Vec<u8>>,
    pub binary_hash: Option<Vec<u8>>,
    pub config_hash: Option<Vec<u8>>,
    pub catchup_head_epoch: Option<i64>,
    pub shadow_epochs: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondedReady {
    pub consensus_public_key: Vec<u8>,
    pub head_epoch: i64,
    pub state_root: Vec<u8>,
    pub head_proposal_id: Option<Vec<u8>>,
    pub extra: ReadyExtra,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bond {
    pub consensus_public_key: Vec<u8>,
    pub proof: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    None,
    Update(ValidatorUpdate),
    LegacyReady(LegacyReady),
    BondedReady(BondedReady),
    Bond(Bond),
    Evidence(VoteConflict),
}
fn bytes(value: Option<&Value>) -> Option<&[u8]> {
    match value {
        Some(Value::String(raw)) => Some(raw),
        _ => None,
    }
}
fn integer(value: &Value, label: &str) -> Result<i64, Error> {
    match value {
        Value::String(raw) => {
            transaction::parse_native_int64(raw).ok_or_else(|| error(format!("invalid {label}")))
        }
        Value::Int(v) => Ok(v.get()),
        _ => Err(error(format!("{label} must be string or int"))),
    }
}
fn field<'a>(doc: &'a Document, name: &[u8]) -> Option<&'a Value> {
    doc.field(doc.root(), name)
}
fn document(message: Option<&[u8]>, missing: &str) -> Result<Document, Error> {
    Document::parse(message.ok_or_else(|| error(missing))?).map_err(Into::into)
}
impl ValidatorUpdate {
    pub fn parse(message: Option<&[u8]>) -> Result<Self, Error> {
        Self::from_document(&document(
            message,
            "validator_set_update requires message payload",
        )?)
    }
    fn from_document(doc: &Document) -> Result<Self, Error> {
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(error("validator_set_update payload must be object"));
        }
        let (Some(epoch), Some(Value::List(entries))) =
            (field(doc, b"activate_epoch"), field(doc, b"validators"))
        else {
            return Err(error(
                "validator_set_update requires activate_epoch and validators",
            ));
        };
        let activate_epoch = integer(epoch, "activate_epoch")?;
        let weighted = match field(doc, b"weighted") {
            None => false,
            Some(Value::Bool(v)) => *v,
            _ => return Err(error("weighted must be bool")),
        };
        let source_epoch = match (weighted, field(doc, b"source_epoch")) {
            (false, None) => None,
            (false, Some(_)) => return Err(error("legacy validator update rejects source_epoch")),
            (true, None) => return Err(error("weighted validator update requires source_epoch")),
            (true, Some(value)) => Some(integer(value, "source_epoch")?),
        };
        match (weighted, field(doc, b"standard")) {
            (false, None) => (),
            (false, Some(_)) => return Err(error("legacy validator update rejects standard")),
            (true, Some(Value::String(value))) if value == b"bonded_stake" => (),
            (true, _) => return Err(error("weighted validator update standard mismatch")),
        }
        let mut validators = Vec::new();
        for &id in entries {
            let value = doc.get(id).expect("document child");
            if !matches!(value, Value::Object(_)) {
                return Err(error("validator entry must be object"));
            }
            let (Some(address), Some(public)) = (
                bytes(doc.field(value, b"address")),
                bytes(doc.field(value, b"pubkey")),
            ) else {
                return Err(error("validator entry requires address and pubkey"));
            };
            let weight = if weighted {
                match doc.field(value, b"weight") {
                    None => return Err(error("weighted validator entry requires weight")),
                    Some(Value::String(raw)) => {
                        let parsed = transaction::parse_native_integer(raw)
                            .ok_or_else(|| error("invalid validator weight"))?;
                        if !parsed.is_positive() {
                            return Err(error("validator weight must be positive"));
                        }
                        parsed
                    }
                    Some(Value::Int(value)) if value.get() > 0 => value.get().into(),
                    _ => return Err(error("validator weight must be a positive integer")),
                }
            } else {
                BigInt::one()
            };
            let public = transaction::decode_base64(public)
                .ok()
                .filter(|raw| raw.len() == 32)
                .ok_or_else(|| error("invalid validator public key"))?;
            let public = STANDARD.encode(public).into_bytes();
            if !transaction::is_valid_address(address) {
                return Err(error("invalid validator address"));
            }
            if !weighted && address != transaction::address_from_public_key(&public) {
                return Err(error("validator address does not match public key"));
            }
            validators.push(ValidatorEntry {
                address: address.to_vec(),
                public_key: public,
                weight,
            });
        }
        if validators.is_empty() {
            return Err(error("validator set cannot be empty"));
        }
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let mut addresses = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for v in &validators {
            if !addresses.insert(&v.address) {
                return Err(error("duplicate validator address"));
            }
            if !keys.insert(&v.public_key) {
                return Err(error("duplicate validator public key"));
            }
        }
        let mut preimage = Vec::new();
        if let Some(source) = source_epoch {
            let mut put = |raw: &[u8]| {
                preimage.extend_from_slice(raw.len().to_string().as_bytes());
                preimage.push(b':');
                preimage.extend_from_slice(raw);
            };
            put(b"octra:validator_set_update:bonded");
            put(source.to_string().as_bytes());
            put(activate_epoch.to_string().as_bytes());
            for v in &validators {
                put(&v.address);
                put(&v.public_key);
                put(v.weight.to_string().as_bytes());
            }
        } else {
            for (index, v) in validators.iter().enumerate() {
                if index != 0 {
                    preimage.push(b',');
                }
                preimage.extend_from_slice(&v.address);
                preimage.push(b':');
                preimage.extend_from_slice(&v.public_key);
            }
        }
        let fingerprint = hex::encode(Sha256::digest(preimage));
        if source_epoch.is_some_and(|source| source >= activate_epoch) {
            return Err(error(
                "weighted validator source epoch must precede activation",
            ));
        }
        if bytes(field(doc, b"fingerprint"))
            .is_some_and(|expected| expected != fingerprint.as_bytes())
        {
            return Err(error("validator set fingerprint mismatch"));
        }
        Ok(Self {
            activate_epoch,
            source_epoch,
            validators,
            weighted,
            fingerprint,
        })
    }
    pub fn validator_set(&self) -> Result<ValidatorSet, crate::consensus::Error> {
        let entries = self
            .validators
            .iter()
            .map(|v| {
                transaction::decode_base64(&v.public_key)
                    .map(|pubkey| {
                        (
                            Validator {
                                address: v.address.clone(),
                                pubkey,
                            },
                            v.weight.clone(),
                        )
                    })
                    .map_err(|e| crate::consensus::Error::new(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if self.weighted {
            ValidatorSet::weighted(entries)
        } else {
            Ok(ValidatorSet::unweighted(
                entries.into_iter().map(|(v, _)| v).collect(),
            ))
        }
    }
}
fn strict_string(doc: &Document, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    match field(doc, key) {
        None => Ok(None),
        Some(Value::String(raw)) => Ok(Some(raw.clone())),
        _ => Err(error(format!(
            "{} must be string",
            String::from_utf8_lossy(key)
        ))),
    }
}
fn strict_hash(doc: &Document, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let value = strict_string(doc, key)?;
    if value.as_ref().is_some_and(|raw| raw.len() != 64) {
        return Err(error(format!("invalid {}", String::from_utf8_lossy(key))));
    }
    Ok(value)
}
fn strict_nonnegative(doc: &Document, key: &[u8], int63: bool) -> Result<Option<i64>, Error> {
    let Some(value) = field(doc, key) else {
        return Ok(None);
    };
    let name = String::from_utf8_lossy(key);
    let result = if int63 {
        match value {
            Value::String(raw) => transaction::parse_native_int(raw)
                .map(transaction::Nonce::get)
                .ok_or_else(|| error(format!("invalid {name}"))),
            Value::Int(v) => Ok(v.get()),
            _ => Err(error(format!("{name} must be string or int"))),
        }
    } else {
        integer(value, &name)
    }?;
    if result < 0 {
        return Err(error(format!("invalid {name}")));
    }
    Ok(Some(result))
}
impl LegacyReady {
    pub fn parse(message: Option<&[u8]>) -> Result<Self, Error> {
        Self::from_document(&document(
            message,
            "validator_ready requires message payload",
        )?)
    }
    fn from_document(doc: &Document) -> Result<Self, Error> {
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(error("validator_ready payload must be object"));
        }
        let (Some(fingerprint), Some(epoch), Some(root)) = (
            bytes(field(doc, b"fingerprint")),
            field(doc, b"head_epoch"),
            bytes(field(doc, b"state_root")),
        ) else {
            return Err(error(
                "validator_ready requires fingerprint, head_epoch, state_root",
            ));
        };
        let head_epoch = integer(epoch, "head_epoch")?;
        if fingerprint.len() != 64 {
            return Err(error("invalid fingerprint"));
        }
        if root.len() != 64 && root.len() != 128 {
            return Err(error("invalid state_root"));
        }
        let chain_id = strict_string(doc, b"chain_id")?;
        if chain_id.as_ref().is_some_and(Vec::is_empty) {
            return Err(error("invalid chain_id"));
        }
        let extra = ReadyExtra {
            chain_id,
            binary_hash: strict_hash(doc, b"binary_hash")?,
            config_hash: strict_hash(doc, b"config_hash")?,
            catchup_head_epoch: strict_nonnegative(doc, b"catchup_head_epoch", false)?,
            shadow_epochs: strict_nonnegative(doc, b"shadow_epochs", true)?,
        };
        Ok(Self {
            fingerprint: fingerprint.to_vec(),
            head_epoch,
            state_root: root.to_vec(),
            extra,
        })
    }
}
impl Bond {
    pub fn parse(message: Option<&[u8]>) -> Result<Self, Error> {
        let raw = message.ok_or_else(|| error("validator bond requires message payload"))?;
        let doc = Document::parse(raw).map_err(|_| error("invalid validator bond payload"))?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(error("validator bond payload must be object"));
        }
        let (Some(key), Some(proof)) = (
            bytes(field(&doc, b"consensus_pubkey")),
            bytes(field(&doc, b"proof")),
        ) else {
            return Err(error("validator bond requires consensus_pubkey and proof"));
        };
        Ok(Self {
            consensus_public_key: key.to_vec(),
            proof: proof.to_vec(),
        })
    }
}
fn loose_string(doc: &Document, key: &[u8]) -> Option<Vec<u8>> {
    bytes(field(doc, key))
        .filter(|v| !v.is_empty())
        .map(<[u8]>::to_vec)
}
fn loose_hash(doc: &Document, key: &[u8]) -> Option<Vec<u8>> {
    loose_string(doc, key).filter(|v| {
        v.len() == 64
            && v.iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    })
}
fn loose_number(doc: &Document, key: &[u8], int63: bool) -> Option<i64> {
    integer(field(doc, key)?, "")
        .ok()
        .filter(|v| *v >= 0 && (!int63 || *v <= transaction::Nonce::MAX.get()))
}
impl BondedReady {
    pub fn parse(message: Option<&[u8]>) -> Result<Self, Error> {
        let raw = message.ok_or_else(|| error("validator ready requires message payload"))?;
        let doc = Document::parse(raw).map_err(|_| error("invalid validator ready payload"))?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(error("validator ready payload must be object"));
        }
        let (Some(key), Some(epoch), Some(root)) = (
            bytes(field(&doc, b"consensus_pubkey")),
            field(&doc, b"head_epoch"),
            bytes(field(&doc, b"state_root")),
        ) else {
            return Err(error(
                "validator ready requires consensus_pubkey, head_epoch and state_root",
            ));
        };
        Ok(Self {
            consensus_public_key: key.to_vec(),
            head_epoch: integer(epoch, "validator ready head epoch")?,
            state_root: root.to_vec(),
            head_proposal_id: loose_hash(&doc, b"head_proposal_id"),
            extra: ReadyExtra {
                chain_id: loose_string(&doc, b"chain_id"),
                binary_hash: loose_hash(&doc, b"binary_hash"),
                config_hash: loose_hash(&doc, b"config_hash"),
                catchup_head_epoch: loose_number(&doc, b"catchup_head_epoch", false),
                shadow_epochs: loose_number(&doc, b"shadow_epochs", true),
            },
        })
    }
}
pub fn evidence(message: Option<&[u8]>) -> Result<VoteConflict, Error> {
    let raw = message.ok_or_else(|| error("validator evidence requires message payload"))?;
    if raw.len() > 8192 {
        return Err(error("validator evidence payload is too large"));
    }
    let doc = Document::parse(raw).map_err(|_| error("invalid validator evidence payload"))?;
    let Value::Object(fields) = doc.root() else {
        return Err(error("validator evidence requires one evidence field"));
    };
    if fields.len() != 1 || fields[0].0 != b"evidence" {
        return Err(error("validator evidence requires one evidence field"));
    }
    let Some(encoded) = bytes(doc.get(fields[0].1)) else {
        return Err(error("validator evidence requires one evidence field"));
    };
    let decoded = transaction::decode_base64(encoded)
        .map_err(|_| error("invalid validator evidence payload"))?;
    if STANDARD.encode(&decoded).as_bytes() != encoded {
        return Err(error("validator evidence base64 is not canonical"));
    }
    let conflict =
        VoteConflict::decode(&decoded).map_err(|_| error("invalid validator evidence"))?;
    if conflict
        .encode()
        .map_err(|_| error("invalid validator evidence"))?
        != decoded
    {
        return Err(error("validator evidence is not canonical"));
    }
    Ok(conflict)
}
pub fn validate_message(op: OpType, message: Option<&[u8]>) -> Result<Payload, Error> {
    match op {
        OpType::ValidatorSetUpdate => ValidatorUpdate::parse(message).map(Payload::Update),
        OpType::ValidatorBond => Bond::parse(message).map(Payload::Bond),
        OpType::ValidatorReady => match LegacyReady::parse(message) {
            Ok(ready) => Ok(Payload::LegacyReady(ready)),
            Err(legacy) => match BondedReady::parse(message) {
                Ok(ready) => Ok(Payload::BondedReady(ready)),
                Err(bonded) => Err(error(format!("{legacy}; {bonded}"))),
            },
        },
        OpType::ValidatorEvidence => evidence(message).map(Payload::Evidence),
        _ => Ok(Payload::None),
    }
}
