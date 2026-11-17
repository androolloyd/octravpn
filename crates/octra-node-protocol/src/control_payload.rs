// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native validator-control payload parsing. Parsing is separate from epoch,
//! bond, authority and signature checks performed by execution.
use crate::{
    consensus::{
        codec::{Wire, MAX_VALIDATORS},
        evidence::VoteConflict,
        Eviction, Validator, ValidatorSet,
    },
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
    /// Present only on an update produced by evicting slashed validators.
    /// A transaction message never carries one; stored updates may.
    pub eviction: Option<Eviction>,
}
/// Largest encoded validator set an eviction witness may carry.
pub const EVICTION_SOURCE_LIMIT: usize = 5 + MAX_VALIDATORS * (12 + 128 + 32 + 256);
pub fn weighted_fingerprint(source: i64, activate: i64, validators: &[ValidatorEntry]) -> String {
    let mut preimage = Vec::new();
    let mut put = |raw: &[u8]| {
        preimage.extend_from_slice(raw.len().to_string().as_bytes());
        preimage.push(b':');
        preimage.extend_from_slice(raw);
    };
    put(b"octra:validator_set_update:bonded");
    put(source.to_string().as_bytes());
    put(activate.to_string().as_bytes());
    for v in validators {
        put(&v.address);
        put(&v.public_key);
        put(v.weight.to_string().as_bytes());
    }
    hex::encode(Sha256::digest(preimage))
}
fn decode_eviction_source(encoded: &[u8]) -> Result<ValidatorSet, Error> {
    if encoded.len() > 4 * EVICTION_SOURCE_LIMIT.div_ceil(3) {
        return Err(error("validator eviction source exceeds size limit"));
    }
    let invalid = || error("validator eviction source is invalid");
    let raw = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if raw.len() > EVICTION_SOURCE_LIMIT || STANDARD.encode(&raw).as_bytes() != encoded {
        return Err(error("validator eviction source encoding differs"));
    }
    let source = ValidatorSet::decode(&raw).map_err(|_| invalid())?;
    let source = source
        .validate_shape()
        .map_err(|e| error(e.message().to_string()))?;
    if source.authors.is_some() {
        return Err(error("validator eviction source has authors"));
    }
    Ok(source)
}
fn ordered_unique(offenders: &[Vec<u8>]) -> bool {
    offenders.windows(2).all(|pair| pair[0] < pair[1])
}
fn eviction_from(doc: &Document, value: &Value) -> Result<Eviction, Error> {
    let Value::Object(fields) = value else {
        return Err(error("validator eviction must be object"));
    };
    let mut fields: Vec<_> = fields
        .iter()
        .map(|(name, index)| (name.as_slice(), doc.get(*index).expect("document child")))
        .collect();
    fields.sort_by(|left, right| left.0.cmp(right.0));
    let [(b"epoch", Value::String(raw)), (b"offenders", Value::List(items)), (b"source", Value::String(encoded))] =
        fields.as_slice()
    else {
        return Err(error("validator eviction fields differ"));
    };
    let epoch =
        transaction::parse_native_int64(raw).ok_or_else(|| error("invalid eviction epoch"))?;
    if epoch < 0 || epoch == i64::MAX || epoch.to_string().as_bytes() != raw.as_slice() {
        return Err(error("validator eviction epoch is invalid"));
    }
    if items.is_empty() || items.len() > MAX_VALIDATORS {
        return Err(error("validator eviction offender count is invalid"));
    }
    let offenders = items
        .iter()
        .map(|index| match doc.get(*index) {
            Some(Value::String(address)) if transaction::is_valid_address(address) => {
                Ok(address.clone())
            }
            _ => Err(error("validator eviction offender is invalid")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !ordered_unique(&offenders) {
        return Err(error(
            "validator eviction offenders are not ordered and unique",
        ));
    }
    Ok(Eviction {
        epoch,
        source: decode_eviction_source(encoded)?,
        offenders,
    })
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
    /// A transaction message: the update alone, never an eviction witness.
    pub fn parse(message: Option<&[u8]>) -> Result<Self, Error> {
        Self::from_document(&document(
            message,
            "validator_set_update requires message payload",
        )?)
    }
    /// A stored update. One that carries an eviction witness must be the
    /// exact removal the witness describes, in its canonical encoding.
    pub fn of_string(raw: &[u8]) -> Result<Self, Error> {
        let doc = Document::parse(raw)?;
        let mut update = Self::from_document(&doc)?;
        let Value::Object(fields) = doc.root() else {
            return Err(error("validator_set_update payload must be object"));
        };
        let mut witnesses = fields.iter().filter(|(name, _)| name == b"eviction");
        let Some((_, index)) = witnesses.next() else {
            return Ok(update);
        };
        if witnesses.next().is_some() {
            return Err(error("duplicate validator eviction field"));
        }
        let eviction = eviction_from(&doc, doc.get(*index).expect("document child"))?;
        update.eviction = Some(eviction);
        update.validate_eviction()?;
        if update.to_bytes() != raw {
            return Err(error("validator eviction update encoding differs"));
        }
        Ok(update)
    }
    /// The set left after the witnessed removal and the weight removed,
    /// if this update is exactly that removal.
    pub fn validate_eviction(&self) -> Result<(ValidatorSet, BigInt), Error> {
        let eviction = self
            .eviction
            .as_ref()
            .ok_or_else(|| error("validator eviction witness is missing"))?;
        let consensus = |e: crate::consensus::Error| error(e.to_string());
        let source = eviction
            .source
            .validate_shape()
            .map_err(|e| consensus(e.message()))?;
        if source != eviction.source || source.authors.is_some() {
            return Err(error("validator eviction source is not exact"));
        }
        if eviction.epoch < 0
            || eviction.epoch == i64::MAX
            || self.source_epoch != Some(eviction.epoch)
            || self.activate_epoch != eviction.epoch + 1
            || !self.weighted
        {
            return Err(error(
                "validator eviction epoch or weight declaration differs",
            ));
        }
        if !ordered_unique(&eviction.offenders) {
            return Err(error(
                "validator eviction offenders are not ordered and unique",
            ));
        }
        if eviction.offenders.len() > MAX_VALIDATORS {
            return Err(error("validator eviction offender count is invalid"));
        }
        let encoded = STANDARD.encode(source.encode().map_err(consensus)?);
        if decode_eviction_source(encoded.as_bytes())? != source {
            return Err(error("validator eviction source encoding differs"));
        }
        let (next, weight) = source.evict(&eviction.offenders).map_err(consensus)?;
        let expected: Vec<_> = next
            .entries()
            .map_err(consensus)?
            .into_iter()
            .map(|(member, weight)| ValidatorEntry {
                address: member.address,
                public_key: STANDARD.encode(member.pubkey).into_bytes(),
                weight,
            })
            .collect();
        if self.validators != expected
            || self.fingerprint
                != weighted_fingerprint(eviction.epoch, self.activate_epoch, &expected)
        {
            return Err(error("validator eviction differs from exact removal"));
        }
        Ok((next, weight))
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
        let fingerprint = if let Some(source) = source_epoch {
            weighted_fingerprint(source, activate_epoch, &validators)
        } else {
            let mut preimage = Vec::new();
            for (index, v) in validators.iter().enumerate() {
                if index != 0 {
                    preimage.push(b',');
                }
                preimage.extend_from_slice(&v.address);
                preimage.push(b':');
                preimage.extend_from_slice(&v.public_key);
            }
            hex::encode(Sha256::digest(preimage))
        };
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
            eviction: None,
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
