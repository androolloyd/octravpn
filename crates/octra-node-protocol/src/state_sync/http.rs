// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native State_sync HTTP projections. Decoding does not authenticate a peer.
use super::{field, int64, integer, list, lower_hex, require, text, Error, Result};
use crate::{
    consensus::{
        self, codec::Wire, CatchupEpochRecord, CatchupFinality, RewardMember, RewardSource,
    },
    light_rpc::json,
    native_integer,
    native_json::{Document, Value},
};
use base64::{engine::general_purpose::STANDARD, Engine};

pub const VERSION: &[u8] = b"octra-state-sync";
pub const PROGRESS_MAX: usize = 65_536;
pub const SNAPSHOT_LAG_MAX: i64 = 3000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub epoch: i64,
    /// Native HEAD state_root, as lowercase hexadecimal ASCII.
    pub state_root: Vec<u8>,
    pub txid_hi: i64,
    pub irmin_commit: Option<Vec<u8>>,
}
impl Head {
    pub fn parse_response(raw: &[u8]) -> Result<Option<Self>> {
        let doc = Document::parse(raw).map_err(|e| Error::from(e.to_string()))?;
        let get = |key| field(&doc, doc.root(), key);
        require(
            text(get(b"version")?)? == VERSION && text(get(b"mode")?)? == b"live_head",
            "invalid state sync head",
        )?;
        if matches!(get(b"head_epoch")?, Value::Null) {
            return Ok(None);
        }
        let epoch = int64(get(b"head_epoch")?)?;
        let state_root = text(get(b"state_root")?)?;
        let txid_hi = int64(get(b"txid_hi")?)?;
        require(
            (0..(1i64 << 62)).contains(&epoch) && txid_hi >= -1 && lower_hex(&state_root, 64),
            "invalid state sync head",
        )?;
        Ok(Some(Self {
            epoch,
            state_root,
            txid_hi,
            irmin_commit: None,
        }))
    }
}
pub fn head_response(
    current_epoch: i64,
    head: Option<&Head>,
    snapshot_epoch: Option<i64>,
) -> Vec<u8> {
    let lag = snapshot_epoch.map(|epoch| {
        current_epoch
            .saturating_sub(1)
            .max(0)
            .saturating_sub(epoch)
            .max(0)
    });
    json::object(&[
        ("version", json::string(VERSION)),
        ("mode", json::string(b"live_head")),
        ("current_epoch", json::number(current_epoch)),
        (
            "snapshot_epoch",
            snapshot_epoch.map_or_else(json::null, json::number),
        ),
        (
            "head_epoch",
            head.map_or_else(json::null, |h| json::number(h.epoch)),
        ),
        (
            "state_root",
            head.map_or_else(json::null, |h| json::string(&h.state_root)),
        ),
        (
            "txid_hi",
            head.map_or_else(json::null, |h| json::string(h.txid_hi.to_string())),
        ),
        (
            "snapshot_status",
            json::string(match lag {
                None => b"missing".as_slice(),
                Some(n) if n > SNAPSHOT_LAG_MAX => b"old_epoch",
                Some(_) => b"ready",
            }),
        ),
        ("snapshot_lag", lag.map_or_else(json::null, json::number)),
        ("snapshot_lag_limit", json::number(SNAPSHOT_LAG_MAX)),
    ])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeQuery {
    pub from_epoch: i64,
    pub max_epochs: i64,
    pub part: Option<i64>,
    pub hash: Option<Vec<u8>>,
}
impl RangeQuery {
    /// The route supplies the first URL value for each field, as Cohttp does.
    pub fn parse(
        from: Option<&[u8]>,
        max: Option<&[u8]>,
        part: Option<&[u8]>,
        hash: Option<&[u8]>,
    ) -> Result<Self> {
        let from_epoch = from.and_then(native_integer::parse_int64).unwrap_or(-1);
        let max_epochs = max.and_then(native_integer::parse_int63).unwrap_or(16);
        let part = part.map(|v| native_integer::parse_int63(v).unwrap_or(-1));
        require(
            (0..=(1i64 << 62) - 1 - 16).contains(&from_epoch)
                && max_epochs > 0
                && part.is_none_or(|p| p >= 0)
                && hash.is_none_or(|h| part.is_some() && lower_hex(h, 64)),
            "invalid range parameters",
        )?;
        Ok(Self {
            from_epoch,
            max_epochs,
            part,
            hash: hash.map(<[u8]>::to_vec),
        })
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum RangeResult {
    Records {
        records: Vec<CatchupEpochRecord>,
        next_epoch: Option<i64>,
    },
    Missing,
    Retry(Vec<u8>),
}
pub fn record_size(record: &CatchupEpochRecord) -> Result<usize> {
    let source = record
        .reward_source
        .as_ref()
        .ok_or_else(|| Error::from("archived reward source missing"))?;
    let proof = record
        .finality
        .as_ref()
        .ok_or_else(|| Error::from("archived finality missing"))?;
    let mut writer = crate::oce1::Writer::new();
    consensus::reward::put(&mut writer, source).map_err(|e| Error::from(e.to_string()))?;
    [
        136,
        writer.into_bytes().len(),
        proof
            .finalize
            .encode()
            .map_err(|e| Error::from(e.to_string()))?
            .len(),
        proof
            .validator_set
            .encode()
            .map_err(|e| Error::from(e.to_string()))?
            .len(),
    ]
    .into_iter()
    .chain(
        record
            .txs_json
            .iter()
            .chain(&record.receipts_json)
            .map(|v| v.len() + 32),
    )
    .try_fold(0usize, |n, v| {
        n.checked_add(v)
            .ok_or_else(|| Error::from("catch-up record size overflow"))
    })
}
fn public_key(key: Option<&[u8]>) -> Vec<u8> {
    key.map_or_else(json::null, |v| json::string(STANDARD.encode(v)))
}
fn reward_json(source: &RewardSource) -> Result<Vec<u8>> {
    let source = consensus::reward::validate(source).map_err(|e| Error::from(e.to_string()))?;
    Ok(json::object(&[
        (
            "proposer_address",
            json::string(&source.reward_proposer_addr),
        ),
        (
            "proposer_public_key",
            public_key(source.reward_proposer_public_key.as_deref()),
        ),
        (
            "members",
            json::array(source.reward_members.iter().map(|m| {
                json::object(&[
                    ("address", json::string(&m.reward_address)),
                    ("public_key", public_key(m.reward_public_key.as_deref())),
                    ("weight", json::string(m.reward_weight.to_string())),
                ])
            })),
        ),
    ]))
}
pub fn record_json(record: &CatchupEpochRecord) -> Result<Vec<u8>> {
    let finality = record
        .finality
        .as_ref()
        .map(|p| -> Result<Vec<u8>> {
            Ok(json::object(&[
                (
                    "finalize",
                    json::string(
                        STANDARD.encode(
                            p.finalize
                                .encode()
                                .map_err(|e| Error::from(e.to_string()))?,
                        ),
                    ),
                ),
                (
                    "validator_set",
                    json::string(
                        STANDARD.encode(
                            p.validator_set
                                .encode()
                                .map_err(|e| Error::from(e.to_string()))?,
                        ),
                    ),
                ),
            ]))
        })
        .transpose()?
        .unwrap_or_else(json::null);
    Ok(json::object(&[
        ("epoch_id", json::string(record.epoch_id.to_string())),
        (
            "prev_state_root",
            json::string(hex::encode(&record.prev_state_root)),
        ),
        ("state_root", json::string(hex::encode(&record.state_root))),
        (
            "tx_list_hash",
            json::string(hex::encode(&record.tx_list_hash)),
        ),
        (
            "tx_hashes",
            json::array(record.tx_hashes.iter().map(json::string)),
        ),
        (
            "txs_json",
            json::array(record.txs_json.iter().map(json::string)),
        ),
        (
            "receipt_root",
            json::string(hex::encode(&record.receipt_root)),
        ),
        (
            "receipts_json",
            json::array(record.receipts_json.iter().map(json::string)),
        ),
        (
            "epoch_ts",
            crate::transaction::native_float(record.epoch_ts)
                .map_err(|e| Error::from(e.to_string()))?
                .into_bytes(),
        ),
        ("creator_addr", json::string(&record.creator_addr)),
        ("commit_round", json::number(record.commit_round)),
        (
            "reward_source",
            record
                .reward_source
                .as_ref()
                .map(reward_json)
                .transpose()?
                .unwrap_or_else(json::null),
        ),
        ("finality", finality),
    ]))
}
pub fn range_response(
    head: Option<&Head>,
    query: &RangeQuery,
    result: &RangeResult,
) -> Result<Vec<u8>> {
    let mut fields = vec![
        ("version", json::string(VERSION)),
        ("mode", json::string(b"catchup_range")),
    ];
    let (status, next, records) = match result {
        RangeResult::Records {
            records,
            next_epoch,
        } => (
            b"ok".as_slice(),
            *next_epoch,
            records
                .iter()
                .map(record_json)
                .collect::<Result<Vec<_>>>()?,
        ),
        RangeResult::Missing => (b"not_found".as_slice(), None, vec![]),
        RangeResult::Retry(error) => {
            fields.push(("status", json::string(b"error")));
            fields.push(("error", json::string(error)));
            (b"error".as_slice(), None, vec![])
        }
    };
    if !matches!(result, RangeResult::Retry(_)) {
        fields.push(("status", json::string(status)));
    }
    fields.extend([
        ("from_epoch", json::string(query.from_epoch.to_string())),
        ("max_epochs", json::number(query.max_epochs)),
        (
            "next_epoch",
            next.map_or_else(json::null, |n| json::string(n.to_string())),
        ),
        ("records", json::array(records)),
        (
            "head_epoch",
            head.map_or_else(json::null, |h| json::number(h.epoch)),
        ),
        (
            "head_state_root",
            head.map_or_else(json::null, |h| json::string(&h.state_root)),
        ),
    ]);
    Ok(json::object(&fields))
}
fn unhex(doc: &Document, value: &Value, name: &[u8]) -> Result<Vec<u8>> {
    let raw = text(field(doc, value, name)?)?;
    require(lower_hex(&raw, 64), "invalid range hash")?;
    hex::decode(raw).map_err(|e| Error::from(e.to_string()))
}
fn decode_key(value: &Value) -> Result<Option<Vec<u8>>> {
    match value {
        Value::Null => Ok(None),
        Value::String(raw) => {
            let decoded = crate::native_base64::decode(raw)
                .map_err(|_| Error::from("reward source public key is invalid"))?;
            require(decoded.len() == 32, "reward source public key is invalid")?;
            Ok(Some(decoded))
        }
        _ => Err("reward source public key is invalid".into()),
    }
}
fn parse_reward(doc: &Document, value: &Value) -> Result<Option<RewardSource>> {
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    let mut members = Vec::new();
    for row in list(doc, field(doc, value, b"members")?)? {
        require(members.len() < 4096, "reward source has too many members")?;
        let weight = text(field(doc, row, b"weight")?)?;
        require(weight.len() <= 256, "reward source weight is invalid")?;
        members.push(RewardMember {
            reward_address: text(field(doc, row, b"address")?)?,
            reward_public_key: decode_key(field(doc, row, b"public_key")?)?,
            reward_weight: consensus::reward::parse_weight(&weight)
                .ok_or_else(|| Error::from("reward source weight is invalid"))?,
        });
    }
    consensus::reward::validate(&RewardSource {
        reward_proposer_addr: text(field(doc, value, b"proposer_address")?)?,
        reward_proposer_public_key: decode_key(field(doc, value, b"proposer_public_key")?)?,
        reward_members: members,
    })
    .map(Some)
    .map_err(|e| Error::from(e.to_string()))
}
// Match the native integer-to-float projection and rounding exactly.
#[allow(clippy::cast_precision_loss)]
pub fn parse_record(doc: &Document, value: &Value) -> Result<CatchupEpochRecord> {
    let strings = |name: &[u8]| -> Result<Vec<Vec<u8>>> {
        list(doc, field(doc, value, name)?)?
            .into_iter()
            .map(text)
            .collect()
    };
    let proof = field(doc, value, b"finality")?;
    let finality = if matches!(proof, Value::Null) {
        None
    } else {
        let decode = |name| -> Result<Vec<u8>> {
            crate::native_base64::decode(&text(field(doc, proof, name)?)?)
                .map_err(|e| Error::from(e.to_string()))
        };
        Some(CatchupFinality {
            finalize: consensus::Finalize::decode(&decode(b"finalize")?)
                .map_err(|e| Error::from(e.to_string()))?,
            validator_set: consensus::ValidatorSet::decode(&decode(b"validator_set")?)
                .map_err(|e| Error::from(e.to_string()))?,
        })
    };
    let epoch_ts = match field(doc, value, b"epoch_ts")? {
        Value::Float(v) => *v,
        Value::Int(v) => v.get() as f64,
        _ => return Err("invalid range epoch timestamp".into()),
    };
    require(epoch_ts.is_finite(), "invalid range epoch timestamp")?;
    Ok(CatchupEpochRecord {
        epoch_id: int64(field(doc, value, b"epoch_id")?)?,
        prev_state_root: unhex(doc, value, b"prev_state_root")?,
        state_root: unhex(doc, value, b"state_root")?,
        tx_list_hash: unhex(doc, value, b"tx_list_hash")?,
        tx_hashes: strings(b"tx_hashes")?,
        txs_json: strings(b"txs_json")?,
        receipt_root: unhex(doc, value, b"receipt_root")?,
        receipts_json: strings(b"receipts_json")?,
        epoch_ts,
        creator_addr: text(field(doc, value, b"creator_addr")?)?,
        commit_round: integer(field(doc, value, b"commit_round")?)?,
        reward_source: parse_reward(doc, field(doc, value, b"reward_source")?)?,
        finality,
    })
}
/// The caller verifies contiguous epochs, transaction/receipt commitments and QC
/// against its independent validator history before using any returned record.
pub fn parse_range(doc: &Document) -> Result<RangeResult> {
    require(
        text(field(doc, doc.root(), b"version")?)? == VERSION
            && text(field(doc, doc.root(), b"mode")?)? == b"catchup_range",
        "invalid range response",
    )?;
    match text(field(doc, doc.root(), b"status")?)?.as_slice() {
        b"not_found" => Ok(RangeResult::Missing),
        b"error" => Ok(RangeResult::Retry(text(field(doc, doc.root(), b"error")?)?)),
        b"ok" => {
            let rows = list(doc, field(doc, doc.root(), b"records")?)?;
            require(rows.len() <= 16, "too many range records")?;
            let records = rows
                .into_iter()
                .map(|v| parse_record(doc, v))
                .collect::<Result<_>>()?;
            let next = field(doc, doc.root(), b"next_epoch")?;
            Ok(RangeResult::Records {
                records,
                next_epoch: if matches!(next, Value::Null) {
                    None
                } else {
                    Some(int64(next)?)
                },
            })
        }
        _ => Err("invalid range response status".into()),
    }
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub peer: Vec<u8>,
    pub phase: Vec<u8>,
    pub path: Vec<u8>,
    pub file_done: i64,
    pub file_size: i64,
    pub total_done: i64,
    pub total_size: i64,
    pub rate_bps: f64,
    pub eta_seconds: Option<f64>,
}
impl Progress {
    // Match the native integer-to-float projection and rounding exactly.
    #[allow(clippy::cast_precision_loss)]
    pub fn parse(doc: &Document) -> Result<Self> {
        require(
            matches!(doc.root(), Value::Object(_)),
            "progress report must be a JSON object",
        )?;
        let string = |key, default: &[u8]| match doc.field(doc.root(), key) {
            Some(Value::String(v)) => v.clone(),
            _ => default.to_vec(),
        };
        let integer = |key| match doc.field(doc.root(), key) {
            Some(Value::Int(v)) => v.get(),
            Some(Value::IntLiteral(v)) => native_integer::parse_int63(v).unwrap_or(0),
            _ => 0,
        };
        let float = |value: Option<&Value>| match value {
            Some(Value::Float(v)) => Some(*v),
            Some(Value::Int(v)) => Some(v.get() as f64),
            Some(Value::IntLiteral(v)) => std::str::from_utf8(v).ok().and_then(|v| v.parse().ok()),
            _ => None,
        };
        Ok(Self {
            peer: string(b"peer", b"unknown"),
            phase: string(b"phase", b"unknown"),
            path: string(b"path", b"-"),
            file_done: integer(b"file_done"),
            file_size: integer(b"file_size"),
            total_done: integer(b"total_done"),
            total_size: integer(b"total_size"),
            rate_bps: float(doc.field(doc.root(), b"rate_bps")).unwrap_or(0.),
            eta_seconds: float(doc.field(doc.root(), b"eta_seconds")),
        })
    }
}
