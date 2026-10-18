// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! The byte-preserving projection of `Epochlog.epoch_of_json` used by the local
//! history adapter. Invalid native headers return None; optional legacy fields
//! retain the native defaults. This decoder authenticates no history itself.
use super::{Header, Recipient};
use crate::{
    consensus::{reward, RewardMember, RewardSource},
    native_integer::parse_int64,
    native_json::{Document, ReadMode, Value},
    transaction::{decode_base64, Nonce},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedHeader {
    pub reward: Header,
    pub state_root: Vec<u8>,
    pub previous_root: Vec<u8>,
    pub parent_commit: Vec<u8>,
    pub start_txid: i64,
    pub transaction_count: Nonce,
}

fn string(value: Option<&Value>) -> Option<Vec<u8>> {
    match value? {
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    }
}

fn key(value: Option<&Value>) -> Result<Option<Vec<u8>>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => {
            let raw = decode_base64(raw).map_err(|_| ())?;
            (raw.len() == 32).then_some(Some(raw)).ok_or(())
        }
        _ => Err(()),
    }
}

fn source(document: &Document, value: &Value) -> Option<RewardSource> {
    let field = |name: &[u8]| document.field(value, name);
    let proposer_key = key(field(b"proposer_public_key")).ok()?;
    let Value::List(members) = field(b"members")? else {
        return None;
    };
    let members = members
        .iter()
        .map(|index| {
            let row = document.get(*index)?;
            let field = |name: &[u8]| document.field(row, name);
            let public_key = key(field(b"public_key")).ok()?;
            let weight = string(field(b"weight"))?;
            if weight.len() > 256 {
                return None;
            }
            Some(RewardMember {
                reward_address: string(field(b"address"))?,
                reward_public_key: public_key,
                reward_weight: reward::parse_weight(&weight)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    reward::validate(&RewardSource {
        reward_proposer_addr: string(field(b"proposer_address"))?,
        reward_proposer_public_key: proposer_key,
        reward_members: members,
    })
    .ok()
}

impl DecodedHeader {
    /// Matches the native decoder's required types and optional-field defaults.
    /// The caller applies its local I/O bound before parsing.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let document = Document::parse_native(raw, ReadMode::Safe).ok()?;
        let field = |name: &[u8]| document.field(document.root(), name);
        let Value::Int(epoch) = field(b"id")? else {
            return None;
        };
        let Value::Int(count) = field(b"tx_count")? else {
            return None;
        };
        // Native Yojson.to_number accepts Int/Float, including nonfinite Float.
        if !matches!(field(b"finalized_at")?, Value::Int(_) | Value::Float(_)) {
            return None;
        }
        let reward_source = match field(b"reward_source") {
            None | Some(Value::Null) => None,
            Some(value) => Some(source(&document, value)?),
        };
        let recipients = match field(b"reward_recipients") {
            Some(Value::List(rows)) => rows
                .iter()
                .filter_map(|index| {
                    let row = document.get(*index)?;
                    // A malformed amount makes the native decoder skip the row,
                    // even though attribution itself never uses the amount.
                    string(document.field(row, b"amount"))?;
                    Some(Recipient {
                        address: string(document.field(row, b"address"))?,
                        role: string(document.field(row, b"role"))?,
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        Some(Self {
            reward: Header {
                epoch: *epoch,
                creator: string(field(b"creator_addr")).unwrap_or_default(),
                finalized_by: string(field(b"finalized_by"))?,
                validator_reward_each: string(field(b"validator_reward_each"))
                    .unwrap_or_else(|| b"0".to_vec()),
                recipients,
                reward_source,
            },
            state_root: string(field(b"state_root"))?,
            previous_root: string(field(b"prev_state_root"))?,
            parent_commit: string(field(b"parent_commit"))?,
            start_txid: parse_int64(&string(field(b"start_txid"))?)?,
            transaction_count: *count,
        })
    }
}
