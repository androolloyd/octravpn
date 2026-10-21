//! Private records are serialized only inside the encrypted database.
use super::Incoming;
use anyhow::{ensure, Result};
use octra_private_payments_experimental::pool::{self, call::Call, Membership};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Meta {
    pub(super) version: u8,
    pub(super) scope: [u8; 32],
    pub(super) wallet: [u8; 32],
    pub(super) next_slot: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallRecord {
    pub(super) quote: [u8; 32],
    pub(super) valid_from: u64,
    pub(super) expires: u64,
    pub(super) payout: String,
    pub(super) deposit: u64,
    pub(super) withdraw: u64,
    pub(super) boxes: [String; 2],
    pub(super) relayer: String,
}
impl CallRecord {
    pub(super) fn new(call: &Call, relayer: &[u8; 47]) -> Result<Self> {
        Ok(Self {
            quote: call.quote,
            valid_from: call.valid_from_ms,
            expires: call.expires_ms,
            payout: std::str::from_utf8(&call.payout)?.to_owned(),
            deposit: call.deposit_ou,
            withdraw: call.withdraw_ou,
            boxes: call.boxes.clone(),
            relayer: std::str::from_utf8(relayer)?.to_owned(),
        })
    }
    pub(super) fn call(&self) -> Result<Call> {
        Ok(Call {
            quote: self.quote,
            valid_from_ms: self.valid_from,
            expires_ms: self.expires,
            payout: super::super::native(&self.payout)?,
            deposit_ou: self.deposit,
            withdraw_ou: self.withdraw,
            boxes: self.boxes.clone(),
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Creation {
    pub(super) epoch: u64,
    pub(super) commitment: [u8; 32],
    pub(super) index: u32,
    pub(super) siblings: Vec<[u8; 32]>,
    pub(super) output: u8,
    pub(super) call: CallRecord,
}
impl Creation {
    pub(super) fn new(input: &Incoming<'_>) -> Result<Self> {
        Ok(Self {
            epoch: input.epoch,
            commitment: input.commitment,
            index: input.membership.index,
            siblings: input
                .membership
                .siblings
                .iter()
                .copied()
                .map(pool::encode_field)
                .collect(),
            output: input.output,
            call: CallRecord::new(input.call, &input.relayer)?,
        })
    }
    pub(super) fn membership(&self) -> Result<Membership> {
        ensure!(
            self.siblings.len() == pool::NOTE_DEPTH,
            "payer note path depth differs"
        );
        Ok(Membership {
            index: self.index,
            siblings: self
                .siblings
                .iter()
                .map(pool::decode_field)
                .collect::<Result<Vec<_>>>()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("payer note path differs"))?,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Income {
    pub(super) wallet: [u8; 32],
    pub(super) credit: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Coin {
    pub(super) slot: u64,
    pub(super) creation: Creation,
    pub(super) reserved: Option<[u8; 32]>,
    pub(super) spent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) income: Option<Income>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Accepted {
    pub(super) receipt: [u8; 32],
    pub(super) class: u8,
    pub(super) bytes: u64,
    pub(super) cost: u64,
    pub(super) relayer: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub(super) roots: [[u8; 32]; 2],
    pub(super) count: u64,
    pub(super) outputs: [[u8; 32]; 2],
    pub(super) call: CallRecord,
    pub(super) parameters: serde_json::Value,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
    Preparing,
    Ready,
    Paid,
    Expired,
    Cancelled,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) invoice: Vec<u8>,
    pub(super) accepted: Accepted,
    pub(super) inputs: Vec<[u8; 32]>,
    pub(super) change_slot: Option<u64>,
    pub(super) progress: Progress,
    pub(super) attempt: Option<Attempt>,
}
