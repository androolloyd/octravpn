// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native outbox records. Field order and string-encoded Int64 values are part
//! of committed storage; they must not pass through a sorted JSON map.
use crate::{
    circle_policy::{fields::Fields, key, Result},
    circle_program::Refusal,
    native_integer::parse_int64,
    native_json::{Document, Value},
    transaction::json_string,
};
pub mod machine;
pub mod verify;
pub mod view;
// Keep record wire names independent of Rust variant names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open,
    Claimed,
    Fulfilled,
    Expired,
    Cancelled,
}
impl Status {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        match raw {
            b"open" => Some(Self::Open),
            b"claimed" => Some(Self::Claimed),
            b"fulfilled" => Some(Self::Fulfilled),
            b"expired" => Some(Self::Expired),
            b"cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Open => b"open",
            Self::Claimed => b"claimed",
            Self::Fulfilled => b"fulfilled",
            Self::Expired => b"expired",
            Self::Cancelled => b"cancelled",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Fulfilled,
    RelayCancelled,
    OwnerCancelled,
    IntentExpired,
    ClaimExpired,
    ClaimSetExhausted,
    KeyInactive,
    KeyExpired,
    KeyRevoked,
    KeyErased,
}
impl Reason {
    pub const fn status(self) -> Status {
        match self {
            Self::Fulfilled => Status::Fulfilled,
            Self::IntentExpired | Self::ClaimExpired => Status::Expired,
            _ => Status::Cancelled,
        }
    }
    pub fn parse(raw: &[u8]) -> Option<Self> {
        match raw {
            b"fulfilled_delivery" => Some(Self::Fulfilled),
            b"relay_cancelled" => Some(Self::RelayCancelled),
            b"owner_cancelled" => Some(Self::OwnerCancelled),
            b"intent_expired" => Some(Self::IntentExpired),
            b"claim_expired" => Some(Self::ClaimExpired),
            b"claim_set_exhausted" => Some(Self::ClaimSetExhausted),
            b"delivery_key_inactive" => Some(Self::KeyInactive),
            b"delivery_key_expired" => Some(Self::KeyExpired),
            b"delivery_key_revoked" => Some(Self::KeyRevoked),
            b"delivery_key_erased" => Some(Self::KeyErased),
            _ => None,
        }
    }
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Fulfilled => b"fulfilled_delivery",
            Self::RelayCancelled => b"relay_cancelled",
            Self::OwnerCancelled => b"owner_cancelled",
            Self::IntentExpired => b"intent_expired",
            Self::ClaimExpired => b"claim_expired",
            Self::ClaimSetExhausted => b"claim_set_exhausted",
            Self::KeyInactive => b"delivery_key_inactive",
            Self::KeyExpired => b"delivery_key_expired",
            Self::KeyRevoked => b"delivery_key_revoked",
            Self::KeyErased => b"delivery_key_erased",
        }
    }
    pub const fn from_key(state: key::State) -> Option<Self> {
        match state {
            key::State::Expired => Some(Self::KeyExpired),
            key::State::Revoked => Some(Self::KeyRevoked),
            key::State::Erased => Some(Self::KeyErased),
            _ => None,
        }
    }
}
fn integer(raw: &[u8]) -> Result<i64> {
    parse_int64(raw).ok_or_else(|| {
        Refusal::new(
            "malformed_transaction_exception",
            b"Failure(\"Int64.of_string\")",
        )
    })
}
/// All native records here use string fields (or null for optional strings).
fn encode(fields: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
    let mut out = vec![b'{'];
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        json_string(&mut out, key);
        out.push(b':');
        match value {
            Some(raw) => json_string(&mut out, raw),
            None => out.extend_from_slice(b"null"),
        }
    }
    out.push(b'}');
    out
}
fn subject(parts: &[&[u8]]) -> Vec<u8> {
    parts.join(&b'|')
}
#[derive(Clone, Debug)]
pub struct Intent {
    pub id: Vec<u8>,
    pub created: i64,
    pub expiry: i64,
    pub relay_policy: Vec<u8>,
    pub payload: Vec<u8>,
    pub ciphertext: Option<Vec<u8>>,
    pub delivery_key: Option<Vec<u8>>,
    pub max_response: i64,
    pub fee_budget: i64,
    pub route: Option<Vec<u8>>,
    pub callback_policy: Option<Vec<u8>>,
}
impl Intent {
    pub fn parse(doc: &Document, created: Option<i64>) -> Result<Self> {
        let scope = if created.is_some() {
            "outbox open payload"
        } else {
            "outbox intent"
        };
        let fields = Fields::object(doc, scope, &format!("{scope} must be a json object"))?;
        let id = fields.required("intent_id")?;
        let created_raw = if created.is_none() {
            Some(fields.required("created_epoch")?)
        } else {
            None
        };
        let expiry = fields.required("expiry_epoch")?;
        let relay_policy = fields.required("relay_policy_hash")?;
        let payload = fields.required("payload_hash")?;
        let ciphertext = fields.text("ciphertext_blob_hash")?;
        let delivery_key = fields.text("delivery_key_id")?;
        let max_response = fields.required("max_response_bytes")?;
        let fee_budget = fields.required("fee_budget")?;
        let route = fields.text("route_hint")?;
        let callback_policy = fields.text("callback_policy_hash")?;
        // Record construction evaluates numeric conversions right to left.
        let fee_budget = integer(&fee_budget)?;
        let max_response = integer(&max_response)?;
        let expiry = integer(&expiry)?;
        let created = match created {
            Some(epoch) => epoch,
            None => integer(created_raw.as_deref().unwrap_or_default())?,
        };
        Ok(Self {
            id,
            created,
            expiry,
            relay_policy,
            payload,
            ciphertext,
            delivery_key,
            max_response,
            fee_budget,
            route,
            callback_policy,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        encode(&[
            (b"intent_id", Some(&self.id)),
            (b"created_epoch", Some(self.created.to_string().as_bytes())),
            (b"expiry_epoch", Some(self.expiry.to_string().as_bytes())),
            (b"relay_policy_hash", Some(&self.relay_policy)),
            (b"payload_hash", Some(&self.payload)),
            (b"ciphertext_blob_hash", self.ciphertext.as_deref()),
            (b"delivery_key_id", self.delivery_key.as_deref()),
            (
                b"max_response_bytes",
                Some(self.max_response.to_string().as_bytes()),
            ),
            (b"fee_budget", Some(self.fee_budget.to_string().as_bytes())),
            (b"route_hint", self.route.as_deref()),
            (b"callback_policy_hash", self.callback_policy.as_deref()),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Claim {
    pub intent: Vec<u8>,
    pub relay: Vec<u8>,
    pub epoch: i64,
    pub expiry: i64,
    pub signature: Vec<u8>,
}
impl Claim {
    pub fn subject(&self, circle: &[u8]) -> Vec<u8> {
        subject(&[
            b"octra_circle_relay_claim",
            circle,
            &self.intent,
            &self.relay,
            self.epoch.to_string().as_bytes(),
            self.expiry.to_string().as_bytes(),
        ])
    }
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::object(doc, "relay claim", "relay claim must be a json object")?;
        let intent = fields.required("intent_id")?;
        let relay = fields.required("relay_id")?;
        let epoch = fields.required("claim_epoch")?;
        let expiry = fields.required("claim_expiry_epoch")?;
        let signature = fields.required("signature")?;
        let expiry = integer(&expiry)?;
        let epoch = integer(&epoch)?;
        Ok(Self {
            intent,
            relay,
            epoch,
            expiry,
            signature,
        })
    }
    pub fn live(&self, epoch: i64) -> bool {
        epoch >= self.epoch && epoch < self.expiry
    }
    pub fn encode(&self) -> Vec<u8> {
        encode(&[
            (b"intent_id", Some(&self.intent)),
            (b"relay_id", Some(&self.relay)),
            (b"claim_epoch", Some(self.epoch.to_string().as_bytes())),
            (
                b"claim_expiry_epoch",
                Some(self.expiry.to_string().as_bytes()),
            ),
            (b"signature", Some(&self.signature)),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Resolution {
    pub intent: Vec<u8>,
    pub status: Status,
    pub reason: Reason,
    pub epoch: i64,
    pub actor: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
}
impl Resolution {
    pub fn make(
        intent: &[u8],
        epoch: i64,
        actor: Option<&[u8]>,
        key: Option<&[u8]>,
        reason: Reason,
    ) -> Self {
        Self {
            intent: intent.to_vec(),
            status: reason.status(),
            reason,
            epoch,
            actor: actor.map(<[u8]>::to_vec),
            key: key.map(<[u8]>::to_vec),
        }
    }
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::object(
            doc,
            "outbox resolution",
            "outbox resolution must be a json object",
        )?;
        let intent = fields.required("intent_id")?;
        let status = fields.required("status")?;
        let reason = fields.required("reason")?;
        let epoch = fields.required("resolved_epoch")?;
        let actor = fields.text("actor_id")?;
        let key = fields.text("related_key_id")?;
        let status = Status::parse(&status).ok_or_else(|| {
            crate::circle_policy::malformed(
                [b"unknown outbox status: ".as_slice(), &status].concat(),
            )
        })?;
        let reason = Reason::parse(&reason).ok_or_else(|| {
            crate::circle_policy::malformed(
                [b"unknown outbox resolution reason: ".as_slice(), &reason].concat(),
            )
        })?;
        Ok(Self {
            intent,
            status,
            reason,
            epoch: integer(&epoch)?,
            actor,
            key,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        encode(&[
            (b"intent_id", Some(&self.intent)),
            (b"status", Some(self.status.as_bytes())),
            (b"reason", Some(self.reason.as_bytes())),
            (b"resolved_epoch", Some(self.epoch.to_string().as_bytes())),
            (b"actor_id", self.actor.as_deref()),
            (b"related_key_id", self.key.as_deref()),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Cancel {
    pub intent: Vec<u8>,
    pub relay: Vec<u8>,
    pub epoch: i64,
    pub reason: Reason,
    pub key: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}
impl Cancel {
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::object(doc, "relay cancel", "relay cancel must be a json object")?;
        let intent = fields.required("intent_id")?;
        let relay = fields.required("relay_id")?;
        let epoch = fields.required("cancel_epoch")?;
        let reason = fields.required("reason")?;
        let key = fields.text("related_key_id")?;
        let signature = fields.required("signature")?;
        let reason = Reason::parse(&reason).ok_or_else(|| {
            crate::circle_policy::malformed(
                [b"unknown outbox resolution reason: ".as_slice(), &reason].concat(),
            )
        })?;
        Ok(Self {
            intent,
            relay,
            epoch: integer(&epoch)?,
            reason,
            key,
            signature,
        })
    }
    pub fn subject(&self, circle: &[u8]) -> Vec<u8> {
        subject(&[
            b"octra_circle_relay_cancel",
            circle,
            &self.intent,
            &self.relay,
            self.epoch.to_string().as_bytes(),
            self.reason.as_bytes(),
            self.key.as_deref().unwrap_or_default(),
        ])
    }
}
#[derive(Clone, Debug)]
pub struct Packet {
    pub intent: Vec<u8>,
    pub relay: Vec<u8>,
    pub nonce: i64,
    pub code: i64,
    pub payload: Vec<u8>,
    pub size: i64,
    pub ciphertext: Option<Vec<u8>>,
    pub receipt: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}
impl Packet {
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::object(
            doc,
            "ingress packet",
            "ingress packet must be a json object",
        )?;
        let intent = fields.required("intent_id")?;
        let relay = fields.required("relay_id")?;
        let nonce = fields.required("ingress_nonce")?;
        let code = fields.get("result_code");
        let payload = fields.required("response_payload_hash")?;
        let size = fields.required("response_size_bytes")?;
        let ciphertext = fields.text("response_ciphertext_blob_hash")?;
        let receipt = fields.text("external_receipt_hash")?;
        let signature = fields.required("signature")?;
        let Some(Value::Int(code)) = code else {
            return Err(crate::circle_policy::malformed(
                b"missing ingress packet field: result_code",
            ));
        };
        let size = integer(&size)?;
        let nonce = integer(&nonce)?;
        Ok(Self {
            intent,
            relay,
            nonce,
            code: code.get(),
            payload,
            size,
            ciphertext,
            receipt,
            signature,
        })
    }
    pub fn subject(&self, circle: &[u8]) -> Vec<u8> {
        subject(&[
            b"octra_circle_ingress_commit",
            circle,
            &self.intent,
            &self.relay,
            self.nonce.to_string().as_bytes(),
            self.code.to_string().as_bytes(),
            &self.payload,
            self.size.to_string().as_bytes(),
            self.ciphertext.as_deref().unwrap_or_default(),
            self.receipt.as_deref().unwrap_or_default(),
        ])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = encode(&[
            (b"intent_id", Some(&self.intent)),
            (b"relay_id", Some(&self.relay)),
            (b"ingress_nonce", Some(self.nonce.to_string().as_bytes())),
        ]);
        raw.pop();
        raw.extend_from_slice(b",\"result_code\":");
        raw.extend_from_slice(self.code.to_string().as_bytes());
        raw.push(b',');
        let tail = encode(&[
            (b"response_payload_hash", Some(&self.payload)),
            (
                b"response_size_bytes",
                Some(self.size.to_string().as_bytes()),
            ),
            (b"response_ciphertext_blob_hash", self.ciphertext.as_deref()),
            (b"external_receipt_hash", self.receipt.as_deref()),
            (b"signature", Some(&self.signature)),
        ]);
        raw.extend_from_slice(&tail[1..]);
        raw
    }
}
