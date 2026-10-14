// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native proof receipts and commitment bytes. A valid receipt is a binding,
//! not proof that its cryptographic work or state transition was executed.
use crate::{
    circle_wasm::transcript,
    native_integer,
    native_json::{Document, Value},
    resource_lanes::{self, Lane, Usage},
    transaction::{is_valid_address, json_string, Transaction},
};
use num_bigint::BigInt;
use num_traits::Signed;
use sha2::{Digest, Sha256};

pub const SCHEMA: &[u8] = b"octra_preverify_receipt_v1";
pub const BOUND_SCHEMA: &[u8] = b"octra_preverify_receipt_v2";
pub const CIRCLE_SCHEMA: &[u8] = b"octra_preverify_receipt_v3";
pub const TRANSITION_SCHEMA: &[u8] = b"octra_private_transition_receipt";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub pre_state_hash: Vec<u8>,
    pub source_cipher_hash: Vec<u8>,
    pub pvac_key_hash: Vec<u8>,
    pub transition_hash: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Circle {
    pub snapshot_hash: Vec<u8>,
    pub circle_id: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub stable_root: Vec<u8>,
    pub public_reads_hash: Vec<u8>,
    pub context_hash: Vec<u8>,
    pub transcript: Vec<transcript::Entry>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    Unbound,
    Private(State),
    Circle(Circle),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tx_hash: Vec<u8>,
    pub lane: Lane,
    pub engine: Vec<u8>,
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub binding: Binding,
    pub ok: bool,
    pub reason: Vec<u8>,
    pub cost: Usage,
}
type Result<T> = std::result::Result<T, String>;
struct Fields<'a> {
    doc: &'a Document,
    value: &'a Value,
}
impl<'a> Fields<'a> {
    fn get(&self, name: &str) -> Result<&'a Value> {
        self.doc
            .field(self.value, name.as_bytes())
            .ok_or_else(|| format!("{name}_missing"))
    }
    fn text(&self, name: &str) -> Result<Vec<u8>> {
        match self.get(name)? {
            Value::String(v) => Ok(v.clone()),
            _ => Err(format!("{name}_invalid")),
        }
    }
    fn int(&self, name: &str) -> Result<i64> {
        match self.get(name)? {
            Value::Int(v) => Ok(v.get()),
            _ => Err(format!("{name}_invalid")),
        }
    }
}
fn hex_len(value: &[u8], len: usize) -> bool {
    value.len() == len && value.iter().all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
}
fn hex64(value: &[u8]) -> bool {
    hex_len(value, 64)
}
fn text(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if out.len() > 1 {
        out.push(b',');
    }
    json_string(out, name);
    out.push(b':');
    json_string(out, value);
}
fn digest(tag: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(tag);
    h.update([0]);
    h.update(payload);
    hex::encode(h.finalize()).into_bytes()
}
pub fn state_hash(root: &[u8]) -> Vec<u8> {
    digest(b"octra:preverify_state:v2", root)
}
impl Binding {
    pub fn schema(&self) -> &'static [u8] {
        match self {
            Self::Unbound => SCHEMA,
            Self::Private(State {
                transition_hash: None,
                ..
            }) => BOUND_SCHEMA,
            Self::Private(_) => TRANSITION_SCHEMA,
            Self::Circle(_) => CIRCLE_SCHEMA,
        }
    }
    pub fn engine(&self, lane: Lane) -> &'static [u8] {
        if matches!(self, Self::Circle(_)) {
            return b"circle_hfhe_preverify_v1";
        }
        match (self, lane) {
            (Self::Unbound, Lane::Pvac) => b"pvac_preverify_v1",
            (Self::Unbound, Lane::Fhe) => b"fhe_preverify_v1",
            (
                Self::Private(State {
                    transition_hash: None,
                    ..
                }),
                Lane::Pvac,
            ) => b"pvac_preverify_v2",
            (
                Self::Private(State {
                    transition_hash: None,
                    ..
                }),
                Lane::Fhe,
            ) => b"fhe_preverify_v2",
            (Self::Private(_), Lane::Pvac) => b"pvac_transition_preverify",
            (Self::Private(_), Lane::Fhe) => b"fhe_transition_preverify",
            _ => b"unsupported_preverify_lane",
        }
    }
    fn payload(&self, tx: &Transaction) -> Result<Vec<u8>> {
        let mut out = tx.to_json_bytes().map_err(|e| e.to_string())?;
        let fields: Vec<&[u8]> = match self {
            Self::Unbound => Vec::new(),
            Self::Private(s) => {
                let mut fields = vec![
                    s.pre_state_hash.as_slice(),
                    s.source_cipher_hash.as_slice(),
                    s.pvac_key_hash.as_slice(),
                ];
                if let Some(h) = &s.transition_hash {
                    fields.push(h);
                }
                fields
            }
            Self::Circle(c) => vec![
                &c.snapshot_hash,
                &c.circle_id,
                &c.code_hash,
                &c.stable_root,
                &c.public_reads_hash,
                &c.context_hash,
            ],
        };
        for field in fields {
            out.push(0);
            out.extend_from_slice(field);
        }
        if let Self::Circle(c) = self {
            out.push(0);
            out.extend_from_slice(&transcript::canonical(&c.transcript));
        }
        Ok(out)
    }
    pub fn input_hash(&self, tx: &Transaction) -> Result<Vec<u8>> {
        let tag: &[u8] = match self {
            Self::Unbound => b"octra:preverify_input:v1",
            Self::Private(_) => b"octra:preverify_input:v2",
            Self::Circle(_) => b"octra:circle_preverify_input:v1",
        };
        Ok(digest(tag, &self.payload(tx)?))
    }
    pub fn output_hash(&self, tx: &Transaction, status: &[u8]) -> Result<Vec<u8>> {
        let tag: &[u8] = match self {
            Self::Unbound => b"octra:preverify_output:v1",
            Self::Private(_) => b"octra:preverify_output:v2",
            Self::Circle(_) => b"octra:circle_preverify_output:v1",
        };
        let mut out = hex::encode(tx.hash().map_err(|e| e.to_string())?).into_bytes();
        out.push(0);
        if !matches!(self, Self::Unbound) {
            out.extend_from_slice(&self.payload(tx)?);
            out.push(0);
        }
        out.extend_from_slice(status);
        Ok(digest(tag, &out))
    }
}
impl Receipt {
    /// Parsing and semantic validation are separate, as in the native runtime.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let doc = Document::parse(raw).map_err(|_| "receipt_json_invalid".to_owned())?;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err("receipt_invalid".into());
        }
        let f = Fields {
            doc: &doc,
            value: doc.root(),
        };
        let schema = f.text("schema")?;
        let tx_hash = f.text("tx_hash")?;
        let lane = match f.text("lane")?.as_slice() {
            b"program" => Lane::Program,
            b"circle_compute" => Lane::CircleCompute,
            b"pvac" => Lane::Pvac,
            b"fhe" => Lane::Fhe,
            _ => return Err("invalid_lane".into()),
        };
        let engine = f.text("engine")?;
        let input_hash = f.text("input_hash")?;
        let output_hash = f.text("output_hash")?;
        let ok = match f.get("ok")? {
            Value::Bool(v) => *v,
            _ => return Err("ok_invalid".into()),
        };
        let reason = f.text("reason")?;
        let cost = f.get("cost")?;
        if !matches!(cost, Value::Object(_)) {
            return Err("cost_invalid".into());
        }
        let c = Fields {
            doc: &doc,
            value: cost,
        };
        let transactions = c.int("txs")?;
        let bytes = c.int("bytes")?;
        let ou =
            native_integer::parse_integer(&c.text("ou")?).ok_or_else(|| "ou_invalid".to_owned())?;
        let proofs = c.int("proof")?;
        let cost = Usage {
            transactions,
            bytes,
            ou,
            proofs,
        };
        let binding = match schema.as_slice() {
            SCHEMA => Binding::Unbound,
            BOUND_SCHEMA | TRANSITION_SCHEMA => Binding::Private(State {
                pre_state_hash: f.text("pre_state_hash")?,
                source_cipher_hash: f.text("source_cipher_hash")?,
                pvac_key_hash: f.text("pvac_key_hash")?,
                transition_hash: if schema == TRANSITION_SCHEMA {
                    Some(f.text("transition_hash")?)
                } else {
                    None
                },
            }),
            CIRCLE_SCHEMA => Binding::Circle(Circle {
                snapshot_hash: f.text("pre_state_hash")?,
                circle_id: f.text("circle_id")?,
                code_hash: f.text("code_hash")?,
                stable_root: f.text("stable_root")?,
                public_reads_hash: f.text("public_reads_hash")?,
                context_hash: f.text("context_hash")?,
                transcript: transcript::decode_value(&doc, f.get("transcript")?)
                    .map_err(|e| e.to_string())?,
            }),
            _ => return Err("invalid_schema".into()),
        };
        Ok(Self {
            tx_hash,
            lane,
            engine,
            input_hash,
            output_hash,
            binding,
            ok,
            reason,
            cost,
        })
    }
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = vec![b'{'];
        for (name, value) in [
            (b"schema".as_slice(), self.binding.schema()),
            (b"tx_hash", &self.tx_hash),
            (b"lane", self.lane.as_str().as_bytes()),
            (b"engine", &self.engine),
            (b"input_hash", &self.input_hash),
            (b"output_hash", &self.output_hash),
        ] {
            text(&mut out, name, value);
        }
        out.extend_from_slice(if self.ok {
            b",\"ok\":true"
        } else {
            b",\"ok\":false"
        });
        text(&mut out, b"reason", &self.reason);
        out.extend_from_slice(
            format!(
                ",\"cost\":{{\"txs\":{},\"bytes\":{},\"ou\":\"{}\",\"proof\":{}}}",
                self.cost.transactions, self.cost.bytes, self.cost.ou, self.cost.proofs
            )
            .as_bytes(),
        );
        match &self.binding {
            Binding::Unbound => (),
            Binding::Private(s) => {
                for (name, value) in [
                    (b"pre_state_hash".as_slice(), &s.pre_state_hash),
                    (b"source_cipher_hash", &s.source_cipher_hash),
                    (b"pvac_key_hash", &s.pvac_key_hash),
                ] {
                    text(&mut out, name, value);
                }
                if let Some(h) = &s.transition_hash {
                    text(&mut out, b"transition_hash", h);
                }
            }
            Binding::Circle(c) => {
                for (name, value) in [
                    (b"pre_state_hash".as_slice(), &c.snapshot_hash),
                    (b"circle_id", &c.circle_id),
                    (b"code_hash", &c.code_hash),
                    (b"stable_root", &c.stable_root),
                    (b"public_reads_hash", &c.public_reads_hash),
                    (b"context_hash", &c.context_hash),
                ] {
                    text(&mut out, name, value);
                }
                out.extend_from_slice(b",\"transcript\":");
                out.extend_from_slice(&transcript::entries_json(&c.transcript));
            }
        }
        out.push(b'}');
        out
    }
    pub fn hash(&self) -> Vec<u8> {
        digest(self.binding.schema(), &self.canonical())
    }
    pub fn validate(&self) -> Result<()> {
        let private = matches!(self.lane, Lane::Pvac | Lane::Fhe);
        let lane = match self.binding {
            Binding::Unbound | Binding::Private(_) => private,
            Binding::Circle(_) => self.lane == Lane::CircleCompute,
        };
        let error = if !hex64(&self.tx_hash) {
            Some("invalid_tx_hash")
        } else if !lane {
            Some("invalid_lane")
        } else if self.engine != self.binding.engine(self.lane) {
            Some("invalid_engine")
        } else if !hex64(&self.input_hash) {
            Some("invalid_input_hash")
        } else if !hex64(&self.output_hash) {
            Some("invalid_output_hash")
        } else if matches!(&self.binding,Binding::Private(s) if !hex64(&s.pre_state_hash)||!hex64(&s.source_cipher_hash)||!hex64(&s.pvac_key_hash)||s.transition_hash.as_deref().is_some_and(|h|!hex64(h)))
        {
            Some("invalid_state_binding")
        } else if matches!(&self.binding,Binding::Circle(c) if !hex64(&c.snapshot_hash)||!is_valid_address(&c.circle_id)||!hex64(&c.code_hash)||!(hex64(&c.stable_root)||hex_len(&c.stable_root,128))||!hex64(&c.public_reads_hash)||!hex64(&c.context_hash)||transcript::validate(&c.transcript).is_err())
        {
            Some("invalid_circle_binding")
        } else if self.ok && !self.reason.is_empty() {
            Some("ok_reason_not_empty")
        } else if !self.ok && self.reason.is_empty() {
            Some("fail_reason_empty")
        } else if self.reason.len() > 128 {
            Some("reason_too_long")
        } else if self.cost.transactions != 1
            || self.cost.bytes < 0
            || self.cost.ou.is_negative()
            || self.cost.proofs < 1
        {
            Some("invalid_cost")
        } else {
            None
        };
        error.map_or(Ok(()), |e| Err(e.into()))
    }
    pub fn for_tx(
        tx: &Transaction,
        binding: Binding,
        input_hash: Vec<u8>,
        output_hash: Vec<u8>,
        ok: bool,
        reason: Vec<u8>,
        minimum: &BigInt,
    ) -> Result<Self> {
        let lane = if matches!(binding, Binding::Circle(_)) {
            Lane::CircleCompute
        } else {
            Lane::of(tx.op_type)
        };
        let receipt = Self {
            tx_hash: hex::encode(tx.hash().map_err(|e| e.to_string())?).into_bytes(),
            lane,
            engine: binding.engine(lane).to_vec(),
            input_hash,
            output_hash,
            binding,
            ok,
            reason,
            cost: resource_lanes::cost(tx, minimum).map_err(|e| e.to_string())?,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}
