// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native balance/register cell payloads and their stable-storage snapshots.
use crate::{
    circle_policy::{hfhe::Proof, Snapshot},
    circle_state::{self, Class, Descriptor, Hfhe},
    circles::{self, MetadataMode},
    native_integer::parse_int64,
    native_json::{Document, Value},
    network::endpoint::native_trim,
    transaction::decode_base64,
};
type Result<T> = std::result::Result<T, Vec<u8>>;
struct Fields<'a> {
    doc: &'a Document,
}
impl Fields<'_> {
    fn get(&self, name: &[u8]) -> Option<&Value> {
        self.doc.field(self.doc.root(), name)
    }
    fn text(&self, name: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            _ => Err([b"invalid ".as_slice(), name].concat()),
        }
    }
    fn required(&self, name: &[u8]) -> Result<Vec<u8>> {
        match self.get(name) {
            Some(Value::String(raw)) => Ok(raw.clone()),
            _ => Err([b"missing ".as_slice(), name].concat()),
        }
    }
    fn integer(&self, name: &[u8]) -> Result<Option<i64>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(value)) => Ok(Some(value.get())),
            Some(Value::String(raw)) => parse_int64(raw)
                .map(Some)
                .ok_or_else(|| [b"invalid ".as_slice(), name].concat()),
            _ => Err([b"invalid ".as_slice(), name].concat()),
        }
    }
    fn flag(&self, name: &[u8]) -> Result<Option<bool>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            _ => Err([b"invalid ".as_slice(), name].concat()),
        }
    }
}
fn nonempty(name: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let raw = native_trim(raw);
    if raw.is_empty() {
        Err([name, b" must not be empty"].concat())
    } else {
        Ok(raw.to_vec())
    }
}
fn hex64(name: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let raw = native_trim(raw).to_ascii_lowercase();
    if raw.len() == 64 && raw.iter().all(u8::is_ascii_hexdigit) {
        Ok(raw)
    } else {
        Err([name, b" must be a 64-char hex string"].concat())
    }
}
fn commitment(name: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let raw = nonempty(name, raw)?;
    match decode_base64(&raw) {
        Ok(value) if value.len() == 32 => Ok(raw),
        Ok(_) => Err([name, b" must decode to 32 bytes"].concat()),
        Err(_) => Err([name, b" must be valid base64"].concat()),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Balance,
    Register,
}
#[derive(Clone, Debug)]
pub struct Request {
    pub kind: Kind,
    pub state: Vec<u8>,
    pub content_type: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub padding: Option<Vec<u8>>,
    pub delivery_key: Option<Vec<u8>>,
    pub activate: Option<i64>,
    pub expire: Option<i64>,
    pub metadata: MetadataMode,
    pub descriptor: Descriptor,
    pub ciphertext_commitment: Vec<u8>,
    pub amount_commitment: Option<Vec<u8>>,
    pub proof: Option<Proof>,
    pub receipt_hash: Option<Vec<u8>>,
}
impl Request {
    pub fn parse(doc: &Document, kind: Kind) -> Result<Self> {
        let balance = kind == Kind::Balance;
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(if balance {
                b"balance cell payload must be an object".to_vec()
            } else {
                b"register cell payload must be an object".to_vec()
            });
        }
        let fields = Fields { doc };
        let state = fields.required(b"state_ref")?;
        let content_type = fields.text(b"content_type")?;
        let encoding = fields.text(b"encoding")?;
        let key = fields.required(b"key_id")?;
        let plaintext = fields.required(b"plaintext_hash")?;
        let padding = fields.text(b"padding_class")?;
        let delivery_key = fields.text(b"delivery_key_id")?;
        let activate = fields.integer(b"activate_after_epoch")?;
        let expire = fields.integer(b"expire_after_epoch")?;
        let metadata = fields
            .text(b"metadata_mode")?
            .map(|raw| match raw.as_slice() {
                b"reveal" => Ok(MetadataMode::Reveal),
                b"opaque" => Ok(MetadataMode::Opaque),
                _ => Err([b"unknown metadata mode: ".as_slice(), &raw].concat()),
            })
            .transpose()?;
        let codec = fields.text(b"codec")?;
        let schema = fields.text(b"schema_hash")?;
        let subject = fields.text(b"subject_addr")?;
        let mutable = fields.flag(b"mutable_state")?;
        let hfhe = fields
            .text(b"hfhe_profile")?
            .as_deref()
            .map(Hfhe::parse)
            .transpose()
            .map_err(|e| e.reason)?;
        let ciphertext_commitment = fields.required(b"ciphertext_commitment")?;
        let amount_commitment = if balance {
            Some(fields.required(b"amount_commitment")?)
        } else {
            None
        };
        let proof = fields
            .text(b"proof_kind")?
            .as_deref()
            .map(Proof::parse)
            .transpose()
            .map_err(|e| e.reason)?;
        let receipt_hash = fields.text(b"proof_receipt_hash")?;
        let state = circles::normalize_state_ref(&state).map_err(|e| e.0)?;
        let default_type: &[u8] = if balance {
            b"application/vnd.octra.balance-cell+ciphertext"
        } else {
            b"application/vnd.octra.register-cell+ciphertext"
        };
        let content_type = content_type
            .map(|raw| native_trim(&raw).to_vec())
            .filter(|raw| !raw.is_empty())
            .unwrap_or_else(|| default_type.to_vec());
        let key = nonempty(b"key_id", &key)?;
        let plaintext = hex64(b"plaintext_hash", &plaintext)?;
        let padding = padding
            .as_deref()
            .map(|raw| nonempty(b"padding_class", raw))
            .transpose()?;
        let delivery_key = delivery_key
            .as_deref()
            .map(|raw| nonempty(b"delivery_key_id", raw))
            .transpose()?;
        let ciphertext_commitment = commitment(b"ciphertext_commitment", &ciphertext_commitment)?;
        let amount_commitment = amount_commitment
            .as_deref()
            .map(|raw| commitment(b"amount_commitment", raw))
            .transpose()?;
        let proof = proof.filter(|proof| *proof != Proof::None);
        let receipt_hash = receipt_hash
            .as_deref()
            .map(|raw| hex64(b"proof_receipt_hash", raw))
            .transpose()?;
        if proof.is_some_and(Proof::receipt_required) {
            if receipt_hash.is_none() {
                return Err(b"proof_receipt_hash required for receipt proof kind".to_vec());
            }
        } else if receipt_hash.is_some() {
            return Err(b"proof_receipt_hash requires a receipt proof kind".to_vec());
        }
        if matches!((activate, expire), (Some(a), Some(e)) if e <= a) {
            return Err(b"expire_after_epoch must be greater than activate_after_epoch".to_vec());
        }
        let descriptor = circle_state::Payload {
            state: state.clone(),
            class: Some(if balance {
                Class::Balance
            } else {
                Class::Register
            }),
            codec,
            schema,
            subject,
            hfhe: Some(hfhe.unwrap_or(if balance {
                Hfhe::Balance
            } else {
                Hfhe::Register
            })),
            mutable,
        }
        .resolve()
        .map_err(|e| e.reason)?;
        if balance && !matches!(descriptor.hfhe, Hfhe::Balance | Hfhe::CommitBound) {
            return Err(
                b"balance cell requires balance_cell_v1 or commit_bound_v1 hfhe profile".to_vec(),
            );
        }
        if !balance && !matches!(descriptor.hfhe, Hfhe::Register | Hfhe::Cipher) {
            return Err(
                b"register cell requires register_cell_v1 or ciphertext_v1 hfhe profile".to_vec(),
            );
        }
        Ok(Self {
            kind,
            state,
            content_type,
            encoding,
            key,
            plaintext,
            padding,
            delivery_key,
            activate,
            expire,
            metadata: metadata.unwrap_or(MetadataMode::Opaque),
            descriptor,
            ciphertext_commitment,
            amount_commitment,
            proof,
            receipt_hash,
        })
    }
    pub fn snapshot(&self, path_key: &[u8]) -> Snapshot {
        let mut out = self.descriptor.payload(&self.state).snapshot(path_key);
        let prefix = [b"state_policy:".as_slice(), path_key].concat();
        out.set(&prefix, b"delivery_key_id", self.delivery_key.clone());
        out.set(
            &prefix,
            b"activate_after_epoch",
            self.activate.map(|v| v.to_string().into_bytes()),
        );
        out.set(
            &prefix,
            b"expire_after_epoch",
            self.expire.map(|v| v.to_string().into_bytes()),
        );
        out.set(&prefix, b"tombstone", None);
        out.set(&prefix, b"revoked", None);
        let mailbox = [b"mailbox:".as_slice(), path_key].concat();
        for name in [
            b"activate_after_epoch".as_slice(),
            b"expire_after_epoch",
            b"tombstone",
            b"revoked",
        ] {
            out.set(&mailbox, name, None);
        }
        let prefix = [
            if self.kind == Kind::Balance {
                b"balance_cell:".as_slice()
            } else {
                b"register_cell:"
            },
            path_key,
        ]
        .concat();
        out.set(
            &prefix,
            b"ciphertext_commitment",
            Some(self.ciphertext_commitment.clone()),
        );
        if self.kind == Kind::Balance {
            out.set(
                &prefix,
                b"amount_commitment",
                self.amount_commitment.clone(),
            );
        }
        out.set(
            &prefix,
            b"proof_kind",
            self.proof.map(|proof| proof.as_bytes().to_vec()),
        );
        out.set(&prefix, b"proof_receipt_hash", self.receipt_hash.clone());
        out
    }
}
pub struct ProofFields {
    pub zero: Option<Vec<u8>>,
    pub range: Option<Vec<u8>>,
    pub amount: Option<Vec<u8>>,
    pub intent: Vec<u8>,
    pub receipt: Option<Value>,
}
impl ProofFields {
    pub fn parse(doc: &Document) -> Result<Self> {
        let Value::Object(fields) = doc.root() else {
            return Err(b"circle cell payload must be an object".to_vec());
        };
        let mut names: Vec<_> = fields.iter().map(|(name, _)| name).collect();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(b"circle cell payload has duplicate fields".to_vec());
        }
        let optional = |name: &[u8]| match doc.field(doc.root(), name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(raw)) if raw.is_empty() => {
                Err([name, b" must not be empty"].concat())
            }
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            _ => Err([name, b" must be a string"].concat()),
        };
        Ok(Self {
            zero: optional(b"zero_proof")?,
            range: optional(b"range_proof")?,
            amount: optional(b"amount_commitment")?,
            intent: optional(b"intent_id")?.unwrap_or_default(),
            receipt: doc
                .field(doc.root(), b"proof_receipt")
                .filter(|v| !matches!(v, Value::Null))
                .cloned(),
        })
    }
}
