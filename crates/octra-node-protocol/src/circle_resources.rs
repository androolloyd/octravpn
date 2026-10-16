// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native resource payloads and locator derivation. Transaction authorization,
//! byte budgets and effect-specific validation belong to the execution host.
use crate::{
    circle_program::Refusal,
    circles::{self, LocatorMode, MetadataMode},
    native_integer::parse_int64,
    native_json::{Document, Value},
};
type Result<T> = std::result::Result<T, Refusal>;
fn malformed(reason: impl Into<Vec<u8>>) -> Refusal {
    Refusal::new("malformed_transaction", reason)
}
pub const MAX_ENCODED_BODY: usize = 33_554_432usize.div_ceil(3) * 4;

struct Fields<'a> {
    doc: &'a Document,
    scope: &'static str,
}
impl<'a> Fields<'a> {
    fn new(doc: &'a Document, scope: &'static str) -> Result<Self> {
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(malformed(
                format!("{scope} must be a json object").into_bytes(),
            ));
        }
        Ok(Self { doc, scope })
    }
    fn get(&self, name: &str) -> Option<&'a Value> {
        self.doc.field(self.doc.root(), name.as_bytes())
    }
    fn invalid(&self, name: &str, missing: bool) -> Refusal {
        malformed(
            format!(
                "{} {} field: {name}",
                if missing { "missing" } else { "invalid" },
                self.scope
            )
            .into_bytes(),
        )
    }
    fn text(&self, name: &str) -> Result<Vec<u8>> {
        match self.get(name) {
            Some(Value::String(raw)) => Ok(raw.clone()),
            _ => Err(self.invalid(name, true)),
        }
    }
    fn optional(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.get(name) {
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            None | Some(Value::Null) => Ok(None),
            _ => Err(self.invalid(name, false)),
        }
    }
    fn integer(&self, name: &str) -> Result<Option<i64>> {
        match self.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(value)) => Ok(Some(value.get())),
            Some(Value::String(raw) | Value::IntLiteral(raw)) => {
                parse_int64(raw).map(Some).ok_or_else(|| {
                    Refusal::new(
                        "malformed_transaction_exception",
                        b"Failure(\"Int64.of_string\")",
                    )
                })
            }
            _ => Err(self.invalid(name, false)),
        }
    }
    fn boolean(&self, name: &str) -> Result<bool> {
        match self.get(name) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(self.invalid(name, false)),
        }
    }
}
fn integer_exceptions(results: &[&Result<Option<i64>>]) -> Result<()> {
    for result in results {
        if let Err(error) = result {
            if error.tag == "malformed_transaction_exception" {
                return Err(error.clone());
            }
        }
    }
    Ok(())
}
pub struct PublicAsset {
    pub path: Vec<u8>,
    pub content_type: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
}
impl PublicAsset {
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::new(doc, "asset put payload")?;
        Ok(Self {
            path: fields.text("path")?,
            content_type: fields.text("content_type")?,
            encoding: fields.optional("encoding")?,
        })
    }
}
pub struct EncryptedAsset {
    pub path: Option<Vec<u8>>,
    pub slot_ref: Option<Vec<u8>>,
    pub state_ref: Option<Vec<u8>>,
    pub content_type: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
    pub key_id: Vec<u8>,
    pub plaintext_hash: Vec<u8>,
    pub padding_class: Option<Vec<u8>>,
    pub activate_after_epoch: Option<i64>,
    pub expire_after_epoch: Option<i64>,
    pub metadata_mode: Option<MetadataMode>,
}
impl EncryptedAsset {
    pub fn parse(doc: &Document, sealed_object: bool) -> Result<Self> {
        let fields = Fields::new(doc, "encrypted asset put payload")?;
        let expire = fields.integer("expire_after_epoch");
        let activate = fields.integer("activate_after_epoch");
        integer_exceptions(&[&expire, &activate])?;
        let path = fields.optional("path")?;
        let slot_ref = fields.optional("slot_ref")?;
        let state_ref = fields.optional("state_ref")?;
        let content_type = fields.text("content_type")?;
        let encoding = fields.optional("encoding")?;
        let key_id = fields.text("key_id")?;
        let plaintext_hash = fields.text("plaintext_hash")?;
        let padding_class = fields.optional("padding_class")?;
        let activate_after_epoch = activate?;
        let expire_after_epoch = expire?;
        let metadata_mode = match fields.optional("metadata_mode")? {
            None => None,
            Some(raw) => Some(match raw.as_slice() {
                b"reveal" => MetadataMode::Reveal,
                b"opaque" => MetadataMode::Opaque,
                _ => {
                    return Err(malformed(
                        [b"unknown metadata mode: ".as_slice(), &raw].concat(),
                    ))
                }
            }),
        };
        if sealed_object {
            let error = if path.is_some() {
                Some("sealed slot put payload must not include path")
            } else if slot_ref.is_none() && state_ref.is_none() {
                Some("sealed slot put payload requires slot_ref or state_ref")
            } else if slot_ref.is_some() && state_ref.is_some() {
                Some("sealed slot put payload requires exactly one of slot_ref or state_ref")
            } else {
                None
            };
            if let Some(error) = error {
                return Err(malformed(error.as_bytes()));
            }
        }
        Ok(Self {
            path,
            slot_ref,
            state_ref,
            content_type,
            encoding,
            key_id,
            plaintext_hash,
            padding_class,
            activate_after_epoch,
            expire_after_epoch,
            metadata_mode,
        })
    }
}
pub struct SlotPolicy {
    pub slot_ref: Option<Vec<u8>>,
    pub state_ref: Option<Vec<u8>>,
    pub delivery_key_id: Option<Vec<u8>>,
    pub activate_after_epoch: Option<i64>,
    pub expire_after_epoch: Option<i64>,
    pub tombstone: bool,
    pub revoked: bool,
}
impl SlotPolicy {
    pub fn parse(doc: &Document) -> Result<Self> {
        let fields = Fields::new(doc, "slot policy payload")?;
        let expire = fields.integer("expire_after_epoch");
        let activate = fields.integer("activate_after_epoch");
        integer_exceptions(&[&expire, &activate])?;
        let payload = Self {
            slot_ref: fields.optional("slot_ref")?,
            state_ref: fields.optional("state_ref")?,
            delivery_key_id: fields.optional("delivery_key_id")?,
            activate_after_epoch: activate?,
            expire_after_epoch: expire?,
            tombstone: fields.boolean("tombstone")?,
            revoked: fields.boolean("revoked")?,
        };
        if payload.slot_ref.is_none() && payload.state_ref.is_none() {
            return Err(malformed(
                b"slot policy payload requires slot_ref or state_ref",
            ));
        }
        if payload.slot_ref.is_some() && payload.state_ref.is_some() {
            return Err(malformed(
                b"slot policy payload requires exactly one of slot_ref or state_ref",
            ));
        }
        Ok(payload)
    }
}

pub struct Locator {
    pub path: Vec<u8>,
    pub key: Vec<u8>,
    pub resource: Vec<u8>,
    pub mode: LocatorMode,
    pub slot: Option<Vec<u8>>,
}
impl Locator {
    pub fn path(circle: &[u8], raw: &[u8]) -> Result<Self> {
        let path = circles::normalize_path(raw)
            .map_err(|e| Refusal::new("invalid_circle_path", e.0))?
            .into_bytes();
        Ok(Self {
            key: circles::path_key(&path).into_bytes(),
            resource: circles::resource_key(circle, &path).into_bytes(),
            path,
            mode: LocatorMode::Path,
            slot: None,
        })
    }
    fn reference(circle: &[u8], raw: &[u8], slot: bool, raw_state_resource: bool) -> Result<Self> {
        let normalized = circles::normalize_state_ref(raw).map_err(|_| {
            Refusal::new(
                if slot {
                    "invalid_circle_slot_ref"
                } else {
                    "invalid_circle_state_ref"
                },
                if slot {
                    b"slot_ref must be a 64-char hex string".as_slice()
                } else {
                    b"state_ref must be a 64-char hex string"
                },
            )
        })?;
        let path = [
            if slot {
                b"/_slots/".as_slice()
            } else {
                b"/_state/"
            },
            &normalized,
        ]
        .concat();
        let key = circles::domain_hash(
            if slot {
                b"octra:asset_path:v1"
            } else {
                b"octra:asset_state_path:v1"
            },
            &[&path],
        )
        .into_bytes();
        let resource = circles::domain_hash(
            if slot {
                b"octra:circle_resource_key:slot:v1"
            } else {
                b"octra:circle_resource_key:state:v1"
            },
            &[
                circle,
                if !slot && raw_state_resource {
                    raw
                } else {
                    &normalized
                },
            ],
        )
        .into_bytes();
        Ok(Self {
            path,
            key,
            resource,
            mode: if slot {
                LocatorMode::Slot
            } else {
                LocatorMode::State
            },
            slot: slot.then_some(normalized),
        })
    }
    pub fn encrypted(
        circle: &[u8],
        path: Option<&[u8]>,
        slot: Option<&[u8]>,
        state: Option<&[u8]>,
    ) -> Result<Self> {
        match (path, slot, state) {
            (Some(path), None, None) => Self::path(circle, path),
            (None, Some(slot), None) => Self::reference(circle, slot, true, true),
            (None, None, Some(state)) => Self::reference(circle, state, false, true),
            (None, None, None) => Err(Refusal::new(
                "invalid_circle_locator",
                b"path, slot_ref, or state_ref is required",
            )),
            _ => Err(Refusal::new(
                "invalid_circle_locator",
                b"provide exactly one of path, slot_ref, or state_ref",
            )),
        }
    }
    pub fn sealed(circle: &[u8], slot: Option<&[u8]>, state: Option<&[u8]>) -> Result<Self> {
        match (slot, state) {
            (Some(slot), None) => Self::reference(circle, slot, true, false),
            (None, Some(state)) => Self::reference(circle, state, false, false),
            (None, None) => Err(Refusal::new(
                "invalid_circle_locator",
                b"sealed object payload requires slot_ref or state_ref",
            )),
            _ => Err(Refusal::new(
                "invalid_circle_locator",
                b"sealed object payload requires exactly one of slot_ref or state_ref",
            )),
        }
    }
}
