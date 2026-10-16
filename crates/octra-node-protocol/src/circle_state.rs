// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native state descriptors. Put snapshots retain the submitted option values;
//! resolved descriptors normalize fields only for validation and consumption.
use crate::{
    circle_policy::{malformed, native_enum, Result, Snapshot},
    circle_program::Refusal,
    circles,
    native_json::{Document, Value},
    network::endpoint::native_trim,
    transaction::is_valid_address,
};
native_enum!(Class, b"unknown state descriptor class: ", {
    Opaque => b"opaque_cell", Cipher => b"cipher_cell", Balance => b"balance_cell", Register => b"register_cell", Program => b"program_object",
});
native_enum!(Hfhe, b"unknown state descriptor hfhe profile: ", {
    None => b"none", Cipher => b"ciphertext_v1", Balance => b"balance_cell_v1", Register => b"register_cell_v1", CommitBound => b"commit_bound_v1",
});
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub class: Class,
    pub codec: Vec<u8>,
    pub schema: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub hfhe: Hfhe,
    pub mutable: bool,
}
impl Default for Descriptor {
    fn default() -> Self {
        Self {
            class: Class::Opaque,
            codec: b"opaque_b64_v1".to_vec(),
            schema: None,
            subject: None,
            hfhe: Hfhe::None,
            mutable: true,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Payload {
    pub state: Vec<u8>,
    pub class: Option<Class>,
    pub codec: Option<Vec<u8>>,
    pub schema: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub hfhe: Option<Hfhe>,
    pub mutable: Option<bool>,
}
impl Payload {
    pub fn parse(doc: &Document) -> Result<Self> {
        if !matches!(doc.root(), Value::Object(_)) {
            return Err(malformed(b"state descriptor payload must be an object"));
        }
        let get = |name: &[u8]| doc.field(doc.root(), name);
        let Some(Value::String(raw)) = get(b"state_ref") else {
            return Err(malformed(b"state descriptor payload requires state_ref"));
        };
        let text = |name: &str| match get(name.as_bytes()) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(raw)) => Ok(Some(raw.clone())),
            _ => Err(malformed(format!("invalid {name}").into_bytes())),
        };
        let class = text("state_class")?
            .as_deref()
            .map(Class::parse)
            .transpose()?;
        let codec = text("codec")?;
        let schema = text("schema_hash")?;
        let subject = text("subject_addr")?;
        let hfhe = text("hfhe_profile")?
            .as_deref()
            .map(Hfhe::parse)
            .transpose()?;
        let mutable = match get(b"mutable_state") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(value)) => Some(*value),
            _ => return Err(malformed(b"invalid mutable_state")),
        };
        let state = circles::normalize_state_ref(raw).map_err(|e| malformed(e.0))?;
        Ok(Self {
            state,
            class,
            codec,
            schema,
            subject,
            hfhe,
            mutable,
        })
    }
    pub fn resolve(&self) -> Result<Descriptor> {
        let default = Descriptor::default();
        Descriptor {
            class: self.class.unwrap_or(default.class),
            codec: self.codec.clone().unwrap_or(default.codec),
            schema: self.schema.clone(),
            subject: self.subject.clone(),
            hfhe: self.hfhe.unwrap_or(default.hfhe),
            mutable: self.mutable.unwrap_or(default.mutable),
        }
        .validate()
    }
    pub fn snapshot(&self, path_key: &[u8]) -> Snapshot {
        let mut out = Snapshot::default();
        let prefix = [b"state_descriptor:".as_slice(), path_key].concat();
        out.set(
            &prefix,
            b"state_class",
            self.class.map(|v| v.as_bytes().to_vec()),
        );
        out.set(&prefix, b"codec", self.codec.clone());
        out.set(&prefix, b"schema_hash", self.schema.clone());
        out.set(&prefix, b"subject_addr", self.subject.clone());
        out.set(
            &prefix,
            b"hfhe_profile",
            self.hfhe.map(|v| v.as_bytes().to_vec()),
        );
        out.set(
            &prefix,
            b"mutable_state",
            self.mutable.map(|v| {
                if v {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                }
            }),
        );
        out
    }
}
impl Descriptor {
    pub fn encode(&self) -> Vec<u8> {
        use crate::circle_policy::view::{boolean, object, optional, string};
        object(&[
            (b"state_class", string(self.class.as_bytes())),
            (b"codec", string(&self.codec)),
            (b"schema_hash", optional(self.schema.as_deref())),
            (b"subject_addr", optional(self.subject.as_deref())),
            (b"hfhe_profile", string(self.hfhe.as_bytes())),
            (b"mutable_state", boolean(self.mutable)),
        ])
    }
    pub fn validate(mut self) -> Result<Self> {
        let invalid =
            |reason: &'static [u8]| Refusal::new("invalid_circle_state_descriptor", reason);
        self.codec = native_trim(&self.codec).to_vec();
        if self.codec.is_empty() {
            return Err(invalid(b"state descriptor codec must not be empty"));
        }
        if let Some(raw) = self.schema.take() {
            let normalized = native_trim(&raw).to_ascii_lowercase();
            if !normalized.is_empty() {
                if normalized.len() != 64 || !normalized.iter().all(u8::is_ascii_hexdigit) {
                    return Err(invalid(
                        b"state descriptor schema_hash must be a 64-char hex string",
                    ));
                }
                self.schema = Some(normalized);
            }
        }
        if let Some(raw) = self.subject.take() {
            let normalized = native_trim(&raw).to_vec();
            if !normalized.is_empty() {
                if !is_valid_address(&normalized) {
                    return Err(invalid(
                        b"state descriptor subject_addr must be a valid octra address",
                    ));
                }
                self.subject = Some(normalized);
            }
        }
        Ok(self)
    }
    pub fn payload(&self, state: &[u8]) -> Payload {
        Payload {
            state: state.to_vec(),
            class: Some(self.class),
            codec: Some(self.codec.clone()),
            schema: self.schema.clone(),
            subject: self.subject.clone(),
            hfhe: Some(self.hfhe),
            mutable: Some(self.mutable),
        }
    }
    pub fn from_stored(mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Self {
        let default = Self::default();
        let class = get(b"state_class")
            .and_then(|raw| Class::parse(native_trim(&raw)).ok())
            .unwrap_or(default.class);
        let codec = get(b"codec")
            .map(|raw| native_trim(&raw).to_vec())
            .filter(|raw| !raw.is_empty())
            .unwrap_or(default.codec);
        let schema = get(b"schema_hash");
        let subject = get(b"subject_addr");
        let hfhe = get(b"hfhe_profile")
            .and_then(|raw| Hfhe::parse(native_trim(&raw)).ok())
            .unwrap_or(default.hfhe);
        let mutable = get(b"mutable_state").map_or(default.mutable, |raw| {
            matches!(
                native_trim(&raw).to_ascii_lowercase().as_slice(),
                b"1" | b"true" | b"yes"
            )
        });
        Self {
            class,
            codec,
            schema,
            subject,
            hfhe,
            mutable,
        }
        .validate()
        .unwrap_or_default()
    }
}
