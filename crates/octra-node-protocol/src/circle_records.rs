// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native binding/workflow snapshots. Schemas fix field order and stored
//! normalization; invalid fields stay absent instead of inventing records.
use crate::{
    circle_policy::{
        hfhe::Proof,
        view::{object, optional},
        Snapshot,
    },
    circles::Error,
    native_integer::parse_int64,
    network::endpoint::native_trim,
    transaction::{decode_base64, is_valid_address},
};
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    BalanceBinding,
    RegisterBinding,
    BalanceWorkflow,
    RegisterWorkflow,
    ObjectBinding,
    ObjectMember,
    ObjectPolicy,
    ObjectTransition,
    BalanceCell,
    RegisterCell,
}
#[derive(Clone, Copy)]
enum Format {
    Text,
    Hex,
    Address,
    Version,
    Commitment,
    Proof,
    Boolean,
    TransitionMode,
}
type Field = (&'static [u8], Format);
const BINDING: &[Field] = &[
    (b"current_state_ref", Format::Hex),
    (b"version", Format::Version),
    (b"status", Format::Text),
    (b"last_workflow_ref", Format::Hex),
];
const BALANCE_FLOW: &[Field] = &[
    (b"flow_kind", Format::Text),
    (b"debit_subject_addr", Format::Address),
    (b"credit_subject_addr", Format::Address),
    (b"debit_state_ref", Format::Hex),
    (b"credit_state_ref", Format::Hex),
    (b"amount_commitment", Format::Commitment),
    (b"proof_kind", Format::Proof),
    (b"proof_receipt_hash", Format::Hex),
    (b"status", Format::Text),
    (b"intent_id", Format::Hex),
];
const REGISTER_FLOW: &[Field] = &[
    (b"register_ref", Format::Hex),
    (b"previous_state_ref", Format::Hex),
    (b"next_state_ref", Format::Hex),
    (b"workflow_kind", Format::Text),
    (b"proof_kind", Format::Proof),
    (b"proof_receipt_hash", Format::Hex),
    (b"status", Format::Text),
    (b"intent_id", Format::Hex),
];
const OBJECT_BINDING: &[Field] = &[
    (b"current_state_ref", Format::Hex),
    (b"version", Format::Version),
    (b"status", Format::Text),
    (b"last_transition_ref", Format::Hex),
];
const OBJECT_MEMBER: &[Field] = &[
    (b"state_ref", Format::Hex),
    (b"member_kind", Format::Text),
    (b"state_class", Format::Text),
    (b"codec", Format::Text),
    (b"status", Format::Text),
];
const OBJECT_POLICY: &[Field] = &[
    (b"delivery_key_id", Format::Text),
    (b"activate_after_epoch", Format::Version),
    (b"expire_after_epoch", Format::Version),
    (b"tombstone", Format::Boolean),
    (b"revoked", Format::Boolean),
    (b"transition_mode", Format::TransitionMode),
    (b"required_proof_kind", Format::Proof),
    (b"member_quorum", Format::Version),
    (b"allow_detach", Format::Boolean),
    (b"allow_root_state_rotation", Format::Boolean),
];
const OBJECT_TRANSITION: &[Field] = &[
    (b"object_ref", Format::Hex),
    (b"previous_state_ref", Format::Hex),
    (b"next_state_ref", Format::Hex),
    (b"touched_members_hash", Format::Hex),
    (b"proof_kind", Format::Proof),
    (b"proof_receipt_hash", Format::Hex),
    (b"status", Format::Text),
    (b"intent_id", Format::Hex),
];
const BALANCE_CELL: &[Field] = &[
    (b"ciphertext_commitment", Format::Commitment),
    (b"amount_commitment", Format::Commitment),
    (b"proof_kind", Format::Proof),
    (b"proof_receipt_hash", Format::Hex),
];
const REGISTER_CELL: &[Field] = &[
    (b"ciphertext_commitment", Format::Commitment),
    (b"proof_kind", Format::Proof),
    (b"proof_receipt_hash", Format::Hex),
];
impl Kind {
    pub const fn prefix(self) -> &'static [u8] {
        match self {
            Self::BalanceBinding => b"balance_binding",
            Self::RegisterBinding => b"register_binding",
            Self::BalanceWorkflow => b"balance_workflow",
            Self::RegisterWorkflow => b"register_workflow",
            Self::ObjectBinding => b"object_binding",
            Self::ObjectMember => b"object_member",
            Self::ObjectPolicy => b"object_policy",
            Self::ObjectTransition => b"object_transition",
            Self::BalanceCell => b"balance_cell",
            Self::RegisterCell => b"register_cell",
        }
    }
    pub const fn subject_field(self) -> &'static str {
        match self {
            Self::BalanceBinding => "subject_addr",
            Self::RegisterBinding => "register_ref",
            Self::BalanceWorkflow | Self::RegisterWorkflow => "workflow_ref",
            Self::ObjectTransition => "transition_ref",
            Self::BalanceCell | Self::RegisterCell => "state_ref",
            Self::ObjectBinding | Self::ObjectMember | Self::ObjectPolicy => "object_ref",
        }
    }
    fn fields(self) -> &'static [Field] {
        match self {
            Self::BalanceBinding | Self::RegisterBinding => BINDING,
            Self::BalanceWorkflow => BALANCE_FLOW,
            Self::RegisterWorkflow => REGISTER_FLOW,
            Self::ObjectBinding => OBJECT_BINDING,
            Self::ObjectMember => OBJECT_MEMBER,
            Self::ObjectPolicy => OBJECT_POLICY,
            Self::ObjectTransition => OBJECT_TRANSITION,
            Self::BalanceCell => BALANCE_CELL,
            Self::RegisterCell => REGISTER_CELL,
        }
    }
    pub fn field_names(self) -> impl Iterator<Item = &'static [u8]> {
        self.fields().iter().map(|(name, _)| *name)
    }
    pub fn normalize_subject(self, raw: &[u8]) -> Result<Vec<u8>, Error> {
        if matches!(self, Self::BalanceBinding) {
            if is_valid_address(raw) {
                Ok(raw.to_vec())
            } else {
                Err(Error(
                    b"subject_addr must be a valid octra address".to_vec(),
                ))
            }
        } else {
            let normalized = native_trim(raw).to_ascii_lowercase();
            if normalized.len() == 64 && normalized.iter().all(u8::is_ascii_hexdigit) {
                Ok(normalized)
            } else {
                Err(Error(
                    format!("{} must be a 64-char hex string", self.subject_field()).into_bytes(),
                ))
            }
        }
    }
    pub fn from_stored(self, mut get: impl FnMut(&[u8]) -> Option<Vec<u8>>) -> Record {
        let fields = self
            .fields()
            .iter()
            .map(|(name, format)| (*name, get(name).and_then(|raw| format.parse(&raw))))
            .collect();
        Record { kind: self, fields }
    }
}
impl Format {
    fn parse(self, raw: &[u8]) -> Option<Vec<u8>> {
        let trimmed = native_trim(raw);
        match self {
            Self::Text => (!trimmed.is_empty()).then(|| trimmed.to_vec()),
            Self::Hex => {
                let normalized = trimmed.to_ascii_lowercase();
                (normalized.len() == 64 && normalized.iter().all(u8::is_ascii_hexdigit))
                    .then_some(normalized)
            }
            Self::Address => is_valid_address(trimmed).then(|| trimmed.to_vec()),
            Self::Version => parse_int64(trimmed)
                .filter(|version| *version >= 0)
                .map(|version| version.to_string().into_bytes()),
            Self::Commitment => decode_base64(trimmed)
                .ok()
                .filter(|raw| raw.len() == 32)
                .map(|_| trimmed.to_vec()),
            Self::Proof => Proof::parse(trimmed)
                .ok()
                .filter(|proof| *proof != Proof::None)
                .map(|proof| proof.as_bytes().to_vec()),
            Self::Boolean => match trimmed.to_ascii_lowercase().as_slice() {
                b"1" | b"true" | b"yes" => Some(b"true".to_vec()),
                b"0" | b"false" | b"no" => Some(b"false".to_vec()),
                _ => None,
            },
            Self::TransitionMode => {
                matches!(trimmed, b"open" | b"proof_required" | b"frozen").then(|| trimmed.to_vec())
            }
        }
    }
    fn encode(self, value: Option<&[u8]>) -> Vec<u8> {
        match (self, value) {
            (Self::Boolean, Some(value)) => value.to_vec(),
            _ => optional(value),
        }
    }
}
pub struct Record {
    kind: Kind,
    fields: Vec<(&'static [u8], Option<Vec<u8>>)>,
}
impl Record {
    pub fn materialized(&self) -> bool {
        self.fields.iter().any(|(_, value)| value.is_some())
    }
    pub fn get(&self, name: &[u8]) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(field, _)| *field == name)
            .and_then(|(_, value)| value.as_deref())
    }
    pub fn encode(&self) -> Vec<u8> {
        object(
            &self
                .fields
                .iter()
                .zip(self.kind.fields())
                .map(|((name, value), (_, format))| (*name, format.encode(value.as_deref())))
                .collect::<Vec<_>>(),
        )
    }
    pub fn snapshot(&self, subject: &[u8]) -> Snapshot {
        let prefix = [self.kind.prefix(), b":", subject].concat();
        let mut out = Snapshot::default();
        for (name, value) in &self.fields {
            out.set(&prefix, name, value.clone());
        }
        out
    }
}
