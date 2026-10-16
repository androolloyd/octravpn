// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Ordered Circle metadata templates from Oct_gen. Typed families consolidate
//! identical layouts while retaining state-path normalization and optional writes.
use super::{Emitter, Error, Result, I};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingKind {
    Balance,
    Register,
    Object,
}
impl BindingKind {
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::Balance => b"balance_binding:",
            Self::Register => b"register_binding:",
            Self::Object => b"object_binding:",
        }
    }
    fn label(self) -> &'static [u8] {
        match self {
            Self::Balance => b"balance binding",
            Self::Register => b"register binding",
            Self::Object => b"object binding",
        }
    }
    fn last(self) -> &'static [u8] {
        if self == Self::Object {
            b"last_transition_ref"
        } else {
            b"last_workflow_ref"
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    State,
    Object,
}
impl PolicyKind {
    fn prefix(self) -> &'static [u8] {
        match self {
            Self::State => b"state_policy:",
            Self::Object => b"object_policy:",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    Tombstone,
    Revoked,
}
impl Flag {
    fn suffix(self) -> &'static [u8] {
        match self {
            Self::Tombstone => b":tombstone",
            Self::Revoked => b":revoked",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    BalanceWorkflow,
    RegisterWorkflow,
    StateDescriptor,
    BalanceCell,
    RegisterCell,
    ObjectTransition,
}
type Fields = &'static [(&'static [u8], bool)];
impl RecordKind {
    fn layout(self) -> (&'static [u8], bool, Fields) {
        match self {
            Self::BalanceWorkflow => (
                b"balance_workflow:",
                false,
                &[
                    (b":flow_kind", false),
                    (b":debit_subject_addr", false),
                    (b":credit_subject_addr", false),
                    (b":debit_state_ref", false),
                    (b":credit_state_ref", false),
                    (b":amount_commitment", false),
                    (b":proof_kind", false),
                    (b":proof_receipt_hash", false),
                    (b":status", false),
                    (b":intent_id", false),
                ],
            ),
            Self::RegisterWorkflow => (
                b"register_workflow:",
                false,
                &[
                    (b":register_ref", false),
                    (b":previous_state_ref", false),
                    (b":next_state_ref", false),
                    (b":workflow_kind", false),
                    (b":proof_kind", false),
                    (b":proof_receipt_hash", false),
                    (b":status", false),
                    (b":intent_id", false),
                ],
            ),
            Self::StateDescriptor => (
                b"state_descriptor:",
                true,
                &[
                    (b":state_class", false),
                    (b":codec", false),
                    (b":schema_hash", true),
                    (b":subject_addr", true),
                    (b":hfhe_profile", false),
                    (b":mutable_state", false),
                ],
            ),
            Self::BalanceCell => (
                b"balance_cell:",
                true,
                &[
                    (b":ciphertext_commitment", false),
                    (b":amount_commitment", false),
                    (b":proof_kind", false),
                    (b":proof_receipt_hash", true),
                ],
            ),
            Self::RegisterCell => (
                b"register_cell:",
                true,
                &[
                    (b":ciphertext_commitment", false),
                    (b":proof_kind", false),
                    (b":proof_receipt_hash", true),
                ],
            ),
            Self::ObjectTransition => (
                b"object_transition:",
                false,
                &[
                    (b":object_ref", false),
                    (b":previous_state_ref", false),
                    (b":next_state_ref", false),
                    (b":touched_members_hash", false),
                    (b":proof_kind", false),
                    (b":proof_receipt_hash", true),
                    (b":status", false),
                    (b":intent_id", false),
                ],
            ),
        }
    }
}
impl Emitter {
    pub fn state_path_key(&mut self, state: u8) -> Result<u8> {
        let key = self.alloc_reg()?;
        self.emit(I::StatePathKey(key, state))?;
        Ok(key)
    }
    fn policy_key(&mut self, kind: PolicyKind, key: u8) -> Result<u8> {
        if kind == PolicyKind::State {
            self.state_path_key(key)
        } else {
            Ok(key)
        }
    }
    pub fn binding_load(&mut self, kind: BindingKind, field: &[u8], key: u8) -> Result<u8> {
        let suffix = [b":".as_slice(), field].concat();
        if field == b"version" {
            self.dynamic_int(kind.prefix(), key, &suffix)
        } else if matches!(field, b"current_state_ref" | b"status") || field == kind.last() {
            self.dynamic_load(kind.prefix(), key, &suffix)
        } else {
            Err(self.error([b"unsupported ".as_slice(), kind.label(), b" field: ", field].concat()))
        }
    }
    pub fn binding_bind(
        &mut self,
        kind: BindingKind,
        destination: u8,
        key: u8,
        state: u8,
        last: u8,
        status: u8,
    ) -> Result<()> {
        self.storage_write()?;
        let version = self.dynamic_int(kind.prefix(), key, b":version")?;
        let one = self.alloc_reg()?;
        self.integer(one, 1)?;
        self.emit(I::Add(version, version, one))?;
        self.dynamic_store(kind.prefix(), key, b":current_state_ref", state)?;
        self.dynamic_store(kind.prefix(), key, b":version", version)?;
        self.dynamic_store(kind.prefix(), key, b":status", status)?;
        self.dynamic_store(
            kind.prefix(),
            key,
            &[b":".as_slice(), kind.last()].concat(),
            last,
        )?;
        self.emit(I::Mov(destination, version))
    }
    pub fn descriptor_load(&mut self, field: &[u8], state: u8) -> Result<u8> {
        let key = self.state_path_key(state)?;
        let suffix = [b":".as_slice(), field].concat();
        match field {
            b"mutable_state" => {
                let value = self.dynamic_load(b"state_descriptor:", key, &suffix)?;
                self.bool_from_storage(value)
            }
            b"state_class" | b"codec" | b"schema_hash" | b"subject_addr" | b"hfhe_profile" => {
                self.dynamic_load(b"state_descriptor:", key, &suffix)
            }
            _ => {
                Err(self
                    .error([b"unsupported state descriptor field: ".as_slice(), field].concat()))
            }
        }
    }
    pub fn state_policy_load(&mut self, field: &[u8], state: u8) -> Result<u8> {
        let key = self.state_path_key(state)?;
        let suffix = [b":".as_slice(), field].concat();
        match field {
            b"activate_after_epoch" | b"expire_after_epoch" => {
                self.dynamic_int(b"state_policy:", key, &suffix)
            }
            b"tombstone" | b"revoked" => {
                let value = self.dynamic_load(b"state_policy:", key, &suffix)?;
                self.bool_from_storage(value)
            }
            b"delivery_key_id" => self.dynamic_load(b"state_policy:", key, &suffix),
            _ => Err(self.error([b"unsupported state policy field: ".as_slice(), field].concat())),
        }
    }
    pub fn cell_load(&mut self, balance: bool, field: &[u8], state: u8) -> Result<u8> {
        let key = self.state_path_key(state)?;
        if matches!(
            field,
            b"ciphertext_commitment" | b"proof_kind" | b"proof_receipt_hash"
        ) || balance && field == b"amount_commitment"
        {
            self.dynamic_load(
                if balance {
                    b"balance_cell:"
                } else {
                    b"register_cell:"
                },
                key,
                &[b":".as_slice(), field].concat(),
            )
        } else {
            Err(self.error(
                [
                    if balance {
                        b"unsupported balance cell field: ".as_slice()
                    } else {
                        b"unsupported register cell field: "
                    },
                    field,
                ]
                .concat(),
            ))
        }
    }
    pub fn member_load(&mut self, field: &[u8], object: u8, member: u8) -> Result<u8> {
        let key = self.joined_key(object, member)?;
        if matches!(
            field,
            b"state_ref" | b"member_kind" | b"state_class" | b"codec" | b"status"
        ) {
            self.dynamic_load(b"object_member:", key, &[b":".as_slice(), field].concat())
        } else {
            Err(self.error([b"unsupported object member field: ".as_slice(), field].concat()))
        }
    }
    pub fn object_policy_load(&mut self, field: &[u8], object: u8) -> Result<u8> {
        let suffix = [b":".as_slice(), field].concat();
        match field {
            b"activate_after_epoch" | b"expire_after_epoch" | b"member_quorum" => {
                self.dynamic_int(b"object_policy:", object, &suffix)
            }
            b"tombstone" | b"revoked" | b"allow_detach" | b"allow_root_state_rotation" => {
                let value = self.dynamic_load(b"object_policy:", object, &suffix)?;
                self.bool_from_storage(value)
            }
            b"delivery_key_id" | b"transition_mode" | b"required_proof_kind" => {
                self.dynamic_load(b"object_policy:", object, &suffix)
            }
            _ => Err(self.error([b"unsupported object policy field: ".as_slice(), field].concat())),
        }
    }
    fn store_fields(
        &mut self,
        prefix: &[u8],
        key: u8,
        fields: &[(&[u8], bool)],
        values: &[u8],
        destination: u8,
    ) -> Result<()> {
        if fields.len() != values.len() {
            return Err(Error::Unavailable(
                "compiler record argument transport differs",
            ));
        }
        for ((suffix, optional), value) in fields.iter().zip(values) {
            if *optional {
                self.dynamic_optional(prefix, key, suffix, *value)?;
            } else {
                self.dynamic_store(prefix, key, suffix, *value)?;
            }
        }
        self.boolean(destination, true)
    }
    pub fn record(
        &mut self,
        kind: RecordKind,
        destination: u8,
        key: u8,
        values: &[u8],
    ) -> Result<()> {
        self.storage_write()?;
        let (prefix, state, fields) = kind.layout();
        let key = if state {
            self.state_path_key(key)?
        } else {
            key
        };
        self.store_fields(prefix, key, fields, values, destination)
    }
    pub fn state_publish(
        &mut self,
        destination: u8,
        state: u8,
        delivery: u8,
        activate: u8,
        expire: u8,
    ) -> Result<()> {
        self.storage_write()?;
        let key = self.state_path_key(state)?;
        let value = self.alloc_reg()?;
        self.boolean(value, false)?;
        self.dynamic_optional(b"state_policy:", key, b":delivery_key_id", delivery)?;
        self.dynamic_store(b"state_policy:", key, b":activate_after_epoch", activate)?;
        self.dynamic_store(b"state_policy:", key, b":expire_after_epoch", expire)?;
        self.dynamic_store(b"state_policy:", key, b":tombstone", value)?;
        self.dynamic_store(b"state_policy:", key, b":revoked", value)?;
        self.boolean(destination, true)
    }
    pub fn policy_release(&mut self, kind: PolicyKind, destination: u8, key: u8) -> Result<()> {
        self.storage_write()?;
        let key = self.policy_key(kind, key)?;
        let value = self.alloc_reg()?;
        self.boolean(value, false)?;
        if kind == PolicyKind::Object {
            self.dynamic_delete(kind.prefix(), key, b":delivery_key_id")?;
        }
        self.dynamic_delete(kind.prefix(), key, b":activate_after_epoch")?;
        self.dynamic_delete(kind.prefix(), key, b":expire_after_epoch")?;
        self.dynamic_store(kind.prefix(), key, b":tombstone", value)?;
        self.dynamic_store(kind.prefix(), key, b":revoked", value)?;
        self.boolean(destination, true)
    }
    pub fn policy_retire(
        &mut self,
        kind: PolicyKind,
        destination: u8,
        key: u8,
        expire: u8,
    ) -> Result<()> {
        self.storage_write()?;
        let key = self.policy_key(kind, key)?;
        self.dynamic_store(kind.prefix(), key, b":expire_after_epoch", expire)?;
        self.boolean(destination, true)
    }
    pub fn policy_flag(
        &mut self,
        kind: PolicyKind,
        destination: u8,
        key: u8,
        flag: Flag,
        enabled: bool,
    ) -> Result<()> {
        self.storage_write()?;
        let key = self.policy_key(kind, key)?;
        let value = self.alloc_reg()?;
        self.boolean(value, enabled)?;
        self.dynamic_store(kind.prefix(), key, flag.suffix(), value)?;
        self.boolean(destination, true)
    }
    pub fn member_attach(
        &mut self,
        destination: u8,
        object: u8,
        member: u8,
        values: [u8; 5],
    ) -> Result<()> {
        self.storage_write()?;
        let key = self.joined_key(object, member)?;
        self.store_fields(
            b"object_member:",
            key,
            &[
                (b":state_ref", false),
                (b":member_kind", false),
                (b":state_class", false),
                (b":codec", false),
                (b":status", false),
            ],
            &values,
            destination,
        )
    }
    pub fn member_detach(&mut self, destination: u8, object: u8, member: u8) -> Result<()> {
        self.storage_write()?;
        let key = self.joined_key(object, member)?;
        for suffix in [
            b":state_ref".as_slice(),
            b":member_kind",
            b":state_class",
            b":codec",
            b":status",
        ] {
            self.dynamic_delete(b"object_member:", key, suffix)?;
        }
        self.boolean(destination, true)
    }
    pub fn object_policy_define(
        &mut self,
        destination: u8,
        object: u8,
        values: [u8; 8],
    ) -> Result<()> {
        self.storage_write()?;
        let value = self.alloc_reg()?;
        self.boolean(value, false)?;
        self.dynamic_optional(b"object_policy:", object, b":delivery_key_id", values[0])?;
        for (suffix, register) in [
            b":activate_after_epoch".as_slice(),
            b":expire_after_epoch",
            b":transition_mode",
            b":required_proof_kind",
            b":member_quorum",
            b":allow_detach",
            b":allow_root_state_rotation",
        ]
        .into_iter()
        .zip(&values[1..])
        {
            self.dynamic_store(b"object_policy:", object, suffix, *register)?;
        }
        self.dynamic_store(b"object_policy:", object, b":tombstone", value)?;
        self.dynamic_store(b"object_policy:", object, b":revoked", value)?;
        self.boolean(destination, true)
    }
    pub fn transition_apply(&mut self, destination: u8, values: [u8; 10]) -> Result<()> {
        self.storage_write()?;
        let [transition, object, previous, next, members, touched, proof, receipt, status, intent] =
            values;
        self.emit(I::ObjectTransitionApply(
            destination,
            transition,
            object,
            previous,
            next,
            members,
            touched,
            proof,
            receipt,
            status,
            intent,
        ))
    }
}
