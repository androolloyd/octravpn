// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Circle builtin names map to the shared ordered metadata templates.
use super::{builtins::Arguments, BindingKind, Emitter, Flag, PolicyKind, RecordKind, Result, I};
impl Emitter {
    pub(super) fn circle_builtin(&mut self, dest: u8, args: &Arguments<'_>) -> Result<bool> {
        use BindingKind::{Balance, Object, Register};
        let binding: Option<(BindingKind, &[u8])> = match args.name {
            b"circle_balance_state_ref" => Some((Balance, b"current_state_ref")),
            b"circle_balance_version" => Some((Balance, b"version")),
            b"circle_balance_status" => Some((Balance, b"status")),
            b"circle_balance_last_workflow" => Some((Balance, b"last_workflow_ref")),
            b"circle_register_state_ref" => Some((Register, b"current_state_ref")),
            b"circle_register_version" => Some((Register, b"version")),
            b"circle_register_status" => Some((Register, b"status")),
            b"circle_register_last_workflow" => Some((Register, b"last_workflow_ref")),
            b"circle_object_state_ref" => Some((Object, b"current_state_ref")),
            b"circle_object_version" => Some((Object, b"version")),
            b"circle_object_status" => Some((Object, b"status")),
            b"circle_object_last_transition" => Some((Object, b"last_transition_ref")),
            _ => None,
        };
        if let Some((kind, field)) = binding {
            let value = self.binding_load(kind, field, args.nth(0)?)?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let member: Option<&[u8]> = match args.name {
            b"circle_object_member_state_ref" => Some(b"state_ref"),
            b"circle_object_member_kind" => Some(b"member_kind"),
            b"circle_object_member_class" => Some(b"state_class"),
            b"circle_object_member_codec" => Some(b"codec"),
            b"circle_object_member_status" => Some(b"status"),
            _ => None,
        };
        if let Some(field) = member {
            let values = args.required(2)?;
            let value = self.member_load(field, values[0], values[1])?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let object_policy: Option<&[u8]> = match args.name {
            b"circle_object_delivery_key_id" => Some(b"delivery_key_id"),
            b"circle_object_activate_after" => Some(b"activate_after_epoch"),
            b"circle_object_expire_after" => Some(b"expire_after_epoch"),
            b"circle_object_tombstone" => Some(b"tombstone"),
            b"circle_object_revoked" => Some(b"revoked"),
            b"circle_object_transition_mode" => Some(b"transition_mode"),
            b"circle_object_required_proof_kind" => Some(b"required_proof_kind"),
            b"circle_object_member_quorum" => Some(b"member_quorum"),
            b"circle_object_allow_detach" => Some(b"allow_detach"),
            b"circle_object_allow_root_state_rotation" => Some(b"allow_root_state_rotation"),
            _ => None,
        };
        if let Some(field) = object_policy {
            let value = self.object_policy_load(field, args.nth(0)?)?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let descriptor: Option<&[u8]> = match args.name {
            b"circle_state_class" => Some(b"state_class"),
            b"circle_state_codec" => Some(b"codec"),
            b"circle_state_schema_hash" => Some(b"schema_hash"),
            b"circle_state_subject_addr" => Some(b"subject_addr"),
            b"circle_state_hfhe_profile" => Some(b"hfhe_profile"),
            b"circle_state_mutable" => Some(b"mutable_state"),
            _ => None,
        };
        if let Some(field) = descriptor {
            let value = self.descriptor_load(field, args.nth(0)?)?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let state_policy: Option<&[u8]> = match args.name {
            b"circle_state_delivery_key_id" => Some(b"delivery_key_id"),
            b"circle_state_activate_after" => Some(b"activate_after_epoch"),
            b"circle_state_expire_after" => Some(b"expire_after_epoch"),
            b"circle_state_tombstone" => Some(b"tombstone"),
            b"circle_state_revoked" => Some(b"revoked"),
            _ => None,
        };
        if let Some(field) = state_policy {
            let value = self.state_policy_load(field, args.nth(0)?)?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let cell: Option<(bool, &[u8])> = match args.name {
            b"circle_balance_cell_ciphertext_commitment" => Some((true, b"ciphertext_commitment")),
            b"circle_balance_cell_amount_commitment" => Some((true, b"amount_commitment")),
            b"circle_balance_cell_proof_kind" => Some((true, b"proof_kind")),
            b"circle_balance_cell_proof_receipt_hash" => Some((true, b"proof_receipt_hash")),
            b"circle_register_cell_ciphertext_commitment" => {
                Some((false, b"ciphertext_commitment"))
            }
            b"circle_register_cell_proof_kind" => Some((false, b"proof_kind")),
            b"circle_register_cell_proof_receipt_hash" => Some((false, b"proof_receipt_hash")),
            _ => None,
        };
        if let Some((balance, field)) = cell {
            let value = self.cell_load(balance, field, args.nth(0)?)?;
            self.emit(I::Mov(dest, value))?;
            return Ok(true);
        }
        let record = match args.name {
            b"circle_state_describe" => Some((RecordKind::StateDescriptor, 7)),
            b"circle_balance_cell_materialize" => Some((RecordKind::BalanceCell, 5)),
            b"circle_register_cell_materialize" => Some((RecordKind::RegisterCell, 4)),
            b"circle_object_transition_record" => Some((RecordKind::ObjectTransition, 9)),
            b"circle_balance_workflow_record" => Some((RecordKind::BalanceWorkflow, 11)),
            b"circle_register_workflow_record" => Some((RecordKind::RegisterWorkflow, 9)),
            _ => None,
        };
        if let Some((kind, count)) = record {
            let values = args.required(count)?;
            self.record(kind, dest, values[0], &values[1..])?;
            return Ok(true);
        }
        let bind = match args.name {
            b"circle_balance_bind" => Some(Balance),
            b"circle_register_bind" => Some(Register),
            b"circle_object_bind" => Some(Object),
            _ => None,
        };
        if let Some(kind) = bind {
            let values = args.required(4)?;
            self.binding_bind(kind, dest, values[0], values[1], values[2], values[3])?;
            return Ok(true);
        }
        let flag = match args.name {
            b"circle_state_tombstone_apply" => Some((PolicyKind::State, Flag::Tombstone, true)),
            b"circle_state_restore" => Some((PolicyKind::State, Flag::Tombstone, false)),
            b"circle_state_revoke_apply" => Some((PolicyKind::State, Flag::Revoked, true)),
            b"circle_state_reinstate" => Some((PolicyKind::State, Flag::Revoked, false)),
            b"circle_object_tombstone_apply" => Some((PolicyKind::Object, Flag::Tombstone, true)),
            b"circle_object_restore" => Some((PolicyKind::Object, Flag::Tombstone, false)),
            b"circle_object_revoke_apply" => Some((PolicyKind::Object, Flag::Revoked, true)),
            b"circle_object_reinstate" => Some((PolicyKind::Object, Flag::Revoked, false)),
            _ => None,
        };
        if let Some((kind, flag, enabled)) = flag {
            self.policy_flag(kind, dest, args.nth(0)?, flag, enabled)?;
            return Ok(true);
        }
        match args.name {
            b"circle_object_member_count" => self.emit(I::ObjectMemberCount(dest, args.nth(0)?))?,
            b"circle_object_member_ref_at" | b"circle_object_has_member" => {
                let values = args.required(2)?;
                self.emit(if args.name == b"circle_object_member_ref_at" {
                    I::ObjectMemberRefAt(dest, values[0], values[1])
                } else {
                    I::ObjectHasMember(dest, values[0], values[1])
                })?;
            }
            b"circle_state_publish" => {
                let values = args.required(4)?;
                self.state_publish(dest, values[0], values[1], values[2], values[3])?;
            }
            b"circle_state_release" | b"circle_object_policy_release" => {
                let kind = if args.name == b"circle_state_release" {
                    PolicyKind::State
                } else {
                    PolicyKind::Object
                };
                self.policy_release(kind, dest, args.nth(0)?)?;
            }
            b"circle_state_retire" | b"circle_object_policy_retire" => {
                let values = args.required(2)?;
                let kind = if args.name == b"circle_state_retire" {
                    PolicyKind::State
                } else {
                    PolicyKind::Object
                };
                self.policy_retire(kind, dest, values[0], values[1])?;
            }
            b"circle_object_member_attach" => {
                let v = args.required(7)?;
                self.member_attach(dest, v[0], v[1], [v[2], v[3], v[4], v[5], v[6]])?;
            }
            b"circle_object_member_detach" => {
                let values = args.required(2)?;
                self.member_detach(dest, values[0], values[1])?;
            }
            b"circle_object_policy_define" => {
                let v = args.required(9)?;
                self.object_policy_define(
                    dest,
                    v[0],
                    [v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]],
                )?;
            }
            b"circle_object_transition_apply" => {
                let v = args.required(10)?;
                self.transition_apply(
                    dest,
                    [v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]],
                )?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
