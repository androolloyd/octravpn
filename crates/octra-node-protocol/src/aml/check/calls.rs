// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_check return classifications; argument/arity policy remains native.
use super::{invalid, Checker, Result, Type, TypeId};
pub(crate) fn builtin(name: &[u8]) -> Option<Type> {
    Some(match name {
        b"concat"
        | b"to_string"
        | b"fhe_ser"
        | b"fhe_ser_pk"
        | b"substr"
        | b"sha256"
        | b"keccak256"
        | b"digest_sha256"
        | b"digest_keccak256"
        | b"current_tx_hash"
        | b"blob_store"
        | b"blob_load"
        | b"join"
        | b"replace"
        | b"circle_balance_state_ref"
        | b"circle_balance_status"
        | b"circle_balance_last_workflow"
        | b"circle_register_state_ref"
        | b"circle_register_status"
        | b"circle_register_last_workflow"
        | b"circle_object_state_ref"
        | b"circle_object_status"
        | b"circle_object_last_transition"
        | b"circle_object_member_ref_at"
        | b"circle_object_member_state_ref"
        | b"circle_object_member_kind"
        | b"circle_object_member_class"
        | b"circle_object_member_codec"
        | b"circle_object_member_status"
        | b"circle_object_delivery_key_id"
        | b"circle_object_transition_mode"
        | b"circle_object_required_proof_kind"
        | b"circle_state_class"
        | b"circle_state_codec"
        | b"circle_state_schema_hash"
        | b"circle_state_subject_addr"
        | b"circle_state_hfhe_profile"
        | b"circle_state_delivery_key_id"
        | b"circle_balance_cell_ciphertext_commitment"
        | b"circle_balance_cell_amount_commitment"
        | b"circle_balance_cell_proof_kind"
        | b"circle_balance_cell_proof_receipt_hash"
        | b"circle_register_cell_ciphertext_commitment"
        | b"circle_register_cell_proof_kind"
        | b"circle_register_cell_proof_receipt_hash"
        | b"call" => Type::String,
        b"len"
        | b"index_of"
        | b"bit_and"
        | b"bit_or"
        | b"bit_xor"
        | b"bit_shl"
        | b"bit_shr"
        | b"min"
        | b"max"
        | b"abs"
        | b"to_int"
        | b"parse_ints"
        | b"mget"
        | b"pow"
        | b"vecdot"
        | b"vecdot_fp"
        | b"vecdot_q16"
        | b"argmax_fp"
        | b"argmax_q16"
        | b"exp_lut"
        | b"exp_q16"
        | b"split"
        | b"circle_balance_version"
        | b"circle_register_version"
        | b"circle_object_version"
        | b"circle_object_member_count"
        | b"circle_object_member_quorum"
        | b"circle_state_activate_after"
        | b"circle_state_expire_after"
        | b"circle_balance_bind"
        | b"circle_register_bind"
        | b"circle_object_bind"
        | b"circle_object_transition_apply" => Type::Int,
        b"fhe_load_pk" | b"fhe_deser_pk" => Type::PubKey,
        b"fhe_add" | b"fhe_sub" | b"fhe_mul" | b"fhe_scale" | b"fhe_div_const"
        | b"fhe_add_const" | b"fhe_sub_const" | b"fhe_deser" => Type::Cipher,
        b"fhe_commit" | b"fhe_pedersen" | b"pedersen_add" | b"pedersen_sub"
        | b"pedersen_identity" => Type::Bytes,
        b"deploy" | b"circle_spawn" => Type::Address,
        b"circle_state_mutable"
        | b"circle_state_tombstone"
        | b"circle_state_revoked"
        | b"circle_object_tombstone"
        | b"circle_object_revoked"
        | b"circle_object_has_member"
        | b"circle_object_allow_detach"
        | b"circle_object_allow_root_state_rotation"
        | b"circle_state_describe"
        | b"circle_state_publish"
        | b"circle_state_release"
        | b"circle_state_retire"
        | b"circle_state_tombstone_apply"
        | b"circle_state_restore"
        | b"circle_state_revoke_apply"
        | b"circle_state_reinstate"
        | b"circle_object_policy_define"
        | b"circle_object_policy_release"
        | b"circle_object_policy_retire"
        | b"circle_object_tombstone_apply"
        | b"circle_object_restore"
        | b"circle_object_revoke_apply"
        | b"circle_object_reinstate"
        | b"circle_balance_cell_materialize"
        | b"circle_register_cell_materialize"
        | b"circle_object_member_attach"
        | b"circle_object_member_detach"
        | b"circle_object_transition_record"
        | b"circle_balance_workflow_record"
        | b"circle_register_workflow_record"
        | b"fhe_verify_zero"
        | b"fhe_verify_range"
        | b"fhe_verify_bound"
        | b"groth16_verify_bn254"
        | b"is_address"
        | b"assert_address"
        | b"starts_with"
        | b"is_hex"
        | b"ed25519_ok"
        | b"sig_ok_ed25519"
        | b"is_some_opt"
        | b"transfer"
        | b"checkpoint"
        | b"rollback"
        | b"commit"
        | b"mset"
        | b"matmul"
        | b"softmax"
        | b"softmax_q16"
        | b"layernorm"
        | b"layernorm_q16"
        | b"relu"
        | b"rmsnorm"
        | b"rmsnorm_q16"
        | b"silu"
        | b"silu_q16"
        | b"elemwise_mul"
        | b"load_int8"
        | b"load_int8_b64"
        | b"residual_add"
        | b"rope_apply"
        | b"rope_apply_q16"
        | b"matmul_q16"
        | b"shift_round"
        | b"matmul_fp"
        | b"rmsnorm_fp"
        | b"silu_fp"
        | b"elemwise_mul_fp"
        | b"residual_add_fp"
        | b"rope_apply_fp"
        | b"load_int8_fp"
        | b"attention_kv_fp"
        | b"attention_kv_q16"
        | b"append_vec_fp"
        | b"load_int8_q16"
        | b"append_vec_q16" => Type::Bool,
        _ => return None,
    })
}
impl Checker<'_> {
    pub(super) fn call(&mut self, name: &[u8], types: &[TypeId]) -> Result<TypeId> {
        if let Some(typ) = builtin(name) {
            return Ok(self.nodes.intern(typ));
        }
        match name {
            b"some" => match types {
                [typ] => return Ok(self.nodes.intern(Type::Option(*typ))),
                _ => return Err(invalid("some argument count differs expected = 1")),
            },
            b"none" => {
                if !types.is_empty() {
                    return Err(invalid("none argument count differs expected = 0"));
                }
                let void = self.nodes.intern(Type::Void);
                return Ok(self.nodes.intern(Type::Option(void)));
            }
            b"unwrap" => {
                return match types {
                    [typ] => match self.nodes.typ(*typ) {
                        Type::Option(child) => Ok(*child),
                        _ => Err(invalid("unwrap argument type differs")),
                    },
                    _ => Err(invalid("unwrap argument count differs expected = 1")),
                }
            }
            _ => (),
        }
        let function = self
            .contract
            .functions
            .iter()
            .find(|function| function.name == name)
            .ok_or_else(|| invalid([b"function is undefined name = ".as_slice(), name].concat()))?;
        if function.params.len() != types.len() {
            return Err(invalid(
                [
                    b"function argument count differs function = ".as_slice(),
                    name,
                    format!(
                        " expected = {} actual = {}",
                        function.params.len(),
                        types.len()
                    )
                    .as_bytes(),
                ]
                .concat(),
            ));
        }
        for (param, actual) in function.params.iter().zip(types) {
            self.require(
                &[
                    b"function argument type differs function = ".as_slice(),
                    name,
                ]
                .concat(),
                param.typ,
                *actual,
            )?;
        }
        Ok(function.ret)
    }
}
