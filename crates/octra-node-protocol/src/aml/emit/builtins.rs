// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Builtins after argument evaluation. Unknown names retain the allocated result
//! register for the generator's ordinary internal-call fallback.
use super::{Emitter, Error, Position, Result, I};
pub(super) struct Arguments<'a> {
    pub name: &'a [u8],
    pub registers: &'a [u8],
    pub position: Position,
}
impl Arguments<'_> {
    pub(super) fn nth(&self, index: usize) -> Result<u8> {
        self.registers
            .get(index)
            .copied()
            .ok_or_else(|| Error::Invalid {
                message: [
                    self.name,
                    format!(": missing argument {}", index + 1).as_bytes(),
                ]
                .concat(),
                line: self.position.line,
                column: 1,
            })
    }
    // Native constructor operands evaluate from right to left. Inspecting the
    // highest required argument first preserves the resulting missing-arg error.
    pub(super) fn required(&self, count: usize) -> Result<&[u8]> {
        if count > 0 {
            self.nth(count - 1)?;
        }
        Ok(&self.registers[..count])
    }
}
impl Emitter {
    pub fn builtin_registers(
        &mut self,
        name: &[u8],
        registers: &[u8],
        program: bool,
    ) -> Result<(u8, bool)> {
        let dest = self.alloc_reg()?;
        if self.is_prior()
            && matches!(
                name,
                b"pedersen_add" | b"pedersen_sub" | b"pedersen_identity"
            )
        {
            return Ok((dest, false));
        }
        let args = Arguments {
            name,
            registers,
            position: self.position,
        };
        macro_rules! op {
            ($kind:ident, $count:expr $(, $index:expr)*) => {{
                let values = args.required($count)?;
                self.emit(I::$kind(dest $(, values[$index])*))?;
            }};
        }
        macro_rules! success {
            ($kind:ident, $count:expr $(, $index:expr)*) => {{
                let values = args.required($count)?;
                self.emit(I::$kind($(values[$index]),*))?;
                self.boolean(dest, true)?;
            }};
        }
        // These guards run after result allocation and before argument lookup.
        if !program
            && matches!(
                name,
                b"vecdot_q16"
                    | b"exp_q16"
                    | b"softmax_q16"
                    | b"layernorm_q16"
                    | b"rmsnorm_q16"
                    | b"silu_q16"
                    | b"elemwise_mul_q16"
                    | b"residual_add_q16"
                    | b"rope_apply_q16"
                    | b"load_int8_q16"
                    | b"append_vec_q16"
                    | b"argmax_q16"
                    | b"attention_kv_q16"
            )
        {
            return Err(self.error([name, b" is available only in Program"].concat()));
        }
        match name {
            b"concat" => op!(Concat, 2, 0, 1),
            b"to_string" => {
                self.string(dest, b"")?;
                self.emit(I::Concat(dest, dest, args.nth(0)?))?;
            }
            b"len" => op!(Strlen, 1, 0),
            b"fhe_load_pk" => op!(FheLoadPk, 1, 0),
            b"fhe_add" => op!(FheAdd, 3, 0, 1, 2),
            b"fhe_sub" => op!(FheSub, 3, 0, 1, 2),
            b"fhe_mul" => op!(FheMul, 3, 0, 1, 2),
            b"fhe_scale" => op!(FheScale, 3, 0, 1, 2),
            b"fhe_div_const" => op!(FheDivConst, 3, 0, 1, 2),
            b"fhe_add_const" => op!(FheAddConst, 3, 0, 1, 2),
            b"fhe_sub_const" => op!(FheSubConst, 3, 0, 1, 2),
            b"fhe_verify_zero" => op!(FheVerifyZero, 3, 0, 1, 2),
            b"fhe_verify_range" => op!(FheVerifyRange, 3, 0, 1, 2),
            b"fhe_verify_bound" => op!(FheVerifyBound, 4, 0, 1, 2, 3),
            b"groth16_verify_bn254" => op!(Groth16VerifyBn254, 3, 0, 1, 2),
            b"fhe_commit" => op!(FheCommit, 2, 0, 1),
            b"fhe_pedersen" => op!(FhePedersen, 2, 0, 1),
            b"pedersen_add" => op!(FhePedersenAdd, 2, 0, 1),
            b"pedersen_sub" => op!(FhePedersenSub, 2, 0, 1),
            b"pedersen_identity" => self.emit(I::FhePedersenIdentity(dest))?,
            b"fhe_ser" => op!(FheSer, 1, 0),
            b"fhe_deser" => op!(FheDeser, 1, 0),
            b"fhe_ser_pk" => op!(FheSerPk, 1, 0),
            b"fhe_deser_pk" => op!(FheDeserPk, 1, 0),
            b"is_address" => op!(Isaddr, 1, 0),
            b"is_hex" => op!(Ishex, 1, 0),
            b"assert_address" => {
                self.emit(I::AssertAddr(args.nth(0)?))?;
                self.boolean(dest, true)?;
            }
            b"transfer" => {
                self.transfer()?;
                op!(Transfer, 2, 0, 1);
            }
            b"to_int" => {
                let zero = self.alloc_reg()?;
                self.integer(zero, 0)?;
                self.emit(I::Add(dest, zero, args.nth(0)?))?;
            }
            b"checkpoint" => {
                self.emit(I::Checkpoint())?;
                self.boolean(dest, true)?;
            }
            b"rollback" => {
                self.emit(I::Rollback())?;
                self.boolean(dest, true)?;
            }
            b"commit" => {
                self.emit(I::Commit())?;
                self.boolean(dest, true)?;
            }
            b"call" => {
                if registers.len() < 2 {
                    return Err(self.error("call: need at least (target, method)"));
                }
                let target = args.nth(0)?;
                let method = args.nth(1)?;
                let count = registers.len() - 2;
                if count == 0 {
                    self.emit(I::Xcall(dest, target, method, 0, 0))?;
                } else {
                    let base = self.alloc_reg()?;
                    for _ in 1..count {
                        self.alloc_reg()?;
                    }
                    for (index, source) in registers[2..].iter().enumerate() {
                        let register = base + index as u8;
                        if *source != register {
                            self.emit(I::Mov(register, *source))?;
                        }
                    }
                    self.emit(I::Xcall(dest, target, method, base, count as u8))?;
                }
            }
            b"deploy" => {
                if registers.is_empty() {
                    return Err(self.error("deploy: need at least (bytecode)"));
                }
                if registers.len() == 1 {
                    self.emit(I::Spawn(dest, registers[0]))?;
                } else {
                    let count = u8::try_from(registers.len() - 1).map_err(|_| {
                        Error::Unavailable("compiler spawn-count transport exhausted")
                    })?;
                    self.emit(I::Spawn2(dest, registers[0], registers[1], count))?;
                }
            }
            b"circle_spawn" => {
                if registers.len() != 2 {
                    return Err(self.error("circle_spawn: need (payload_json, owner_mode)"));
                }
                self.emit(I::Spawn2(dest, registers[0], registers[1], 1))?;
            }
            b"mget" => op!(Mloadr, 1, 0),
            b"mset" => success!(Mstorer, 2, 0, 1),
            b"parse_ints" => op!(ParseInts, 2, 0, 1),
            b"substr" => op!(Substr, 3, 0, 1, 2),
            b"index_of" => op!(Indexof, 2, 0, 1),
            b"sha256" | b"digest_sha256" => op!(Sha256, 1, 0),
            b"keccak256" | b"digest_keccak256" => op!(Keccak256, 1, 0),
            b"current_tx_hash" => self.emit(I::Txhash(dest))?,
            b"ed25519_ok" | b"sig_ok_ed25519" => op!(Ed25519Ok, 3, 0, 1, 2),
            b"bit_and" => op!(Bitand, 2, 0, 1),
            b"bit_or" => op!(Bitor, 2, 0, 1),
            b"bit_xor" => op!(Bitxor, 2, 0, 1),
            b"bit_shl" => op!(Bitshl, 2, 0, 1),
            b"bit_shr" => op!(Bitshr, 2, 0, 1),
            b"matmul" => success!(Matmul, 6, 0, 1, 2, 3, 4, 5),
            b"vecdot" => op!(Vecdot, 3, 0, 1, 2),
            b"vecdot_q16" => op!(VecdotQ16, 3, 0, 1, 2),
            b"exp_lut" => op!(ExpLut, 1, 0),
            b"exp_q16" => op!(ExpQ16, 1, 0),
            b"softmax" => success!(SoftmaxInplace, 2, 0, 1),
            b"softmax_q16" => success!(SoftmaxQ16Inplace, 2, 0, 1),
            b"layernorm" => success!(LayernormInplace, 4, 0, 1, 2, 3),
            b"layernorm_q16" => success!(LayernormQ16Inplace, 4, 0, 1, 2, 3),
            b"relu" => success!(ReluInplace, 2, 0, 1),
            b"rmsnorm" => success!(RmsnormInplace, 3, 0, 1, 2),
            b"rmsnorm_q16" => success!(RmsnormQ16Inplace, 3, 0, 1, 2),
            b"silu" => success!(SiluInplace, 2, 0, 1),
            b"silu_q16" => success!(SiluQ16Inplace, 2, 0, 1),
            b"elemwise_mul" => success!(ElemwiseMulInplace, 3, 0, 1, 2),
            b"elemwise_mul_q16" => success!(ElemwiseMulQ16, 3, 0, 1, 2),
            b"load_int8" => success!(LoadInt8BytesToMem, 5, 0, 1, 2, 3, 4),
            b"load_int8_b64" => success!(LoadInt8B64ToMem, 5, 0, 1, 2, 3, 4),
            b"load_int8_q16" => success!(LoadInt8Q16, 5, 0, 1, 2, 3, 4),
            b"residual_add" => success!(ResidualAdd, 3, 0, 1, 2),
            b"residual_add_q16" => success!(ResidualAddQ16, 3, 0, 1, 2),
            b"rope_apply" => success!(RopeApply, 4, 0, 1, 2, 3),
            b"rope_apply_q16" => success!(RopeApplyQ16, 4, 0, 1, 2, 3),
            b"append_vec_q16" => success!(AppendVecQ16, 4, 0, 1, 2, 3),
            b"argmax_q16" => op!(ArgmaxQ16, 2, 0, 1),
            b"matmul_q16" => success!(MatmulQ16, 6, 0, 1, 2, 3, 4, 5),
            b"shift_round" => success!(ShiftRoundInplace, 3, 0, 1, 2),
            b"matmul_fp" => success!(MatmulFp, 6, 0, 1, 2, 3, 4, 5),
            b"rmsnorm_fp" => success!(RmsnormFp, 3, 0, 1, 2),
            b"silu_fp" => success!(SiluFp, 2, 0, 1),
            b"elemwise_mul_fp" => success!(ElemwiseMulFp, 3, 0, 1, 2),
            b"residual_add_fp" => success!(ResidualAddFp, 3, 0, 1, 2),
            b"rope_apply_fp" => success!(RopeApplyFp, 4, 0, 1, 2, 3),
            b"load_int8_fp" => success!(LoadInt8Fp, 5, 0, 1, 2, 3, 4),
            b"vecdot_fp" => op!(VecdotFp, 3, 0, 1, 2),
            b"argmax_fp" => op!(ArgmaxFp, 2, 0, 1),
            b"attention_kv_fp" => success!(AttentionKvFp, 8, 0, 1, 2, 3, 4, 5, 6, 7),
            b"attention_kv_q16" => success!(AttentionKvQ16, 8, 0, 1, 2, 3, 4, 5, 6, 7),
            b"append_vec_fp" => success!(AppendVecFp, 4, 0, 1, 2, 3),
            b"blob_store" => op!(Fstore, 1, 0),
            b"blob_load" => op!(Fload, 1, 0),
            b"min" | b"max" => {
                let left = args.nth(0)?;
                let right = args.nth(1)?;
                let compare = self.alloc_reg()?;
                let use_left = self.alloc_label()?;
                let done = self.alloc_label()?;
                self.emit(if name == b"min" {
                    I::Lt(compare, left, right)
                } else {
                    I::Gt(compare, left, right)
                })?;
                self.emit(I::Jif(compare, use_left))?;
                self.emit(I::Mov(dest, right))?;
                self.emit(I::Jmp(done))?;
                self.emit(I::Jdest(use_left))?;
                self.emit(I::Mov(dest, left))?;
                self.emit(I::Jdest(done))?;
            }
            b"abs" => {
                let value = args.nth(0)?;
                let zero = self.alloc_reg()?;
                let compare = self.alloc_reg()?;
                let negative = self.alloc_label()?;
                let done = self.alloc_label()?;
                self.integer(zero, 0)?;
                self.emit(I::Lt(compare, value, zero))?;
                self.emit(I::Jif(compare, negative))?;
                self.emit(I::Mov(dest, value))?;
                self.emit(I::Jmp(done))?;
                self.emit(I::Jdest(negative))?;
                self.emit(I::Neg(dest, value))?;
                self.emit(I::Jdest(done))?;
            }
            b"starts_with" => {
                let index = self.alloc_reg()?;
                let values = args.required(2)?;
                self.emit(I::Indexof(index, values[0], values[1]))?;
                let zero = self.alloc_reg()?;
                self.integer(zero, 0)?;
                self.emit(I::Eq(dest, index, zero))?;
            }
            b"split" | b"join" => {
                let values = args.required(2)?;
                if name == b"split" {
                    self.split_text(dest, values[0], values[1])?;
                } else {
                    self.join_text(dest, values[0], values[1])?;
                }
            }
            b"replace" | b"replace_all" => {
                let values = args.required(3)?;
                if name == b"replace" {
                    self.replace_text(dest, values[0], values[1], values[2])?;
                } else {
                    self.replace_all_text(dest, values[0], values[1], values[2])?;
                }
            }
            b"pow" => {
                let base = args.nth(0)?;
                let exponent = args.nth(1)?;
                self.integer(dest, 1)?;
                let index = self.alloc_reg()?;
                self.integer(index, 0)?;
                let test = self.alloc_label()?;
                let body = self.alloc_label()?;
                self.emit(I::Jmp(test))?;
                self.emit(I::Jdest(body))?;
                self.emit(I::Mul(dest, dest, base))?;
                let one = self.alloc_reg()?;
                self.integer(one, 1)?;
                self.emit(I::Add(index, index, one))?;
                self.emit(I::Jdest(test))?;
                let compare = self.alloc_reg()?;
                self.emit(I::Lt(compare, index, exponent))?;
                self.emit(I::Jif(compare, body))?;
            }
            _ => return Ok((dest, self.circle_builtin(dest, &args)?)),
        }
        Ok((dest, true))
    }
}
