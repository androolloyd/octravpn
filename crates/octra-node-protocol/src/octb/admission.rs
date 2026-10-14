// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native legacy OCTB verification, opcode policy and ordered effect inventory.
//! OCPG certificates, Program type flow and AML proof verification are separate.
use super::{Error, Image, Instruction};
use num_bigint::BigInt;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    MemoryRead,
    MemoryWrite,
    StorageRead,
    StorageWrite,
    Call,
    Deploy,
    Transfer,
    Emit,
    Fhe,
    Journal,
}
impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Self::MemoryRead => "memory_read",
            Self::MemoryWrite => "memory_write",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::Call => "call",
            Self::Deploy => "deploy",
            Self::Transfer => "transfer",
            Self::Emit => "emit",
            Self::Fhe => "fhe",
            Self::Journal => "journal",
        }
    }
    fn of(instruction: &Instruction) -> Option<Self> {
        Some(match instruction.opcode() {
            0x12 | 0x2e => Self::MemoryRead,
            0x13 | 0x2f => Self::MemoryWrite,
            0x0d | 0x10 | 0x4c | 0x51 | 0x4d | 0x50 | 0x58 | 0x59 | 0x5a => Self::StorageRead,
            0x0e | 0x11 | 0x0f | 0x54 | 0x4e | 0x4f | 0x57 => Self::StorageWrite,
            0x21 | 0x2d => Self::Call,
            0x22 | 0x53 => Self::Deploy,
            0x23 => Self::Transfer,
            0x27 => Self::Emit,
            0x30..=0x3f | 0x5b..=0x5f => Self::Fhe,
            0x24..=0x26 => Self::Journal,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Admitted {
    code: Vec<Instruction>,
    effects: Vec<Effect>,
}
impl Admitted {
    pub fn code(&self) -> &[Instruction] {
        &self.code
    }
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }
}
fn register(pc: usize, reg: u8) -> Result<(), Error> {
    if reg > 63 {
        Err(Error::message(format!(
            "invalid register r{reg} at pc {pc}"
        )))
    } else {
        Ok(())
    }
}
fn span(pc: usize, base: u8, count: u8) -> Result<(), Error> {
    if base > 63 || u16::from(count) > 64 - u16::from(base) {
        Err(Error::message(format!(
            "invalid register span r{base}+{count} at pc {pc}"
        )))
    } else {
        Ok(())
    }
}
/// Validate native register, span, label, reserved-key and capability constraints.
/// Duplicate labels are checked before the instruction walk; the last wins.
pub fn verify(code: &[Instruction]) -> Result<(), Error> {
    use Instruction::{
        CallInt, CapCheck, CapClose, Emit, Jdest, Jif, Jmp, Ldi, Mload, Mstore, Sdel, Sload,
        Spawn2, Sstore, Xcall,
    };
    if code.is_empty() {
        return Err(Error::message("empty code"));
    }
    if code.len() > 1_048_576 {
        return Err(Error::message(format!(
            "code too large: {} instructions",
            code.len()
        )));
    }
    let mut destinations = HashSet::new();
    let mut duplicate = None;
    for instruction in code {
        if let Jdest(dest) = instruction {
            if !destinations.insert(*dest) {
                duplicate = Some(dest);
            }
        }
    }
    if let Some(dest) = duplicate {
        return Err(Error::message(format!("duplicate JDEST {dest}")));
    }
    for (pc, instruction) in code.iter().enumerate() {
        let jump = |dest: &u32| {
            if destinations.contains(dest) {
                Ok(())
            } else {
                Err(Error::message(format!("invalid jump destination {dest}")))
            }
        };
        let reserved = |key: &[u8]| {
            if key.first() == Some(&0) {
                Err(Error::message(format!("write to reserved key at pc {pc}")))
            } else {
                Ok(())
            }
        };
        match instruction {
            CapCheck(kind, reg) | CapClose(kind, reg) => {
                if kind.as_ref() < &BigInt::from(0) || kind.as_ref() > &BigInt::from(1_000_000) {
                    return Err(Error::message(format!("capability kind {kind} at pc {pc}")));
                }
                register(pc, *reg)?;
            }
            Ldi(reg, _) | Sload(reg, _) | Mload(reg, _) | Mstore(_, reg) => register(pc, *reg)?,
            Sstore(key, reg) => {
                reserved(key)?;
                register(pc, *reg)?;
            }
            Sdel(key) => reserved(key)?,
            Xcall(d, t, m, base, count) => {
                for reg in [d, t, m] {
                    register(pc, *reg)?;
                }
                span(pc, *base, *count)?;
            }
            Spawn2(d, s, base, count) => {
                for reg in [d, s] {
                    register(pc, *reg)?;
                }
                span(pc, *base, *count)?;
            }
            Emit(_, regs) => {
                for reg in regs {
                    register(pc, *reg)?;
                }
            }
            Jif(reg, dest) | CallInt(reg, dest) => {
                register(pc, *reg)?;
                jump(dest)?;
            }
            Jmp(dest) => jump(dest)?,
            _ => {
                if let Some(reg) = instruction.first_invalid_byte() {
                    register(pc, reg)?;
                }
            }
        }
    }
    Ok(())
}
fn host_float(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0x62 => "EXP_LUT",
        0x63 => "SOFTMAX_INPLACE",
        0x64 => "LAYERNORM_INPLACE",
        0x66 => "RMSNORM_INPLACE",
        0x67 => "SILU_INPLACE",
        0x6b => "ROPE_APPLY",
        0x6f => "MATMUL_FP",
        0x70 => "RMSNORM_FP",
        0x71 => "SILU_FP",
        0x72 => "ELEMWISE_MUL_FP",
        0x73 => "RESIDUAL_ADD_FP",
        0x74 => "ROPE_APPLY_FP",
        0x75 => "LOAD_INT8_FP",
        0x76 => "VECDOT_FP",
        0x77 => "ARGMAX_FP",
        0x78 => "ATTENTION_KV_FP",
        0x79 => "APPEND_VEC_FP",
        _ => return None,
    })
}
fn program_only(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0x7c => "EXP_Q16",
        0x7d => "SOFTMAX_Q16_INPLACE",
        0x7e => "LAYERNORM_Q16_INPLACE",
        0x7f => "RMSNORM_Q16_INPLACE",
        0x80 => "SILU_Q16_INPLACE",
        0x81 => "ROPE_APPLY_Q16",
        0x82 => "ATTENTION_KV_Q16",
        0x83 => "VECDOT_Q16",
        0x84 => "ELEMWISE_MUL_Q16",
        0x85 => "RESIDUAL_ADD_Q16",
        0x86 => "LOAD_INT8_Q16",
        0x87 => "APPEND_VEC_Q16",
        0x88 => "ARGMAX_Q16",
        _ => return None,
    })
}
fn standard(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0x5d => "FHE_PEDERSEN_ADD",
        0x5e => "FHE_PEDERSEN_SUB",
        0x5f => "FHE_PEDERSEN_IDENTITY",
        0x89 => "CAP_CHECK",
        0x8a => "CAP_CLOSE",
        _ => return None,
    })
}
fn first(
    code: &[Instruction],
    policy: fn(u8) -> Option<&'static str>,
) -> Option<(usize, &'static str)> {
    code.iter()
        .enumerate()
        .find_map(|(pc, instruction)| policy(instruction.opcode()).map(|name| (pc, name)))
}
pub fn of_code(code: Vec<Instruction>, point_ops: bool) -> Result<Admitted, Error> {
    verify(&code)?;
    if !point_ops {
        if let Some((pc, name)) = first(&code, standard) {
            return Err(Error::message(format!(
                "standard opcode {name} is not active at pc {pc}"
            )));
        }
    }
    if let Some((pc, name)) = first(&code, program_only) {
        return Err(Error::message(format!(
            "Program-only opcode {name} at pc {pc}"
        )));
    }
    if let Some((pc, name)) = first(&code, host_float) {
        return Err(Error::message(format!(
            "consensus unsafe opcode {name} at pc {pc}"
        )));
    }
    let mut effects = Vec::new();
    for instruction in &code {
        if let Some(effect) = Effect::of(instruction) {
            if !effects.contains(&effect) {
                effects.push(effect);
            }
        }
    }
    Ok(Admitted { code, effects })
}
pub fn decode(raw: &[u8], point_ops: bool) -> Result<Admitted, Error> {
    of_code(Image::decode(raw, point_ops)?.code, point_ops)
}
