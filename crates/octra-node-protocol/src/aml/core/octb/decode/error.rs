// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::wire;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InputSize(usize),
    Header,
    Magic,
    Version(u16),
    ConstantCount(usize),
    InstructionCount(u32),
    ConstantHeader(usize),
    ConstantSize(usize, usize),
    ConstantData(usize),
    ConstantTag(usize, u8),
    ConstantValue(usize),
    InstructionData(usize),
    ConstantRef(usize, usize),
    Opcode(usize, i32),
    RegisterRef(usize, u32),
    JumpValue(usize, u32),
    JumpRef(usize, u32),
    JumpMark(usize),
    TrailingData(usize),
    EmptyCode,
    ResultHeader,
    SchemaInvalid,
    EmissionInvalid,
    EmissionRepeated,
    VeilInvalid,
    VeilRepeated,
    ExactImage,
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn wire_failure(error: wire::Error) -> DecodeError {
    let reason = error.to_string();
    match reason.as_str() {
        "OCTB AML emission is invalid" => return DecodeError::EmissionInvalid,
        "OCTB AML emission is repeated" => return DecodeError::EmissionRepeated,
        "OCTB AML veil is invalid" => return DecodeError::VeilInvalid,
        "OCTB AML veil is repeated" => return DecodeError::VeilRepeated,
        _ => (),
    }
    if let Some(value) = reason
        .strip_prefix("unsupported OCTB version: ")
        .and_then(|value| value.parse().ok())
    {
        return DecodeError::Version(value);
    }
    if let Some((tag, pc)) = reason
        .strip_prefix("unknown opcode 0x")
        .and_then(|rest| rest.split_once(" at pc "))
    {
        if let (Ok(tag), Ok(pc)) = (i32::from_str_radix(tag, 16), pc.parse()) {
            return DecodeError::Opcode(pc, tag);
        }
    }
    if let Some(pc) = reason
        .strip_prefix("truncated instruction at pc ")
        .and_then(|pc| pc.parse().ok())
    {
        return DecodeError::InstructionData(pc);
    }
    if let Some((id, pc)) = reason
        .strip_prefix("constant reference ")
        .and_then(|rest| rest.split_once(" at pc "))
    {
        if let (Ok(id), Ok(pc)) = (id.parse(), pc.parse()) {
            return DecodeError::ConstantRef(pc, id);
        }
    }
    if let Some(count) = reason
        .strip_prefix("OCTB trailing bytes: ")
        .and_then(|count| count.parse().ok())
    {
        return DecodeError::TrailingData(count);
    }
    DecodeError::InstructionData(0)
}
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputSize(value) => {
                write!(f, "OCTB input size = {value} maximum = {}", wire::MAX_BYTES)
            }
            Self::Header => f.write_str("OCTB header is incomplete"),
            Self::Magic => f.write_str("OCTB magic is invalid"),
            Self::Version(value) => write!(f, "OCTB version = {value} expected = 1"),
            Self::ConstantCount(value) => write!(
                f,
                "OCTB constant count = {value} maximum = {}",
                wire::MAX_CONSTANTS
            ),
            Self::InstructionCount(value) => write!(
                f,
                "OCTB instruction count = {value} maximum = {}",
                wire::MAX_INSTRUCTIONS
            ),
            Self::ConstantHeader(id) => write!(f, "OCTB constant header is incomplete id = {id}"),
            Self::ConstantSize(id, maximum) => write!(
                f,
                "OCTB constant size exceeds maximum id = {id} maximum = {maximum}"
            ),
            Self::ConstantData(id) => write!(f, "OCTB constant data is incomplete id = {id}"),
            Self::ConstantTag(id, tag) => {
                write!(f, "OCTB constant tag is invalid id = {id} tag = {tag}")
            }
            Self::ConstantValue(id) => write!(f, "OCTB constant value is invalid id = {id}"),
            Self::InstructionData(pc) => write!(f, "OCTB instruction is incomplete pc = {pc}"),
            Self::ConstantRef(pc, id) => {
                write!(f, "OCTB constant reference is invalid pc = {pc} id = {id}")
            }
            Self::Opcode(pc, tag) => write!(
                f,
                "OCTB opcode is outside AML profile pc = {pc} tag = {tag}"
            ),
            Self::RegisterRef(pc, reg) => {
                write!(f, "OCTB register is invalid pc = {pc} reg = {reg}")
            }
            Self::JumpValue(pc, target) | Self::JumpRef(pc, target) => {
                write!(f, "OCTB jump is invalid pc = {pc} target = {target}")
            }
            Self::JumpMark(pc) => write!(f, "OCTB mark differs from pc = {pc}"),
            Self::TrailingData(value) => write!(f, "OCTB trailing bytes = {value}"),
            Self::EmptyCode => f.write_str("OCTB instruction stream is empty"),
            Self::ResultHeader => f.write_str("OCTB result header is invalid"),
            Self::SchemaInvalid => f.write_str("OCTB AML schema is invalid"),
            Self::EmissionInvalid => f.write_str("OCTB AML emission is invalid"),
            Self::EmissionRepeated => f.write_str("OCTB AML emission is repeated"),
            Self::VeilInvalid => f.write_str("OCTB AML veil is invalid"),
            Self::VeilRepeated => f.write_str("OCTB AML veil is repeated"),
            Self::ExactImage => f.write_str("OCTB open image differs from exact encoding"),
        }
    }
}
impl std::error::Error for DecodeError {}
