// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_eval errors retain separate static, fuel, dynamic and integer-work failures.
use super::{check, BigInt, Effects, Natural, RuleError, TypeId, Types};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Static(check::Error),
    Missing(Natural),
    NeedBool,
    NeedInt,
    DivideZero,
    ModuloZero,
    NeedPair,
    NeedSum,
    NeedBytes,
    NeedVector,
    NeedCapability,
    NeedSequence,
    ByteIndex(Natural, Natural),
    VectorIndex(Natural, Natural),
    Input(Natural),
    InputType(Natural, TypeId),
    InputDepth(Natural, usize, usize),
    InputNodes(Natural, usize, usize),
    CapabilityDuplicate(Natural, Natural),
    Fuel(BigInt, BigInt),
    Cost(BigInt, BigInt),
    Work(BigInt, BigInt),
    Arithmetic(BigInt, BigInt),
    Effects(Effects, Effects),
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Static(error) => error.text(types),
            Self::Missing(id) => format!("missing id = {}", id.get()).into_bytes(),
            Self::NeedBool => b"value expected = bool".to_vec(),
            Self::NeedInt => b"value expected = int".to_vec(),
            Self::DivideZero => b"integer division rejected = zero divisor".to_vec(),
            Self::ModuloZero => b"integer remainder rejected = zero divisor".to_vec(),
            Self::NeedPair => b"value expected = pair".to_vec(),
            Self::NeedSum => b"value expected = sum".to_vec(),
            Self::NeedBytes => b"value expected = bytes".to_vec(),
            Self::NeedVector => b"value expected = vec".to_vec(),
            Self::NeedCapability => b"value expected = cap".to_vec(),
            Self::NeedSequence => b"value expected = sequence".to_vec(),
            Self::ByteIndex(index, total) => {
                format!("byte index = {} size = {}", index.get(), total.get()).into_bytes()
            }
            Self::VectorIndex(index, total) => {
                format!("vec index = {} size = {}", index.get(), total.get()).into_bytes()
            }
            Self::Input(id) => format!("duplicate input id = {}", id.get()).into_bytes(),
            Self::InputType(id, typ) => [
                format!("input id = {} expected = ", id.get()).as_bytes(),
                &types.text(*typ),
            ]
            .concat(),
            Self::InputDepth(id, limit, actual) => format!(
                "input id = {} depth limit = {limit} actual = {actual}",
                id.get()
            )
            .into_bytes(),
            Self::InputNodes(id, limit, actual) => format!(
                "input id = {} node limit = {limit} actual = {actual}",
                id.get()
            )
            .into_bytes(),
            Self::CapabilityDuplicate(kind, id) => format!(
                "duplicate capability kind = {} id = {}",
                kind.get(),
                id.get()
            )
            .into_bytes(),
            Self::Fuel(limit, needed) => {
                format!("fuel limit = {limit} needed = {needed}").into_bytes()
            }
            Self::Cost(limit, actual) => {
                format!("cost limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Work(limit, actual) => {
                format!("work limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Arithmetic(limit, actual) => {
                format!("integer work limit = {limit} actual = {actual}").into_bytes()
            }
            Self::Effects(row, used) => [
                b"effects row = ".as_slice(),
                &super::super::effects_text(row),
                b" actual = ",
                &super::super::effects_text(used),
            ]
            .concat(),
        }
    }
}
impl RuleError {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Rule(error) => super::super::text::clip(error.to_string().as_bytes()),
            Self::Run(error) => error.text(types),
        }
    }
}
