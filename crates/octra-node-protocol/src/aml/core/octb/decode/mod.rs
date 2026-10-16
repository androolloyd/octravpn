// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent C_octb profile reconstruction over the native wire decoder.
//! Bytecode parsing alone does not establish this machine/evidence profile.
use super::super::{
    eval::Values,
    machine::{Emission, Literal, Shapes},
    result::Record,
    types::{Type, TypeId, Types},
    Natural,
};
use super::{Operation as Op, Schema};
use crate::{
    native_integer::parse_integer,
    octb::{self as wire, Instruction as I, Value as V},
};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::{collections::BTreeMap, sync::Arc};
mod error;
mod open;
mod profile;
mod reader;
pub use error::DecodeError;
use reader::Reader;
type Result<T> = std::result::Result<T, DecodeError>;
#[derive(Clone, Debug)]
pub enum Constant {
    Int(Arc<[u8]>),
    Bool(bool),
    Text(Arc<[u8]>),
    Data(Record),
    Bytes(Arc<[u8]>),
}
#[derive(Clone, Debug)]
pub struct ConstantRow {
    pub id: usize,
    pub at: usize,
    pub size: usize,
    pub value: Constant,
}
#[derive(Clone, Debug)]
pub struct Decoded {
    pub inputs: Vec<TypeId>,
    pub output: Option<TypeId>,
    pub results: Vec<u8>,
    pub guarded: bool,
    pub entry: usize,
    pub emission: Option<Emission>,
    pub veil: Option<(usize, Natural)>,
    pub consts: Vec<ConstantRow>,
    pub cells: Vec<wire::CodeCell>,
    pub text_at: usize,
    pub code: Vec<Op>,
}
struct Context<'a> {
    types: &'a mut Types,
    values: &'a mut Values,
    data: BTreeMap<Arc<[u8]>, Option<Record>>,
}
impl Context<'_> {
    fn data(&mut self, raw: &Arc<[u8]>) -> Option<Record> {
        if let Some(found) = self.data.get(raw) {
            return found.clone();
        }
        let found = Record::decode(self.types, self.values, raw).ok();
        self.data.insert(raw.clone(), found.clone());
        found
    }
}
fn verify(code: &[Op], forward: bool) -> Result<()> {
    if code.is_empty() {
        return Err(DecodeError::EmptyCode);
    }
    for (pc, op) in code.iter().enumerate() {
        if matches!(op, Op::Mark(target) if *target as usize != pc) {
            return Err(DecodeError::JumpMark(pc));
        }
    }
    for (pc, op) in code.iter().enumerate() {
        if let Op::Jump(target) | Op::JumpIf(_, target) = op {
            if !matches!(code.get(*target as usize), Some(Op::Mark(found)) if found == target) {
                return Err(DecodeError::JumpRef(pc, *target));
            }
        }
    }
    if forward {
        for (pc, op) in code.iter().enumerate() {
            if let Op::Jump(target) | Op::JumpIf(_, target) = op {
                if *target as usize <= pc {
                    return Err(DecodeError::JumpRef(pc, *target));
                }
            }
        }
    }
    Ok(())
}
pub fn decode(types: &mut Types, values: &mut Values, raw: &[u8]) -> Result<Decoded> {
    let mut context = Context {
        types,
        values,
        data: BTreeMap::new(),
    };
    let mut reader = Reader::new(raw);
    let (constant_count, instruction_count) = reader.header()?;
    let consts = reader.constants(&mut context, constant_count)?;
    let text_at = reader.at;
    let native = wire::Image::decode(raw, true).map_err(error::wire_failure)?;
    if native.text_at != text_at {
        return Err(DecodeError::Header);
    }
    if native.code.len() != instruction_count as usize {
        return Err(DecodeError::InstructionCount(instruction_count));
    }
    let metadata = wire::Metadata {
        emission: native.metadata.emission,
        veil: native.metadata.veil.clone(),
        ..wire::Metadata::default()
    };
    let exact = wire::encode(&native.code, &metadata, false).map_err(error::wire_failure)?;
    if exact != raw {
        return Err(DecodeError::ExactImage);
    }
    let emission = native.metadata.emission.map(|emitted| match emitted {
        wire::Emission::Lowered => Emission::Lowered,
        wire::Emission::Specialized => Emission::Specialized,
    });
    let veil = native
        .metadata
        .veil
        .as_ref()
        .map(|veil| {
            let count = Natural::new(&veil.count).ok_or(DecodeError::VeilInvalid)?;
            let depth = Natural::new(&veil.depth).ok_or(DecodeError::VeilInvalid)?;
            if count.get() == 0 && depth.get() != 0 {
                return Err(DecodeError::VeilInvalid);
            }
            Ok((count.get() as usize, depth))
        })
        .transpose()?;
    let (inputs, output, results, entry, code, guarded) =
        if let Some(open) = context.open_claim(&native.code)? {
            (
                open.inputs,
                Some(open.output),
                open.results,
                open.entry,
                open.code,
                open.guarded,
            )
        } else {
            let code = native
                .code
                .iter()
                .enumerate()
                .map(|(pc, op)| context.profile(pc, op))
                .collect::<Result<Vec<_>>>()?;
            (vec![], None, vec![], 0, code, false)
        };
    let cells = (0..code.len())
        .map(|pc| {
            let mut cell = native.cells[entry + pc].clone();
            cell.pc = pc;
            cell
        })
        .collect();
    verify(
        &code,
        output.is_some() || emission.is_some() || veil.is_some(),
    )?;
    Ok(Decoded {
        inputs,
        output,
        results,
        guarded,
        entry,
        emission,
        veil,
        consts,
        cells,
        text_at,
        code,
    })
}
pub fn claims_aml(raw: &[u8]) -> bool {
    let mut types = Types::default();
    let mut values = Values::default();
    let mut context = Context {
        types: &mut types,
        values: &mut values,
        data: BTreeMap::new(),
    };
    let mut reader = Reader::new(raw);
    let result: Result<bool> = (|| {
        let (count, _) = reader.claim_header(false)?;
        let constants = reader.constants(&mut context, count)?;
        Ok(constants.iter().any(|row| matches!(&row.value, Constant::Text(raw) if raw.starts_with(b"\0OCTRA_AML_EMISSION\0") || raw.starts_with(b"\0OCTRA_AML_VEIL\0"))))
    })();
    result.unwrap_or(false)
}
pub fn claims_open(raw: &[u8]) -> bool {
    let mut types = Types::default();
    let mut values = Values::default();
    let mut context = Context {
        types: &mut types,
        values: &mut values,
        data: BTreeMap::new(),
    };
    let mut reader = Reader::new(raw);
    let result: Result<bool> = (|| {
        let (count, _) = reader.claim_header(true)?;
        let constants = reader.constants(&mut context, count)?;
        reader.expect(&[0x16])?;
        reader.wide(100)?;
        reader.expect(&[0x12, 61])?;
        reader.word(1000)?;
        reader.expect(&[0x0b, 62])?;
        let id = reader.u16(DecodeError::Header)? as usize;
        if !matches!(constants.get(id).map(|row| &row.value), Some(Constant::Text(raw)) if raw.as_ref() == b"main")
        {
            return Ok(false);
        }
        reader.expect(&[0x07, 63, 61, 62, 0x15, 63])?;
        reader.wide(200)?;
        reader.expect(&[0x18, 0x16])?;
        reader.wide(200)?;
        Ok(true)
    })();
    result.unwrap_or(false)
}
