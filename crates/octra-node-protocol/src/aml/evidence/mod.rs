// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_evidence canonical host-effect records. Decoding regenerates the full
//! record from the checked program and registry; metadata alone is not trusted.
use super::{
    core::{
        bin::{self, Bits, CodeId, Codes},
        eval::Values,
        octb, program_codec,
        term::Program,
        types::{TypeId, Types},
    },
    effects::{self, Block, Registry, Sealed},
};
use num_traits::ToPrimitive;
use std::sync::Arc;
mod codec;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub payload: Vec<u8>,
    pub scratch: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Evidence {
    sealed: Sealed,
    layouts: Vec<Layout>,
    blocks: Vec<Block>,
    bits: Arc<[bool]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Effect(Vec<u8>),
    Lower(Vec<u8>),
    LayoutCount(usize, usize),
    Registry,
    Form,
}
type Result<T> = std::result::Result<T, Error>;
impl Error {
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn effect(error: effects::Error, types: &Types) -> Self {
        Self::Effect(error.text(types))
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn lower(error: octb::Error, types: &Types, values: &Values) -> Self {
        Self::Lower(error.text(types, values))
    }
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Effect(reason) => {
                [b"effect evidence failed reason = ".as_slice(), reason].concat()
            }
            Self::Lower(reason) => [
                b"effect evidence lowering failed reason = ".as_slice(),
                reason,
            ]
            .concat(),
            Self::LayoutCount(expected, actual) => format!(
                "effect evidence layout count differs expected = {expected} actual = {actual}"
            )
            .into_bytes(),
            Self::Registry => b"effect evidence registry differs".to_vec(),
            Self::Form => b"effect evidence form is invalid".to_vec(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Error {}
fn assemble(sealed: &Sealed, layouts: &[Layout]) -> Result<Vec<Block>> {
    let expected = sealed
        .locations()
        .iter()
        .try_fold(0_usize, |total, location| {
            total.checked_add(location.count().to_usize()?)
        })
        .unwrap_or((i64::MAX >> 1) as usize);
    let actual = layouts.len();
    if expected != actual {
        return Err(Error::LayoutCount(expected, actual));
    }
    let mut blocks = Vec::with_capacity(actual);
    let mut cursor = 0;
    for (index, location) in sealed.locations().iter().enumerate() {
        let count = location
            .count()
            .to_usize()
            .ok_or(Error::LayoutCount(expected, actual))?;
        for _ in 0..count {
            let layout = layouts
                .get(cursor)
                .ok_or(Error::LayoutCount(expected, actual))?;
            let payload = layout
                .payload
                .iter()
                .copied()
                .map(i64::from)
                .collect::<Vec<_>>();
            let scratch = layout
                .scratch
                .iter()
                .copied()
                .map(i64::from)
                .collect::<Vec<_>>();
            let block = sealed
                .lower(index as i64, &payload, &scratch)
                .map_err(|error| Error::effect(error, sealed.types()))?;
            blocks.push(block);
            cursor += 1;
        }
    }
    Ok(blocks)
}
impl Evidence {
    pub fn make(sealed: Sealed) -> Result<Self> {
        let mut types = sealed.types().clone();
        let mut values = Values::default();
        let found = octb::effect_layouts(&mut types, sealed.terms(), &mut values, sealed.program())
            .map_err(|error| Error::lower(error, &types, &values))?;
        let layouts = found
            .into_iter()
            .map(|layout| Layout {
                payload: layout.payload,
                scratch: layout.scratch,
            })
            .collect::<Vec<_>>();
        let blocks = assemble(&sealed, &layouts)?;
        let bits = codec::encode(&sealed, &layouts, &blocks).ok_or(Error::Form)?;
        Ok(Self {
            sealed,
            layouts,
            blocks,
            bits: bits.into(),
        })
    }
    pub fn encode(&self) -> &[bool] {
        &self.bits
    }
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }
    pub fn layouts(&self) -> &[Layout] {
        &self.layouts
    }
    pub fn program(&self) -> &Program {
        self.sealed.program()
    }
    pub fn output(&self) -> TypeId {
        self.sealed.typ()
    }
    pub fn sealed(&self) -> &Sealed {
        &self.sealed
    }
    pub fn runtime(&self) -> Result<Vec<crate::octb::Instruction>> {
        let mut types = self.sealed.types().clone();
        let mut values = Values::default();
        let found =
            octb::effect_layouts(&mut types, self.sealed.terms(), &mut values, self.program())
                .map_err(|error| Error::lower(error, &types, &values))?;
        if found.len() != self.blocks.len() {
            return Err(Error::LayoutCount(found.len(), self.blocks.len()));
        }
        let blocks = found
            .into_iter()
            .zip(&self.blocks)
            .map(|(layout, block)| octb::HostBlock {
                layout,
                code: block.ops().to_vec(),
            })
            .collect::<Vec<_>>();
        octb::emit_effects(
            &mut types,
            self.sealed.terms(),
            &mut values,
            self.program(),
            &blocks,
        )
        .map_err(|error| Error::lower(error, &types, &values))
    }
}
pub fn decode(expected: &Registry, bits: &[bool]) -> Result<Evidence> {
    let decoded = bin::decode(bits).ok_or(Error::Form)?;
    let (program, entries) = codec::root(&decoded.codes, decoded.root).ok_or(Error::Form)?;
    let mut types = Types::default();
    let mut terms = super::core::term::Terms::default();
    let program =
        program_codec::get(&decoded.codes, &mut types, &mut terms, program).ok_or(Error::Form)?;
    let entries = codec::entries_get(&decoded.codes, entries).ok_or(Error::Form)?;
    if entries != expected.entries() {
        return Err(Error::Registry);
    }
    let sealed = expected
        .seal(&mut types, &terms, &program)
        .map_err(|error| Error::effect(error, &types))?;
    let value = Evidence::make(sealed)?;
    if value.encode() != bits {
        return Err(Error::Form);
    }
    Ok(value)
}
pub fn decode_any(bits: &[bool]) -> Result<Evidence> {
    let decoded = bin::decode(bits).ok_or(Error::Form)?;
    let (_, entries) = codec::root(&decoded.codes, decoded.root).ok_or(Error::Form)?;
    let entries = codec::entries_get(&decoded.codes, entries).ok_or(Error::Form)?;
    let expected = Registry::restore(&entries).map_err(|error| match error {
        effects::RestoreError::Registry => Error::Registry,
        effects::RestoreError::Effect(error) => Error::effect(error, &Types::default()),
    })?;
    decode(&expected, bits)
}
