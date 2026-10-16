// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb machine artifacts. Schema parsing is distinct from register lowering,
//! bytecode verification, source/liveness maps and evidence construction.
mod assembly;
mod cells;
mod decode;
mod effects;
mod encode;
pub use decode::{claims_aml, claims_open, decode, Constant, ConstantRow, DecodeError, Decoded};
pub use effects::{effect_layouts, emit_effects, HostBlock};
mod guards;
mod image;
pub use image::{encode, finish, Image};
mod layout;
mod lower;
mod public;
pub use assembly::{resolve, Asm, Assembly, EffectLayout, Marked, Operation};
pub use cells::{seed, Cell, Cells, Seed};
pub use encode::{encode_open, encode_raw, result_code, Open};
pub use guards::{data_input_code, guard_code};
pub use lower::{lower, Machine, Plan};
pub use public::{
    body_label, body_target, check_label, data_label, dispatch_label, guard_label, image_emission,
    image_veil, image_veil_depth, image_veils, label_count, op_text, registers, result_regs,
    veil_text, INPUT_LIMIT, LABEL_LIMIT,
};
mod schema;
mod source;
pub use super::list::ListId as VectorId;
pub use layout::{Generator, Layout, LayoutId, Layouts};
pub use schema::Schema;
pub use source::{compile, compile_feed, SourceFailure, SourceImage};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Stack,
    Register,
    Label,
    Slot,
    Map,
    Constants(usize),
    OutputCode,
    ResultRegister,
    Wire(crate::octb::Error),
    Output(DecodeError),
    Mach(super::machine::Error),
    Smap(super::maps::source::Error),
    Lmap(super::maps::live::Error),
    EffectMap,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Constants(count) => {
                return write!(f, "OCTB constant count = {count} maximum = 32768")
            }
            Self::Wire(error) => return std::fmt::Display::fmt(error, f),
            Self::Output(error) => return write!(f, "OCTB output refusal reason = {error}"),
            Self::Smap(error) => return std::fmt::Display::fmt(error, f),
            Self::Lmap(error) => return std::fmt::Display::fmt(error, f),
            _ => (),
        }
        f.write_str(match self {
            Self::Stack => "OCTB stack shape is invalid",
            Self::Register => "OCTB register capacity exceeded",
            Self::Label => "OCTB control label is invalid",
            Self::Slot => "OCTB linear slot transition is invalid",
            Self::Map => "OCTB source position map differs from machine plan",
            Self::OutputCode => "OCTB output differs after decoding",
            Self::ResultRegister => "OCTB result registers must be distinct and below 61",
            Self::EffectMap => "OCTB effect register map differs from static sites",
            Self::Mach(_) => "OCTB machine image is invalid",
            Self::Constants(_)
            | Self::Wire(_)
            | Self::Output(_)
            | Self::Smap(_)
            | Self::Lmap(_) => unreachable!(),
        })
    }
}
impl std::error::Error for Error {}
impl Error {
    pub fn text(&self, types: &super::types::Types, values: &super::eval::Values) -> Vec<u8> {
        match self {
            Self::Mach(error) => error.text(types, values),
            _ => self.to_string().into_bytes(),
        }
    }
}
