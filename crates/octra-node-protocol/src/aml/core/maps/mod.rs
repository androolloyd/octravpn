// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_smap/C_live artifact images. These preserve diagnostics and linear slot
//! traces, but require independent agreement with the emitted machine code.
use super::{
    bin::{self, Code, CodeId, Codes},
    rule::{Field, LOCAL},
    Natural,
};
use num_traits::ToPrimitive;
pub mod live;
pub mod source;
pub use live::{LiveMap, Slot};
pub use source::SourceMap;
pub const MAX_ROWS: usize = 4 * LOCAL.get(Field::TermNodes) as usize + 2;
fn tagged(codes: &Codes, id: CodeId, expected: u32) -> Option<CodeId> {
    let Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    (tag.to_u32()? == expected).then_some(*body)
}
fn natural(codes: &Codes, id: CodeId) -> Option<Natural> {
    let Code::Num(value) = codes.get(id) else {
        return None;
    };
    Natural::new(value)
}
