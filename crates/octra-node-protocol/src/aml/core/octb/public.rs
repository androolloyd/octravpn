// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb public layout, label and diagnostic helpers.
use super::super::{
    machine::{Literal, ShapeId, Shapes},
    types::Types,
};
use super::{Decoded, Error, Generator, Layouts, Operation};
use std::collections::BTreeSet;

pub const INPUT_LIMIT: i64 = 60;
pub const LABEL_LIMIT: i64 = 1_000_000;
pub fn registers(first: i64, shapes: &Shapes, shape: ShapeId) -> Result<(Vec<u8>, u32), Error> {
    let first = u32::try_from(first).map_err(|_| Error::Register)?;
    let mut state = Generator::new(first)?;
    let mut layouts = Layouts::default();
    let root = layouts.alloc(shapes, shape, &mut state)?;
    Ok((layouts.registers(root), state.next()))
}
pub fn result_regs(values: &[i64]) -> bool {
    let mut used = BTreeSet::new();
    values
        .iter()
        .all(|value| (0..=INPUT_LIMIT).contains(value) && used.insert(*value))
}
fn host(value: i128) -> i64 {
    let value = value & ((1_i128 << 63) - 1);
    if value & (1_i128 << 62) != 0 {
        (value - (1_i128 << 63)) as i64
    } else {
        value as i64
    }
}
pub fn dispatch_label(index: i64) -> i64 {
    host(100 + i128::from(index) * 100)
}
pub fn check_label(index: i64, side: i64) -> i64 {
    host(1000 + i128::from(index) * 2 + i128::from(side))
}
pub fn data_label(index: i64) -> i64 {
    host(i128::from(LABEL_LIMIT) + i128::from(index))
}
pub fn guard_label(index: i64) -> i64 {
    host(i128::from(LABEL_LIMIT) * 2 + i128::from(index))
}
pub fn body_label(index: i64) -> i64 {
    host(i128::from(LABEL_LIMIT) * 10 + i128::from(index))
}
pub fn label_count(count: i64) -> bool {
    (0..=LABEL_LIMIT).contains(&count)
}
pub fn body_target(count: i64, target: i64) -> Option<i64> {
    let base = body_label(0);
    let index = host(i128::from(target) - i128::from(base));
    (!(count < 0 || target < base || index >= count)).then_some(index)
}
pub fn image_emission(image: &Decoded) -> &'static str {
    image.emission.map_or("opaque", |emission| emission.text())
}
pub fn veil_text(count: usize) -> &'static str {
    if count == 0 {
        "none"
    } else {
        "static"
    }
}
pub fn image_veil(image: &Decoded) -> &'static str {
    image.veil.map_or("unknown", |(count, _)| veil_text(count))
}
pub fn image_veils(image: &Decoded) -> Vec<u8> {
    image.veil.map_or_else(
        || b"unknown".to_vec(),
        |(count, _)| count.to_string().into_bytes(),
    )
}
pub fn image_veil_depth(image: &Decoded) -> Vec<u8> {
    image.veil.map_or_else(
        || b"unknown".to_vec(),
        |(_, depth)| depth.get().to_string().into_bytes(),
    )
}
fn literal_text(types: &Types, value: &Literal) -> Vec<u8> {
    match value {
        Literal::Bool(value) => format!("bool:{value}").into_bytes(),
        Literal::Int(value) => format!("int:{value}").into_bytes(),
        Literal::Bytes(value) => format!("bytes[{}]", value.len()).into_bytes(),
        Literal::Data(value) => [b"data[".as_slice(), &types.text(value.typ()), b"]"].concat(),
        Literal::Cap(kind, id) => format!("cap[{}]#{}", kind.get(), id.get()).into_bytes(),
    }
}
pub fn op_text(types: &Types, operation: &Operation) -> Vec<u8> {
    use Operation as O;
    match operation {
        O::Load(dst, value) => {
            return [
                format!("ldi(r{dst},").as_bytes(),
                &literal_text(types, value),
                b")",
            ]
            .concat()
        }
        O::Move(dst, src) => format!("mov(r{dst},r{src})"),
        O::Plus(dst, left, right)
        | O::Times(dst, left, right)
        | O::Quotient(dst, left, right)
        | O::Remainder(dst, left, right)
        | O::Same(dst, left, right)
        | O::Different(dst, left, right)
        | O::Less(dst, left, right)
        | O::Greater(dst, left, right)
        | O::Join(dst, left, right)
        | O::Minus(dst, left, right) => {
            let op = match operation {
                O::Plus(..) => "add",
                O::Times(..) => "mul",
                O::Quotient(..) => "div",
                O::Remainder(..) => "mod",
                O::Same(..) => "eq",
                O::Different(..) => "neq",
                O::Less(..) => "lt",
                O::Greater(..) => "gt",
                O::Join(..) => "concat",
                _ => "sub",
            };
            format!("{op}(r{dst},r{left},r{right})")
        }
        O::Negate(dst, src) | O::Absolute(dst, src) | O::Size(dst, src) => {
            let op = match operation {
                O::Negate(..) => "neg",
                O::Absolute(..) => "abs",
                _ => "strlen",
            };
            format!("{op}(r{dst},r{src})")
        }
        O::Slice(dst, src, first, count) => format!("substr(r{dst},r{src},r{first},r{count})"),
        O::CapClose(kind, reg) => format!("cap_close({},r{reg})", kind.get()),
        O::Jump(at) => format!("jmp({at})"),
        O::JumpIf(reg, at) => format!("jif(r{reg},{at})"),
        O::Mark(at) => format!("jdest({at})"),
        O::Noop => "nop".into(),
        O::Stop => "stop".into(),
    }
    .into_bytes()
}
