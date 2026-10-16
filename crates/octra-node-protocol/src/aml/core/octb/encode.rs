// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb raw, scalar-open and aggregate-open wire construction. Emission must
//! still pass the independent machine-profile decoder and evidence checks.
use super::super::{
    eval::Values,
    machine::{Emission, Literal},
    term::Bind,
    types::{Type, TypeId, Types},
};
use super::{
    guards::{self, integer, text},
    Error, Operation as Op, Schema,
};
use crate::octb::{self as wire, Instruction as I, Metadata, Veil};
use num_bigint::BigInt;
use std::collections::BTreeSet;
use std::sync::Arc;
const BODY_BASE: u32 = 10_000_000;
pub struct Open<'a> {
    pub inputs: &'a [Bind],
    pub regs: &'a [u8],
    pub typ: TypeId,
    pub results: &'a [u8],
    pub code: &'a [Op],
    pub emission: Emission,
    pub veil: Veil,
}
fn literal_integer(value: impl Into<BigInt>) -> Literal {
    Literal::Int(Arc::new(value.into()))
}
fn emission(value: Emission) -> wire::Emission {
    match value {
        Emission::Lowered => wire::Emission::Lowered,
        Emission::Specialized => wire::Emission::Specialized,
    }
}
fn count(code: &[Op]) -> Result<(), Error> {
    let mut constants = BTreeSet::new();
    for op in code {
        if let Op::Load(_, value) = op {
            let constant = match value {
                Literal::Int(value) => (0_u8, value.to_string().into_bytes()),
                Literal::Bool(value) => (1, if *value { b"1" } else { b"0" }.to_vec()),
                Literal::Bytes(value) => (3, value.to_vec()),
                Literal::Data(value) => (2, value.encode().to_vec()),
                Literal::Cap(..) => return Err(Error::OutputCode),
            };
            constants.insert(constant);
        }
    }
    if constants.len() > 32768 {
        Err(Error::Constants(constants.len()))
    } else {
        Ok(())
    }
}
pub(super) fn open_vm(op: &Op) -> Result<I, Error> {
    Ok(match op {
        Op::Jump(at) => I::Jmp(BODY_BASE.checked_add(*at).ok_or(Error::OutputCode)?),
        Op::JumpIf(reg, at) => I::Jif(*reg, BODY_BASE.checked_add(*at).ok_or(Error::OutputCode)?),
        Op::Mark(at) => I::Jdest(BODY_BASE.checked_add(*at).ok_or(Error::OutputCode)?),
        _ => op.vm().ok_or(Error::OutputCode)?,
    })
}
fn header() -> Vec<I> {
    vec![
        I::Jdest(100),
        I::Mload(61, 1000),
        text(62, b"main"),
        I::Eq(63, 61, 62),
        I::Jif(63, 200),
        I::Revert(),
        I::Jdest(200),
    ]
}
pub fn encode_raw(
    code: &[Op],
    emitted: Option<Emission>,
    veil: Option<Veil>,
) -> Result<Vec<u8>, Error> {
    count(code)?;
    let code = code
        .iter()
        .map(|op| op.vm().ok_or(Error::OutputCode))
        .collect::<Result<Vec<_>, _>>()?;
    let metadata = Metadata {
        emission: emitted.map(emission),
        veil,
        ..Metadata::default()
    };
    wire::encode(&code, &metadata, false).map_err(Error::Wire)
}
pub(super) fn scalar_type(typ: &Type) -> bool {
    matches!(typ, Type::Bool | Type::Int | Type::Bytes(_))
}
pub fn result_code(types: &Types, typ: TypeId, code: &[Op]) -> Option<Vec<Op>> {
    if !matches!(code.last(), Some(Op::Stop)) {
        return None;
    }
    let mut body = code[..code.len() - 1].to_vec();
    let first = u32::try_from(body.len()).ok()?;
    match types.get(typ) {
        Type::Int => body.extend([
            Op::Load(61, literal_integer(0)),
            Op::Minus(0, 0, 61),
            Op::Stop,
        ]),
        Type::Bool => {
            let yes = first.checked_add(3)?;
            let done = first.checked_add(5)?;
            body.extend([
                Op::JumpIf(0, yes),
                Op::Noop,
                Op::Jump(done),
                Op::Mark(yes),
                Op::Jump(done),
                Op::Mark(done),
                Op::Stop,
            ]);
        }
        Type::Bytes(length) => {
            let mark = first.checked_add(9)?;
            body.extend([
                Op::Load(61, Literal::Bytes(Vec::new().into())),
                Op::Same(63, 0, 61),
                Op::Size(61, 0),
                Op::Load(62, literal_integer(length.get())),
                Op::Same(63, 61, 62),
                Op::JumpIf(63, mark),
                Op::Load(61, literal_integer(1)),
                Op::Load(62, literal_integer(0)),
                Op::Quotient(61, 61, 62),
                Op::Mark(mark),
                Op::Stop,
            ]);
        }
        _ => return None,
    }
    Some(body)
}
fn input_code(types: &Types, index: usize, reg: u8, typ: TypeId) -> Result<Vec<I>, Error> {
    let memory = u16::try_from(1001 + index).map_err(|_| Error::OutputCode)?;
    let label = u32::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(2))
        .and_then(|index| index.checked_add(1000))
        .ok_or(Error::OutputCode)?;
    let mut code = vec![I::Mload(reg, memory)];
    match types.get(typ) {
        Type::Int => code.extend([integer(61, 0), I::Sub(reg, reg, 61)]),
        Type::Bool => code.extend(guards::bool_check(reg, label, label + 1)),
        Type::Bytes(length) => code.extend(guards::bytes_check(reg, length.get(), label)),
        _ => return Err(Error::OutputCode),
    }
    Ok(code)
}
fn encode_scalar(types: &Types, open: &Open<'_>) -> Result<Vec<u8>, Error> {
    let inputs = open.inputs;
    let regs = open.regs;
    let typ = open.typ;
    let code = open.code;
    let emitted = open.emission;
    let veil = open.veil.clone();
    let code = result_code(types, typ, code).ok_or(Error::OutputCode)?;
    count(&code)?;
    let mut out = header();
    for (index, bind) in inputs.iter().enumerate() {
        out.extend(input_code(
            types,
            index,
            *regs.get(index).ok_or(Error::OutputCode)?,
            bind.typ,
        )?);
    }
    out.push(I::Nop());
    out.extend(code.iter().map(open_vm).collect::<Result<Vec<_>, _>>()?);
    wire::encode(
        &out,
        &Metadata {
            emission: Some(emission(emitted)),
            veil: Some(veil),
            ..Metadata::default()
        },
        false,
    )
    .map_err(Error::Wire)
}
fn result_regs(regs: &[u8]) -> bool {
    let mut seen = BTreeSet::new();
    regs.iter().all(|reg| *reg <= 60 && seen.insert(*reg))
}
fn encode_data(types: &Types, values: &mut Values, open: &Open<'_>) -> Result<Vec<u8>, Error> {
    let inputs = open.inputs;
    let regs = open.regs;
    let typ = open.typ;
    let results = open.results;
    let code = open.code;
    let emitted = open.emission;
    let veil = open.veil.clone();
    let input_types = inputs.iter().map(|bind| bind.typ).collect::<Vec<_>>();
    let (checks, count) = guards::data_input_code(types, values, &input_types)?;
    if count != regs.len()
        || !regs
            .iter()
            .enumerate()
            .all(|(index, reg)| index + 1 == usize::from(*reg))
    {
        return Err(Error::OutputCode);
    }
    if !result_regs(results) {
        return Err(Error::ResultRegister);
    }
    let schema = Schema::make(
        types,
        &input_types,
        typ,
        &results.iter().copied().map(u32::from).collect::<Vec<_>>(),
    )
    .ok_or(Error::OutputCode)?;
    let guard = guards::guard_code(types, values, typ, results)?;
    if !matches!(code.last(), Some(Op::Stop)) {
        return Err(Error::OutputCode);
    }
    let mut out = header();
    out.push(text(61, schema.encode()));
    for (index, reg) in regs.iter().enumerate() {
        out.push(I::Mload(
            *reg,
            u16::try_from(1001 + index).map_err(|_| Error::OutputCode)?,
        ));
    }
    out.extend(checks);
    out.push(I::Nop());
    out.extend(
        code[..code.len() - 1]
            .iter()
            .map(open_vm)
            .collect::<Result<Vec<_>, _>>()?,
    );
    out.push(I::Jdest(
        BODY_BASE
            .checked_add(u32::try_from(code.len() - 1).map_err(|_| Error::OutputCode)?)
            .ok_or(Error::OutputCode)?,
    ));
    out.extend(guard);
    out.push(I::Stop());
    wire::encode(
        &out,
        &Metadata {
            emission: Some(emission(emitted)),
            veil: Some(veil),
            ..Metadata::default()
        },
        false,
    )
    .map_err(Error::Wire)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
pub fn encode_open(types: &Types, values: &mut Values, open: Open<'_>) -> Result<Vec<u8>, Error> {
    if open
        .inputs
        .iter()
        .all(|bind| scalar_type(types.get(bind.typ)))
        && scalar_type(types.get(open.typ))
    {
        encode_scalar(types, &open)
    } else {
        encode_data(types, values, &open)
    }
}
