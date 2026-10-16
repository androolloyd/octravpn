// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_emit closed-literal projection and its minimal OCTB image. Unlike machine
//! projection, C_emit.lit does not admit Num scalars through its Int case.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
pub use super::machine::Literal;
use super::{
    check, eval,
    eval::{Value, ValueId, Values},
    result::Record,
    types::{Type, TypeId, Types},
};
use super::{
    lexer::Span,
    term::{Program, Terms},
    Atom, Effects,
};
#[derive(Clone, Debug)]
pub struct Image {
    pub lit: Literal,
    pub octb: Vec<u8>,
    pub span: Span,
}
#[derive(Clone, Debug)]
pub struct SourceImage {
    pub types: Types,
    pub values: Values,
    pub image: Image,
}
#[derive(Clone, Debug)]
pub enum Error {
    Source(super::parse::Error),
    Check(check::Error),
    Inputs(usize),
    Effects(Effects),
    Run(eval::Error),
    Plan(Vec<Atom>),
    Value(TypeId, ValueId),
    Constant,
}
/// Source failures keep diagnostic IDs together with their creating arenas.
#[derive(Clone, Debug)]
pub struct SourceFailure {
    pub error: Error,
    pub types: Types,
    pub values: Values,
}
impl SourceFailure {
    pub fn text(&self) -> Vec<u8> {
        self.error.text(&self.types, &self.values)
    }
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for SourceFailure {}
pub fn lit(types: &Types, values: &mut Values, typ: TypeId, value: ValueId) -> Option<Literal> {
    Some(match (types.get(typ), values.get(value)) {
        (Type::Bool, Value::Bool(value)) => Literal::Bool(*value),
        (Type::Int, Value::Int(value)) => Literal::Int(value.clone()),
        (Type::Bytes(length), Value::Bytes(value)) if length.get() as usize == value.len() => {
            Literal::Bytes(value.clone())
        }
        (Type::Cap(kind), Value::Cap(found, id)) if kind == found => Literal::Cap(*kind, *id),
        _ => Literal::Data(Record::make(types, values, typ, value).ok()?),
    })
}
/// Capability literals cannot be constants. This encoder grants no admission
/// authority and does not contain the machine schema or its evidence sections.
pub fn octb(literal: &Literal) -> Option<Vec<u8>> {
    let (tag, raw): (u8, Vec<u8>) = match literal {
        Literal::Bool(value) => (1, if *value { b"1" } else { b"0" }.to_vec()),
        Literal::Int(value) => (0, value.to_string().into_bytes()),
        Literal::Bytes(value) => (3, value.to_vec()),
        Literal::Data(value) => (2, value.encode().to_vec()),
        Literal::Cap(..) => return None,
    };
    let length = u32::try_from(raw.len()).ok()?;
    let mut out = Vec::with_capacity(22 + raw.len());
    out.extend_from_slice(b"OCTB");
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&2_u32.to_le_bytes());
    out.push(tag);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&raw);
    out.extend_from_slice(&[0x0b, 0, 0, 0, 0x17]);
    Some(out)
}
/// Compile an already lowered core program; surface parsing and source binding
/// must still be performed by the compiler frontend.
pub fn compile(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
    span: Span,
) -> Result<Image, Error> {
    let checked =
        check::check_in(types, terms, &program.inputs, program.term).map_err(Error::Check)?;
    compile_checked(types, terms, values, program, span, checked.info())
}
fn compile_checked(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
    span: Span,
    info: &check::Info,
) -> Result<Image, Error> {
    if !program.inputs.is_empty() {
        return Err(Error::Inputs(program.inputs.len()));
    }
    if !info.effects().is_empty() {
        return Err(Error::Effects(info.effects().clone()));
    }
    let out = eval::run(types, terms, values, program.term, None).map_err(Error::Run)?;
    if !out.plan().is_empty() {
        return Err(Error::Plan(out.plan().to_vec()));
    }
    let lit =
        lit(types, values, info.typ(), out.value()).ok_or(Error::Value(info.typ(), out.value()))?;
    let octb = octb(&lit).ok_or(Error::Constant)?;
    Ok(Image { lit, octb, span })
}
/// C_emit.compile checks the complete source program before applying its closed
/// literal profile. In particular, unused forms and permissions are validated.
pub fn compile_source(source_text: &[u8]) -> Result<SourceImage, SourceFailure> {
    let super::parse::Compiled {
        lowered:
            super::parse::Lowered {
                program,
                mut types,
                terms,
            },
        checked,
        origins,
    } = super::parse::parse(source_text)
        .and_then(super::parse::Program::into_compiled)
        .map_err(|error| SourceFailure {
            error: Error::Source(error),
            types: Types::default(),
            values: Values::default(),
        })?;
    let mut values = Values::default();
    let result = compile_checked(
        &mut types,
        &terms,
        &mut values,
        &program,
        origins.span,
        checked.info(),
    );
    match result {
        Ok(image) => Ok(SourceImage {
            types,
            values,
            image,
        }),
        Err(error) => Err(SourceFailure {
            error,
            types,
            values,
        }),
    }
}
impl Error {
    pub fn text(&self, types: &Types, values: &Values) -> Vec<u8> {
        match self {
            Self::Source(error) => error.text(),
            Self::Check(error) => error.text(types),
            Self::Run(error) => error.text(types),
            Self::Inputs(count) => format!("OCTB input count = {count} expected = 0").into_bytes(),
            Self::Effects(effects) => [
                b"OCTB effects are not representable effects = ".as_slice(),
                &super::effects_text(effects),
            ]
            .concat(),
            Self::Plan(plan) => [
                b"OCTB execution plan is not empty effects = ".as_slice(),
                &super::effects_text(&plan.iter().copied().collect()),
            ]
            .concat(),
            Self::Value(typ, value) => [
                b"OCTB value is not representable type = ".as_slice(),
                &types.text(*typ),
                b" value = ",
                &values.text(*value),
            ]
            .concat(),
            Self::Constant => b"capability cannot be a constant".to_vec(),
        }
    }
}
