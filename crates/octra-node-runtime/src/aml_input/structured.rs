// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Structured Aml_input bridge. Core IDs refer to the caller's Values arena.
use super::{hex, integer, tagged, Error};
use crate::octb::{Capability, Value};
use octra_node_protocol::aml::core::{
    eval::{Value as Core, ValueId, Values},
    feed,
    machine::{self, Literal, Shapes},
    term::Bind,
    types::{Type, TypeId, Types},
};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct CoreValue {
    pub vms: Vec<Value>,
    pub lits: Vec<Literal>,
    pub lit: Literal,
    pub value: ValueId,
}

pub fn vm(literal: &Literal) -> Option<Value> {
    Some(match literal {
        Literal::Bool(value) => Value::Bool(*value),
        Literal::Int(value) => Value::Int(value.clone()),
        Literal::Bytes(value) => Value::Bytes(value.clone()),
        Literal::Cap(kind, id) => Value::Capability(Capability {
            scope: vec![0; 32],
            kind: i64::from(kind.get()),
            id: i64::from(id.get()),
            revision: 0,
        }),
        Literal::Data(_) => return None,
    })
}

pub fn core_eval(
    index: usize,
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    value: ValueId,
) -> Result<CoreValue, Error> {
    let shape = Shapes::default().from_type(types, typ);
    let lits = machine::atoms(types, values, typ, value);
    let lit = machine::literal(types, values, typ, value);
    let (Some(_), Some(lits), Some(lit)) = (shape, lits, lit) else {
        return Err(Error::Type(index, types.text(typ)));
    };
    let vms = lits
        .iter()
        .map(vm)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::Value(index, types.text(typ)))?;
    Ok(CoreValue {
        vms,
        lits,
        lit,
        value,
    })
}

pub fn core_value(
    index: usize,
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    vm: &Value,
) -> Result<CoreValue, Error> {
    let value = match (types.get(typ), vm) {
        (Type::Int | Type::Num(..), Value::Int(value)) => Core::Int(value.clone()),
        (Type::Bool, Value::Bool(value)) => Core::Bool(*value),
        (Type::Bytes(length), Value::Bytes(value)) if length.get() as usize == value.len() => {
            Core::Bytes(value.clone())
        }
        _ => return Err(Error::Value(index, types.text(typ))),
    };
    let value = values.push(value);
    core_eval(index, types, values, typ, value)
}

fn parsed(
    index: usize,
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    raw: &[u8],
) -> Result<CoreValue, Error> {
    let shape = Shapes::default().from_type(types, typ);
    let value = feed::parse_value(types, values, typ, raw);
    match (shape, value) {
        (Some(_), Ok(value)) => core_eval(index, types, values, typ, value),
        (Some(_), Err(_)) => Err(Error::Value(index, types.text(typ))),
        (None, _) => Err(Error::Type(index, types.text(typ))),
    }
}

pub fn core_source(
    index: usize,
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    raw: &[u8],
) -> Result<CoreValue, Error> {
    let scalar = match types.get(typ) {
        Type::Int | Type::Num(..) => integer(raw).map(|value| Value::Int(Arc::new(value))),
        Type::Bool if raw == b"true" => Some(Value::Bool(true)),
        Type::Bool if raw == b"false" => Some(Value::Bool(false)),
        Type::Bytes(_) => hex(raw).map(Value::Bytes),
        _ => None,
    };
    match scalar {
        Some(value) => core_value(index, types, values, typ, &value),
        None => parsed(index, types, values, typ, raw),
    }
}

pub fn core(
    types: &Types,
    values: &mut Values,
    inputs: &[Bind],
    raws: &[Vec<u8>],
) -> Result<Vec<CoreValue>, Error> {
    if inputs.len() != raws.len() {
        return Err(Error::Arity(inputs.len(), raws.len()));
    }
    inputs
        .iter()
        .zip(raws)
        .enumerate()
        .map(|(index, (bind, raw))| core_source(index, types, values, bind.typ, raw))
        .collect()
}

pub fn core_octb(
    types: &Types,
    values: &mut Values,
    inputs: &[TypeId],
    raws: &[Vec<u8>],
) -> Result<Vec<CoreValue>, Error> {
    if inputs.len() != raws.len() {
        return Err(Error::Arity(inputs.len(), raws.len()));
    }
    inputs
        .iter()
        .zip(raws)
        .enumerate()
        .map(|(index, (typ, raw))| match tagged(raw) {
            Some(value) => core_value(index, types, values, *typ, &value),
            None => parsed(index, types, values, *typ, raw),
        })
        .collect()
}
