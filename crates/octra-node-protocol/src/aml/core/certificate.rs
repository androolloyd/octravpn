// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_cert deterministic static-check certificates. Verification rechecks the
//! program under the selected epoch rule; these are not consensus signatures.
use super::{
    bin::{self, Bits, Code, Codes},
    check,
    limit::Limit,
    program_codec,
    rule::Schedule,
    term::{Program, Terms},
    types::{TypeId, Types},
    Atom,
};
use num_bigint::{BigInt, Sign};
use num_traits::Zero;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Check(check::RuleError),
    Encode,
}
struct Certificate {
    program: Program,
    rule: Vec<BigInt>,
    typ: TypeId,
    row: Vec<Atom>,
    resources: Limit,
}
fn encode(types: &mut Types, terms: &Terms, value: &Certificate) -> Option<Bits> {
    let mut codes = Codes::default();
    let program = program_codec::code(&mut codes, types, terms, &value.program)?;
    let rule = value
        .rule
        .iter()
        .map(|value| (value.sign() != Sign::Minus).then(|| codes.num(value.clone())))
        .collect::<Option<Vec<_>>>()?;
    let rule = codes.list(&rule);
    let typ = codes.type_code(types, value.typ);
    let row = codes.row_code(&value.row);
    let res = codes.resources_code(&value.resources)?;
    let fields = codes.list(&[program, rule, typ, row, res]);
    let root = codes.tag(0, fields);
    bin::encode(&codes, root)
}
fn decode(types: &mut Types, terms: &mut Terms, input: &[bool]) -> Option<Certificate> {
    let decoded = bin::decode(input)?;
    let Code::Tag(tag, body) = decoded.codes.get(decoded.root) else {
        return None;
    };
    if !tag.is_zero() {
        return None;
    }
    let [program, rule, typ, row, res] = decoded.codes.fields::<5>(*body)?;
    let program = program_codec::get(&decoded.codes, types, terms, program)?;
    let rule = decoded
        .codes
        .list_get(rule)?
        .into_iter()
        .map(|id| {
            let Code::Num(value) = decoded.codes.get(id) else {
                return None;
            };
            (value.sign() != Sign::Minus).then(|| (**value).clone())
        })
        .collect::<Option<Vec<_>>>()?;
    // The twelve rule fields are arbitrary nonnegative integers in the wire
    // grammar. Epoch verification compares them to the selected rule identity.
    if rule.len() != 12 {
        return None;
    }
    let typ = decoded.codes.type_get(types, typ)?;
    let row = decoded.codes.row_get(row)?;
    let resources = decoded.codes.resources_get(res)?;
    let value = Certificate {
        program,
        rule,
        typ,
        row,
        resources,
    };
    (encode(types, terms, &value)?.as_slice() == input).then_some(value)
}
pub fn issue(
    schedule: &Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &Terms,
    program: &Program,
) -> Result<Bits, Error> {
    let selected = check::check_in_at(schedule, epoch, types, terms, &program.inputs, program.term)
        .map_err(Error::Check)?;
    let info = selected.checked().info();
    let value = Certificate {
        program: program.clone(),
        rule: selected
            .rule()
            .values()
            .into_iter()
            .map(BigInt::from)
            .collect(),
        typ: info.typ(),
        row: info.effects().iter().copied().collect(),
        resources: info.resources().clone(),
    };
    encode(types, terms, &value).ok_or(Error::Encode)
}
pub fn verify(
    schedule: &Schedule,
    epoch: &BigInt,
    types: &mut Types,
    terms: &mut Terms,
    input: &[bool],
) -> bool {
    let Some(value) = decode(types, terms, input) else {
        return false;
    };
    let Ok(selected) = check::check_in_at(
        schedule,
        epoch,
        types,
        terms,
        &value.program.inputs,
        value.program.term,
    ) else {
        return false;
    };
    let info = selected.checked().info();
    value.rule
        == selected
            .rule()
            .values()
            .into_iter()
            .map(BigInt::from)
            .collect::<Vec<_>>()
        && value.typ == info.typ()
        && value.row == info.effects().iter().copied().collect::<Vec<_>>()
        && value.resources == *info.resources()
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Check(error) => error.text(types),
            Self::Encode => b"certificate encoding failed".to_vec(),
        }
    }
}
