// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_pbin checked-program artifacts. Raw reconstruction and canonical decoding
//! remain separate; decoded syntax is not evidence of emitted-code agreement.
use super::{
    bin::{self, Bits, Code, CodeId, Codes},
    check,
    rule::{Field, LOCAL},
    term::{Bind, Fold, Program, Relation, Term, TermId, Terms},
    types::{Multiplicity, Type, TypeId, Types},
    Atom, Natural,
};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::sync::Arc;
mod decode;
mod encode;
pub fn code(
    codes: &mut Codes,
    types: &mut Types,
    terms: &Terms,
    program: &Program,
) -> Option<CodeId> {
    check::check_in(types, terms, &program.inputs, program.term).ok()?;
    let inputs = program
        .inputs
        .iter()
        .map(|bind| bind_code(codes, types, *bind))
        .collect::<Vec<_>>();
    let inputs = codes.list(&inputs);
    let mut env = encode::Env::default();
    for bind in &program.inputs {
        env = env.bind(*bind);
    }
    let term = encode::term(codes, types, terms, program.term, env)?;
    let fields = codes.list(&[inputs, term]);
    Some(codes.tag(26, fields))
}
pub fn get(codes: &Codes, types: &mut Types, terms: &mut Terms, root: CodeId) -> Option<Program> {
    let [inputs, term] = fields::<2>(codes, tagged(codes, root, 26)?)?;
    let mut inputs_code = inputs;
    let mut inputs = vec![];
    loop {
        match codes.get(inputs_code) {
            Code::Nil => break,
            Code::Cons(bind, rest) if inputs.len() < LOCAL.get(Field::Inputs) as usize => {
                inputs.push(bind_get(codes, types, *bind)?);
                inputs_code = *rest;
            }
            _ => return None,
        }
    }
    let term = decode::term(codes, types, terms, term)?;
    let program = Program { inputs, term };
    check::check_in(types, terms, &program.inputs, program.term).ok()?;
    Some(program)
}
pub fn encode(types: &mut Types, terms: &Terms, program: &Program) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = code(&mut codes, types, terms, program)?;
    bin::encode(&codes, root)
}
pub fn valid(types: &mut Types, terms: &Terms, program: &Program) -> bool {
    encode(types, terms, program).is_some()
}
pub fn decode(types: &mut Types, terms: &mut Terms, input: &[bool]) -> Option<Program> {
    let decoded = bin::decode(input)?;
    let program = get(&decoded.codes, types, terms, decoded.root)?;
    (encode(types, terms, &program)?.as_slice() == input).then_some(program)
}
fn fields<const N: usize>(codes: &Codes, mut id: CodeId) -> Option<[CodeId; N]> {
    let mut out = [codes.nil(); N];
    for field in &mut out {
        let Code::Cons(first, rest) = codes.get(id) else {
            return None;
        };
        *field = *first;
        id = *rest;
    }
    matches!(codes.get(id), Code::Nil).then_some(out)
}
fn tagged(codes: &Codes, id: CodeId, expected: u32) -> Option<CodeId> {
    let Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    (tag.to_u32()? == expected).then_some(*body)
}
fn number(codes: &Codes, id: CodeId) -> Option<Natural> {
    let Code::Num(value) = codes.get(id) else {
        return None;
    };
    Natural::new(value)
}
fn symbol(codes: &Codes, id: CodeId) -> Option<u32> {
    let Code::Tag(tag, body) = codes.get(id) else {
        return None;
    };
    if !matches!(codes.get(*body), Code::Nil) {
        return None;
    }
    tag.to_u32()
}
fn bind_code(codes: &mut Codes, types: &Types, bind: Bind) -> CodeId {
    let id = codes.num(bind.id.get());
    let mode = codes.tag(
        match bind.multiplicity {
            Multiplicity::Zero => 0,
            Multiplicity::One => 1,
            Multiplicity::Many => 2,
        },
        codes.nil(),
    );
    let typ = codes.type_code(types, bind.typ);
    let fields = codes.list(&[id, mode, typ]);
    codes.tag(0, fields)
}
fn bind_get(codes: &Codes, types: &mut Types, id: CodeId) -> Option<Bind> {
    let [id, mode, typ] = fields::<3>(codes, tagged(codes, id, 0)?)?;
    let id = number(codes, id)?;
    let multiplicity = match symbol(codes, mode)? {
        0 => Multiplicity::Zero,
        1 => Multiplicity::One,
        2 => Multiplicity::Many,
        _ => return None,
    };
    Some(Bind {
        id,
        multiplicity,
        typ: codes.type_get(types, typ)?,
    })
}
fn relation_code(codes: &mut Codes, rel: Relation) -> CodeId {
    codes.tag(
        match rel {
            Relation::Lt => 0,
            Relation::Le => 1,
            Relation::Gt => 2,
            Relation::Ge => 3,
        },
        codes.nil(),
    )
}
fn relation_get(codes: &Codes, id: CodeId) -> Option<Relation> {
    Some(match symbol(codes, id)? {
        0 => Relation::Lt,
        1 => Relation::Le,
        2 => Relation::Gt,
        3 => Relation::Ge,
        _ => return None,
    })
}
