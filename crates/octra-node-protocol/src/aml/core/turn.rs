// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_turn executes canonical program/value/token artifacts, advances scoped
//! capability revisions, and seals the resulting state under its new root.
use super::{
    bin::{self, Bits},
    check,
    eval::{self, Values},
    program_codec, root,
    rule::{Field, LOCAL},
    session, source_binary,
    term::Terms,
    types::Types,
};
use num_bigint::BigInt;

#[derive(Clone, Debug)]
pub struct Output {
    pub types: Types,
    pub values: Values,
    eval: eval::Output,
    state: Bits,
    tokens: Vec<Bits>,
    root: [u8; 32],
}
impl Output {
    pub fn eval(&self) -> &eval::Output {
        &self.eval
    }
    pub fn state(&self) -> &[bool] {
        &self.state
    }
    pub fn tokens(&self) -> &[Bits] {
        &self.tokens
    }
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Program,
    State,
    Input(usize),
    Token(usize),
    Arity(usize, usize),
    Live,
    Static(check::Error),
    Session(session::Error),
    Root,
    Seal,
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        match self {
            Self::Program => b"turn program refused".to_vec(),
            Self::State => b"turn state refused".to_vec(),
            Self::Input(index) => format!("turn input refused index = {index}").into_bytes(),
            Self::Token(index) => format!("turn token refused index = {index}").into_bytes(),
            Self::Arity(binds, values) => {
                format!("turn input arity binds = {binds} values = {values}").into_bytes()
            }
            Self::Live => b"turn live capability set differs".to_vec(),
            Self::Static(error) => [
                b"turn checker refused reason = ".as_slice(),
                &error.text(types),
            ]
            .concat(),
            Self::Session(error) => [
                b"turn session refused reason = ".as_slice(),
                &error.text(types),
            ]
            .concat(),
            Self::Root => b"turn root refused".to_vec(),
            Self::Seal => b"turn seal refused".to_vec(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Failure {
    pub error: Error,
    pub types: Types,
}
impl Failure {
    pub fn text(&self) -> Vec<u8> {
        self.error.text(&self.types)
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Failure {}

fn domain(state: &session::State, root: &[u8]) -> Result<(session::Scope, session::State), Error> {
    let prior = state.scope();
    let scope = session::scope(prior.chain(), prior.program(), root).map_err(Error::Session)?;
    let state = session::of_cells(&scope, &state.cells()).map_err(Error::Session)?;
    Ok((scope, state))
}
pub fn verify(program: &[bool], prior: &[u8], state: &[bool], expected_root: &[u8]) -> bool {
    let Some(sealed) = source_binary::decode_state(state) else {
        return false;
    };
    if expected_root.len() != 32
        || sealed.scope().program() != root::image(program)
        || sealed.scope().root() != expected_root
    {
        return false;
    }
    let Ok((_, opened)) = domain(&sealed, prior) else {
        return false;
    };
    let Some(bits) = source_binary::encode_state(&opened) else {
        return false;
    };
    root::root(program, prior, &bits).is_some_and(|found| found.as_slice() == expected_root)
}
struct Completed {
    eval: eval::Output,
    state: Bits,
    tokens: Vec<Bits>,
    root: [u8; 32],
}
fn execute(
    types: &mut Types,
    values: &mut Values,
    program: &[bool],
    prior: &[u8],
    state: &[bool],
    inputs: &[Bits],
    token_bits: &[Bits],
) -> Result<Completed, Error> {
    let mut terms = Terms::default();
    let program_value = program_codec::decode(types, &mut terms, program).ok_or(Error::Program)?;
    let state_value = source_binary::decode_state(state).ok_or(Error::State)?;
    root::root(program, prior, state).ok_or(Error::Root)?;
    let mut decoded_values = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        if index == LOCAL.get(Field::Inputs) as usize {
            return Err(Error::Input(index));
        }
        decoded_values.push(bin::decode_value(values, input).ok_or(Error::Input(index))?);
    }
    let mut token_values = Vec::new();
    for (index, token) in token_bits.iter().enumerate() {
        if index == LOCAL.get(Field::TermNodes) as usize {
            return Err(Error::Token(index));
        }
        token_values.push(source_binary::decode_token(token).ok_or(Error::Token(index))?);
    }
    let live = state_value
        .cells()
        .into_iter()
        .filter(super::session::Cell::live)
        .map(|cell| (cell.kind(), cell.id()))
        .collect::<Vec<_>>();
    let mut token_keys = token_values
        .iter()
        .map(|token| (token.kind(), token.id()))
        .collect::<Vec<_>>();
    token_keys.sort();
    if live != token_keys {
        return Err(Error::Live);
    }
    let common = program_value.inputs.len().min(decoded_values.len());
    if program_value.inputs.len() != decoded_values.len() {
        return Err(Error::Arity(
            program_value.inputs.len() - common,
            decoded_values.len() - common,
        ));
    }
    let inputs = program_value
        .inputs
        .iter()
        .copied()
        .zip(decoded_values)
        .collect::<Vec<_>>();
    let info = check::check_in(types, &terms, &program_value.inputs, program_value.term)
        .map_err(Error::Static)?;
    let fuel: BigInt = info.info().resources().steps.clone();
    let session = session::run(
        types,
        &terms,
        values,
        &state_value,
        &token_values,
        &inputs,
        program_value.term,
        Some(&fuel),
    )
    .map_err(Error::Session)?;
    let open_bits = source_binary::encode_state(session.state()).ok_or(Error::Seal)?;
    let next_root = root::root(program, prior, &open_bits).ok_or(Error::Root)?;
    let (scope, sealed) = domain(session.state(), &next_root)?;
    let mut fresh_tokens = Vec::new();
    for token in session.tokens() {
        let token = session::token(
            &scope,
            &token.kind().get().into(),
            &token.id().get().into(),
            &token.revision().get().into(),
        )
        .map_err(Error::Session)?;
        fresh_tokens.push(token);
    }
    let state = source_binary::encode_state(&sealed).ok_or(Error::Seal)?;
    let tokens = fresh_tokens
        .iter()
        .map(|token| source_binary::encode_token(token).ok_or(Error::Seal))
        .collect::<Result<Vec<_>, _>>()?;
    if !verify(program, prior, &state, &next_root) {
        return Err(Error::Seal);
    }
    Ok(Completed {
        eval: session.eval().clone(),
        state,
        tokens,
        root: next_root,
    })
}
pub fn run(
    program: &[bool],
    prior: &[u8],
    state: &[bool],
    inputs: &[Bits],
    tokens: &[Bits],
) -> Result<Output, Failure> {
    let mut types = Types::default();
    let mut values = Values::default();
    match execute(
        &mut types,
        &mut values,
        program,
        prior,
        state,
        inputs,
        tokens,
    ) {
        Ok(Completed {
            eval,
            state,
            tokens,
            root,
        }) => Ok(Output {
            types,
            values,
            eval,
            state,
            tokens,
            root,
        }),
        Err(error) => Err(Failure { error, types }),
    }
}
