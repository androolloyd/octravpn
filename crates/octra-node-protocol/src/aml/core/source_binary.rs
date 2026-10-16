// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_sbin canonical scope, token and session-state bit codecs. Reconstruction
//! uses the same scope, natural and identity-order checks as session execution.
use super::{
    bin::{self, Bits, Code, CodeId, Codes},
    session::{self, Cell, Scope, State, Token},
    Natural,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn raw_code(codes: &mut Codes, raw: &[u8]) -> CodeId {
    let bytes = raw.iter().map(|byte| codes.num(*byte)).collect::<Vec<_>>();
    codes.list(&bytes)
}
fn raw_get(codes: &Codes, root: CodeId) -> Option<Vec<u8>> {
    codes
        .list_get(root)?
        .into_iter()
        .map(|id| {
            let Code::Num(byte) = codes.get(id) else {
                return None;
            };
            Natural::byte(byte)
        })
        .collect()
}
fn tagged(codes: &Codes, root: CodeId, expected: u32) -> Option<CodeId> {
    let Code::Tag(tag, body) = codes.get(root) else {
        return None;
    };
    (tag.to_u32()? == expected).then_some(*body)
}
fn number(codes: &Codes, root: CodeId) -> Option<&BigInt> {
    let Code::Num(value) = codes.get(root) else {
        return None;
    };
    Some(value)
}
pub fn scope_code(codes: &mut Codes, scope: &Scope) -> CodeId {
    let chain = raw_code(codes, scope.chain());
    let prog = raw_code(codes, scope.program());
    let root = raw_code(codes, scope.root());
    let fields = codes.list(&[chain, prog, root]);
    codes.tag(0, fields)
}
pub fn scope_get(codes: &Codes, root: CodeId) -> Option<Scope> {
    let [chain, prog, root] = codes.fields::<3>(tagged(codes, root, 0)?)?;
    session::scope(
        &raw_get(codes, chain)?,
        &raw_get(codes, prog)?,
        &raw_get(codes, root)?,
    )
    .ok()
}
pub fn token_code(codes: &mut Codes, token: &Token) -> CodeId {
    let scope = scope_code(codes, token.scope());
    let kind = codes.num(token.kind().get());
    let id = codes.num(token.id().get());
    let rev = codes.num(token.revision().get());
    let fields = codes.list(&[scope, kind, id, rev]);
    codes.tag(1, fields)
}
pub fn token_get(codes: &Codes, root: CodeId) -> Option<Token> {
    let [scope, kind, id, rev] = codes.fields::<4>(tagged(codes, root, 1)?)?;
    session::token(
        &scope_get(codes, scope)?,
        number(codes, kind)?,
        number(codes, id)?,
        number(codes, rev)?,
    )
    .ok()
}
fn cell_code(codes: &mut Codes, cell: &Cell) -> CodeId {
    let kind = codes.num(cell.kind().get());
    let id = codes.num(cell.id().get());
    let rev = codes.num(cell.revision().get());
    let live = codes.num(u8::from(cell.live()));
    let fields = codes.list(&[kind, id, rev, live]);
    codes.tag(2, fields)
}
fn cell_get(codes: &Codes, root: CodeId) -> Option<Cell> {
    let [kind, id, rev, live] = codes.fields::<4>(tagged(codes, root, 2)?)?;
    let live = match number(codes, live)?.to_u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    session::cell(
        number(codes, kind)?,
        number(codes, id)?,
        number(codes, rev)?,
        live,
    )
    .ok()
}
pub fn state_code(codes: &mut Codes, state: &State) -> CodeId {
    let scope = scope_code(codes, state.scope());
    let cells = state
        .cells()
        .iter()
        .map(|cell| cell_code(codes, cell))
        .collect::<Vec<_>>();
    let cells = codes.list(&cells);
    let fields = codes.list(&[scope, cells]);
    codes.tag(3, fields)
}
pub fn state_get(codes: &Codes, root: CodeId) -> Option<State> {
    let [scope, cells] = codes.fields::<2>(tagged(codes, root, 3)?)?;
    let scope = scope_get(codes, scope)?;
    let cells = codes
        .list_get(cells)?
        .into_iter()
        .map(|id| cell_get(codes, id))
        .collect::<Option<Vec<_>>>()?;
    session::of_cells(&scope, &cells).ok()
}
fn encode<T>(value: &T, put: fn(&mut Codes, &T) -> CodeId) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = put(&mut codes, value);
    bin::encode(&codes, root)
}
fn decode<T>(
    input: &[bool],
    put: fn(&mut Codes, &T) -> CodeId,
    get: fn(&Codes, CodeId) -> Option<T>,
) -> Option<T> {
    let decoded = bin::decode(input)?;
    let value = get(&decoded.codes, decoded.root)?;
    (encode(&value, put)?.as_slice() == input).then_some(value)
}
pub fn encode_scope(value: &Scope) -> Option<Bits> {
    encode(value, scope_code)
}
pub fn decode_scope(input: &[bool]) -> Option<Scope> {
    decode(input, scope_code, scope_get)
}
pub fn encode_token(value: &Token) -> Option<Bits> {
    encode(value, token_code)
}
pub fn decode_token(input: &[bool]) -> Option<Token> {
    decode(input, token_code, token_get)
}
pub fn encode_state(value: &State) -> Option<Bits> {
    encode(value, state_code)
}
pub fn decode_state(input: &[bool]) -> Option<State> {
    decode(input, state_code, state_get)
}
