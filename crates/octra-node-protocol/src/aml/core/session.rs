// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_sess scoped, single-use capability revisions. Evaluation is checked before
//! immutable session advancement; rejected output cannot consume input tokens.
use super::{
    eval::{self, Value, ValueId, Values},
    rule::{Field as RuleField, LOCAL},
    term::{Bind, TermId, Terms},
    text,
    types::Types,
    Natural,
};
use num_bigint::BigInt;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

type Key = (Natural, Natural);
type Result<T> = std::result::Result<T, Error>;
const MAX_NATURAL: u32 = super::super::limits::NATURAL;
const MAX_NODES: usize = LOCAL.get(RuleField::TermNodes) as usize;
const MAX_DEPTH: usize = LOCAL.get(RuleField::TermDepth) as usize;
const MAX_INPUTS: usize = LOCAL.get(RuleField::Inputs) as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    chain: Arc<[u8]>,
    prog: Arc<[u8]>,
    root: Arc<[u8]>,
}
impl Scope {
    pub fn chain(&self) -> &[u8] {
        &self.chain
    }
    pub fn program(&self) -> &[u8] {
        &self.prog
    }
    pub fn root(&self) -> &[u8] {
        &self.root
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    scope: Scope,
    kind: Natural,
    id: Natural,
    rev: Natural,
}
impl Token {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn kind(&self) -> Natural {
        self.kind
    }
    pub fn id(&self) -> Natural {
        self.id
    }
    pub fn revision(&self) -> Natural {
        self.rev
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    kind: Natural,
    id: Natural,
    rev: Natural,
    live: bool,
}
impl Cell {
    pub fn kind(&self) -> Natural {
        self.kind
    }
    pub fn id(&self) -> Natural {
        self.id
    }
    pub fn revision(&self) -> Natural {
        self.rev
    }
    pub fn live(&self) -> bool {
        self.live
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    rev: Natural,
    live: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    scope: Scope,
    slots: BTreeMap<Key, Slot>,
}
impl State {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn cells(&self) -> Vec<Cell> {
        self.slots
            .iter()
            .map(|((kind, id), slot)| Cell {
                kind: *kind,
                id: *id,
                rev: slot.rev,
                live: slot.live,
            })
            .collect()
    }
}
#[derive(Clone, Debug)]
pub struct Output {
    eval: eval::Output,
    state: State,
    tokens: Vec<Token>,
}
impl Output {
    pub fn eval(&self) -> &eval::Output {
        &self.eval
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Chain,
    Prog,
    Root,
    Kind,
    Id,
    Rev,
}
impl Field {
    fn text(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Prog => "program",
            Self::Root => "prior_root",
            Self::Kind => "kind",
            Self::Id => "id",
            Self::Rev => "revision",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Natural(Field, BigInt),
    Length(Field, usize),
    Scope,
    Order(Key, Key),
    Exists(Key),
    Absent(Key),
    Stale(Natural, Natural, Natural, Natural),
    TokenDuplicate(Key),
    TokenMissing(Key),
    TokenExtra(Key),
    ValueDuplicate(Key),
    ValueDepth(usize, usize),
    ValueNodes(usize, usize),
    InputCount(usize, usize),
    StateCount(usize, usize),
    New(Key),
    RevisionMaximum(Key),
    Eval(eval::Error),
}
fn natural(field: Field, value: &BigInt) -> Result<Natural> {
    Natural::new(value).ok_or_else(|| Error::Natural(field, value.clone()))
}
pub fn scope(chain: &[u8], prog: &[u8], root: &[u8]) -> Result<Scope> {
    for (field, value) in [
        (Field::Chain, chain),
        (Field::Prog, prog),
        (Field::Root, root),
    ] {
        if value.len() > MAX_NATURAL as usize {
            return Err(Error::Length(field, value.len()));
        }
    }
    Ok(Scope {
        chain: chain.into(),
        prog: prog.into(),
        root: root.into(),
    })
}
pub fn scope_equal(left: &Scope, right: &Scope) -> bool {
    left == right
}
pub fn token(scope: &Scope, kind: &BigInt, id: &BigInt, rev: &BigInt) -> Result<Token> {
    let kind = natural(Field::Kind, kind)?;
    let id = natural(Field::Id, id)?;
    let rev = natural(Field::Rev, rev)?;
    Ok(Token {
        scope: scope.clone(),
        kind,
        id,
        rev,
    })
}
pub fn cell(kind: &BigInt, id: &BigInt, rev: &BigInt, live: bool) -> Result<Cell> {
    let kind = natural(Field::Kind, kind)?;
    let id = natural(Field::Id, id)?;
    let rev = natural(Field::Rev, rev)?;
    Ok(Cell {
        kind,
        id,
        rev,
        live,
    })
}
pub fn empty(scope: &Scope) -> State {
    State {
        scope: scope.clone(),
        slots: BTreeMap::new(),
    }
}
pub fn scope_of(state: &State) -> &Scope {
    state.scope()
}
pub fn view(state: &State) -> (&Scope, Vec<Cell>) {
    (state.scope(), state.cells())
}
pub fn of_cells(scope: &Scope, cells: &[Cell]) -> Result<State> {
    let mut state = empty(scope);
    let mut prior = None;
    for cell in cells {
        if state.slots.len() == MAX_NODES {
            return Err(Error::StateCount(MAX_NODES, MAX_NODES + 1));
        }
        let key = (cell.kind, cell.id);
        if let Some(prior) = prior {
            if prior >= key {
                return Err(Error::Order(prior, key));
            }
        }
        state.slots.insert(
            key,
            Slot {
                rev: cell.rev,
                live: cell.live,
            },
        );
        prior = Some(key);
    }
    Ok(state)
}
pub fn issue(state: &State, kind: &BigInt, id: &BigInt) -> Result<(State, Token)> {
    let kind = natural(Field::Kind, kind)?;
    let id = natural(Field::Id, id)?;
    let key = (kind, id);
    if state.slots.contains_key(&key) {
        return Err(Error::Exists(key));
    }
    if state.slots.len() == MAX_NODES {
        return Err(Error::StateCount(MAX_NODES, MAX_NODES + 1));
    }
    let rev = Natural::from_u32(0).expect("zero revision");
    let token = Token {
        scope: state.scope.clone(),
        kind,
        id,
        rev,
    };
    let mut state = state.clone();
    state.slots.insert(key, Slot { rev, live: true });
    Ok((state, token))
}
pub fn current(state: &State, token: &Token) -> bool {
    state.scope == token.scope
        && state
            .slots
            .get(&(token.kind, token.id))
            .is_some_and(|slot| slot.live && slot.rev == token.rev)
}
pub fn take(state: &State, token: &Token, keep: bool) -> Result<(State, Option<Token>)> {
    let mut state = state.clone();
    let fresh = consume(&mut state, token, keep)?;
    Ok((state, fresh))
}
fn consume(state: &mut State, token: &Token, keep: bool) -> Result<Option<Token>> {
    let key = (token.kind, token.id);
    if state.scope != token.scope {
        return Err(Error::Scope);
    }
    let slot = state.slots.get(&key).ok_or(Error::Absent(key))?;
    if !slot.live || slot.rev != token.rev {
        return Err(Error::Stale(token.kind, token.id, slot.rev, token.rev));
    }
    let fresh = if keep {
        let rev = token
            .rev
            .checked_add(Natural::from_u32(1).expect("one revision"))
            .ok_or(Error::RevisionMaximum(key))?;
        Some(Token {
            rev,
            ..token.clone()
        })
    } else {
        None
    };
    state.slots.insert(
        key,
        Slot {
            rev: fresh.as_ref().map_or(token.rev, |token| token.rev),
            live: keep,
        },
    );
    Ok(fresh)
}
fn caps(
    values: &Values,
    root: ValueId,
    output: &mut BTreeSet<Key>,
    nodes: &mut usize,
) -> Result<()> {
    let mut pending = vec![(0, root)];
    while let Some((depth, id)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(Error::ValueDepth(MAX_DEPTH, depth));
        }
        if *nodes >= MAX_NODES {
            return Err(Error::ValueNodes(MAX_NODES, *nodes + 1));
        }
        let value = values.get(id);
        if let Value::Cap(kind, id) = value {
            if !output.insert((*kind, *id)) {
                return Err(Error::ValueDuplicate((*kind, *id)));
            }
        }
        pending.extend(value.children().into_iter().rev().map(|id| (depth + 1, id)));
        *nodes += 1;
    }
    Ok(())
}
fn input_caps(values: &Values, inputs: &[(Bind, ValueId)]) -> Result<BTreeSet<Key>> {
    let mut output = BTreeSet::new();
    let mut nodes = 0;
    for (count, (_, value)) in inputs.iter().enumerate() {
        if count == MAX_INPUTS {
            return Err(Error::InputCount(MAX_INPUTS, MAX_INPUTS + 1));
        }
        caps(values, *value, &mut output, &mut nodes)?;
    }
    Ok(output)
}
fn token_map(tokens: &[Token]) -> Result<BTreeMap<Key, &Token>> {
    let mut output = BTreeMap::new();
    for (count, token) in tokens.iter().enumerate() {
        if count == MAX_NODES {
            return Err(Error::ValueNodes(MAX_NODES, MAX_NODES + 1));
        }
        let key = (token.kind, token.id);
        if output.insert(key, token).is_some() {
            return Err(Error::TokenDuplicate(key));
        }
    }
    Ok(output)
}
fn verify(state: &State, expected: &BTreeSet<Key>, supplied: &BTreeMap<Key, &Token>) -> Result<()> {
    for key in expected {
        let token = supplied.get(key).ok_or(Error::TokenMissing(*key))?;
        if state.scope != token.scope {
            return Err(Error::Scope);
        }
        if !current(state, token) {
            let slot = state.slots.get(key).ok_or(Error::Absent(*key))?;
            return Err(Error::Stale(token.kind, token.id, slot.rev, token.rev));
        }
    }
    for key in supplied.keys() {
        if !expected.contains(key) {
            return Err(Error::TokenExtra(*key));
        }
    }
    Ok(())
}
/// Value and term IDs belong to the caller's arenas throughout evaluation.
pub fn run(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    state: &State,
    tokens: &[Token],
    inputs: &[(Bind, ValueId)],
    term: TermId,
    fuel: Option<&BigInt>,
) -> Result<Output> {
    let input = input_caps(values, inputs)?;
    let supplied = token_map(tokens)?;
    verify(state, &input, &supplied)?;
    let eval = eval::run_in(types, terms, values, inputs, term, fuel).map_err(Error::Eval)?;
    let mut output = BTreeSet::new();
    let mut nodes = 0;
    caps(values, eval.value(), &mut output, &mut nodes)?;
    for key in &output {
        if !input.contains(key) {
            return Err(Error::New(*key));
        }
    }
    let mut state = state.clone();
    let mut tokens = Vec::new();
    for key in input {
        let fresh = consume(&mut state, supplied[&key], output.contains(&key))?;
        tokens.extend(fresh);
    }
    Ok(Output {
        eval,
        state,
        tokens,
    })
}
pub fn token_text(token: &Token) -> Vec<u8> {
    format!(
        "token[{},{},{}]",
        token.kind.get(),
        token.id.get(),
        token.rev.get()
    )
    .into_bytes()
}
fn key_text((kind, id): Key) -> String {
    format!("{}:{}", kind.get(), id.get())
}
impl Error {
    pub fn text(&self, types: &Types) -> Vec<u8> {
        let raw = match self {
            Self::Natural(field, value) => format!(
                "session natural outside profile field = {} value = {value}",
                field.text()
            )
            .into_bytes(),
            Self::Length(field, actual) => format!(
                "session bytes limit field = {} limit = {MAX_NATURAL} actual = {actual}",
                field.text()
            )
            .into_bytes(),
            Self::Scope => b"session context differs".to_vec(),
            Self::Order(left, right) => format!(
                "session identity order differs left = {} right = {}",
                key_text(*left),
                key_text(*right)
            )
            .into_bytes(),
            Self::Exists(key) => {
                format!("session identity already issued = {}", key_text(*key)).into_bytes()
            }
            Self::Absent(key) => {
                format!("session identity absent = {}", key_text(*key)).into_bytes()
            }
            Self::Stale(kind, id, expected, actual) => format!(
                "session token revision differs identity = {} expected = {} actual = {}",
                key_text((*kind, *id)),
                expected.get(),
                actual.get()
            )
            .into_bytes(),
            Self::TokenDuplicate(key) => {
                format!("session token repeated = {}", key_text(*key)).into_bytes()
            }
            Self::TokenMissing(key) => {
                format!("session token missing = {}", key_text(*key)).into_bytes()
            }
            Self::TokenExtra(key) => {
                format!("session token has no input = {}", key_text(*key)).into_bytes()
            }
            Self::ValueDuplicate(key) => {
                format!("session value repeats identity = {}", key_text(*key)).into_bytes()
            }
            Self::ValueDepth(limit, actual) => {
                format!("session value depth limit = {limit} actual = {actual}").into_bytes()
            }
            Self::ValueNodes(limit, actual) => {
                format!("session value nodes limit = {limit} actual = {actual}").into_bytes()
            }
            Self::InputCount(limit, actual) => {
                format!("session input count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::StateCount(limit, actual) => {
                format!("session identity count limit = {limit} actual = {actual}").into_bytes()
            }
            Self::New(key) => format!(
                "session output identity was not an input = {}",
                key_text(*key)
            )
            .into_bytes(),
            Self::RevisionMaximum(key) => {
                format!("session token revision limit identity = {}", key_text(*key)).into_bytes()
            }
            Self::Eval(error) => [
                b"session evaluator refused reason = ".as_slice(),
                &error.text(types),
            ]
            .concat(),
        };
        text::clip(&raw)
    }
}
