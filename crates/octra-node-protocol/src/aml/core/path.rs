// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_path relates checked evaluation to the compiler's machine plan, source
//! positions and linear-slot rows. Both independently built arenas are owned.
use super::{
    eval::{self, Value, ValueId, Values},
    feed::Feed,
    lexer::Span,
    limit::Limit,
    machine::{self, Literal},
    maps::Slot,
    octb, parse,
    types::{TypeId, Types},
    Atom,
};
use num_bigint::BigInt;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Load,
    Move,
    Plus,
    Times,
    Quotient,
    Remainder,
    Negate,
    Absolute,
    Same,
    Different,
    Less,
    Greater,
    Join,
    Minus,
    Size,
    Slice,
    CapClose,
    Jump,
    JumpIf,
    Mark,
    Noop,
    Stop,
}
fn kind(operation: &octb::Operation) -> Kind {
    use octb::Operation as O;
    match operation {
        O::Load(..) => Kind::Load,
        O::Move(..) => Kind::Move,
        O::Plus(..) => Kind::Plus,
        O::Times(..) => Kind::Times,
        O::Quotient(..) => Kind::Quotient,
        O::Remainder(..) => Kind::Remainder,
        O::Negate(..) => Kind::Negate,
        O::Absolute(..) => Kind::Absolute,
        O::Same(..) => Kind::Same,
        O::Different(..) => Kind::Different,
        O::Less(..) => Kind::Less,
        O::Greater(..) => Kind::Greater,
        O::Join(..) => Kind::Join,
        O::Minus(..) => Kind::Minus,
        O::Size(..) => Kind::Size,
        O::Slice(..) => Kind::Slice,
        O::CapClose(..) => Kind::CapClose,
        O::Jump(..) => Kind::Jump,
        O::JumpIf(..) => Kind::JumpIf,
        O::Mark(..) => Kind::Mark,
        O::Noop => Kind::Noop,
        O::Stop => Kind::Stop,
    }
}
#[derive(Clone, Debug)]
pub struct Frame {
    pc: usize,
    kind: Kind,
    span: Span,
    slots: Arc<[Slot]>,
}
impl Frame {
    pub fn pc(&self) -> usize {
        self.pc
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn span(&self) -> Span {
        self.span
    }
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }
}
#[derive(Clone, Debug)]
pub struct Path {
    pub types: Types,
    pub values: Values,
    artifact: octb::SourceImage,
    frames: Vec<Frame>,
    shape: TypeId,
    row: Vec<Atom>,
    effects: Vec<Atom>,
    used: Limit,
    resources: Limit,
    depth: BigInt,
    result: Literal,
}
impl Path {
    pub fn artifact(&self) -> &octb::SourceImage {
        &self.artifact
    }
    pub fn plan(&self) -> (&machine::Codes, machine::CodeId) {
        let machine = self.artifact.image.machine();
        (machine.codes(), machine.code())
    }
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
    pub fn shape(&self) -> TypeId {
        self.shape
    }
    pub fn row(&self) -> &[Atom] {
        &self.row
    }
    pub fn effects(&self) -> &[Atom] {
        &self.effects
    }
    pub fn used(&self) -> &Limit {
        &self.used
    }
    pub fn resources(&self) -> &Limit {
        &self.resources
    }
    pub fn depth(&self) -> &BigInt {
        &self.depth
    }
    pub fn result(&self) -> &Literal {
        &self.result
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    Source,
    Feed,
    Machine,
    Slots,
    Map,
    Run,
}
impl Cause {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Source => b"source refusal",
            Self::Feed => b"feed refusal",
            Self::Machine => b"machine refusal",
            Self::Slots => b"linear-slot refusal",
            Self::Map => b"source-map refusal",
            Self::Run => b"execution refusal",
        }
    }
}
fn source(source: &[u8]) -> Result<parse::Compiled, Cause> {
    parse::parse(source)
        .and_then(parse::Program::into_compiled)
        .map_err(|_| Cause::Source)
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn finish(
    compiled: parse::Compiled,
    mut values: Values,
    artifact: octb::SourceImage,
    out: eval::Output,
) -> Result<Path, Cause> {
    let info = compiled.checked.info();
    let result = machine::literal(
        &compiled.lowered.types,
        &mut values,
        info.typ(),
        out.value(),
    )
    .ok_or(Cause::Run)?;
    if artifact
        .image
        .result()
        .is_some_and(|value| !value.equal(&result))
    {
        return Err(Cause::Run);
    }
    let size = artifact.image.code().len();
    if artifact.image.source_map().spans().len() != size {
        return Err(Cause::Map);
    }
    if artifact.image.live_map().rows().len() != size {
        return Err(Cause::Slots);
    }
    let frames = artifact
        .image
        .code()
        .iter()
        .enumerate()
        .map(|(pc, op)| Frame {
            pc,
            kind: kind(op),
            span: artifact.image.source_map().spans()[pc],
            slots: artifact.image.live_map().rows()[pc].clone(),
        })
        .collect();
    let shape = info.typ();
    let row = info.effects().iter().copied().collect();
    let resources = info.resources().clone();
    Ok(Path {
        types: compiled.lowered.types,
        values,
        artifact,
        frames,
        shape,
        row,
        effects: out.plan().to_vec(),
        used: Limit::used(out.steps().clone(), out.work().clone()),
        depth: resources.depth.clone(),
        resources,
        result,
    })
}
pub fn make(source_text: &[u8]) -> Result<Path, Cause> {
    let mut compiled = source(source_text)?;
    let artifact = octb::compile(source_text).map_err(|_| Cause::Machine)?;
    let mut values = Values::default();
    let out = eval::run(
        &mut compiled.lowered.types,
        &compiled.lowered.terms,
        &mut values,
        compiled.lowered.program.term,
        None,
    )
    .map_err(|_| Cause::Run)?;
    finish(compiled, values, artifact, out)
}
pub fn make_feed(source_text: &[u8], feed: &Feed) -> Result<Path, Cause> {
    let mut compiled = source(source_text)?;
    let mut values = Values::default();
    let input = Feed::decode(&mut values, feed.encode()).map_err(|_| Cause::Feed)?;
    let pairs = input
        .attach(
            &compiled.lowered.types,
            &mut values,
            &compiled.lowered.program.inputs,
        )
        .map_err(|_| Cause::Feed)?;
    let artifact = octb::compile_feed(source_text, feed).map_err(|_| Cause::Machine)?;
    let out = eval::run_in(
        &mut compiled.lowered.types,
        &compiled.lowered.terms,
        &mut values,
        &pairs,
        compiled.lowered.program.term,
        None,
    )
    .map_err(|_| Cause::Run)?;
    finish(compiled, values, artifact, out)
}
fn import_values(source: &Values, destination: &mut Values, roots: &[ValueId]) -> Vec<ValueId> {
    let mut copied = BTreeMap::new();
    let mut pending = roots
        .iter()
        .rev()
        .map(|root| (*root, false))
        .collect::<Vec<_>>();
    while let Some((id, finish)) = pending.pop() {
        if copied.contains_key(&id) {
            continue;
        }
        let value = source.get(id);
        if !finish {
            pending.push((id, true));
            pending.extend(value.children().into_iter().rev().map(|id| (id, false)));
            continue;
        }
        let value = match value {
            Value::Vec(items) => {
                Value::Vec(items.iter().map(|id| copied[id]).collect::<Vec<_>>().into())
            }
            Value::Pair(left, right) => Value::Pair(copied[left], copied[right]),
            Value::Inl(inner) => Value::Inl(copied[inner]),
            Value::Inr(inner) => Value::Inr(copied[inner]),
            value => value.clone(),
        };
        copied.insert(id, destination.push(value));
    }
    roots.iter().map(|root| copied[root]).collect()
}
/// Raw value copying adds no binary-codec profile restriction to C_path.make_in.
pub fn make_in(
    source_text: &[u8],
    source_values: &Values,
    inputs: &[ValueId],
) -> Result<Path, Cause> {
    let mut compiled = source(source_text)?;
    if compiled.lowered.program.inputs.len() != inputs.len() {
        return Err(Cause::Run);
    }
    let mut values = Values::default();
    let inputs = import_values(source_values, &mut values, inputs);
    let pairs = compiled
        .lowered
        .program
        .inputs
        .iter()
        .copied()
        .zip(inputs)
        .collect::<Vec<_>>();
    let artifact = octb::compile(source_text).map_err(|_| Cause::Machine)?;
    let out = eval::run_in(
        &mut compiled.lowered.types,
        &compiled.lowered.terms,
        &mut values,
        &pairs,
        compiled.lowered.program.term,
        None,
    )
    .map_err(|_| Cause::Run)?;
    finish(compiled, values, artifact, out)
}
#[derive(Clone, Debug)]
pub struct Replayed {
    pub types: Types,
    pub values: Values,
    pub literals: Vec<Literal>,
}
pub fn replay(path: &Path) -> Option<Replayed> {
    let mut types = path.artifact.types.clone();
    let mut values = path.artifact.values.clone();
    let machine = path.artifact.image.machine();
    let mut shapes = machine.shapes().clone();
    let replay = machine.codes().replay_actions_in(
        &mut shapes,
        &mut types,
        &mut values,
        machine.code(),
        &[],
    )?;
    Some(Replayed {
        types,
        values,
        literals: replay.literals,
    })
}
