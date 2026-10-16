// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent C_mach replay. This is an evidence cross-check, not host
//! execution or a replacement for C_eval's resource and integer-work gates.
use super::super::{
    eval::{Action, Value, Values},
    term::Bind,
    types::{Multiplicity, TypeId, Types},
    Atom, Effects,
};
use super::{
    value::{Id, Item, Items},
    Code, CodeId, Codes, Literal, Operation as Op, ShapeId, Shapes,
};
use num_traits::ToPrimitive;
use std::sync::Arc;
mod operations;
#[derive(Clone, Debug)]
pub struct Replay {
    pub literals: Vec<Literal>,
    pub actions: Vec<Action>,
}
#[derive(Clone)]
struct Slot {
    bind: Bind,
    value: Id,
    live: bool,
}
enum Check {
    None,
    Top(ShapeId),
    Branch(ShapeId, Vec<Id>),
}
struct Fold {
    fuel: usize,
    body: CodeId,
    rest: CodeId,
    item: Bind,
    state: Bind,
    values: Arc<[Id]>,
    index: usize,
    remainder: Vec<Id>,
}
enum Frame {
    Resume {
        fuel: usize,
        rest: CodeId,
        close: Vec<Bind>,
        check: Check,
    },
    Effect {
        fuel: usize,
        rest: CodeId,
        atom: Atom,
        previous: Vec<Action>,
    },
    Fold(Fold),
}
struct Engine<'a> {
    codes: &'a Codes,
    shapes: &'a mut Shapes,
    types: &'a mut Types,
    values: &'a mut Values,
    items: Items,
    env: Vec<Slot>,
    stack: Vec<Id>,
    actions: Vec<Action>,
}
impl Engine<'_> {
    fn open(&mut self, bind: Bind, value: Id) -> Option<()> {
        if bind.multiplicity == Multiplicity::Zero
            || self.shapes.from_type(self.types, bind.typ)? != self.items.shape(value)
        {
            return None;
        }
        self.env.push(Slot {
            bind,
            value,
            live: true,
        });
        Some(())
    }
    fn close(&mut self, bind: Bind) -> Option<()> {
        let slot = self.env.pop()?;
        if slot.bind.id != bind.id {
            return None;
        }
        match (bind.multiplicity, slot.bind.multiplicity, slot.live) {
            (Multiplicity::One, Multiplicity::One, false)
            | (Multiplicity::Many, Multiplicity::Many, _) => Some(()),
            _ => None,
        }
    }
    fn take(&mut self, id: super::super::Natural) -> Option<Id> {
        let slot = self.env.iter_mut().rev().find(|slot| slot.bind.id == id)?;
        match (slot.bind.multiplicity, slot.live) {
            (Multiplicity::One, true) => {
                slot.live = false;
                Some(slot.value)
            }
            (Multiplicity::Many, _) => Some(slot.value),
            _ => None,
        }
    }
    fn terminal(&self, inputs: &[(Bind, Literal)]) -> bool {
        inputs.iter().all(|(bind, _)| {
            let slot = self.env.iter().rev().find(|slot| slot.bind.id == bind.id);
            match (bind.multiplicity, slot) {
                (Multiplicity::Zero, None) => true,
                (Multiplicity::One, Some(slot)) => !slot.live,
                (Multiplicity::Many, Some(slot)) => slot.live,
                _ => false,
            }
        })
    }
    fn open_inputs(&mut self, inputs: &[(Bind, Literal)]) -> Option<()> {
        for (bind, literal) in inputs {
            let value = self
                .items
                .atom(self.shapes, self.types, self.values, bind.typ, literal)?;
            if bind.multiplicity != Multiplicity::Zero {
                self.open(*bind, value)?;
            }
        }
        Some(())
    }
    fn push(&mut self, value: Item) {
        self.stack.push(self.items.push(self.shapes, value));
    }
    fn fold_next(&mut self, fold: &Fold, state: Id) -> Option<bool> {
        if let Some(item) = fold.values.get(fold.index) {
            self.open(fold.item, *item)?;
            self.open(fold.state, state)?;
            self.stack.clone_from(&fold.remainder);
            Some(false)
        } else {
            self.stack.clone_from(&fold.remainder);
            self.stack.push(state);
            Some(true)
        }
    }
    fn run(&mut self, mut code: CodeId) -> Option<()> {
        let mut fuel = self.codes.size(code).to_usize()?.checked_add(1)?;
        let mut frames = vec![];
        loop {
            if fuel == 0 {
                return None;
            }
            let left = fuel - 1;
            let node = self.codes.get(code).clone();
            let (op, rest) = match &node {
                Code::Next(op, rest) => (op, *rest),
                Code::Done => {
                    let Some(frame) = frames.pop() else {
                        return Some(());
                    };
                    match frame {
                        Frame::Resume {
                            fuel: prior,
                            rest,
                            close,
                            check,
                        } => {
                            for bind in close {
                                self.close(bind)?;
                            }
                            match check {
                                Check::None => (),
                                Check::Top(form) => {
                                    if self.items.shape(*self.stack.last()?) != form {
                                        return None;
                                    }
                                }
                                Check::Branch(form, remainder) => {
                                    if self.items.shape(*self.stack.last()?) != form
                                        || !self.items.same_shapes(
                                            &self.stack[..self.stack.len() - 1],
                                            &remainder,
                                        )
                                    {
                                        return None;
                                    }
                                }
                            }
                            code = rest;
                            fuel = prior;
                        }
                        Frame::Effect {
                            fuel: prior,
                            rest,
                            atom,
                            mut previous,
                        } => {
                            let payload = self.items.eval(self.values, *self.stack.last()?)?;
                            previous.push(Action::direct(atom, payload));
                            previous.append(&mut self.actions);
                            self.actions = previous;
                            code = rest;
                            fuel = prior;
                        }
                        Frame::Fold(mut fold) => {
                            let state = self.stack.pop()?;
                            if !self.items.same_shapes(&self.stack, &fold.remainder) {
                                return None;
                            }
                            self.close(fold.state)?;
                            self.close(fold.item)?;
                            fold.index += 1;
                            fuel = fold.fuel;
                            if self.fold_next(&fold, state)? {
                                code = fold.rest;
                            } else {
                                code = fold.body;
                                frames.push(Frame::Fold(fold));
                            }
                        }
                    }
                    continue;
                }
            };
            match op {
                Op::Scope(bind, body) => {
                    let value = self.stack.pop()?;
                    self.open(*bind, value)?;
                    frames.push(Frame::Resume {
                        fuel: left,
                        rest,
                        close: vec![*bind],
                        check: Check::None,
                    });
                    code = *body;
                }
                Op::Scope2(lhs, rhs, body) => {
                    let Item::Pair(left_item, right_item) =
                        self.items.get(self.stack.pop()?).clone()
                    else {
                        return None;
                    };
                    self.open(*lhs, left_item)?;
                    self.open(*rhs, right_item)?;
                    frames.push(Frame::Resume {
                        fuel: left,
                        rest,
                        close: vec![*rhs, *lhs],
                        check: Check::None,
                    });
                    code = *body;
                }
                Op::Choice {
                    left: lhs,
                    yes,
                    right: rhs,
                    no,
                    shape,
                } => {
                    if lhs.multiplicity == Multiplicity::Zero
                        || rhs.multiplicity == Multiplicity::Zero
                    {
                        return None;
                    }
                    let Item::Sum(side, payload) = self.items.get(self.stack.pop()?).clone() else {
                        return None;
                    };
                    let bind = if side { *lhs } else { *rhs };
                    self.open(bind, payload)?;
                    frames.push(Frame::Resume {
                        fuel: left,
                        rest,
                        close: vec![bind],
                        check: Check::Branch(*shape, self.stack.clone()),
                    });
                    code = if side { *yes } else { *no };
                }
                Op::Fork { shape, yes, no } => {
                    let Item::Atom(Literal::Bool(side)) = self.items.get(self.stack.pop()?) else {
                        return None;
                    };
                    frames.push(Frame::Resume {
                        fuel: left,
                        rest,
                        close: vec![],
                        check: Check::Top(*shape),
                    });
                    code = if *side { *yes } else { *no };
                }
                Op::Effect { atom, body, .. } => {
                    let previous = std::mem::take(&mut self.actions);
                    frames.push(Frame::Effect {
                        fuel: left,
                        rest,
                        atom: *atom,
                        previous,
                    });
                    code = *body;
                }
                Op::Iter {
                    sequence,
                    count,
                    item,
                    state,
                    body,
                } => {
                    if item.multiplicity == Multiplicity::Zero
                        || state.multiplicity == Multiplicity::Zero
                    {
                        return None;
                    }
                    let seed = self.stack.pop()?;
                    let mut vector = self.stack.pop()?;
                    let mut active = count.get() as usize;
                    if *sequence {
                        let Item::Pair(length, padded) = self.items.get(vector) else {
                            return None;
                        };
                        let Item::Atom(Literal::Int(length)) = self.items.get(*length) else {
                            return None;
                        };
                        active = length.to_usize()?;
                        if active > count.get() as usize {
                            return None;
                        }
                        vector = *padded;
                    }
                    let Item::Vec(elem, list) = self.items.get(vector) else {
                        return None;
                    };
                    if self.items.lists.len(*list) != count.get() as usize
                        || self.shapes.from_type(self.types, item.typ)? != *elem
                        || self.shapes.from_type(self.types, state.typ)? != self.items.shape(seed)
                    {
                        return None;
                    }
                    let mut values = self.items.lists.collect(*list);
                    if values.iter().any(|value| self.items.shape(*value) != *elem) {
                        return None;
                    }
                    values.truncate(active);
                    let fold = Fold {
                        fuel: left,
                        body: *body,
                        rest,
                        item: *item,
                        state: *state,
                        values: values.into(),
                        index: 0,
                        remainder: self.stack.clone(),
                    };
                    if self.fold_next(&fold, seed)? {
                        code = rest;
                    } else {
                        code = *body;
                        frames.push(Frame::Fold(fold));
                    }
                }
                _ => {
                    self.linear(op)?;
                    code = rest;
                }
            }
            fuel = left;
        }
    }
}
impl Codes {
    pub fn effects(&self, root: CodeId) -> Effects {
        let mut effects = Effects::new();
        let mut pending = vec![root];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Code::Next(op, rest) = self.get(id) {
                match op {
                    Op::Close(kind) => {
                        effects.insert(Atom::Close(*kind));
                    }
                    Op::Effect { atom, .. } => {
                        effects.insert(*atom);
                    }
                    _ => (),
                }
                pending.push(*rest);
                pending.extend(op.children());
            }
        }
        effects
    }
    /// All type/value IDs, including Data literals, belong to the supplied arenas.
    pub fn replay_actions_in(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
        inputs: &[(Bind, Literal)],
    ) -> Option<Replay> {
        self.replay_actions_with(shapes, types, values, root, inputs, false)
    }
    fn replay_actions_with(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
        inputs: &[(Bind, Literal)],
        closed: bool,
    ) -> Option<Replay> {
        let mut engine = Engine {
            codes: self,
            shapes,
            types,
            values,
            items: Items::default(),
            env: vec![],
            stack: vec![],
            actions: vec![],
        };
        engine.open_inputs(inputs)?;
        engine.run(root)?;
        if closed && !engine.env.is_empty() || !closed && !engine.terminal(inputs) {
            return None;
        }
        let [value] = engine.stack.as_slice() else {
            return None;
        };
        let Item::Atom(literal) = engine.items.get(*value) else {
            return None;
        };
        Some(Replay {
            literals: vec![literal.clone()],
            actions: engine.actions,
        })
    }
    pub fn replay_actions(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
    ) -> Option<Replay> {
        self.replay_actions_with(shapes, types, values, root, &[], true)
    }
    pub fn replay_plan_in(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
        inputs: &[(Bind, Literal)],
    ) -> Option<(Vec<Literal>, Vec<Atom>)> {
        let replay = self.replay_actions_in(shapes, types, values, root, inputs)?;
        Some((replay.literals, super::super::eval::atoms(&replay.actions)))
    }
    pub fn replay_plan(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
    ) -> Option<(Vec<Literal>, Vec<Atom>)> {
        let replay = self.replay_actions(shapes, types, values, root)?;
        Some((replay.literals, super::super::eval::atoms(&replay.actions)))
    }
    pub fn replay_in(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
        inputs: &[(Bind, Literal)],
    ) -> Option<Vec<Literal>> {
        Some(
            self.replay_actions_in(shapes, types, values, root, inputs)?
                .literals,
        )
    }
    pub fn replay(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
    ) -> Option<Vec<Literal>> {
        Some(self.replay_actions(shapes, types, values, root)?.literals)
    }
    pub fn replay_value_in(
        &self,
        shapes: &mut Shapes,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
        inputs: &[(Bind, Literal)],
        typ: TypeId,
    ) -> Option<Literal> {
        let mut engine = Engine {
            codes: self,
            shapes,
            types,
            values,
            items: Items::default(),
            env: vec![],
            stack: vec![],
            actions: vec![],
        };
        engine.open_inputs(inputs)?;
        engine.run(root)?;
        if !engine.terminal(inputs) {
            return None;
        }
        let [value] = engine.stack.as_slice() else {
            return None;
        };
        let value = engine.items.eval(engine.values, *value)?;
        super::literal(engine.types, engine.values, typ, value)
    }
}
