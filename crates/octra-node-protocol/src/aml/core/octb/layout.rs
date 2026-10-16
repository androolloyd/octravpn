// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_octb register layouts. Free-list order, sum tags and container
//! shape identities remain distinct from simple register-width arithmetic.
use super::super::list::Lists;
use super::super::{
    machine::{Shape, ShapeId, Shapes},
    Atom,
};
use super::{Error, VectorId};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutId(usize);
#[derive(Clone, Debug)]
pub enum Layout {
    Unit,
    Atom(u8),
    Pair(LayoutId, LayoutId),
    Vec(ShapeId, VectorId),
    Sum(u8, LayoutId),
}
#[derive(Clone, Debug, Default)]
pub struct Layouts {
    items: Vec<Layout>,
    pub(super) vectors: Lists<LayoutId>,
}
#[derive(Clone, Debug)]
pub struct Generator {
    pub(super) next: u32,
    pub(super) free: Vec<u8>,
    pub(super) label: u32,
}
impl Generator {
    pub fn new(first: u32) -> Result<Self, Error> {
        if first > 64 {
            return Err(Error::Register);
        }
        Ok(Self {
            next: first,
            free: vec![],
            label: 0,
        })
    }
    pub fn next(&self) -> u32 {
        self.next
    }
    pub fn fresh(&mut self) -> Result<u8, Error> {
        if let Some(reg) = self.free.pop() {
            return Ok(reg);
        }
        if self.next >= 64 {
            return Err(Error::Register);
        }
        let reg = self.next as u8;
        self.next += 1;
        Ok(reg)
    }
    pub fn release(&mut self, reg: u8) {
        if reg != 0 {
            self.free.push(reg);
        }
    }
    pub fn fresh_label(&mut self) -> Result<u32, Error> {
        let label = self.label;
        self.label = self.label.checked_add(1).ok_or(Error::Label)?;
        Ok(label)
    }
    pub fn scratch(&self, atom: Atom) -> Result<Vec<u8>, Error> {
        // C_octb.scratch returns the registers without retaining its state.
        let mut temporary = self.clone();
        let count = if matches!(atom, Atom::Read(_) | Atom::Fail(_)) {
            2
        } else {
            0
        };
        (0..count).map(|_| temporary.fresh()).collect()
    }
    /// Native avail returns a descending list whose head is allocated first.
    pub fn available(&mut self, next: u32, live: &[u8]) -> Result<(), Error> {
        if next > 64 {
            return Err(Error::Register);
        }
        self.next = next;
        self.free = (1..next as u8).filter(|reg| !live.contains(reg)).collect();
        Ok(())
    }
}
impl Layouts {
    pub fn get(&self, id: LayoutId) -> &Layout {
        &self.items[id.0]
    }
    pub fn vector_len(&self, id: VectorId) -> usize {
        self.vectors.len(id)
    }
    pub fn vector_values(&self, id: VectorId) -> Vec<LayoutId> {
        self.vectors.collect(id)
    }
    pub(super) fn push(&mut self, value: Layout) -> LayoutId {
        let children = match &value {
            Layout::Pair(left, right) => vec![*left, *right],
            // Vector lists are composed from existing layout IDs. Rewalking a
            // shared tail here would make repeated Cons quadratic.
            Layout::Vec(_, children) => {
                self.vectors.len(*children);
                vec![]
            }
            Layout::Sum(_, child) => vec![*child],
            _ => vec![],
        };
        assert!(
            children.iter().all(|id| id.0 < self.items.len()),
            "register layout children precede parent"
        );
        let id = LayoutId(self.items.len());
        self.items.push(value);
        id
    }
    pub fn registers(&self, root: LayoutId) -> Vec<u8> {
        let mut pending = vec![root];
        let mut out = vec![];
        while let Some(id) = pending.pop() {
            match self.get(id) {
                Layout::Unit => (),
                Layout::Atom(reg) => out.push(*reg),
                Layout::Pair(left, right) => {
                    pending.push(*right);
                    pending.push(*left);
                }
                Layout::Vec(_, children) => {
                    pending.extend(self.vectors.collect(*children).into_iter().rev());
                }
                Layout::Sum(tag, payload) => {
                    out.push(*tag);
                    pending.push(*payload);
                }
            }
        }
        out
    }
    pub fn release(&self, root: LayoutId, state: &mut Generator) {
        for reg in self.registers(root).into_iter().rev() {
            state.release(reg);
        }
    }
    pub fn release_all(&self, values: &[LayoutId], state: &mut Generator) {
        for value in values.iter().rev() {
            self.release(*value, state);
        }
    }
    pub fn pick(
        &self,
        index: usize,
        values: &[LayoutId],
        state: &mut Generator,
    ) -> Option<LayoutId> {
        let target = *values.get(index)?;
        for prior in &values[..index] {
            self.release(*prior, state);
        }
        self.release_all(&values[index + 1..], state);
        Some(target)
    }
    pub fn same(&self, left: LayoutId, right: LayoutId) -> bool {
        self.copy(left, right)
            .is_some_and(|moves| moves.iter().all(|(target, source)| target == source))
    }
    pub fn fits(&self, shapes: &Shapes, form: ShapeId, value: LayoutId) -> bool {
        let mut pending = vec![(form, value)];
        while let Some((shape, value)) = pending.pop() {
            match (shapes.get(shape), self.get(value)) {
                (Shape::Unit, Layout::Unit) | (Shape::Atom | Shape::Cap(_), Layout::Atom(_)) => (),
                (Shape::Pair(lf, rf), Layout::Pair(left, right)) => {
                    pending.push((*rf, *right));
                    pending.push((*lf, *left));
                }
                (Shape::Vec(length, elem), Layout::Vec(found, values))
                    if elem == found && length.get() as usize == self.vectors.len(*values) =>
                {
                    pending.extend(self.vectors.iter(*values).map(|value| (*elem, value)));
                }
                (Shape::Sum(payload), Layout::Sum(_, value)) => pending.push((*payload, *value)),
                _ => return false,
            }
        }
        true
    }
    pub fn alloc(
        &mut self,
        shapes: &Shapes,
        root: ShapeId,
        state: &mut Generator,
    ) -> Result<LayoutId, Error> {
        enum Task {
            Shape(ShapeId),
            Pair,
            Vector(ShapeId, usize),
            Sum(u8),
        }
        let prior = state.clone();
        let result: Result<LayoutId, Error> = (|| {
            let mut pending = vec![Task::Shape(root)];
            let mut out = vec![];
            while let Some(task) = pending.pop() {
                let value = match task {
                    Task::Shape(id) => match shapes.get(id) {
                        Shape::Unit => Layout::Unit,
                        Shape::Atom | Shape::Cap(_) => Layout::Atom(state.fresh()?),
                        Shape::Pair(left, right) => {
                            pending.push(Task::Pair);
                            pending.push(Task::Shape(*right));
                            pending.push(Task::Shape(*left));
                            continue;
                        }
                        Shape::Vec(length, elem) => {
                            pending.push(Task::Vector(*elem, length.get() as usize));
                            pending.extend((0..length.get()).map(|_| Task::Shape(*elem)));
                            continue;
                        }
                        Shape::Sum(payload) => {
                            pending.push(Task::Sum(state.fresh()?));
                            pending.push(Task::Shape(*payload));
                            continue;
                        }
                    },
                    Task::Pair => {
                        let right = out.pop().expect("register pair right");
                        let left = out.pop().expect("register pair left");
                        Layout::Pair(left, right)
                    }
                    Task::Vector(elem, count) => {
                        let children = out.split_off(out.len() - count);
                        Layout::Vec(elem, self.vectors.array(children))
                    }
                    Task::Sum(tag) => Layout::Sum(tag, out.pop().expect("register sum payload")),
                };
                out.push(self.push(value));
            }
            Ok(out.pop().expect("allocated register layout root"))
        })();
        if result.is_err() {
            *state = prior;
        }
        result
    }
    /// Move rows are (destination, source) in native emission order.
    pub fn copy(&self, source: LayoutId, target: LayoutId) -> Option<Vec<(u8, u8)>> {
        let mut pending = vec![(source, target)];
        let mut moves = vec![];
        while let Some((source, target)) = pending.pop() {
            match (self.get(source), self.get(target)) {
                (Layout::Unit, Layout::Unit) => (),
                (Layout::Atom(source), Layout::Atom(target)) => moves.push((*target, *source)),
                (Layout::Pair(sl, sr), Layout::Pair(tl, tr)) => {
                    pending.push((*sr, *tr));
                    pending.push((*sl, *tl));
                }
                (Layout::Vec(se, source), Layout::Vec(te, target))
                    if se == te && self.vectors.len(*source) == self.vectors.len(*target) =>
                {
                    let source = self.vectors.collect(*source);
                    let target = self.vectors.collect(*target);
                    pending.extend(source.into_iter().zip(target).rev());
                }
                (Layout::Sum(st, source), Layout::Sum(tt, target)) => {
                    moves.push((*tt, *st));
                    pending.push((*source, *target));
                }
                _ => return None,
            }
        }
        Some(moves)
    }
    pub fn clone_layout(
        &mut self,
        root: LayoutId,
        state: &mut Generator,
    ) -> Result<(LayoutId, Vec<(u8, u8)>), Error> {
        enum Task {
            Visit(LayoutId),
            Pair,
            Vector(ShapeId, usize),
            Sum(u8),
        }
        let prior = state.clone();
        let result: Result<(LayoutId, Vec<(u8, u8)>), Error> = (|| {
            let mut pending = vec![Task::Visit(root)];
            let mut out = vec![];
            let mut moves = vec![];
            while let Some(task) = pending.pop() {
                let value = match task {
                    Task::Visit(id) => match self.get(id).clone() {
                        Layout::Unit => Layout::Unit,
                        Layout::Atom(source) => {
                            let target = state.fresh()?;
                            moves.push((target, source));
                            Layout::Atom(target)
                        }
                        Layout::Pair(left, right) => {
                            pending.push(Task::Pair);
                            pending.push(Task::Visit(right));
                            pending.push(Task::Visit(left));
                            continue;
                        }
                        Layout::Vec(elem, values) => {
                            let values = self.vectors.collect(values);
                            pending.push(Task::Vector(elem, values.len()));
                            pending.extend(values.into_iter().rev().map(Task::Visit));
                            continue;
                        }
                        Layout::Sum(source, payload) => {
                            let tag = state.fresh()?;
                            moves.push((tag, source));
                            pending.push(Task::Sum(tag));
                            pending.push(Task::Visit(payload));
                            continue;
                        }
                    },
                    Task::Pair => {
                        let right = out.pop().expect("cloned register pair right");
                        let left = out.pop().expect("cloned register pair left");
                        Layout::Pair(left, right)
                    }
                    Task::Vector(elem, count) => {
                        let values = out.split_off(out.len() - count);
                        Layout::Vec(elem, self.vectors.array(values))
                    }
                    Task::Sum(tag) => {
                        Layout::Sum(tag, out.pop().expect("cloned register sum payload"))
                    }
                };
                out.push(self.push(value));
            }
            Ok((out.pop().expect("cloned register layout root"), moves))
        })();
        if result.is_err() {
            *state = prior;
        }
        result
    }
}
