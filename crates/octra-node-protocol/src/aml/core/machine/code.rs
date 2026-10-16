// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat C_mach continuation graph. Control bodies and continuations retain
//! their distinct edges; no recursive ownership is exposed to source input.
use super::super::{
    rule::{Field, LOCAL},
    term::{Bind, Relation},
    types::TypeId,
    Atom, Natural,
};
use super::{Literal, ShapeId};
use num_bigint::BigInt;
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeId(usize);
#[derive(Clone, Debug)]
pub enum Code {
    Done,
    Next(Operation, CodeId),
}
#[derive(Clone, Debug)]
pub enum Operation {
    Push(Literal),
    Void,
    Get(Natural, ShapeId),
    Plus,
    Minus,
    Times,
    Quot,
    Rem,
    Negate,
    Absolute,
    Same,
    Different,
    Order(Relation),
    Join,
    Clip(Natural),
    Skip(Natural),
    Duo,
    First,
    Second,
    Empty(ShapeId),
    Cons,
    Append,
    Pick(Natural),
    Unhead,
    Left,
    Right,
    Pack(Natural, TypeId),
    Fit(TypeId),
    Wide,
    Close(Natural),
    Effect {
        index: i64,
        atom: Atom,
        body: CodeId,
    },
    Scope(Bind, CodeId),
    Scope2(Bind, Bind, CodeId),
    Iter {
        sequence: bool,
        count: Natural,
        item: Bind,
        state: Bind,
        body: CodeId,
    },
    Choice {
        left: Bind,
        yes: CodeId,
        right: Bind,
        no: CodeId,
        shape: ShapeId,
    },
    Fork {
        shape: ShapeId,
        yes: CodeId,
        no: CodeId,
    },
}
impl Operation {
    pub(crate) fn children(&self) -> Vec<CodeId> {
        match self {
            Self::Effect { body, .. }
            | Self::Scope(_, body)
            | Self::Scope2(_, _, body)
            | Self::Iter { body, .. } => vec![*body],
            Self::Choice { yes, no, .. } | Self::Fork { yes, no, .. } => vec![*yes, *no],
            _ => vec![],
        }
    }
    pub(crate) fn map_children(&mut self, mut map: impl FnMut(CodeId) -> CodeId) {
        match self {
            Self::Effect { body, .. }
            | Self::Scope(_, body)
            | Self::Scope2(_, _, body)
            | Self::Iter { body, .. } => *body = map(*body),
            Self::Choice { yes, no, .. } | Self::Fork { yes, no, .. } => {
                *yes = map(*yes);
                *no = map(*no);
            }
            _ => (),
        }
    }
}
#[derive(Clone, Debug, Default)]
pub struct Codes {
    items: Vec<Code>,
}
impl Codes {
    pub fn try_get(&self, id: CodeId) -> Option<&Code> {
        self.items.get(id.0)
    }
    fn require(&self, id: CodeId) -> Result<(), super::super::arena::Reference> {
        self.try_get(id)
            .map(|_| ())
            .ok_or(super::super::arena::Reference {
                kind: super::super::arena::Kind::MachineCode,
                index: id.0,
                length: self.items.len(),
            })
    }
    pub fn insert(
        &mut self,
        shapes: &super::Shapes,
        types: &super::super::types::Types,
        values: &super::super::eval::Values,
        code: Code,
    ) -> Result<CodeId, super::super::arena::Reference> {
        if let Code::Next(op, rest) = &code {
            self.require(*rest)?;
            for child in op.children() {
                self.require(child)?;
            }
            match op {
                Operation::Get(_, shape)
                | Operation::Empty(shape)
                | Operation::Choice { shape, .. }
                | Operation::Fork { shape, .. } => shapes.require(*shape)?,
                _ => (),
            }
            let refs = match op {
                Operation::Pack(_, typ) | Operation::Fit(typ) => vec![*typ],
                Operation::Scope(bind, _) => vec![bind.typ],
                Operation::Scope2(left, right, _)
                | Operation::Iter {
                    item: left,
                    state: right,
                    ..
                }
                | Operation::Choice { left, right, .. } => vec![left.typ, right.typ],
                Operation::Push(Literal::Data(record)) => {
                    values.require(record.value())?;
                    vec![record.typ()]
                }
                _ => Vec::new(),
            };
            for typ in refs {
                types.require(typ)?;
            }
        }
        Ok(self.push(code))
    }
    pub fn get(&self, id: CodeId) -> &Code {
        &self.items[id.0]
    }
    pub(crate) fn push(&mut self, code: Code) -> CodeId {
        if let Code::Next(op, rest) = &code {
            assert!(
                rest.0 < self.items.len(),
                "machine continuation precedes parent"
            );
            for child in op.children() {
                assert!(child.0 < self.items.len(), "machine body precedes parent");
            }
        }
        let id = CodeId(self.items.len());
        self.items.push(code);
        id
    }
    pub(crate) fn next(&mut self, op: Operation, rest: CodeId) -> CodeId {
        self.push(Code::Next(op, rest))
    }
    pub(crate) fn done(&mut self) -> CodeId {
        self.push(Code::Done)
    }
    /// Replace only the terminal continuation, leaving nested bodies intact.
    pub(crate) fn continue_with(&mut self, mut code: CodeId, mut rest: CodeId) -> CodeId {
        let mut path = vec![];
        while let Code::Next(op, next) = self.get(code) {
            path.push(op.clone());
            code = *next;
        }
        while let Some(op) = path.pop() {
            rest = self.next(op, rest);
        }
        rest
    }
    /// Saturation includes loop expansion, but does not unroll machine bodies.
    pub fn size(&self, root: CodeId) -> BigInt {
        let stop = BigInt::from(LOCAL.get(Field::Fuel) + 1);
        let mut memo = BTreeMap::<CodeId, BigInt>::new();
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            match self.get(id) {
                Code::Done => {
                    memo.insert(id, BigInt::from(1));
                }
                Code::Next(op, rest) if !finish => {
                    pending.push((id, true));
                    pending.push((*rest, false));
                    pending.extend(op.children().into_iter().rev().map(|child| (child, false)));
                }
                Code::Next(op, rest) => {
                    let mut size: BigInt = &memo[rest] + 1;
                    match op {
                        Operation::Iter { count, body, .. } => {
                            size += BigInt::from(count.get()) * &memo[body];
                        }
                        _ => {
                            for child in op.children() {
                                size += &memo[&child];
                            }
                        }
                    }
                    memo.insert(id, size.min(stop.clone()));
                }
            }
        }
        memo.remove(&root).expect("machine code size root")
    }
    /// Index effects in preorder, independently for every syntactic occurrence.
    pub(crate) fn index_effects(&mut self, root: CodeId) -> CodeId {
        enum Task {
            Visit(CodeId),
            Finish(Operation, usize),
        }
        let mut pending = vec![Task::Visit(root)];
        let mut out = vec![];
        let mut index = 0;
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(id) => match self.get(id).clone() {
                    Code::Done => {
                        let done = self.done();
                        out.push(done);
                    }
                    Code::Next(mut op, rest) => {
                        if let Operation::Effect { index: at, .. } = &mut op {
                            *at = index;
                            index += 1;
                        }
                        let children = op.children();
                        let count = children.len();
                        pending.push(Task::Finish(op, count));
                        pending.push(Task::Visit(rest));
                        pending.extend(children.into_iter().rev().map(Task::Visit));
                    }
                },
                Task::Finish(mut op, count) => {
                    let rest = out.pop().expect("indexed machine continuation");
                    let mut children = out.split_off(out.len() - count).into_iter();
                    op.map_children(|_| children.next().expect("indexed machine body"));
                    out.push(self.next(op, rest));
                }
            }
        }
        out.pop().expect("indexed machine root")
    }
}
