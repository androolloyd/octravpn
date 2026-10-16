// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach instruction locations and code-map agreement. Only native location
//! parameters participate in agreement; source spans remain diagnostic data.
use super::super::{
    lexer::Span,
    term::{Relation, Term, TermId, Terms},
    types::{Multiplicity, Type, Types},
    Natural,
};
use super::{Code, CodeId, Codes, Operation as Op, TreeId, Trees};
use std::collections::BTreeMap;
mod lower;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocationId(usize);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Push,
    Void,
    Get,
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
    Empty,
    Cons,
    Append,
    Pick(Natural),
    Unhead,
    Left,
    Right,
    Pack,
    Fit,
    Wide,
    Close,
    Effect,
    Scope,
    Scope2,
    Iter,
    Choice,
    Fork,
}
impl Tag {
    fn bodies(self) -> usize {
        match self {
            Self::Effect | Self::Scope | Self::Scope2 | Self::Iter => 1,
            Self::Choice | Self::Fork => 2,
            _ => 0,
        }
    }
    pub(crate) fn of(op: &Op) -> Self {
        match op {
            Op::Push(_) => Self::Push,
            Op::Void => Self::Void,
            Op::Get(..) => Self::Get,
            Op::Plus => Self::Plus,
            Op::Minus => Self::Minus,
            Op::Times => Self::Times,
            Op::Quot => Self::Quot,
            Op::Rem => Self::Rem,
            Op::Negate => Self::Negate,
            Op::Absolute => Self::Absolute,
            Op::Same => Self::Same,
            Op::Different => Self::Different,
            Op::Order(rel) => Self::Order(*rel),
            Op::Join => Self::Join,
            Op::Clip(length) => Self::Clip(*length),
            Op::Skip(length) => Self::Skip(*length),
            Op::Duo => Self::Duo,
            Op::First => Self::First,
            Op::Second => Self::Second,
            Op::Empty(_) => Self::Empty,
            Op::Cons => Self::Cons,
            Op::Append => Self::Append,
            Op::Pick(index) => Self::Pick(*index),
            Op::Unhead => Self::Unhead,
            Op::Left => Self::Left,
            Op::Right => Self::Right,
            Op::Pack(..) => Self::Pack,
            Op::Fit(_) => Self::Fit,
            Op::Wide => Self::Wide,
            Op::Close(_) => Self::Close,
            Op::Effect { .. } => Self::Effect,
            Op::Scope(..) => Self::Scope,
            Op::Scope2(..) => Self::Scope2,
            Op::Iter { .. } => Self::Iter,
            Op::Choice { .. } => Self::Choice,
            Op::Fork { .. } => Self::Fork,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Location {
    Done,
    Next {
        tag: Tag,
        at: Span,
        branches: Option<[Span; 2]>,
        bodies: Vec<LocationId>,
        rest: LocationId,
    },
}
#[derive(Clone, Debug, Default)]
pub struct Locations {
    items: Vec<Location>,
}
impl Locations {
    pub fn get(&self, id: LocationId) -> &Location {
        &self.items[id.0]
    }
    fn done(&mut self) -> LocationId {
        let id = LocationId(self.items.len());
        self.items.push(Location::Done);
        id
    }
    fn next(
        &mut self,
        tag: Tag,
        at: Span,
        branches: Option<[Span; 2]>,
        bodies: Vec<LocationId>,
        rest: LocationId,
    ) -> LocationId {
        assert!(
            rest.0 < self.items.len() && bodies.iter().all(|id| id.0 < self.items.len()),
            "location children precede parent"
        );
        assert_eq!(bodies.len(), tag.bodies(), "location body count");
        assert_eq!(
            branches.is_some(),
            matches!(tag, Tag::Choice | Tag::Fork),
            "location branch spans"
        );
        let id = LocationId(self.items.len());
        self.items.push(Location::Next {
            tag,
            at,
            branches,
            bodies,
            rest,
        });
        id
    }
    fn step(&mut self, tag: Tag, at: Span, rest: LocationId) -> LocationId {
        self.next(tag, at, None, vec![], rest)
    }
    fn continue_with(&mut self, mut code: LocationId, mut rest: LocationId) -> LocationId {
        let mut pending = vec![];
        while let Location::Next {
            tag,
            at,
            branches,
            bodies,
            rest,
        } = self.get(code)
        {
            pending.push((*tag, *at, *branches, bodies.clone()));
            code = *rest;
        }
        while let Some((tag, at, branches, bodies)) = pending.pop() {
            rest = self.next(tag, at, branches, bodies, rest);
        }
        rest
    }
    pub fn locate(&mut self, codes: &Codes, root: CodeId, at: Span) -> LocationId {
        let mut memo = BTreeMap::new();
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            match codes.get(id) {
                Code::Done => {
                    memo.insert(id, self.done());
                }
                Code::Next(op, rest) if !finish => {
                    pending.push((id, true));
                    pending.push((*rest, false));
                    pending.extend(op.children().into_iter().rev().map(|child| (child, false)));
                }
                Code::Next(op, rest) => {
                    let tag = Tag::of(op);
                    let branches = matches!(tag, Tag::Choice | Tag::Fork).then_some([at, at]);
                    let bodies = op
                        .children()
                        .into_iter()
                        .map(|child| memo[&child])
                        .collect();
                    memo.insert(id, self.next(tag, at, branches, bodies, memo[rest]));
                }
            }
        }
        memo.remove(&root).expect("uniform machine location root")
    }
    pub fn same(&self, codes: &Codes, code: CodeId, location: LocationId) -> bool {
        let mut pending = vec![(code, location)];
        while let Some((code, location)) = pending.pop() {
            match (codes.get(code), self.get(location)) {
                (Code::Done, Location::Done) => (),
                (
                    Code::Next(op, rest),
                    Location::Next {
                        tag,
                        bodies,
                        rest: lrest,
                        ..
                    },
                ) if Tag::of(op) == *tag => {
                    let children = op.children();
                    if children.len() != bodies.len() {
                        return false;
                    }
                    pending.push((*rest, *lrest));
                    pending.extend(children.into_iter().zip(bodies.iter().copied()));
                }
                _ => return false,
            }
        }
        true
    }
}
