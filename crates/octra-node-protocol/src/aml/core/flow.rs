// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Flat C_check effect-flow representation. Location order includes both fork
//! branches and retains zero-count loop sites, as required by evidence layout.
use super::{types::TypeId, Atom, Natural};
use num_bigint::BigInt;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    Direct,
    Held(Natural),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    pub(crate) atom: Atom,
    pub(crate) payload: TypeId,
    pub(crate) origin: Origin,
}
impl Site {
    pub fn atom(self) -> Atom {
        self.atom
    }
    pub fn payload(self) -> TypeId {
        self.payload
    }
    pub fn origin(self) -> Origin {
        self.origin
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Flow {
    Pure,
    Action(Site),
    Seq(FlowId, FlowId),
    Fork(FlowId, FlowId),
    Loop(Natural, FlowId),
}
#[derive(Clone, Debug)]
pub struct Flows {
    items: Vec<Flow>,
}
impl Default for Flows {
    fn default() -> Self {
        Self {
            items: vec![Flow::Pure],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    index: usize,
    site: Site,
    count: BigInt,
}
impl Location {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn site(&self) -> Site {
        self.site
    }
    pub fn count(&self) -> &BigInt {
        &self.count
    }
}
impl Flows {
    pub fn pure(&self) -> FlowId {
        FlowId(0)
    }
    pub fn get(&self, id: FlowId) -> &Flow {
        &self.items[id.0]
    }
    fn push(&mut self, flow: Flow) -> FlowId {
        let id = FlowId(self.items.len());
        self.items.push(flow);
        id
    }
    pub(crate) fn action(&mut self, site: Site) -> FlowId {
        self.push(Flow::Action(site))
    }
    pub(crate) fn sequence(&mut self, left: FlowId, right: FlowId) -> FlowId {
        match (self.get(left), self.get(right)) {
            (Flow::Pure, _) => right,
            (_, Flow::Pure) => left,
            _ => self.push(Flow::Seq(left, right)),
        }
    }
    pub(crate) fn fork(&mut self, left: FlowId, right: FlowId) -> FlowId {
        match (self.get(left), self.get(right)) {
            (Flow::Pure, Flow::Pure) => self.pure(),
            _ => self.push(Flow::Fork(left, right)),
        }
    }
    pub(crate) fn repeat(&mut self, count: Natural, body: FlowId) -> FlowId {
        if self.get(body) == &Flow::Pure {
            self.pure()
        } else {
            self.push(Flow::Loop(count, body))
        }
    }
    pub fn locations(&self, root: FlowId) -> Vec<Location> {
        let mut pending = vec![(BigInt::from(1), root)];
        let mut out = vec![];
        while let Some((count, id)) = pending.pop() {
            match self.get(id) {
                Flow::Pure => (),
                Flow::Action(site) => out.push(Location {
                    index: out.len(),
                    site: *site,
                    count,
                }),
                Flow::Seq(left, right) | Flow::Fork(left, right) => {
                    pending.push((count.clone(), *right));
                    pending.push((count, *left));
                }
                Flow::Loop(length, body) => pending.push((count * length.get(), *body)),
            }
        }
        out
    }
}
