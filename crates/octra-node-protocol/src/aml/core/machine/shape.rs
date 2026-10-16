// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach shape width and cells remain distinct arbitrary-precision quantities.
use super::super::{
    types::{Type, TypeId, Types},
    Natural,
};
use num_bigint::BigInt;
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShapeId(usize);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Shape {
    Unit,
    Atom,
    Cap(Natural),
    Pair(ShapeId, ShapeId),
    Vec(Natural, ShapeId),
    Sum(ShapeId),
}
#[derive(Clone, Debug, Default)]
pub struct Shapes {
    items: Vec<Shape>,
    interned: BTreeMap<Shape, ShapeId>,
}
impl Shapes {
    pub fn try_get(&self, id: ShapeId) -> Option<&Shape> {
        self.items.get(id.0)
    }
    pub(super) fn require(&self, id: ShapeId) -> Result<(), super::super::arena::Reference> {
        self.try_get(id)
            .map(|_| ())
            .ok_or(super::super::arena::Reference {
                kind: super::super::arena::Kind::MachineShape,
                index: id.0,
                length: self.items.len(),
            })
    }
    pub fn insert(&mut self, shape: Shape) -> Result<ShapeId, super::super::arena::Reference> {
        let children = match &shape {
            Shape::Pair(left, right) => vec![*left, *right],
            Shape::Vec(_, child) | Shape::Sum(child) => vec![*child],
            _ => Vec::new(),
        };
        for child in children {
            self.require(child)?;
        }
        Ok(self.intern(shape))
    }
    pub fn get(&self, id: ShapeId) -> &Shape {
        &self.items[id.0]
    }
    pub(crate) fn intern(&mut self, shape: Shape) -> ShapeId {
        if let Some(id) = self.interned.get(&shape) {
            return *id;
        }
        match &shape {
            Shape::Pair(left, right) => assert!(
                left.0 < self.items.len() && right.0 < self.items.len(),
                "shape children precede parent"
            ),
            Shape::Vec(_, child) | Shape::Sum(child) => {
                assert!(child.0 < self.items.len(), "shape child precedes parent");
            }
            _ => (),
        }
        let id = ShapeId(self.items.len());
        self.items.push(shape.clone());
        self.interned.insert(shape, id);
        id
    }
    pub fn from_type(&mut self, types: &Types, root: TypeId) -> Option<ShapeId> {
        let mut pending = vec![(root, false)];
        let mut memo: BTreeMap<TypeId, Option<ShapeId>> = BTreeMap::new();
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            if !finish {
                pending.push((id, true));
                match types.get(id) {
                    Type::Vec(_, child) | Type::Seq(_, child) => pending.push((*child, false)),
                    Type::Pair(left, right) | Type::Sum(left, right) => {
                        pending.push((*right, false));
                        pending.push((*left, false));
                    }
                    _ => (),
                }
                continue;
            }
            let shape = match types.get(id) {
                Type::Unit => Some(self.intern(Shape::Unit)),
                Type::Bool | Type::Int | Type::Num(..) | Type::Bytes(_) => {
                    Some(self.intern(Shape::Atom))
                }
                Type::Cap(kind) => Some(self.intern(Shape::Cap(*kind))),
                Type::Vec(length, elem) => {
                    memo[elem].map(|elem| self.intern(Shape::Vec(*length, elem)))
                }
                Type::Seq(capacity, elem) => memo[elem].map(|elem| {
                    let atom = self.intern(Shape::Atom);
                    let vector = self.intern(Shape::Vec(*capacity, elem));
                    self.intern(Shape::Pair(atom, vector))
                }),
                Type::Pair(left, right) => match (memo[left], memo[right]) {
                    (Some(left), Some(right)) => Some(self.intern(Shape::Pair(left, right))),
                    _ => None,
                },
                Type::Sum(left, right) => match (memo[left], memo[right]) {
                    (Some(left), Some(right)) if left == right => {
                        Some(self.intern(Shape::Sum(left)))
                    }
                    _ => None,
                },
                Type::Enc(..) => None,
            };
            memo.insert(id, shape);
        }
        memo.remove(&root).expect("shape root")
    }
    fn measure(&self, root: ShapeId, cells: bool) -> BigInt {
        let mut pending = vec![(root, false)];
        let mut memo: BTreeMap<ShapeId, BigInt> = BTreeMap::new();
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            if !finish {
                pending.push((id, true));
                match self.get(id) {
                    Shape::Pair(left, right) => {
                        pending.push((*right, false));
                        pending.push((*left, false));
                    }
                    Shape::Vec(_, child) | Shape::Sum(child) => pending.push((*child, false)),
                    _ => (),
                }
                continue;
            }
            let value = match self.get(id) {
                Shape::Unit => BigInt::from(u8::from(cells)),
                Shape::Atom | Shape::Cap(_) => BigInt::from(1),
                Shape::Pair(left, right) => &memo[left] + &memo[right] + u8::from(cells),
                Shape::Vec(length, elem) => {
                    BigInt::from(length.get()) * &memo[elem] + u8::from(cells)
                }
                Shape::Sum(payload) => &memo[payload] + 1,
            };
            memo.insert(id, value);
        }
        memo.remove(&root).expect("shape measure root")
    }
    pub fn width(&self, root: ShapeId) -> BigInt {
        self.measure(root, false)
    }
    pub fn cells(&self, root: ShapeId) -> BigInt {
        self.measure(root, true)
    }
    pub fn same(&self, left: ShapeId, right: ShapeId) -> bool {
        left == right
    }
}
