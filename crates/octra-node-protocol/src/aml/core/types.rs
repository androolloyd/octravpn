// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_type in a flat, interned arena. Child IDs precede parents; type operations
//! preserve native occurrence counts without recursive host-stack ownership.
use super::{text::Text, Natural};
use num_bigint::BigInt;
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_DEPTH: usize = 256;
pub const MAX_NODES: usize = 4096;
pub const MAX_BITS: u32 = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Multiplicity {
    Zero,
    One,
    Many,
}
impl Multiplicity {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Zero => b"0",
            Self::One => b"1",
            Self::Many => b"many",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Data,
    Resource,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sign {
    Signed,
    Unsigned,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeId(usize);
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    Unit,
    Bool,
    Int,
    Num(Sign, Natural),
    Bytes(Natural),
    Vec(Natural, TypeId),
    Seq(Natural, TypeId),
    Cap(Natural),
    Enc(Natural, Natural),
    Pair(TypeId, TypeId),
    Sum(TypeId, TypeId),
}
#[derive(Clone, Debug, Default)]
pub struct Types {
    items: Vec<Type>,
    interned: BTreeMap<Type, TypeId>,
}
impl Types {
    /// IDs are indices in this arena (or its unchanged clone). Reference
    /// checks precede insertion; native semantic validity is checked later.
    pub fn insert(&mut self, typ: Type) -> Result<TypeId, super::arena::Reference> {
        let children = match &typ {
            Type::Vec(_, child) | Type::Seq(_, child) => vec![*child],
            Type::Pair(left, right) | Type::Sum(left, right) => vec![*left, *right],
            _ => Vec::new(),
        };
        for child in children {
            self.require(child)?;
        }
        Ok(self.intern(typ))
    }
    pub fn try_get(&self, id: TypeId) -> Option<&Type> {
        self.items.get(id.0)
    }
    pub(crate) fn require(&self, id: TypeId) -> Result<(), super::arena::Reference> {
        self.try_get(id).map(|_| ()).ok_or(super::arena::Reference {
            kind: super::arena::Kind::Type,
            index: id.0,
            length: self.items.len(),
        })
    }
    pub fn get(&self, id: TypeId) -> &Type {
        &self.items[id.0]
    }
    pub(crate) fn intern(&mut self, typ: Type) -> TypeId {
        if let Some(id) = self.interned.get(&typ) {
            return *id;
        }
        let children: &[TypeId] = match &typ {
            Type::Vec(_, child) | Type::Seq(_, child) => std::slice::from_ref(child),
            _ => &[],
        };
        for child in children {
            assert!(
                child.0 < self.items.len(),
                "core type child precedes parent"
            );
        }
        if let Type::Pair(left, right) | Type::Sum(left, right) = &typ {
            assert!(
                left.0 < self.items.len() && right.0 < self.items.len(),
                "core type children precede parent"
            );
        }
        let id = TypeId(self.items.len());
        self.items.push(typ.clone());
        self.interned.insert(typ, id);
        id
    }
    pub fn nodes(&self, root: TypeId) -> Option<usize> {
        let mut count = 0;
        let mut pending = vec![(0, root)];
        while let Some((depth, id)) = pending.pop() {
            if depth > MAX_DEPTH || count >= MAX_NODES {
                return None;
            }
            count += 1;
            match self.get(id) {
                Type::Num(_, bits) if bits.get() == 0 || bits.get() > MAX_BITS => return None,
                Type::Vec(_, child) | Type::Seq(_, child) => pending.push((depth + 1, *child)),
                Type::Pair(left, right) | Type::Sum(left, right) => {
                    pending.push((depth + 1, *right));
                    pending.push((depth + 1, *left));
                }
                _ => (),
            }
        }
        Some(count)
    }
    fn all(&self, root: TypeId, mode: Mode) -> bool {
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            match self.get(id) {
                Type::Cap(_) => return false,
                Type::Enc(..) if mode != Mode::Kind => return false,
                Type::Vec(length, _) if length.get() == 0 && mode != Mode::Plain => (),
                Type::Vec(_, child) | Type::Seq(_, child) => pending.push(*child),
                Type::Pair(left, right) | Type::Sum(left, right) => {
                    pending.push(*right);
                    pending.push(*left);
                }
                _ => (),
            }
        }
        true
    }
    pub fn plain(&self, root: TypeId) -> bool {
        self.all(root, Mode::Plain)
    }
    pub fn kind(&self, root: TypeId) -> Kind {
        if self.all(root, Mode::Kind) {
            Kind::Data
        } else {
            Kind::Resource
        }
    }
    pub fn equatable(&self, root: TypeId) -> bool {
        self.all(root, Mode::Equatable)
    }
    pub fn valid(&self, root: TypeId) -> bool {
        if self.nodes(root).is_none() {
            return false;
        }
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            match self.get(id) {
                Type::Seq(_, child) if !self.plain(*child) => return false,
                Type::Vec(_, child) | Type::Seq(_, child) => pending.push(*child),
                Type::Pair(left, right) | Type::Sum(left, right) => {
                    pending.push(*right);
                    pending.push(*left);
                }
                _ => (),
            }
        }
        true
    }
    pub fn repr(&mut self, root: TypeId) -> TypeId {
        match self.get(root).clone() {
            Type::Num(..) => self.intern(Type::Int),
            Type::Seq(capacity, element) => {
                let integer = self.intern(Type::Int);
                let vector = self.intern(Type::Vec(capacity, element));
                self.intern(Type::Pair(integer, vector))
            }
            _ => root,
        }
    }
    pub fn admits(&self, root: TypeId, value: &BigInt) -> bool {
        match self.get(root) {
            Type::Int => true,
            Type::Num(sign, bits) => {
                range(*sign, *bits).is_some_and(|(low, high)| &low <= value && value <= &high)
            }
            _ => false,
        }
    }
    pub fn equality_work(&self, root: TypeId) -> BigInt {
        let mut memo: BTreeMap<TypeId, BigInt> = BTreeMap::new();
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            if !finish {
                pending.push((id, true));
                match self.get(id) {
                    Type::Vec(_, child) | Type::Seq(_, child) => pending.push((*child, false)),
                    Type::Pair(left, right) | Type::Sum(left, right) => {
                        pending.push((*right, false));
                        pending.push((*left, false));
                    }
                    _ => (),
                }
                continue;
            }
            let work = match self.get(id) {
                Type::Bytes(length) => BigInt::from(length.get()) + 1,
                Type::Vec(length, element) | Type::Seq(length, element) => {
                    &memo[element] * length.get() + 1
                }
                Type::Pair(left, right) => &memo[left] + &memo[right] + 1,
                Type::Sum(left, right) => memo[left].clone().max(memo[right].clone()) + 1,
                _ => BigInt::from(1),
            };
            memo.insert(id, work);
        }
        memo.remove(&root).expect("equality work root")
    }
    pub fn text(&self, root: TypeId) -> Vec<u8> {
        enum Part {
            Type(TypeId),
            Text(Vec<u8>),
        }
        let mut out = Text::default();
        let mut pending = vec![Part::Type(root)];
        while let Some(part) = pending.pop() {
            if out.full() {
                break;
            }
            let typ = match part {
                Part::Text(text) => {
                    out.add(&text);
                    continue;
                }
                Part::Type(id) => self.get(id),
            };
            match typ {
                Type::Unit => out.add(b"unit"),
                Type::Bool => out.add(b"bool"),
                Type::Int => out.add(b"int"),
                Type::Num(sign, bits) => out.add(
                    format!(
                        "{}[{}]",
                        if *sign == Sign::Signed {
                            "sint"
                        } else {
                            "uint"
                        },
                        bits.get()
                    )
                    .as_bytes(),
                ),
                Type::Bytes(length) => out.add(format!("bytes[{}]", length.get()).as_bytes()),
                Type::Cap(kind) => out.add(format!("cap[{}]", kind.get()).as_bytes()),
                Type::Enc(key, remaining) => {
                    out.add(format!("enc[{},{}]", key.get(), remaining.get()).as_bytes());
                }
                Type::Vec(length, element) | Type::Seq(length, element) => {
                    pending.push(Part::Text(b"]".to_vec()));
                    pending.push(Part::Type(*element));
                    pending.push(Part::Text(b", ".to_vec()));
                    pending.push(Part::Text(length.get().to_string().into_bytes()));
                    pending.push(Part::Text(if matches!(typ, Type::Vec(..)) {
                        b"vec[".to_vec()
                    } else {
                        b"seq[".to_vec()
                    }));
                }
                Type::Pair(left, right) | Type::Sum(left, right) => {
                    pending.push(Part::Text(b")".to_vec()));
                    pending.push(Part::Type(*right));
                    pending.push(Part::Text(if matches!(typ, Type::Pair(..)) {
                        b" * ".to_vec()
                    } else {
                        b" + ".to_vec()
                    }));
                    pending.push(Part::Type(*left));
                    pending.push(Part::Text(b"(".to_vec()));
                }
            }
        }
        out.finish()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plain,
    Kind,
    Equatable,
}
pub fn range(sign: Sign, bits: Natural) -> Option<(BigInt, BigInt)> {
    let width = bits.get();
    if !(1..=MAX_BITS).contains(&width) {
        return None;
    }
    Some(match sign {
        Sign::Unsigned => (BigInt::from(0), (BigInt::from(1u8) << width as usize) - 1),
        Sign::Signed => {
            let half = BigInt::from(1u8) << (width - 1) as usize;
            (-&half, half - 1)
        }
    })
}
