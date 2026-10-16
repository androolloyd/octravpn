// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_bin generic code tree and canonical bit/byte transport. Decoding a generic
//! code tree confers no type, term, effect or deployment authority.
use super::rule::{Field, LOCAL};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::Zero;
use std::sync::Arc;
mod snapshot;
mod typed;
mod value;
mod wire;
pub use snapshot::{decode_snapshot, encode_snapshot, Reject, Snapshot};
pub use typed::{
    decode_resources, decode_row, decode_type, encode_resources, encode_row, encode_type,
};
pub use value::{decode_value, encode_value, value_valid};
pub use wire::{decode, encode, pack, transcript, unpack};
pub type Bits = Vec<bool>;
pub const MAX_BITS: usize = LOCAL.get(Field::Str) as usize;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeId(usize);
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Code {
    Num(Arc<BigInt>),
    Int(Arc<BigInt>),
    Nil,
    Cons(CodeId, CodeId),
    Tag(Arc<BigInt>, CodeId),
}
#[derive(Clone, Debug)]
pub struct Codes {
    items: Vec<Code>,
}
impl Default for Codes {
    fn default() -> Self {
        Self {
            items: vec![Code::Nil],
        }
    }
}
#[derive(Clone, Debug)]
pub struct Decoded {
    pub codes: Codes,
    pub root: CodeId,
}
impl Codes {
    pub fn try_get(&self, id: CodeId) -> Option<&Code> {
        self.items.get(id.0)
    }
    pub fn insert(&mut self, code: Code) -> Result<CodeId, super::arena::Reference> {
        let children = match &code {
            Code::Cons(left, right) => vec![*left, *right],
            Code::Tag(_, body) => vec![*body],
            _ => Vec::new(),
        };
        for child in children {
            if self.try_get(child).is_none() {
                return Err(super::arena::Reference {
                    kind: super::arena::Kind::BinaryCode,
                    index: child.0,
                    length: self.items.len(),
                });
            }
        }
        Ok(self.push(code))
    }
    pub fn nil(&self) -> CodeId {
        CodeId(0)
    }
    pub fn get(&self, id: CodeId) -> &Code {
        &self.items[id.0]
    }
    /// Child IDs belong to this arena or its unchanged clone.
    pub fn push(&mut self, code: Code) -> CodeId {
        match &code {
            Code::Cons(left, right) => assert!(
                left.0 < self.items.len() && right.0 < self.items.len(),
                "code children precede parent"
            ),
            Code::Tag(_, body) => assert!(body.0 < self.items.len(), "code child precedes parent"),
            Code::Nil => return self.nil(),
            _ => (),
        }
        let id = CodeId(self.items.len());
        self.items.push(code);
        id
    }
    pub fn num(&mut self, value: impl Into<BigInt>) -> CodeId {
        self.push(Code::Num(Arc::new(value.into())))
    }
    pub fn integer(&mut self, value: impl Into<BigInt>) -> CodeId {
        self.push(Code::Int(Arc::new(value.into())))
    }
    pub fn tag(&mut self, tag: impl Into<BigInt>, body: CodeId) -> CodeId {
        self.push(Code::Tag(Arc::new(tag.into()), body))
    }
    pub fn cons(&mut self, first: CodeId, rest: CodeId) -> CodeId {
        self.push(Code::Cons(first, rest))
    }
    pub fn list(&mut self, values: &[CodeId]) -> CodeId {
        let mut rest = self.nil();
        for value in values.iter().rev() {
            rest = self.cons(*value, rest);
        }
        rest
    }
    pub fn list_get(&self, mut input: CodeId) -> Option<Vec<CodeId>> {
        let mut out = vec![];
        loop {
            match self.get(input) {
                Code::Nil => return Some(out),
                Code::Cons(first, rest) => {
                    out.push(*first);
                    input = *rest;
                }
                _ => return None,
            }
        }
    }
    /// Match a fixed-arity Cons spine without allocating or walking extra fields.
    pub fn fields<const N: usize>(&self, mut input: CodeId) -> Option<[CodeId; N]> {
        let mut fields = [self.nil(); N];
        for field in &mut fields {
            let Code::Cons(first, rest) = self.get(input) else {
                return None;
            };
            *field = *first;
            input = *rest;
        }
        matches!(self.get(input), Code::Nil).then_some(fields)
    }
    /// Import a structural code graph from another request-local arena.
    pub fn import(&mut self, source: &Self, root: CodeId) -> CodeId {
        let mut memo = std::collections::BTreeMap::new();
        let mut pending = vec![(root, false)];
        while let Some((id, finish)) = pending.pop() {
            if memo.contains_key(&id) {
                continue;
            }
            if !finish {
                pending.push((id, true));
                match source.get(id) {
                    Code::Cons(first, rest) => {
                        pending.push((*rest, false));
                        pending.push((*first, false));
                    }
                    Code::Tag(_, body) => pending.push((*body, false)),
                    _ => (),
                }
                continue;
            }
            let code = match source.get(id) {
                Code::Num(value) => Code::Num(value.clone()),
                Code::Int(value) => Code::Int(value.clone()),
                Code::Nil => Code::Nil,
                Code::Cons(first, rest) => Code::Cons(memo[first], memo[rest]),
                Code::Tag(tag, body) => Code::Tag(tag.clone(), memo[body]),
            };
            memo.insert(id, self.push(code));
        }
        memo[&root]
    }
}
