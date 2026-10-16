// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_bin type/effect/resource projections retain raw-get versus canonical typed
//! decoding distinctions. Resource encoding does not clamp derived bounds.
use super::super::{
    limit::Limit,
    types::{Sign as NumberSign, Type, TypeId, Types, MAX_DEPTH},
    Atom, Natural,
};
use super::{decode, encode, Bits, Code, CodeId, Codes, Zero};
use num_traits::{Signed, ToPrimitive};
use std::collections::BTreeMap;
enum Put {
    Type(TypeId),
    Finish(TypeId),
}
enum Get {
    Type(CodeId, usize),
    Finish(u8, Option<Natural>),
}
impl Codes {
    pub fn natural_get(&self, id: CodeId) -> Option<Natural> {
        match self.get(id) {
            Code::Num(value) => Natural::new(value),
            _ => None,
        }
    }
    pub fn atom_code(&mut self, atom: Atom) -> CodeId {
        let (tag, kind) = match atom {
            Atom::Read(kind) => (0, kind),
            Atom::Write(kind) => (1, kind),
            Atom::Emit(kind) => (2, kind),
            Atom::Fail(kind) => (3, kind),
            Atom::Close(kind) => (4, kind),
        };
        let kind = self.num(kind.get());
        self.tag(tag, kind)
    }
    pub fn atom_get(&self, id: CodeId) -> Option<Atom> {
        let Code::Tag(tag, body) = self.get(id) else {
            return None;
        };
        let kind = self.natural_get(*body)?;
        Some(match tag.to_u8()? {
            0 => Atom::Read(kind),
            1 => Atom::Write(kind),
            2 => Atom::Emit(kind),
            3 => Atom::Fail(kind),
            4 => Atom::Close(kind),
            _ => return None,
        })
    }
    pub fn row_code(&mut self, atoms: &[Atom]) -> CodeId {
        let values: Vec<_> = atoms.iter().map(|atom| self.atom_code(*atom)).collect();
        self.list(&values)
    }
    pub fn row_get(&self, root: CodeId) -> Option<Vec<Atom>> {
        self.list_get(root)?
            .into_iter()
            .map(|code| self.atom_get(code))
            .collect()
    }
    pub fn resources_code(&mut self, resources: &Limit) -> Option<CodeId> {
        if resources.steps.is_negative()
            || resources.depth.is_negative()
            || resources.work.is_negative()
        {
            return None;
        }
        let fields = [
            self.num(resources.steps.clone()),
            self.num(resources.depth.clone()),
            self.num(resources.work.clone()),
        ];
        let body = self.list(&fields);
        Some(self.tag(0, body))
    }
    pub fn resources_get(&self, root: CodeId) -> Option<Limit> {
        let Code::Tag(tag, body) = self.get(root) else {
            return None;
        };
        if !tag.is_zero() {
            return None;
        }
        let fields = self.list_get(*body)?;
        let [steps, depth, work] = fields.as_slice() else {
            return None;
        };
        let (Code::Num(steps), Code::Num(depth), Code::Num(work)) =
            (self.get(*steps), self.get(*depth), self.get(*work))
        else {
            return None;
        };
        Some(Limit {
            steps: steps.as_ref().clone(),
            depth: depth.as_ref().clone(),
            work: work.as_ref().clone(),
        })
    }
    /// Raw ty_code does not add the wrapper's whole-type validity check.
    pub fn type_code(&mut self, types: &Types, root: TypeId) -> CodeId {
        let mut pending = vec![Put::Type(root)];
        let mut memo = BTreeMap::new();
        while let Some(task) = pending.pop() {
            let id = match task {
                Put::Type(id) => {
                    if memo.contains_key(&id) {
                        continue;
                    }
                    pending.push(Put::Finish(id));
                    match types.get(id) {
                        Type::Vec(_, child) | Type::Seq(_, child) => {
                            pending.push(Put::Type(*child));
                        }
                        Type::Pair(left, right) | Type::Sum(left, right) => {
                            pending.push(Put::Type(*right));
                            pending.push(Put::Type(*left));
                        }
                        _ => (),
                    }
                    continue;
                }
                Put::Finish(id) => id,
            };
            let (tag, body) = match types.get(id) {
                Type::Unit => (0, self.nil()),
                Type::Bool => (1, self.nil()),
                Type::Int => (2, self.nil()),
                Type::Bytes(length) => (3, self.num(length.get())),
                Type::Cap(kind) => (5, self.num(kind.get())),
                Type::Vec(length, elem) | Type::Seq(length, elem) => {
                    let length = self.num(length.get());
                    let body = self.list(&[length, memo[elem]]);
                    (
                        if matches!(types.get(id), Type::Vec(..)) {
                            4
                        } else {
                            10
                        },
                        body,
                    )
                }
                Type::Pair(left, right) | Type::Sum(left, right) => (
                    if matches!(types.get(id), Type::Pair(..)) {
                        6
                    } else {
                        7
                    },
                    self.list(&[memo[left], memo[right]]),
                ),
                Type::Enc(key, remaining) => {
                    let fields = [self.num(key.get()), self.num(remaining.get())];
                    (8, self.list(&fields))
                }
                Type::Num(sign, bits) => {
                    let sign = self.num(i32::from(*sign != NumberSign::Signed));
                    let bits = self.num(bits.get());
                    (9, self.list(&[sign, bits]))
                }
            };
            memo.insert(id, self.tag(tag, body));
        }
        memo.remove(&root).expect("type code root")
    }
    /// Raw ty_get validates Num/Seq locally, with fuel 257; its callers may
    /// require the separate whole-type validity and canonical re-encoding.
    pub fn type_get(&self, types: &mut Types, root: CodeId) -> Option<TypeId> {
        let mut pending = vec![Get::Type(root, MAX_DEPTH + 1)];
        let mut values = vec![];
        while let Some(task) = pending.pop() {
            let typ = match task {
                Get::Type(id, fuel) => {
                    if fuel == 0 {
                        return None;
                    }
                    let fuel = fuel - 1;
                    let Code::Tag(tag, body) = self.get(id) else {
                        return None;
                    };
                    let tag = tag.to_u8()?;
                    match tag {
                        0..=2 if self.get(*body) == &Code::Nil => match tag {
                            0 => Type::Unit,
                            1 => Type::Bool,
                            _ => Type::Int,
                        },
                        3 => Type::Bytes(self.natural_get(*body)?),
                        5 => Type::Cap(self.natural_get(*body)?),
                        4 | 10 => {
                            let fields = self.list_get(*body)?;
                            let [length, elem] = fields.as_slice() else {
                                return None;
                            };
                            let length = self.natural_get(*length)?;
                            pending.push(Get::Finish(tag, Some(length)));
                            pending.push(Get::Type(*elem, fuel));
                            continue;
                        }
                        6 | 7 => {
                            let fields = self.list_get(*body)?;
                            let [left, right] = fields.as_slice() else {
                                return None;
                            };
                            pending.push(Get::Finish(tag, None));
                            pending.push(Get::Type(*right, fuel));
                            pending.push(Get::Type(*left, fuel));
                            continue;
                        }
                        8 => {
                            let fields = self.list_get(*body)?;
                            let [key, remaining] = fields.as_slice() else {
                                return None;
                            };
                            Type::Enc(self.natural_get(*key)?, self.natural_get(*remaining)?)
                        }
                        9 => {
                            let fields = self.list_get(*body)?;
                            let [sign, bits] = fields.as_slice() else {
                                return None;
                            };
                            let Code::Num(sign) = self.get(*sign) else {
                                return None;
                            };
                            let sign = match sign.to_u8()? {
                                0 => NumberSign::Signed,
                                1 => NumberSign::Unsigned,
                                _ => return None,
                            };
                            let typ = types.intern(Type::Num(sign, self.natural_get(*bits)?));
                            if !types.valid(typ) {
                                return None;
                            }
                            values.push(typ);
                            continue;
                        }
                        _ => return None,
                    }
                }
                Get::Finish(tag, length) => match tag {
                    4 | 10 => {
                        let elem = values.pop()?;
                        let length = length?;
                        if tag == 4 {
                            Type::Vec(length, elem)
                        } else {
                            let typ = types.intern(Type::Seq(length, elem));
                            if !types.valid(typ) {
                                return None;
                            }
                            values.push(typ);
                            continue;
                        }
                    }
                    6 | 7 => {
                        let right = values.pop()?;
                        let left = values.pop()?;
                        if tag == 6 {
                            Type::Pair(left, right)
                        } else {
                            Type::Sum(left, right)
                        }
                    }
                    _ => unreachable!("composite type tag"),
                },
            };
            values.push(types.intern(typ));
        }
        values.pop()
    }
}
pub fn encode_type(types: &Types, root: TypeId) -> Option<Bits> {
    if !types.valid(root) {
        return None;
    }
    let mut codes = Codes::default();
    let root = codes.type_code(types, root);
    encode(&codes, root)
}
pub fn decode_type(types: &mut Types, bits: &[bool]) -> Option<TypeId> {
    let decoded = decode(bits)?;
    let typ = decoded.codes.type_get(types, decoded.root)?;
    (encode_type(types, typ)?.as_slice() == bits).then_some(typ)
}
pub fn encode_row(atoms: &[Atom]) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = codes.row_code(atoms);
    encode(&codes, root)
}
pub fn decode_row(bits: &[bool]) -> Option<Vec<Atom>> {
    let decoded = decode(bits)?;
    let atoms = decoded.codes.row_get(decoded.root)?;
    (encode_row(&atoms)?.as_slice() == bits).then_some(atoms)
}
pub fn encode_resources(resources: &Limit) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = codes.resources_code(resources)?;
    encode(&codes, root)
}
pub fn decode_resources(bits: &[bool]) -> Option<Limit> {
    let decoded = decode(bits)?;
    let resources = decoded.codes.resources_get(decoded.root)?;
    (encode_resources(&resources)?.as_slice() == bits).then_some(resources)
}
