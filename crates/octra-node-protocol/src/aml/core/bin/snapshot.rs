// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_bin snapshot records describe a core evaluation result, not chain finality.
use super::super::{
    eval::{ValueId, Values},
    limit::Limit,
    types::{TypeId, Types},
    Atom,
};
use super::{decode, encode, value_valid, Bits, Code, CodeId, Codes};
use num_traits::ToPrimitive;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    DivideZero,
    ModuloZero,
}
#[derive(Clone, Debug, PartialEq, Eq)]
// Native bounded task/snapshot records remain inline without extra allocations.
#[allow(clippy::large_enum_variant)]
pub enum Snapshot {
    Refuse,
    Reject(Reject),
    Accept {
        typ: TypeId,
        row: Vec<Atom>,
        limit: Limit,
        value: ValueId,
        plan: Vec<Atom>,
        used: Limit,
    },
}
impl Codes {
    pub fn snapshot_code(
        &mut self,
        types: &Types,
        values: &Values,
        snapshot: &Snapshot,
    ) -> Option<CodeId> {
        Some(match snapshot {
            Snapshot::Refuse => self.tag(0, self.nil()),
            Snapshot::Reject(reason) => {
                let reason = self.num(match reason {
                    Reject::DivideZero => 0,
                    Reject::ModuloZero => 1,
                });
                self.tag(2, reason)
            }
            Snapshot::Accept {
                typ,
                row,
                limit,
                value,
                plan,
                used,
            } => {
                if !types.valid(*typ) || !value_valid(values, *value) {
                    return None;
                }
                let fields = [
                    self.type_code(types, *typ),
                    self.row_code(row),
                    self.resources_code(limit)?,
                    self.value_code(values, *value),
                    self.row_code(plan),
                    self.resources_code(used)?,
                ];
                let body = self.list(&fields);
                self.tag(1, body)
            }
        })
    }
    pub fn snapshot_get(
        &self,
        types: &mut Types,
        values: &mut Values,
        root: CodeId,
    ) -> Option<Snapshot> {
        let Code::Tag(tag, body) = self.get(root) else {
            return None;
        };
        Some(match tag.to_u8()? {
            0 if self.get(*body) == &Code::Nil => Snapshot::Refuse,
            2 => {
                let Code::Num(value) = self.get(*body) else {
                    return None;
                };
                Snapshot::Reject(match value.to_u8()? {
                    0 => Reject::DivideZero,
                    1 => Reject::ModuloZero,
                    _ => return None,
                })
            }
            1 => {
                let fields = self.list_get(*body)?;
                let [typ, row, limit, value, plan, used] = fields.as_slice() else {
                    return None;
                };
                Snapshot::Accept {
                    typ: self.type_get(types, *typ)?,
                    row: self.row_get(*row)?,
                    limit: self.resources_get(*limit)?,
                    value: self.value_get(values, *value)?,
                    plan: self.row_get(*plan)?,
                    used: self.resources_get(*used)?,
                }
            }
            _ => return None,
        })
    }
}
pub fn encode_snapshot(types: &Types, values: &Values, snapshot: &Snapshot) -> Option<Bits> {
    let mut codes = Codes::default();
    let root = codes.snapshot_code(types, values, snapshot)?;
    encode(&codes, root)
}
pub fn decode_snapshot(types: &mut Types, values: &mut Values, bits: &[bool]) -> Option<Snapshot> {
    let decoded = decode(bits)?;
    let snapshot = decoded.codes.snapshot_get(types, values, decoded.root)?;
    (encode_snapshot(types, values, &snapshot)?.as_slice() == bits).then_some(snapshot)
}
