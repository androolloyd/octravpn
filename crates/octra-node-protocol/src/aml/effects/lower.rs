// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Host instruction blocks come only from checked effect locations.
use super::{Arc, Atom, BTreeSet, BigInt, Entry, Error, Result, Sealed, Site, Type, TypeId, Types};
use crate::octb::{Instruction as I, Value};
use num_traits::Zero;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rollback {
    Preserve,
    Journal,
    Record,
    Abort,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    Exact,
    Storage,
}
#[derive(Clone, Debug)]
pub struct Block {
    index: usize,
    site: Site,
    rollback: Rollback,
    ops: Vec<I>,
    cost: BigInt,
    charge: Charge,
}
impl Block {
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn site(&self) -> Site {
        self.site
    }
    pub fn rollback(&self) -> Rollback {
        self.rollback
    }
    pub fn ops(&self) -> &[I] {
        &self.ops
    }
    pub fn cost(&self) -> &BigInt {
        &self.cost
    }
    pub fn charge(&self) -> Charge {
        self.charge
    }
}
fn width(types: &Types, root: TypeId) -> Option<usize> {
    let mut pending = vec![root];
    let mut count = 0;
    while let Some(typ) = pending.pop() {
        match types.get(typ) {
            Type::Unit => (),
            Type::Bool | Type::Int | Type::Num(..) | Type::Bytes(_) => count += 1,
            Type::Pair(left, right) => {
                pending.push(*right);
                pending.push(*left);
            }
            _ => return None,
        }
    }
    Some(count)
}
fn register(value: i64) -> Result<u8> {
    if (0..64).contains(&value) {
        Ok(value as u8)
    } else {
        Err(Error::Register(value))
    }
}
fn payload(atom: Atom, expected: usize, registers: &[i64]) -> Result<Vec<u8>> {
    if registers.len() != expected {
        return Err(Error::PayloadRegisters(atom, expected, registers.len()));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(registers.len());
    for value in registers {
        let reg = register(*value)?;
        if !seen.insert(reg) {
            return Err(Error::RegisterAlias(atom, *value));
        }
        out.push(reg);
    }
    Ok(out)
}
fn scratch(atom: Atom, expected: usize, payload: &[u8], registers: &[i64]) -> Result<Vec<u8>> {
    if registers.len() != expected {
        return Err(Error::ScratchRegisters(atom, expected, registers.len()));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(registers.len());
    for value in registers {
        let reg = register(*value)?;
        if payload.contains(&reg) || !seen.insert(reg) {
            return Err(Error::RegisterAlias(atom, *value));
        }
        out.push(reg);
    }
    Ok(out)
}
impl Sealed {
    pub fn lower(&self, index: i64, registers: &[i64], scratch_regs: &[i64]) -> Result<Block> {
        let location = usize::try_from(index)
            .ok()
            .and_then(|index| self.locations.get(index))
            .ok_or(Error::SiteIndex(index))?;
        let site = location.site();
        let atom = site.atom();
        if location.count() <= &BigInt::zero() {
            return Err(Error::SiteLimit(atom));
        }
        let count =
            width(&self.types, site.payload()).ok_or(Error::SitePayload(atom, site.payload()))?;
        let payload = payload(atom, count, registers)?;
        let entry = self.registry.find(atom).ok_or(Error::BindingAbsent(atom))?;
        let (rollback, ops, charge) = match entry {
            Entry::State(name, _) => match (atom, payload.as_slice()) {
                (Atom::Read(_), [value]) => {
                    let scratch = scratch(atom, 2, &payload, scratch_regs)?;
                    (
                        Rollback::Preserve,
                        vec![
                            I::Sload(scratch[0], Arc::from(name.as_slice())),
                            I::Eq(scratch[1], scratch[0], *value),
                            I::Assert(scratch[1]),
                        ],
                        Charge::Exact,
                    )
                }
                (Atom::Write(_), [value]) => {
                    scratch(atom, 0, &payload, scratch_regs)?;
                    (
                        Rollback::Journal,
                        vec![I::Sstore(Arc::from(name.as_slice()), *value)],
                        Charge::Storage,
                    )
                }
                _ => return Err(Error::PayloadRegisters(atom, 1, payload.len())),
            },
            Entry::Event(name, _) => {
                scratch(atom, 0, &payload, scratch_regs)?;
                (
                    Rollback::Record,
                    vec![I::Emit(Arc::from(name.as_slice()), payload)],
                    Charge::Exact,
                )
            }
            Entry::Fault(name, code, message) => {
                let scratch = scratch(atom, 2, &payload, scratch_regs)?;
                let mut args = scratch.clone();
                args.extend(payload);
                let ops = vec![
                    I::Ldi(
                        scratch[0],
                        Arc::new(Value::Int(Arc::new(BigInt::from(*code)))),
                    ),
                    I::Ldi(
                        scratch[1],
                        Arc::new(Value::Str(Arc::from(message.as_slice()))),
                    ),
                    I::Emit([b"Error:".as_slice(), name].concat().into(), args),
                    I::Revert(),
                ];
                (Rollback::Abort, ops, Charge::Exact)
            }
        };
        let cost = ops
            .iter()
            .fold(BigInt::zero(), |cost, op| cost + op.effort_cost());
        Ok(Block {
            index: index as usize,
            site,
            rollback,
            ops,
            cost,
            charge,
        })
    }
}
