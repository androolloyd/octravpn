// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb aggregate input and result guards. Input and output sequence checks
//! retain their different native default-validation order.
use super::super::{
    eval::Values,
    machine::{self, Literal},
    types::{self, Type, TypeId, Types},
};
use super::{Error, Operation};
use crate::octb::{Instruction as I, Value as V};
use num_bigint::BigInt;
use std::{collections::BTreeMap, sync::Arc};
const LIMIT: u32 = 1_000_000;
enum Task {
    Type(TypeId),
    Vector(TypeId, usize),
    SumRight {
        left: TypeId,
        start: usize,
        yes: u32,
        done: u32,
    },
    SumLeft {
        end: usize,
        done: u32,
    },
    Sequence {
        elem: TypeId,
        count: usize,
        index: usize,
        length: u8,
    },
    InputItem {
        elem: TypeId,
        count: usize,
        index: usize,
        length: u8,
        start: usize,
    },
    OutputItem {
        elem: TypeId,
        count: usize,
        index: usize,
        length: u8,
        end: usize,
        regs: Vec<u8>,
        lits: Vec<Literal>,
    },
}
struct Builder<'a> {
    types: &'a Types,
    values: &'a mut Values,
    regs: Option<&'a [u8]>,
    cursor: usize,
    label: u32,
    base: u32,
    code: Vec<I>,
    zeros: BTreeMap<TypeId, Option<Vec<Literal>>>,
}
pub(super) fn integer(reg: u8, value: impl Into<BigInt>) -> I {
    I::Ldi(reg, Arc::new(V::Int(Arc::new(value.into()))))
}
pub(super) fn bytes(reg: u8, value: &[u8]) -> I {
    I::Ldi(reg, Arc::new(V::Bytes(value.into())))
}
pub(super) fn text(reg: u8, value: &[u8]) -> I {
    I::Ldi(reg, Arc::new(V::Str(value.into())))
}
pub(super) fn bool_check(reg: u8, yes: u32, done: u32) -> Vec<I> {
    vec![
        I::Jif(reg, yes),
        I::Nop(),
        I::Jmp(done),
        I::Jdest(yes),
        I::Jmp(done),
        I::Jdest(done),
    ]
}
pub(super) fn bytes_check(reg: u8, length: u32, next: u32) -> Vec<I> {
    vec![
        bytes(61, b""),
        I::Eq(63, reg, 61),
        I::Strlen(61, reg),
        integer(62, length),
        I::Eq(63, 61, 62),
        I::Jif(63, next),
        I::Revert(),
        I::Jdest(next),
        integer(61, 0),
        I::Substr(reg, reg, 61, 62),
    ]
}
impl Builder<'_> {
    fn take(&mut self) -> Result<u8, Error> {
        let reg = match self.regs {
            Some(regs) => *regs.get(self.cursor).ok_or(Error::OutputCode)?,
            None => u8::try_from(self.cursor + 1).map_err(|_| Error::OutputCode)?,
        };
        self.cursor += 1;
        Ok(reg)
    }
    fn labels(&mut self, count: u32) -> Result<u32, Error> {
        let first = self.base.checked_add(self.label).ok_or(Error::OutputCode)?;
        self.label = self.label.checked_add(count).ok_or(Error::OutputCode)?;
        Ok(first)
    }
    fn range(&mut self, reg: u8, low: BigInt, high: BigInt) -> Result<(), Error> {
        let bad = self.labels(2)?;
        let done = bad + 1;
        self.code.extend([
            integer(61, low),
            I::Lt(63, reg, 61),
            I::Jif(63, bad),
            integer(62, high),
            I::Gt(63, reg, 62),
            I::Jif(63, bad),
            I::Jmp(done),
            I::Jdest(bad),
            I::Revert(),
            I::Jdest(done),
        ]);
        Ok(())
    }
    fn zero(&mut self, typ: TypeId) -> Result<Vec<Literal>, Error> {
        if let Some(value) = self.zeros.get(&typ) {
            return value.clone().ok_or(Error::OutputCode);
        }
        let value = self
            .values
            .zero(self.types, typ)
            .and_then(|zero| machine::atoms(self.types, self.values, typ, zero));
        self.zeros.insert(typ, value.clone());
        value.ok_or(Error::OutputCode)
    }
    fn zero_code(
        &mut self,
        length: u8,
        index: usize,
        regs: &[u8],
        lits: &[Literal],
    ) -> Result<(), Error> {
        if regs.len() != lits.len() {
            return Err(Error::OutputCode);
        }
        let active = self.labels(2)?;
        let done = active + 1;
        self.code.extend([
            integer(61, index),
            I::Lt(63, 61, length),
            I::Jif(63, active),
        ]);
        for (reg, lit) in regs.iter().zip(lits) {
            let yes = self.labels(1)?;
            let load = Operation::Load(61, lit.clone())
                .vm()
                .ok_or(Error::OutputCode)?;
            self.code.extend([
                load,
                I::Eq(63, *reg, 61),
                I::Jif(63, yes),
                I::Revert(),
                I::Jdest(yes),
            ]);
        }
        self.code.extend([I::Jmp(done), I::Jdest(active)]);
        self.code.extend((0..9 * lits.len()).map(|_| I::Nop()));
        self.code.push(I::Jdest(done));
        Ok(())
    }
    fn run(&mut self, roots: &[TypeId]) -> Result<(), Error> {
        let mut pending = roots
            .iter()
            .copied()
            .rev()
            .map(Task::Type)
            .collect::<Vec<_>>();
        while let Some(task) = pending.pop() {
            let typ = match task {
                Task::Type(typ) => typ,
                Task::Vector(typ, remaining) => {
                    if remaining > 0 {
                        pending.push(Task::Vector(typ, remaining - 1));
                        pending.push(Task::Type(typ));
                    }
                    continue;
                }
                Task::SumRight {
                    left,
                    start,
                    yes,
                    done,
                } => {
                    pending.push(Task::SumLeft {
                        end: self.cursor,
                        done,
                    });
                    self.cursor = start;
                    self.code.extend([I::Jmp(done), I::Jdest(yes)]);
                    pending.push(Task::Type(left));
                    continue;
                }
                Task::SumLeft { end, done } => {
                    if self.cursor != end {
                        return Err(Error::OutputCode);
                    }
                    self.code.push(I::Jdest(done));
                    continue;
                }
                Task::Sequence {
                    elem,
                    count,
                    index,
                    length,
                } => {
                    if index == count {
                        continue;
                    }
                    if let Some(regs) = self.regs {
                        let lits = self.zero(elem)?;
                        let end = self
                            .cursor
                            .checked_add(lits.len())
                            .ok_or(Error::OutputCode)?;
                        let regs = regs
                            .get(self.cursor..end)
                            .ok_or(Error::OutputCode)?
                            .to_vec();
                        pending.push(Task::OutputItem {
                            elem,
                            count,
                            index,
                            length,
                            end,
                            regs,
                            lits,
                        });
                    } else {
                        pending.push(Task::InputItem {
                            elem,
                            count,
                            index,
                            length,
                            start: self.cursor,
                        });
                    }
                    pending.push(Task::Type(elem));
                    continue;
                }
                Task::InputItem {
                    elem,
                    count,
                    index,
                    length,
                    start,
                } => {
                    let lits = self.zero(elem)?;
                    if self.cursor - start != lits.len() {
                        return Err(Error::OutputCode);
                    }
                    let regs = (start + 1..=self.cursor)
                        .map(|reg| u8::try_from(reg).map_err(|_| Error::OutputCode))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.zero_code(length, index, &regs, &lits)?;
                    pending.push(Task::Sequence {
                        elem,
                        count,
                        index: index + 1,
                        length,
                    });
                    continue;
                }
                Task::OutputItem {
                    elem,
                    count,
                    index,
                    length,
                    end,
                    regs,
                    lits,
                } => {
                    if self.cursor != end {
                        return Err(Error::OutputCode);
                    }
                    self.zero_code(length, index, &regs, &lits)?;
                    pending.push(Task::Sequence {
                        elem,
                        count,
                        index: index + 1,
                        length,
                    });
                    continue;
                }
            };
            let node = self.types.get(typ).clone();
            match &node {
                Type::Unit => (),
                Type::Int => {
                    let reg = self.take()?;
                    self.code.extend([integer(61, 0), I::Sub(reg, reg, 61)]);
                }
                Type::Num(sign, bits) => {
                    let reg = self.take()?;
                    let (low, high) = types::range(*sign, *bits).ok_or(Error::OutputCode)?;
                    self.range(reg, low, high)?;
                }
                Type::Bool => {
                    let reg = self.take()?;
                    let yes = self.labels(2)?;
                    self.code.extend(bool_check(reg, yes, yes + 1));
                }
                Type::Bytes(length) => {
                    let reg = self.take()?;
                    let next = self.labels(1)?;
                    self.code.extend(bytes_check(reg, length.get(), next));
                }
                Type::Cap(kind) if self.regs.is_none() => {
                    let reg = self.take()?;
                    self.code
                        .push(I::CapCheck(Arc::new(kind.get().into()), reg));
                }
                Type::Vec(length, elem) => pending.push(Task::Vector(*elem, length.get() as usize)),
                Type::Seq(capacity, elem) => {
                    let length = self.take()?;
                    self.range(length, BigInt::from(0), BigInt::from(capacity.get()))?;
                    pending.push(Task::Sequence {
                        elem: *elem,
                        count: capacity.get() as usize,
                        index: 0,
                        length,
                    });
                }
                Type::Pair(left, right) => {
                    pending.push(Task::Type(*right));
                    pending.push(Task::Type(*left));
                }
                Type::Sum(left, right) => {
                    let reg = self.take()?;
                    let yes = self.labels(2)?;
                    self.code.push(I::Jif(reg, yes));
                    pending.push(Task::SumRight {
                        left: *left,
                        start: self.cursor,
                        yes,
                        done: yes + 1,
                    });
                    pending.push(Task::Type(*right));
                }
                Type::Cap(_) | Type::Enc(..) => return Err(Error::OutputCode),
            }
        }
        if self.label > LIMIT {
            return Err(Error::OutputCode);
        }
        Ok(())
    }
}
pub fn data_input_code(
    types: &Types,
    values: &mut Values,
    inputs: &[TypeId],
) -> Result<(Vec<I>, usize), Error> {
    let mut builder = Builder {
        types,
        values,
        regs: None,
        cursor: 0,
        label: 0,
        base: LIMIT,
        code: vec![],
        zeros: BTreeMap::new(),
    };
    builder.run(inputs)?;
    Ok((builder.code, builder.cursor))
}
pub fn guard_code(
    types: &Types,
    values: &mut Values,
    typ: TypeId,
    regs: &[u8],
) -> Result<Vec<I>, Error> {
    let mut builder = Builder {
        types,
        values,
        regs: Some(regs),
        cursor: 0,
        label: 0,
        base: 2 * LIMIT,
        code: vec![],
        zeros: BTreeMap::new(),
    };
    builder.run(&[typ])?;
    if builder.cursor != regs.len() {
        return Err(Error::OutputCode);
    }
    Ok(builder.code)
}
