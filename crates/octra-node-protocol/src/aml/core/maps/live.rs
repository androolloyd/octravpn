// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::types::Multiplicity;
use super::{
    bin, natural, tagged, Code, CodeId, Codes, Field, Natural, ToPrimitive, LOCAL, MAX_ROWS,
};
use std::{collections::BTreeSet, sync::Arc};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub id: Natural,
    pub multiplicity: Multiplicity,
    pub live: bool,
}
#[derive(Clone, Debug)]
pub struct LiveMap {
    rows: Arc<[Arc<[Slot]>]>,
    bits: Arc<[bool]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    Size(usize),
    Row(usize, usize),
    Mul(usize, Natural),
    Dup(usize, Natural),
    Bits,
}
fn mode(slot: Slot) -> u8 {
    let mul = match slot.multiplicity {
        Multiplicity::Zero => 0,
        Multiplicity::One => 2,
        Multiplicity::Many => 4,
    };
    mul + u8::from(slot.live)
}
fn slot_code(codes: &mut Codes, slot: Slot) -> CodeId {
    let id = codes.num(slot.id.get());
    let mode = codes.num(mode(slot));
    let fields = codes.list(&[id, mode]);
    codes.tag(0, fields)
}
fn slot_get(codes: &Codes, id: CodeId) -> Option<Slot> {
    let fields = codes.list_get(tagged(codes, id, 0)?)?;
    let [id, mode] = fields.as_slice() else {
        return None;
    };
    let id = natural(codes, *id)?;
    let Code::Num(mode) = codes.get(*mode) else {
        return None;
    };
    let mode = mode.to_u8()?;
    let multiplicity = match mode {
        0 | 1 => Multiplicity::Zero,
        2 | 3 => Multiplicity::One,
        4 | 5 => Multiplicity::Many,
        _ => return None,
    };
    Some(Slot {
        id,
        multiplicity,
        live: mode % 2 == 1,
    })
}
impl LiveMap {
    pub fn make(rows: &[Arc<[Slot]>]) -> Result<Self, Error> {
        if rows.is_empty() {
            return Err(Error::Empty);
        }
        if rows.len() > MAX_ROWS {
            return Err(Error::Size(rows.len()));
        }
        let row_max = LOCAL.get(Field::TermNodes) as usize;
        for (at, row) in rows.iter().enumerate() {
            if row.len() > row_max {
                return Err(Error::Row(at, row.len()));
            }
            let mut seen = BTreeSet::new();
            for slot in row.iter() {
                // Natural's private constructor already enforces C_nat.valid.
                if slot.multiplicity == Multiplicity::Zero
                    || slot.multiplicity == Multiplicity::Many && !slot.live
                {
                    return Err(Error::Mul(at, slot.id));
                }
                if !seen.insert(slot.id) {
                    return Err(Error::Dup(at, slot.id));
                }
            }
        }
        let mut codes = Codes::default();
        let mut bodies = vec![];
        for row in rows {
            let slots = row
                .iter()
                .map(|slot| slot_code(&mut codes, *slot))
                .collect::<Vec<_>>();
            let body = codes.list(&slots);
            bodies.push(codes.tag(1, body));
        }
        let body = codes.list(&bodies);
        let root = codes.tag(2, body);
        let bits = bin::encode(&codes, root).ok_or(Error::Bits)?;
        Ok(Self {
            rows: rows.into(),
            bits: bits.into(),
        })
    }
    pub fn decode(bits: &[bool]) -> Option<Self> {
        let decoded = bin::decode(bits)?;
        let bodies = decoded
            .codes
            .list_get(tagged(&decoded.codes, decoded.root, 2)?)?;
        let rows = bodies
            .into_iter()
            .map(|row| {
                let slots = decoded.codes.list_get(tagged(&decoded.codes, row, 1)?)?;
                Some(Arc::<[Slot]>::from(
                    slots
                        .into_iter()
                        .map(|slot| slot_get(&decoded.codes, slot))
                        .collect::<Option<Vec<_>>>()?,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let map = Self::make(&rows).ok()?;
        (map.encode() == bits).then_some(map)
    }
    pub fn rows(&self) -> &[Arc<[Slot]>] {
        &self.rows
    }
    pub fn encode(&self) -> &[bool] {
        &self.bits
    }
    pub fn equal(&self, right: &Self) -> bool {
        self.bits == right.bits
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("liveness map is empty"),
            Self::Size(size) => write!(f, "liveness map size = {size} maximum = {MAX_ROWS}"),
            Self::Row(at, size) => write!(
                f,
                "liveness row size = {size} maximum = {} pc = {at}",
                LOCAL.get(Field::TermNodes)
            ),
            Self::Mul(at, id) => write!(
                f,
                "liveness map multiplicity is invalid pc = {at} id = {}",
                id.get()
            ),
            Self::Dup(at, id) => {
                write!(f, "liveness map id is repeated pc = {at} id = {}", id.get())
            }
            Self::Bits => f.write_str("liveness map bit image exceeds the local limit"),
        }
    }
}
impl std::error::Error for Error {}
