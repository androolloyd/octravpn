// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb effect layout expansion and exact host-block attachment. Blocks are
//! emitted by Aml_effect's declaration checks; attachment itself is not trust.
use super::super::{
    check::{self, Checked},
    eval::Values,
    lexer::{Position, Span},
    machine::{CodeId, Codes, LocationId, Locations, Shapes},
    rule::{Field, LOCAL},
    term::{Program, Terms},
    types::Types,
};
use super::{
    lower::{lower_effect, Machine},
    Asm, EffectLayout, Error, Marked,
};
use crate::octb::{self as wire, Instruction as I};
use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use std::collections::{BTreeMap, VecDeque};
#[derive(Clone, Debug)]
pub struct HostBlock {
    pub layout: EffectLayout,
    pub code: Vec<I>,
}
struct CheckedPlan {
    checked: Checked,
    codes: Codes,
    root: CodeId,
    shapes: Shapes,
    locations: Locations,
    location: LocationId,
    span: Span,
}
impl CheckedPlan {
    fn make(types: &mut Types, terms: &Terms, program: &Program) -> Result<Self, Error> {
        let checked = check::check_in(types, terms, &program.inputs, program.term)
            .map_err(|_| Error::EffectMap)?;
        if checked.info().resources().steps > BigInt::from(LOCAL.get(Field::Fuel)) {
            return Err(Error::EffectMap);
        }
        let mut count = BigInt::zero();
        for location in checked.locations() {
            count += location.count();
            if count > BigInt::from(LOCAL.get(Field::TermNodes)) {
                return Err(Error::EffectMap);
            }
        }
        let mut codes = Codes::default();
        let mut shapes = Shapes::default();
        let root = codes
            .lower(&mut shapes, types, terms, &program.inputs, program.term)
            .ok_or(Error::EffectMap)?;
        let point = Position {
            offset: 0,
            line: 1,
            column: 1,
        };
        let span = Span {
            first: point,
            last: point,
        };
        let mut locations = Locations::default();
        let location = locations.locate(&codes, root, span);
        Ok(Self {
            checked,
            codes,
            root,
            shapes,
            locations,
            location,
            span,
        })
    }
    fn machine<'a>(&'a self, program: &'a Program) -> Machine<'a> {
        Machine {
            inputs: &program.inputs,
            codes: &self.codes,
            root: self.root,
            locations: &self.locations,
            location: self.location,
            span: self.span,
            shapes: &self.shapes,
        }
    }
}
pub fn effect_layouts(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
) -> Result<Vec<EffectLayout>, Error> {
    let plan = CheckedPlan::make(types, terms, program)?;
    let mut layouts = lower_effect(types, values, plan.machine(program), false)?
        .resolve()?
        .effects;
    layouts.sort_by_key(|layout| layout.index);
    let mut at: usize = 0;
    for (index, location) in plan.checked.locations().iter().enumerate() {
        if location.index() != index {
            return Err(Error::EffectMap);
        }
        let count = location.count().to_usize().ok_or(Error::EffectMap)?;
        let end = at.checked_add(count).ok_or(Error::EffectMap)?;
        let rows = layouts.get(at..end).ok_or(Error::EffectMap)?;
        if rows
            .iter()
            .any(|row| row.index != index as i64 || row.atom != location.site().atom())
        {
            return Err(Error::EffectMap);
        }
        at = end;
    }
    if at != layouts.len() {
        return Err(Error::EffectMap);
    }
    Ok(layouts)
}
enum Piece {
    Plain(Marked),
    Host(Vec<I>),
}
fn attach(values: Vec<Marked>, blocks: &[HostBlock]) -> Result<Vec<Piece>, Error> {
    let mut rows: BTreeMap<EffectLayout, VecDeque<Vec<I>>> = BTreeMap::new();
    for block in blocks {
        if block.code.is_empty() {
            return Err(Error::EffectMap);
        }
        rows.entry(block.layout.clone())
            .or_default()
            .push_back(block.code.clone());
    }
    let mut out = vec![];
    for value in values {
        if let Asm::Apply(layout) = &value.asm {
            let queue = rows.get_mut(layout).ok_or(Error::EffectMap)?;
            let code = queue.pop_front().ok_or(Error::EffectMap)?;
            if queue.is_empty() {
                rows.remove(layout);
            }
            out.push(Piece::Host(code));
        } else {
            out.push(Piece::Plain(value));
        }
    }
    if !rows.is_empty() {
        return Err(Error::EffectMap);
    }
    Ok(out)
}
fn resolve(values: Vec<Piece>) -> Result<Vec<I>, Error> {
    let mut labels = BTreeMap::new();
    let mut pc = 0_usize;
    for piece in &values {
        match piece {
            Piece::Host(code) => pc = pc.checked_add(code.len()).ok_or(Error::Label)?,
            Piece::Plain(value) => {
                if let Asm::Place(id) = &value.asm {
                    if labels
                        .insert(*id, u32::try_from(pc).map_err(|_| Error::Label)?)
                        .is_some()
                    {
                        return Err(Error::Label);
                    }
                }
                pc += 1;
            }
        }
    }
    let mut code = Vec::with_capacity(pc);
    for piece in values {
        match piece {
            Piece::Host(host) => code.extend(host),
            Piece::Plain(value) => code.push(match value.asm {
                Asm::Op(op) => op.vm().ok_or(Error::OutputCode)?,
                Asm::Goto(id) => I::Jmp(*labels.get(&id).ok_or(Error::Label)?),
                Asm::Branch(reg, id) => I::Jif(reg, *labels.get(&id).ok_or(Error::Label)?),
                Asm::Place(id) => I::Jdest(*labels.get(&id).ok_or(Error::Label)?),
                Asm::Apply(_) => return Err(Error::EffectMap),
            }),
        }
    }
    Ok(code)
}
pub fn emit_effects(
    types: &mut Types,
    terms: &Terms,
    values: &mut Values,
    program: &Program,
    blocks: &[HostBlock],
) -> Result<Vec<I>, Error> {
    let plan = CheckedPlan::make(types, terms, program)?;
    let marked = lower_effect(types, values, plan.machine(program), true)?.marked;
    let code = resolve(attach(marked, blocks)?)?;
    let raw = wire::encode(&code, &wire::Metadata::default(), false).map_err(Error::Wire)?;
    let decoded = wire::Image::decode(&raw, true).map_err(|_| Error::OutputCode)?;
    if decoded.code != code {
        return Err(Error::OutputCode);
    }
    Ok(code)
}
