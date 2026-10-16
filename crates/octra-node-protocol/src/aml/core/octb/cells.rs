// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_octb linear cells and input seeding. Physical argument registers are
//! allocated for erased inputs too, then returned to the initial free list.
use super::super::{
    machine::Shapes,
    maps::Slot,
    term::Bind,
    types::{Multiplicity, Type, Types},
    Natural,
};
use super::{Error, Generator, LayoutId, Layouts};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct Cell {
    pub bind: Bind,
    pub layout: LayoutId,
    pub live: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Cells {
    items: Vec<Cell>,
}
#[derive(Clone, Debug)]
pub struct Seed {
    pub env: Cells,
    pub generator: Generator,
    pub inputs: Vec<LayoutId>,
}
impl Cells {
    pub fn view(&self) -> Arc<[Slot]> {
        self.items
            .iter()
            .rev()
            .map(|cell| Slot {
                id: cell.bind.id,
                multiplicity: cell.bind.multiplicity,
                live: cell.live,
            })
            .collect::<Vec<_>>()
            .into()
    }
    pub fn take(&mut self, id: Natural) -> Option<LayoutId> {
        let cell = self
            .items
            .iter_mut()
            .rev()
            .find(|cell| cell.bind.id == id)?;
        match (cell.bind.multiplicity, cell.live) {
            (Multiplicity::One, true) => {
                cell.live = false;
                Some(cell.layout)
            }
            (Multiplicity::Many, _) => Some(cell.layout),
            _ => None,
        }
    }
    pub fn moves_sequence(&self, types: &Types, id: Natural) -> bool {
        self.items
            .iter()
            .rev()
            .find(|cell| cell.bind.id == id)
            .is_some_and(|cell| {
                cell.bind.multiplicity == Multiplicity::One
                    && matches!(types.get(cell.bind.typ), Type::Seq(..))
            })
    }
    pub fn open(
        &mut self,
        shapes: &mut Shapes,
        types: &Types,
        layouts: &Layouts,
        bind: Bind,
        layout: LayoutId,
    ) -> Option<()> {
        if self.items.iter().any(|cell| cell.bind.id == bind.id)
            || bind.multiplicity == Multiplicity::Zero
        {
            return None;
        }
        let form = shapes.from_type(types, bind.typ)?;
        if !layouts.fits(shapes, form, layout) {
            return None;
        }
        self.items.push(Cell {
            bind,
            layout,
            live: true,
        });
        Some(())
    }
    pub fn close(&mut self, bind: Bind) -> Option<()> {
        let cell = self.items.pop()?;
        if cell.bind.id != bind.id {
            return None;
        }
        match (bind.multiplicity, cell.bind.multiplicity, cell.live) {
            (Multiplicity::One, Multiplicity::One, false)
            | (Multiplicity::Many, Multiplicity::Many, _) => Some(()),
            _ => None,
        }
    }
    pub fn same(&self, layouts: &Layouts, right: &Self) -> bool {
        self.items.len() == right.items.len()
            && self.items.iter().zip(&right.items).all(|(left, right)| {
                left.bind == right.bind
                    && left.live == right.live
                    && layouts.same(left.layout, right.layout)
            })
    }
    pub fn registers(&self, layouts: &Layouts, live_only: bool) -> Vec<u8> {
        self.items
            .iter()
            .rev()
            .filter(|cell| !live_only || cell.live)
            .flat_map(|cell| layouts.registers(cell.layout))
            .collect()
    }
    pub fn terminal(&self, inputs: &[Bind]) -> bool {
        inputs
            .iter()
            .filter(|bind| bind.multiplicity != Multiplicity::Zero)
            .count()
            == self.items.len()
            && self.items.iter().all(|cell| {
                let Some(bind) = inputs.iter().find(|bind| bind.id == cell.bind.id) else {
                    return false;
                };
                matches!(
                    (bind.multiplicity, cell.bind.multiplicity, cell.live),
                    (Multiplicity::One, Multiplicity::One, false)
                        | (Multiplicity::Many, Multiplicity::Many, true)
                )
            })
    }
}
pub fn seed(
    shapes: &mut Shapes,
    types: &Types,
    layouts: &mut Layouts,
    inputs: &[Bind],
) -> Result<Seed, Error> {
    let mut generator = Generator::new(1)?;
    let mut cells = vec![];
    let mut erased = vec![];
    let mut out = vec![];
    for bind in inputs {
        let form = shapes.from_type(types, bind.typ).ok_or(Error::Register)?;
        let layout = layouts.alloc(shapes, form, &mut generator)?;
        if generator.next() - 1 > 60 {
            return Err(Error::Register);
        }
        if bind.multiplicity == Multiplicity::Zero {
            erased.extend(layouts.registers(layout));
        } else {
            cells.push(Cell {
                bind: *bind,
                layout,
                live: true,
            });
        }
        out.push(layout);
    }
    cells.reverse();
    generator.free = erased.into_iter().rev().collect();
    Ok(Seed {
        env: Cells { items: cells },
        generator,
        inputs: out,
    })
}
