// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Persistent environments keep native newest-first lookup and pending-use order.
use super::{Arc, Bind, Error, Kind, Multiplicity, Natural, Result, TypeId, Types};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    bind: Bind,
    live: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Env(Arc<Vec<Slot>>);
impl Env {
    fn position(&self, id: Natural) -> Option<usize> {
        self.0.iter().rposition(|slot| slot.bind.id == id)
    }
    pub(super) fn use_value(&mut self, id: Natural) -> Result<TypeId> {
        let index = self.position(id).ok_or(Error::Unknown(id))?;
        let slot = self.0[index];
        match (slot.bind.multiplicity, slot.live) {
            (Multiplicity::Zero, _) => Err(Error::Ghost(id)),
            (Multiplicity::One, false) => Err(Error::Used(id)),
            (Multiplicity::One, true) => {
                Arc::make_mut(&mut self.0)[index].live = false;
                Ok(slot.bind.typ)
            }
            (Multiplicity::Many, _) => Ok(slot.bind.typ),
        }
    }
    pub(super) fn open(&mut self, types: &Types, bind: Bind) -> Result<()> {
        if !types.valid(bind.typ) {
            return Err(Error::Bad(bind.typ));
        }
        if types.kind(bind.typ) == Kind::Resource && bind.multiplicity != Multiplicity::One {
            return Err(Error::Mode(bind.id, bind.multiplicity));
        }
        if self.position(bind.id).is_some() {
            return Err(Error::Shadow(bind.id));
        }
        if bind.multiplicity != Multiplicity::Zero {
            Arc::make_mut(&mut self.0).push(Slot { bind, live: true });
        }
        Ok(())
    }
    pub(super) fn close(&mut self, bind: Bind) -> Result<()> {
        if bind.multiplicity == Multiplicity::Zero {
            return Ok(());
        }
        let index = self.position(bind.id).ok_or(Error::Unknown(bind.id))?;
        if bind.multiplicity == Multiplicity::One && self.0[index].live {
            return Err(Error::Unused(bind.id));
        }
        Arc::make_mut(&mut self.0).remove(index);
        Ok(())
    }
    pub(super) fn difference(&self, right: &Self) -> Vec<Natural> {
        let mut ids = BTreeSet::new();
        for slot in self.0.iter() {
            if right
                .position(slot.bind.id)
                .is_none_or(|index| right.0[index] != *slot)
            {
                ids.insert(slot.bind.id);
            }
        }
        for slot in right.0.iter() {
            if self.position(slot.bind.id).is_none() {
                ids.insert(slot.bind.id);
            }
        }
        ids.into_iter().collect()
    }
    pub(super) fn pending(&self) -> Option<Natural> {
        self.0
            .iter()
            .rev()
            .find(|slot| slot.live && slot.bind.multiplicity == Multiplicity::One)
            .map(|slot| slot.bind.id)
    }
}
