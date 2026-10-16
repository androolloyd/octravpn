// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native analysis algebra, including erased initializers and bounded folds.
use super::{BigInt, Checker, Effects, Info, Limit, Natural, TypeId};
impl Checker<'_> {
    pub(super) fn item(&self, typ: TypeId, resources: Limit) -> Info {
        Info {
            typ,
            effects: Effects::new(),
            resources,
            flow: self.flows.pure(),
        }
    }
    pub(super) fn leaf(&self, typ: TypeId) -> Info {
        self.item(typ, Limit::one())
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn sequence(&mut self, typ: TypeId, left: Info, right: Info) -> Info {
        Info {
            typ,
            effects: left.effects.union(&right.effects).copied().collect(),
            resources: left.resources.add(&right.resources).successor(),
            flow: self.flows.sequence(left.flow, right.flow),
        }
    }
    pub(super) fn join(&mut self, typ: TypeId, guard: Info, yes: Info, no: Info) -> Info {
        let branches = self.flows.fork(yes.flow, no.flow);
        let flow = self.flows.sequence(guard.flow, branches);
        let mut effects = guard.effects;
        effects.extend(yes.effects);
        effects.extend(no.effects);
        Info {
            typ,
            effects,
            resources: guard
                .resources
                .add(&yes.resources.maximum(&no.resources))
                .successor(),
            flow,
        }
    }
    pub(super) fn copy_sequence(
        &mut self,
        typ: TypeId,
        length: Natural,
        left: Info,
        right: Info,
    ) -> Info {
        let mut info = self.sequence(typ, left, right);
        info.resources = Limit::make(BigInt::from(length.get())).add(&info.resources);
        info
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    pub(super) fn copy_one(&self, typ: TypeId, length: Natural, mut info: Info) -> Info {
        info.typ = typ;
        info.resources = Limit::make(BigInt::from(length.get())).add(&info.resources.successor());
        info
    }
    pub(super) fn fold_info(
        &mut self,
        length: Natural,
        vector: Info,
        seed: Info,
        body: Info,
    ) -> Info {
        let turns = body
            .resources
            .successor()
            .scale(&BigInt::from(length.get()));
        let resources = vector
            .resources
            .add(&seed.resources.add(&turns))
            .successor();
        let repeated = self.flows.repeat(length, body.flow);
        let seeded = self.flows.sequence(seed.flow, repeated);
        let flow = self.flows.sequence(vector.flow, seeded);
        let mut effects = vector.effects;
        effects.extend(seed.effects);
        effects.extend(body.effects);
        Info {
            typ: seed.typ,
            effects,
            resources,
            flow,
        }
    }
}
