// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native ordered trace recognition. Forks union positions; loops retain their
//! full static count, including when their payload is a runtime sequence.
use super::core::{
    eval::{Action, Origin as RuntimeOrigin, Values},
    flow::{Flow, FlowId, Flows},
};
use super::{BTreeSet, Origin, Sealed, Site, Types};
type Positions = BTreeSet<usize>;
enum Task {
    Walk(FlowId, Positions),
    Sequence(FlowId),
    ForkFirst(FlowId, Positions),
    ForkSecond(Positions),
    Repeat(u32, FlowId, Positions),
    Repeated(u32, FlowId),
}
fn same_site(types: &Types, values: &mut Values, site: Site, action: Action) -> bool {
    let origin = match (site.origin(), action.origin()) {
        (Origin::Direct, RuntimeOrigin::Direct) => true,
        (Origin::Held(expected), RuntimeOrigin::Held(actual, _)) => expected == actual,
        _ => false,
    };
    site.atom() == action.atom() && origin && values.typed(types, site.payload(), action.payload())
}
fn trace(
    types: &Types,
    flows: &Flows,
    root: FlowId,
    values: &mut Values,
    actions: &[Action],
) -> bool {
    let mut pending = vec![Task::Walk(root, BTreeSet::from([0]))];
    let mut results: Vec<Positions> = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Task::Walk(id, positions) => match flows.get(id) {
                Flow::Pure => results.push(positions),
                Flow::Action(site) => {
                    let mut out = BTreeSet::new();
                    for index in positions {
                        if actions
                            .get(index)
                            .is_some_and(|action| same_site(types, values, *site, *action))
                        {
                            out.insert(index + 1);
                        }
                    }
                    results.push(out);
                }
                Flow::Seq(first, second) => {
                    pending.push(Task::Sequence(*second));
                    pending.push(Task::Walk(*first, positions));
                }
                Flow::Fork(first, second) => {
                    pending.push(Task::ForkFirst(*second, positions.clone()));
                    pending.push(Task::Walk(*first, positions));
                }
                Flow::Loop(count, body) => {
                    pending.push(Task::Repeat(count.get(), *body, positions));
                }
            },
            Task::Sequence(second) => {
                let positions = results.pop().expect("trace sequence first");
                pending.push(Task::Walk(second, positions));
            }
            Task::ForkFirst(second, positions) => {
                let first = results.pop().expect("trace fork first");
                pending.push(Task::ForkSecond(first));
                pending.push(Task::Walk(second, positions));
            }
            Task::ForkSecond(mut first) => {
                first.extend(results.pop().expect("trace fork second"));
                results.push(first);
            }
            Task::Repeat(count, body, positions) => {
                if count == 0 || positions.is_empty() {
                    results.push(positions);
                } else {
                    pending.push(Task::Repeated(count - 1, body));
                    pending.push(Task::Walk(body, positions));
                }
            }
            Task::Repeated(count, body) => {
                let positions = results.pop().expect("trace loop body");
                pending.push(Task::Repeat(count, body, positions));
            }
        }
    }
    results.pop().expect("trace root").contains(&actions.len())
}
impl Sealed {
    /// Action payload IDs belong to `values`; this checks order and payloads but
    /// does not execute hosts or consume the separate action quota inventory.
    pub fn trace(&self, values: &mut Values, actions: &[Action]) -> bool {
        trace(
            &self.types,
            self.checked.flows(),
            self.checked.info().flow(),
            values,
            actions,
        )
    }
}
