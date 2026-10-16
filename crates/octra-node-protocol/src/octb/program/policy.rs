// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Capability, Facts};
use crate::octb::{admission::Effect, Instruction};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug)]
pub(super) enum Error {
    Certificate,
    Policy(String),
}
type Result<T> = std::result::Result<T, Error>;
fn refuse<T>(reason: impl Into<String>) -> Result<T> {
    Err(Error::Policy(reason.into()))
}
fn add(names: &mut Vec<Vec<u8>>, value: &[u8]) {
    if !names.iter().any(|v| v == value) {
        names.push(value.to_vec());
    }
}
fn normalized(names: &[Vec<u8>]) -> Vec<Vec<u8>> {
    names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
enum State {
    Visiting,
    Complete(Vec<Vec<u8>>, usize),
}
struct Graph<'a> {
    code: &'a [Instruction],
    facts: &'a Facts,
    nodes: BTreeMap<i64, (usize, usize)>,
    children: BTreeMap<i64, Vec<i64>>,
    states: BTreeMap<i64, State>,
}
impl Graph<'_> {
    fn direct(&self, start: usize, stop: usize) -> Result<Vec<Vec<u8>>> {
        let slice = self.code.get(start..stop).ok_or(Error::Certificate)?;
        let mut names = vec![];
        for op in slice {
            if let Some(effect) = Effect::of(op) {
                add(&mut names, effect.name().as_bytes());
            }
        }
        for pc in start..stop {
            if matches!(self.code[pc], Instruction::Xcall(..)) {
                let call = self
                    .facts
                    .xcalls
                    .iter()
                    .find(|c| c.pc == pc as i64)
                    .ok_or_else(|| {
                        Error::Policy(format!("external XCALL at pc {pc} has no checked ABI"))
                    })?;
                for capability in &call.capabilities {
                    if *capability != Capability::View {
                        add(&mut names, capability.name().as_bytes());
                    }
                }
            }
        }
        Ok(names)
    }
    fn summary(&mut self, target: i64) -> Result<(Vec<Vec<u8>>, usize)> {
        match self.states.get(&target) {
            Some(State::Visiting) => {
                return refuse(format!("effect graph cycle at entry {target}"))
            }
            Some(State::Complete(names, depth)) => return Ok((names.clone(), *depth)),
            None => (),
        }
        let (start, stop) = *self
            .nodes
            .get(&target)
            .ok_or_else(|| Error::Policy(format!("effect graph target {target} is missing")))?;
        self.states.insert(target, State::Visiting);
        let mut names = self.direct(start, stop)?;
        let mut max_depth = 0;
        for child in self.children.get(&target).cloned().unwrap_or_default() {
            let (inherited, depth) = self.summary(child)?;
            for name in inherited {
                add(&mut names, &name);
            }
            max_depth = max_depth.max(depth);
        }
        let depth = max_depth + 1;
        if depth > 64 {
            return refuse(format!(
                "effect graph depth exceeds limit at entry {target}"
            ));
        }
        self.states
            .insert(target, State::Complete(names.clone(), depth));
        Ok((names, depth))
    }
}
struct Computed {
    effects: Vec<Vec<u8>>,
    summaries: Vec<(i64, Vec<Vec<u8>>)>,
}
fn compute(code: &[Instruction], facts: &Facts) -> Result<Computed> {
    let targets = std::iter::once(0)
        .chain(facts.entries.iter().map(|e| e.target))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if targets.len() > 256 {
        return refuse("effect graph function limit exceeded");
    }
    if facts.calls.len() > 4096 {
        return refuse("effect graph call limit exceeded");
    }
    for (pc, op) in code.iter().enumerate() {
        if matches!(op, Instruction::Xcall(..)) && !facts.xcalls.iter().any(|c| c.pc == pc as i64) {
            return refuse(format!("external XCALL at pc {pc} has no checked ABI"));
        }
    }
    let mut nodes = BTreeMap::new();
    for (i, target) in targets.iter().enumerate() {
        let start = usize::try_from(*target).map_err(|_| Error::Certificate)?;
        let stop = targets.get(i + 1).copied().unwrap_or(code.len() as i64);
        nodes.insert(
            *target,
            (
                start,
                usize::try_from(stop).map_err(|_| Error::Certificate)?,
            ),
        );
    }
    let mut children = BTreeMap::<i64, Vec<i64>>::new();
    for call in &facts.calls {
        children.entry(call.owner).or_default().push(call.target);
    }
    let mut graph = Graph {
        code,
        facts,
        nodes,
        children,
        states: BTreeMap::new(),
    };
    let mut summaries = vec![];
    for target in targets {
        let (names, _) = graph.summary(target)?;
        summaries.insert(0, (target, names));
    }
    let mut effective = vec![];
    for (_, names) in &summaries {
        for name in names {
            add(&mut effective, name);
        }
    }
    Ok(Computed {
        effects: normalized(&effective),
        summaries,
    })
}
pub(super) fn complete(code: &[Instruction], facts: &Facts) -> Result<Facts> {
    let computed = compute(code, facts)?;
    let mut facts = facts.clone();
    for entry in &mut facts.entries {
        if let Some((_, names)) = computed
            .summaries
            .iter()
            .find(|(target, _)| *target == entry.target)
        {
            entry.effects = normalized(names);
        }
    }
    Ok(facts)
}
pub(super) fn effects(code: &[Instruction], facts: &Facts) -> Result<Vec<Vec<u8>>> {
    Ok(compute(code, facts)?.effects)
}
pub(super) fn verify(code: &[Instruction], facts: &Facts, declared: &[Vec<u8>]) -> Result<()> {
    let computed = compute(code, facts)?;
    if computed.effects != normalized(declared) {
        return refuse("program effect policy mismatch");
    }
    for entry in &facts.entries {
        let expected = computed
            .summaries
            .iter()
            .find(|(target, _)| *target == entry.target)
            .map_or_else(Vec::new, |(_, names)| normalized(names));
        if normalized(&entry.effects) != expected {
            return refuse(format!("effect summary mismatch at entry {}", entry.target));
        }
    }
    Ok(())
}
