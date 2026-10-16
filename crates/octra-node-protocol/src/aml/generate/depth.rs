// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native direct-form call-depth validation over emitted entry ranges.
use super::{Arc, BTreeMap, Error, Generator, Name, Result, Visibility};
use crate::octb::Instruction as I;
use std::collections::BTreeSet;
type Graph = BTreeMap<Name, Vec<Name>>;
fn invalid(message: impl AsRef<[u8]>) -> Error {
    Error::Invalid {
        message: message.as_ref().to_vec(),
        line: 0,
        column: 1,
    }
}
enum Task {
    Enter(Name, bool, Arc<Vec<Name>>),
    Finish(Name, bool, usize),
}
fn span(
    graph: &Graph,
    forms: &BTreeSet<Name>,
    leads: &BTreeSet<Name>,
    memo: &mut BTreeMap<(Name, bool), usize>,
    root: &[u8],
) -> Result<usize> {
    let mut tasks = vec![Task::Enter(root.to_vec(), false, Arc::new(vec![]))];
    let mut values: Vec<usize> = vec![];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Enter(name, entered, mut trail) => {
                if trail.contains(&name) {
                    return Err(invalid(
                        [b"direct form recursion is forbidden = ".as_slice(), &name].concat(),
                    ));
                }
                let entered = entered || forms.contains(&name);
                if let Some(value) = memo.get(&(name.clone(), entered)) {
                    values.push(*value);
                    continue;
                }
                let targets: Vec<_> = graph
                    .get(&name)
                    .into_iter()
                    .flatten()
                    .filter(|target| entered || leads.contains(*target))
                    .cloned()
                    .collect();
                tasks.push(Task::Finish(name.clone(), entered, targets.len()));
                Arc::make_mut(&mut trail).push(name);
                for target in targets.into_iter().rev() {
                    tasks.push(Task::Enter(target, entered, trail.clone()));
                }
            }
            Task::Finish(name, entered, count) => {
                let children = values.split_off(values.len() - count);
                let value = children
                    .into_iter()
                    .map(|depth| depth + 1)
                    .max()
                    .unwrap_or(0);
                memo.insert((name, entered), value);
                values.push(value);
            }
        }
    }
    Ok(values.pop().expect("call-depth root"))
}
impl Generator<'_> {
    fn call_graph(&self, code: &[I]) -> Result<(Graph, Vec<Name>)> {
        let mut labels = vec![];
        for function in &self.contract.functions {
            let label = self
                .function_labels
                .get(&function.name)
                .copied()
                .ok_or(Error::Unavailable("compiler graph label transport differs"))?;
            labels.push((label, function.name.clone()));
        }
        let calls = |first: usize, last: usize| -> Result<Vec<Name>> {
            let mut targets = BTreeSet::new();
            for instruction in code.iter().take(last).skip(first) {
                if let I::CallInt(_, label) = instruction {
                    let name = labels
                        .iter()
                        .find(|(found, _)| found == label)
                        .map(|(_, name)| name)
                        .ok_or_else(|| {
                            invalid(format!("function call label is absent = {label}"))
                        })?;
                    targets.insert(name.clone());
                }
            }
            Ok(targets.into_iter().collect())
        };
        let mut starts = vec![];
        for (index, function) in self.contract.functions.iter().enumerate() {
            let label = super::entries::entry_label(index)?;
            let pc = code
                .iter()
                .position(|instruction| matches!(instruction, I::Jdest(found) if *found == label))
                .ok_or_else(|| invalid(format!("function label is absent = {label}")))?;
            starts.push((function.name.clone(), pc));
        }
        let mut graph = BTreeMap::new();
        for (index, (name, first)) in starts.iter().enumerate() {
            let last = starts.get(index + 1).map_or(code.len(), |(_, pc)| *pc);
            graph.insert(name.clone(), calls(*first, last)?);
        }
        let root = match starts.first() {
            Some((_, first)) => calls(0, *first)?,
            None => vec![],
        };
        Ok((graph, root))
    }
    pub fn validate_depth(&self, code: &[I]) -> Result<()> {
        let (graph, root) = self.call_graph(code)?;
        let forms: BTreeSet<_> = self.forms.iter().cloned().collect();
        let mut leads = forms.clone();
        loop {
            let mut next = leads.clone();
            for (caller, targets) in &graph {
                if targets.iter().any(|target| next.contains(target)) {
                    next.insert(caller.clone());
                }
            }
            if leads == next {
                break;
            }
            leads = next;
        }
        let check = |depth: usize| -> Result<()> {
            let maximum = super::super::limits::CALL_DEPTH;
            if depth > maximum {
                Err(invalid(format!(
                    "direct form call depth max = {maximum} actual = {depth}"
                )))
            } else {
                Ok(())
            }
        };
        let mut memo = BTreeMap::new();
        for function in &self.contract.functions {
            if function.visibility == Visibility::Public && leads.contains(&function.name) {
                check(span(&graph, &forms, &leads, &mut memo, &function.name)?)?;
            }
        }
        let mut depth = 0;
        for target in root {
            if leads.contains(&target) {
                depth = depth.max(1 + span(&graph, &forms, &leads, &mut memo, &target)?);
            }
        }
        check(depth)
    }
}
