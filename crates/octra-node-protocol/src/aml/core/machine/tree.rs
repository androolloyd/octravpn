// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach source trees and substitution mark transfer. Marks follow syntactic
//! occurrences in postorder, including erased initializers.
use super::super::{
    lexer::Span,
    term::{Term, TermId, Terms},
};
use std::sync::Arc;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeId(usize);
#[derive(Clone, Debug)]
pub struct Tree {
    pub at: Span,
    pub children: Arc<[TreeId]>,
}
#[derive(Clone, Debug, Default)]
pub struct Trees {
    items: Vec<Tree>,
}
impl Trees {
    pub fn get(&self, id: TreeId) -> &Tree {
        &self.items[id.0]
    }
    fn push(&mut self, at: Span, children: Vec<TreeId>) -> TreeId {
        assert!(
            children.iter().all(|child| child.0 < self.items.len()),
            "source marks precede parent"
        );
        let id = TreeId(self.items.len());
        self.items.push(Tree {
            at,
            children: children.into(),
        });
        id
    }
    pub fn from_marks(
        &mut self,
        terms: &Terms,
        root: TermId,
        marks: &[Option<Span>],
    ) -> Option<(TreeId, usize)> {
        enum Task {
            Visit(TermId),
            Finish(usize),
        }
        let mut pending = vec![Task::Visit(root)];
        let mut out = vec![];
        let mut at = 0;
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(id) => {
                    if matches!(terms.get(id), Term::Step(..)) {
                        return None;
                    }
                    let children = terms.get(id).children();
                    pending.push(Task::Finish(children.len()));
                    pending.extend(children.into_iter().rev().map(Task::Visit));
                }
                Task::Finish(count) => {
                    let span = (*marks.get(at)?)?;
                    at += 1;
                    let children = out.split_off(out.len() - count);
                    out.push(self.push(span, children));
                }
            }
        }
        Some((out.pop().expect("source mark root"), at))
    }
    /// A substituted variable spreads its original span across the replacement.
    pub fn spread(&mut self, terms: &Terms, root: TermId, at: Span) -> TreeId {
        enum Task {
            Visit(TermId),
            Finish(usize),
        }
        let mut pending = vec![Task::Visit(root)];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Visit(id) => {
                    let children = terms.get(id).children();
                    pending.push(Task::Finish(children.len()));
                    pending.extend(children.into_iter().rev().map(Task::Visit));
                }
                Task::Finish(count) => {
                    let children = out.split_off(out.len() - count);
                    out.push(self.push(at, children));
                }
            }
        }
        out.pop().expect("spread source mark root")
    }
    pub fn retree(
        &mut self,
        terms: &Terms,
        source: TermId,
        target: TermId,
        mark: TreeId,
    ) -> Option<TreeId> {
        enum Task {
            Visit(TermId, TermId, TreeId),
            Finish(Span, usize),
        }
        let mut pending = vec![Task::Visit(source, target, mark)];
        let mut out = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Finish(at, count) => {
                    let children = out.split_off(out.len() - count);
                    out.push(self.push(at, children));
                }
                Task::Visit(source, target, mark) => {
                    let node = self.get(mark).clone();
                    let lhs = terms.get(source);
                    let rhs = terms.get(target);
                    if matches!(lhs, Term::Var(_)) && node.children.is_empty() {
                        out.push(self.spread(terms, target, node.at));
                        continue;
                    }
                    if !compatible(lhs, rhs) {
                        return None;
                    }
                    let left = lhs.children();
                    let right = rhs.children();
                    if left.len() != right.len() || left.len() != node.children.len() {
                        return None;
                    }
                    pending.push(Task::Finish(node.at, left.len()));
                    pending.extend(
                        left.into_iter()
                            .zip(right)
                            .zip(node.children.iter().copied())
                            .rev()
                            .map(|((left, right), mark)| Task::Visit(left, right, mark)),
                    );
                }
            }
        }
        out.pop()
    }
}
fn compatible(left: &Term, right: &Term) -> bool {
    match (left, right) {
        (Term::Seq(lc, lt, _), Term::Seq(rc, rt, _)) => lc == rc && lt == rt,
        (Term::Cmp(left, ..), Term::Cmp(right, ..)) => left == right,
        (Term::Fit(left, _), Term::Fit(right, _)) => left == right,
        (Term::Act(left, _), Term::Act(right, _)) => left == right,
        (Term::Var(_) | Term::Step(..), _) => false,
        _ => std::mem::discriminant(left) == std::mem::discriminant(right),
    }
}
