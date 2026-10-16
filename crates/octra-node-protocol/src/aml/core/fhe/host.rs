// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{BigInt, Enc, Environment, Name, Natural, Profile, Term, TermId, Terms};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Node {
    Argument(Name),
    Trim(Natural, usize),
    Add(usize, usize),
    Multiply(usize, usize),
    Recrypt(usize),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostNode {
    pub node: Node,
    pub typ: Enc,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub(super) nodes: Vec<HostNode>,
    pub(super) root: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    Load(Name, Enc),
    Narrow(Natural, Enc),
    Add(Enc),
    Multiply(Enc),
    Recrypt(Enc),
}
impl Host {
    pub fn typ(&self) -> Enc {
        self.nodes[self.root].typ
    }
    pub fn term(&self) -> (Terms, TermId) {
        let mut terms = Terms::default();
        let mut ids = Vec::with_capacity(self.nodes.len());
        for value in &self.nodes {
            let term = match &value.node {
                Node::Argument(name) => Term::Var(name.clone()),
                Node::Trim(rem, body) => Term::Trim(BigInt::from(rem.get()), ids[*body]),
                Node::Add(left, right) => Term::Add(ids[*left], ids[*right]),
                Node::Multiply(left, right) => Term::Mul(ids[*left], ids[*right]),
                Node::Recrypt(body) => Term::Recrypt(ids[*body]),
            };
            ids.push(terms.push(term));
        }
        let root = ids[self.root];
        (terms, root)
    }
    pub fn check(&self, profile: &Profile, environment: &Environment) -> bool {
        let mut values: Vec<Option<Enc>> = Vec::with_capacity(self.nodes.len());
        for value in &self.nodes {
            let actual = match &value.node {
                Node::Argument(name) => environment.0.get(name).copied(),
                Node::Trim(rem, body) => values[*body]
                    .filter(|prior| *rem <= prior.remaining && profile.0.contains_key(&prior.key))
                    .map(|prior| Enc {
                        remaining: *rem,
                        ..prior
                    }),
                Node::Add(left, right) => match (values[*left], values[*right]) {
                    (Some(left), Some(right))
                        if left == right && profile.0.contains_key(&left.key) =>
                    {
                        Some(left)
                    }
                    _ => None,
                },
                Node::Multiply(left, right) => match (values[*left], values[*right]) {
                    (Some(left), Some(right))
                        if left == right
                            && left.remaining.get() != 0
                            && profile.0.contains_key(&left.key) =>
                    {
                        left.remaining
                            .checked_sub(Natural::from_u32(1).expect("fixed FHE one"))
                            .map(|remaining| Enc { remaining, ..left })
                    }
                    _ => None,
                },
                Node::Recrypt(body) => values[*body]
                    .filter(|prior| prior.remaining.get() == 0)
                    .and_then(|prior| {
                        profile.0.get(&prior.key).map(|config| Enc {
                            remaining: config.full,
                            ..prior
                        })
                    }),
            };
            values.push(actual.filter(|actual| *actual == value.typ));
        }
        values[self.root] == Some(self.typ())
    }
    pub fn emit(&self) -> Vec<Instruction> {
        enum Task {
            Visit(usize),
            Emit(Instruction),
        }
        let mut pending = vec![Task::Visit(self.root)];
        let mut out = Vec::new();
        while let Some(task) = pending.pop() {
            match task {
                Task::Emit(instruction) => out.push(instruction),
                Task::Visit(id) => {
                    let value = &self.nodes[id];
                    match &value.node {
                        Node::Argument(name) => {
                            out.push(Instruction::Load(name.clone(), value.typ));
                        }
                        Node::Trim(rem, body) => {
                            pending.push(Task::Emit(Instruction::Narrow(*rem, value.typ)));
                            pending.push(Task::Visit(*body));
                        }
                        Node::Add(left, right) | Node::Multiply(left, right) => {
                            pending.push(Task::Emit(if matches!(value.node, Node::Add(..)) {
                                Instruction::Add(value.typ)
                            } else {
                                Instruction::Multiply(value.typ)
                            }));
                            pending.push(Task::Visit(*right));
                            pending.push(Task::Visit(*left));
                        }
                        Node::Recrypt(body) => {
                            pending.push(Task::Emit(Instruction::Recrypt(value.typ)));
                            pending.push(Task::Visit(*body));
                        }
                    }
                }
            }
        }
        out
    }
    pub fn emit_check(&self, profile: &Profile, environment: &Environment) -> bool {
        execute(profile, environment, &self.emit()).is_some_and(|stack| stack == [self.typ()])
    }
}
fn execute(profile: &Profile, environment: &Environment, code: &[Instruction]) -> Option<Vec<Enc>> {
    let mut stack: Vec<Enc> = Vec::new();
    for instruction in code {
        let (actual, out) = match instruction {
            Instruction::Load(name, out) => (*environment.0.get(name)?, *out),
            Instruction::Narrow(rem, out) => {
                let prior = stack.pop()?;
                if *rem > prior.remaining || !profile.0.contains_key(&prior.key) {
                    return None;
                }
                (
                    Enc {
                        remaining: *rem,
                        ..prior
                    },
                    *out,
                )
            }
            Instruction::Add(out) | Instruction::Multiply(out) => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                if left != right || !profile.0.contains_key(&left.key) {
                    return None;
                }
                let actual = if matches!(instruction, Instruction::Multiply(_)) {
                    Enc {
                        remaining: left
                            .remaining
                            .checked_sub(Natural::from_u32(1).expect("fixed FHE one"))?,
                        ..left
                    }
                } else {
                    left
                };
                (actual, *out)
            }
            Instruction::Recrypt(out) => {
                let prior = stack.pop()?;
                if prior.remaining.get() != 0 {
                    return None;
                }
                (
                    Enc {
                        remaining: profile.0.get(&prior.key)?.full,
                        ..prior
                    },
                    *out,
                )
            }
        };
        if actual != out {
            return None;
        }
        stack.push(out);
    }
    Some(stack)
}
