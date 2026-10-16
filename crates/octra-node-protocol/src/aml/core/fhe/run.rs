// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    host, nat, Axis, BigInt, Config, Enc, Environment, Error, Field, Host, Info, Natural,
    Operation, Profile, Result, Term, TermId, Terms,
};
use host::{HostNode, Node};
enum Trace {
    Nil,
    Atom(Operation),
    Cat(usize, usize),
}
fn cat(trace: &mut Vec<Trace>, left: usize, right: usize) -> usize {
    if left == 0 {
        return right;
    }
    if right == 0 {
        return left;
    }
    let id = trace.len();
    trace.push(Trace::Cat(left, right));
    id
}
fn atom(trace: &mut Vec<Trace>, operation: Operation) -> usize {
    let id = trace.len();
    trace.push(Trace::Atom(operation));
    id
}
fn zero() -> Natural {
    Natural::from_u32(0).expect("fixed FHE zero")
}
fn one() -> Natural {
    Natural::from_u32(1).expect("fixed FHE one")
}
fn sum(axis: Axis, values: &[Natural]) -> Result<Natural> {
    let raw = values
        .iter()
        .map(|value| BigInt::from(value.get()))
        .sum::<BigInt>();
    Natural::new(&raw).ok_or(Error::Statistic(axis, raw))
}
fn used(config: Config, remaining: Natural) -> Natural {
    config.full.checked_sub(remaining).unwrap_or_else(zero)
}
struct Raw {
    typ: Enc,
    steps: Natural,
    work: Natural,
    peak: Natural,
    trace: usize,
    host: usize,
}
enum Task {
    Visit(TermId),
    Finish(Term),
}
pub(super) fn run(
    profile: &Profile,
    environment: &Environment,
    terms: &Terms,
    root: TermId,
) -> Result<(Info, Host)> {
    terms.shape(root)?;
    let mut pending = vec![Task::Visit(root)];
    let mut values: Vec<Raw> = Vec::new();
    let mut nodes = Vec::new();
    let mut trace = vec![Trace::Nil];
    while let Some(task) = pending.pop() {
        match task {
            Task::Visit(id) => {
                let term = terms.get(id).clone();
                let children = term.children();
                pending.push(Task::Finish(term));
                pending.extend(children.into_iter().rev().map(Task::Visit));
            }
            Task::Finish(term) => {
                let (mut raw, node) = match term {
                    Term::Var(name) => {
                        let typ = environment
                            .0
                            .get(&name)
                            .copied()
                            .ok_or_else(|| Error::Free(name.text().to_vec()))?;
                        let config = profile.legal(typ)?;
                        (
                            Raw {
                                typ,
                                steps: zero(),
                                work: zero(),
                                peak: used(config, typ.remaining),
                                trace: 0,
                                host: 0,
                            },
                            Node::Argument(name),
                        )
                    }
                    Term::Trim(remaining, _) => {
                        let mut out = values.pop().expect("FHE trim input");
                        let remaining = nat(Field::Depth, &remaining)?;
                        if remaining > out.typ.remaining {
                            return Err(Error::InputDepth(
                                out.typ.key,
                                remaining,
                                out.typ.remaining,
                            ));
                        }
                        let config = profile.config(out.typ.key)?;
                        let node = Node::Trim(remaining, out.host);
                        out.typ.remaining = remaining;
                        out.peak = out.peak.max(used(config, remaining));
                        (out, node)
                    }
                    Term::Add(..) | Term::Mul(..) => {
                        let right = values.pop().expect("FHE right input");
                        let left = values.pop().expect("FHE left input");
                        if left.typ != right.typ {
                            return Err(Error::Need(left.typ, right.typ));
                        }
                        let multiply = matches!(term, Term::Mul(..));
                        if multiply && left.typ.remaining.get() == 0 {
                            return Err(Error::MultiplyZero(left.typ.key));
                        }
                        let config = profile.config(left.typ.key)?;
                        let steps = sum(Axis::Steps, &[left.steps, right.steps, one()])?;
                        let work = sum(
                            Axis::Work,
                            &[
                                left.work,
                                right.work,
                                if multiply {
                                    config.multiply
                                } else {
                                    config.add
                                },
                            ],
                        )?;
                        let typ = if multiply {
                            Enc {
                                remaining: left
                                    .typ
                                    .remaining
                                    .checked_sub(one())
                                    .unwrap_or_else(zero),
                                ..left.typ
                            }
                        } else {
                            left.typ
                        };
                        let mut plan = cat(&mut trace, left.trace, right.trace);
                        let mut peak = left.peak.max(right.peak);
                        if multiply {
                            let operation = atom(&mut trace, Operation::Multiply(typ.key));
                            plan = cat(&mut trace, plan, operation);
                            peak = peak.max(used(config, typ.remaining));
                        }
                        (
                            Raw {
                                typ,
                                steps,
                                work,
                                peak,
                                trace: plan,
                                host: 0,
                            },
                            if multiply {
                                Node::Multiply(left.host, right.host)
                            } else {
                                Node::Add(left.host, right.host)
                            },
                        )
                    }
                    Term::Recrypt(_) => {
                        let out = values.pop().expect("FHE recrypt input");
                        if out.typ.remaining.get() != 0 {
                            return Err(Error::RecryptNeed(out.typ.key, out.typ.remaining));
                        }
                        let config = profile.config(out.typ.key)?;
                        let steps = sum(Axis::Steps, &[out.steps, one()])?;
                        let work = sum(Axis::Work, &[out.work, config.recrypt])?;
                        let typ = Enc {
                            remaining: config.full,
                            ..out.typ
                        };
                        let operation = atom(&mut trace, Operation::Recrypt(out.typ.key));
                        let plan = cat(&mut trace, out.trace, operation);
                        (
                            Raw {
                                typ,
                                steps,
                                work,
                                peak: out.peak.max(config.full),
                                trace: plan,
                                host: 0,
                            },
                            Node::Recrypt(out.host),
                        )
                    }
                };
                raw.host = nodes.len();
                nodes.push(HostNode { node, typ: raw.typ });
                values.push(raw);
            }
        }
    }
    let raw = values.pop().expect("FHE root result");
    let mut plan = Vec::new();
    let mut pending = vec![raw.trace];
    while let Some(id) = pending.pop() {
        match trace[id] {
            Trace::Nil => (),
            Trace::Atom(operation) => plan.push(operation),
            Trace::Cat(left, right) => {
                pending.push(right);
                pending.push(left);
            }
        }
    }
    let info = Info {
        typ: raw.typ,
        steps: raw.steps,
        work: raw.work,
        peak: raw.peak,
        plan,
    };
    Ok((
        info,
        Host {
            nodes,
            root: raw.host,
        },
    ))
}
