// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{
    target, Bodies, Body, BodyId, Error, Field, Function, Result, Syntax, Term, TermId, Types,
    LOCAL,
};
enum Job {
    Syntax(usize, TermId),
    Function(usize, BodyId),
}
pub(super) fn shape(
    syntax: &Syntax,
    types: &mut Types,
    bodies: &Bodies,
    functions: &[Function],
    root: BodyId,
) -> Result<()> {
    let maximum_nodes = LOCAL.get(Field::TermNodes) as usize;
    let maximum_depth = LOCAL.get(Field::TermDepth) as usize;
    let mut pending = vec![Job::Function(0, root)];
    let mut count = 0;
    while let Some(job) = pending.pop() {
        // C_fun checks count strictly after scheduling, including expanded lets.
        if count > maximum_nodes {
            return Err(Error::Nodes(maximum_nodes, count));
        }
        let depth = match &job {
            Job::Syntax(depth, _) | Job::Function(depth, _) => *depth,
        };
        if depth > maximum_depth {
            return Err(Error::Depth(maximum_depth, depth));
        }
        match job {
            Job::Syntax(depth, id) => {
                let term = syntax.term(id);
                let children = term.children();
                if matches!(term, Term::Vec(..) | Term::Seq(..)) {
                    pending.extend(
                        children
                            .into_iter()
                            .map(|child| Job::Syntax(depth + 1, child)),
                    );
                } else {
                    pending.extend(
                        children
                            .into_iter()
                            .rev()
                            .map(|child| Job::Syntax(depth + 1, child)),
                    );
                }
                count += 1;
            }
            Job::Function(depth, id) => match bodies.get(id) {
                Body::Ret(term) => pending.push(Job::Syntax(depth, *term)),
                Body::Let(_, value, body) => {
                    pending.push(Job::Function(depth + 1, *body));
                    pending.push(Job::Syntax(depth + 1, *value));
                    count += 1;
                }
                Body::If(guard, yes, no) => {
                    pending.push(Job::Function(depth + 1, *no));
                    pending.push(Job::Function(depth + 1, *yes));
                    pending.push(Job::Syntax(depth + 1, *guard));
                    count += 1;
                }
                Body::Call(result, name, caps, arg, rest) => {
                    let item = target(syntax, types, functions, result, name, caps)?;
                    let call_depth = depth + 1;
                    for (offset, value) in caps.iter().chain(std::iter::once(arg)).enumerate() {
                        pending.push(Job::Syntax(call_depth + offset + 1, *value));
                    }
                    pending.push(Job::Function(depth + 1, *rest));
                    pending.push(Job::Syntax(
                        call_depth + item.arrow.caps.len() + 1,
                        item.body,
                    ));
                    count += item.arrow.caps.len() + 2;
                }
            },
        }
    }
    Ok(())
}
