// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{Name, Syntax, Term, TermId};
use std::sync::Arc;
type Env = Arc<Vec<(Name, Name)>>;
fn drop_names(env: &Env, names: &[&Name]) -> Env {
    if env.iter().any(|(key, _)| names.contains(&key)) {
        Arc::new(
            env.iter()
                .filter(|(key, _)| !names.contains(&key))
                .cloned()
                .collect(),
        )
    } else {
        env.clone()
    }
}
/// Substitute free formal names. Each binder masks only its own lexical body.
pub fn rename(syntax: &mut Syntax, env: &[(Name, Name)], root: TermId) -> TermId {
    enum Task {
        Visit(TermId, Env),
        Finish(Term, usize),
    }
    let mut pending = vec![Task::Visit(root, Arc::new(env.to_vec()))];
    let mut values = vec![];
    while let Some(task) = pending.pop() {
        match task {
            Task::Visit(id, env) => {
                let mut term = syntax.term(id).clone();
                if let Term::Var(name) = &mut term {
                    if let Some((_, replacement)) = env.iter().find(|(key, _)| key == name) {
                        *name = replacement.clone();
                    }
                }
                let children = term.children();
                let scoped = match &term {
                    Term::Let(bind, ..) => Some((1, drop_names(&env, &[&bind.name]))),
                    Term::Unpair(_, left, right, _) => {
                        Some((1, drop_names(&env, &[&left.name, &right.name])))
                    }
                    Term::Vfold(_, _, fold) => {
                        Some((2, drop_names(&env, &[&fold.item.name, &fold.state.name])))
                    }
                    _ => None,
                };
                let branches = if let Term::Case(_, left, _, right, _) = &term {
                    Some((
                        drop_names(&env, &[&left.name]),
                        drop_names(&env, &[&right.name]),
                    ))
                } else {
                    None
                };
                pending.push(Task::Finish(term, children.len()));
                for (index, child) in children.into_iter().enumerate().rev() {
                    let child_env = match (&scoped, &branches) {
                        (Some((scope, scoped)), _) if index == *scope => scoped.clone(),
                        (_, Some((yes, _))) if index == 1 => yes.clone(),
                        (_, Some((_, no))) if index == 2 => no.clone(),
                        _ => env.clone(),
                    };
                    pending.push(Task::Visit(child, child_env));
                }
            }
            Task::Finish(term, count) => {
                let children = values.split_off(values.len() - count);
                let mut children = children.into_iter();
                let term = term.map_terms(|_| children.next().expect("renamed child"));
                values.push(syntax.add_term(term));
            }
        }
    }
    values.pop().expect("renamed root")
}
