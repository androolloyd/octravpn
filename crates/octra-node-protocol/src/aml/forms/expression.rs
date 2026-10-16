// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    ast, core, ct, error, functions, located, max_calls, max_depth, multiplicity, name, named,
    node_limit, syn, BigInt, Checked, Core, Elaborator, Env, Finish, Result, Task,
};
impl Elaborator<'_> {
    fn arguments(tasks: &mut Vec<Task>, env: &Env, values: &[ast::ExprId]) {
        tasks.extend(
            values
                .iter()
                .rev()
                .map(|id| Task::Expression(*id, env.clone())),
        );
    }
    pub(super) fn expression(
        &mut self,
        id: ast::ExprId,
        env: Env,
        tasks: &mut Vec<Task>,
        values: &mut Vec<Core>,
    ) -> Result<()> {
        use ast::Expr as E;
        match self.ast.nodes.expression(id).clone() {
            E::Int(value) => {
                let typ = self.syntax.add_type(syn::Type::Int);
                values.push(self.node(syn::Term::Int(value), typ, 1, 0, 0)?);
            }
            E::Bool(value) => {
                let typ = self.syntax.add_type(syn::Type::Bool);
                values.push(self.node(syn::Term::Bool(value), typ, 1, 0, 0)?);
            }
            E::String(_) => return Err(error(b"direct form text requires finite bytes")),
            E::Caller => {
                return Err(error(
                    b"direct form context requires function wrapper = caller",
                ))
            }
            E::Origin => {
                return Err(error(
                    b"direct form context requires function wrapper = origin",
                ))
            }
            E::SelfAddr => {
                return Err(error(
                    b"direct form context requires function wrapper = self_addr",
                ))
            }
            E::Epoch => {
                return Err(error(
                    b"direct form context requires function wrapper = epoch",
                ))
            }
            E::EpochTime => {
                return Err(error(
                    b"direct form context requires function wrapper = epoch_time",
                ))
            }
            E::Value => {
                return Err(error(
                    b"direct form context requires function wrapper = value",
                ))
            }
            E::Balance(_) => {
                return Err(error(
                    b"direct form context requires function wrapper = balance",
                ))
            }
            E::TreeHash => {
                return Err(error(
                    b"direct form context requires function wrapper = tree_hash",
                ))
            }
            E::NodeId => {
                return Err(error(
                    b"direct form context requires function wrapper = node_id",
                ))
            }
            E::TxHash => {
                return Err(error(
                    b"direct form context requires function wrapper = tx_hash",
                ))
            }
            E::Field(_)
            | E::Index(..)
            | E::StoragePath(..)
            | E::FieldProp(..)
            | E::IndexField(..) => {
                return Err(error(b"direct form state requires a proved effect"))
            }
            E::Array(_) => return Err(error(b"direct form list requires a finite sequence")),
            E::Var(name) => {
                let (_, key, typ) = env
                    .find(&name)
                    .ok_or_else(|| named(b"direct form variable is absent = ", &name))?;
                values.push(self.node(syn::Term::Var(key.clone()), *typ, 1, 0, 0)?);
            }
            E::Binop(op, left, right) => {
                tasks.push(Task::Finish(Finish::Binary(op)));
                Self::arguments(tasks, &env, &[left, right]);
            }
            E::Unop(op, value) => {
                tasks.push(Task::Finish(Finish::Unary(op)));
                tasks.push(Task::Expression(value, env));
            }
            E::Tuple(items) if items.len() == 2 => {
                tasks.push(Task::Finish(Finish::Pair));
                Self::arguments(tasks, &env, &items);
            }
            E::Equal(declared, left, right) => {
                let declared = self.typ(0, 1, declared)?;
                tasks.push(Task::Finish(Finish::Equal(declared)));
                Self::arguments(tasks, &env, &[left, right]);
            }
            E::Let(binding, input, body) => {
                tasks.push(Task::Finish(Finish::LetStart(binding, body, env.clone())));
                tasks.push(Task::Expression(input, env));
            }
            E::Split(pair, left, right, body) => {
                tasks.push(Task::Finish(Finish::SplitStart(
                    left,
                    right,
                    body,
                    env.clone(),
                )));
                tasks.push(Task::Expression(pair, env));
            }
            E::Orbit(count, turns, seed, binding, body) => {
                tasks.push(Task::Finish(Finish::OrbitSeed(
                    count,
                    turns,
                    binding,
                    body,
                    env.clone(),
                )));
                tasks.push(Task::Expression(seed, env));
            }
            E::Ternary(guard, yes, no) => {
                tasks.push(Task::Finish(Finish::Branch(None)));
                Self::arguments(tasks, &env, &[guard, yes, no]);
            }
            E::Action(atom, input) => {
                tasks.push(Task::Finish(Finish::Action(atom)));
                tasks.push(Task::Expression(input, env));
            }
            E::Call(name, args) if name == b"abs" && !self.declared(&name) => {
                if args.len() != 1 {
                    return Err(error(format!(
                        "function arity name = abs expected = 1 actual = {}",
                        args.len()
                    )));
                }
                tasks.push(Task::Finish(Finish::Abs));
                tasks.push(Task::Expression(args[0], env));
            }
            E::Call(name, args) => {
                tasks.push(Task::Finish(Finish::Call(name, args.len())));
                Self::arguments(tasks, &env, &args);
            }
            E::Use(value) => {
                if !self
                    .ast
                    .contract
                    .forms
                    .iter()
                    .any(|form| form.name == value.name)
                {
                    return Err(named(b"form is absent = ", &value.name));
                }
                let mut args = value.caps.clone();
                args.push(value.arg);
                tasks.push(Task::Finish(Finish::UseArgs(value, env.clone())));
                Self::arguments(tasks, &env, &args);
            }
            _ => return Err(error(b"direct form expression is unsupported")),
        }
        Ok(())
    }
    fn apply(&mut self, target: &Checked, values: &[Core]) -> Result<syn::TermId> {
        functions::apply(
            &mut self.syntax,
            &target.function,
            &values.iter().map(|value| value.term).collect::<Vec<_>>(),
        )
        .map_err(|failure| error(failure.text(&self.types)))
    }
    fn arity(target: &Checked, requested: &[u8], actual: usize) -> Result<()> {
        if target.arity == actual {
            Ok(())
        } else {
            Err(error(
                [
                    b"function arity name = ".as_slice(),
                    requested,
                    format!(" expected = {} actual = {actual}", target.arity).as_bytes(),
                ]
                .concat(),
            ))
        }
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn orbit(
        &mut self,
        count: core::Natural,
        turns: Option<Core>,
        seed: Core,
        bind: syn::Bind,
        body: Core,
    ) -> Result<Core> {
        let term = match &turns {
            None => core::orbit::make(
                &mut self.syntax,
                &mut self.types,
                &mut self.terms,
                count,
                seed.term,
                &bind,
                body.term,
            ),
            Some(turns) => {
                let integer = self.syntax.add_type(syn::Type::Int);
                self.same(integer, turns.typ, b"direct form orbit count requires int")?;
                core::orbit::upto(
                    &mut self.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    turns.term,
                    seed.term,
                    &bind,
                    body.term,
                )
            }
        }
        .map_err(|failure| error(failure.text(&self.types)))?;
        let calls = turns
            .map_or(0, |turns| turns.calls)
            .max(seed.calls)
            .max(body.calls);
        self.finite(term, bind.typ, calls)
    }
    pub(super) fn finish(
        &mut self,
        trail: &[ast::Name],
        finish: Finish,
        tasks: &mut Vec<Task>,
        values: &mut Vec<Core>,
    ) -> Result<()> {
        let mut pop = || values.pop().expect("elaborated child");
        let result = match finish {
            Finish::Binary(op) => {
                let right = pop();
                let left = pop();
                self.binary(op, left, right)?
            }
            Finish::Unary(op) => self.unary(Some(op), pop())?,
            Finish::Abs => self.unary(None, pop())?,
            Finish::Pair | Finish::Equal(_) => {
                let right = pop();
                let left = pop();
                let (term, typ) = if let Finish::Equal(declared) = finish {
                    self.same(
                        declared,
                        left.typ,
                        b"direct form equality left type differs",
                    )?;
                    self.same(
                        declared,
                        right.typ,
                        b"direct form equality right type differs",
                    )?;
                    (
                        syn::Term::Eq(declared, left.term, right.term),
                        self.syntax.add_type(syn::Type::Bool),
                    )
                } else {
                    (
                        syn::Term::Pair(left.term, right.term),
                        self.syntax.add_type(syn::Type::Pair(left.typ, right.typ)),
                    )
                };
                self.node(
                    term,
                    typ,
                    left.nodes + right.nodes + 1,
                    left.depth.max(right.depth),
                    left.calls.max(right.calls),
                )?
            }
            Finish::Branch(location) => {
                let no = pop();
                let yes = pop();
                let guard = pop();
                self.branch(location, guard, yes, no)?
            }
            Finish::Action(atom) => {
                let input = pop();
                let atom = match atom {
                    ast::Atom::Read(id) => syn::Atom::Read(BigInt::from(id.get())),
                    ast::Atom::Write(id) => syn::Atom::Write(BigInt::from(id.get())),
                    ast::Atom::Emit(id) => syn::Atom::Emit(BigInt::from(id.get())),
                    ast::Atom::Fail(id) => syn::Atom::Fail(BigInt::from(id.get())),
                    ast::Atom::Close(id) => syn::Atom::Close(BigInt::from(id.get())),
                };
                self.node(
                    syn::Term::Act(atom, input.term),
                    input.typ,
                    input.nodes + 1,
                    input.depth,
                    input.calls,
                )?
            }
            Finish::LetStart(binding, body, env) => {
                let input = pop();
                let typ = self.typ(0, 1, binding.typ)?;
                self.same(typ, input.typ, b"direct form local type differs")?;
                let bind = syn::Bind {
                    name: name(0, 1, &binding.name)?,
                    typ,
                    multiplicity: multiplicity(binding.mult),
                };
                let env = env.add(binding.name, &bind);
                tasks.push(Task::Finish(Finish::LetEnd(bind, input, true)));
                tasks.push(Task::Expression(body, env));
                return Ok(());
            }
            Finish::LetEnd(bind, input, finite) => {
                let body = pop();
                let term = syn::Term::Let(bind, input.term, body.term);
                if finite {
                    let term = self.syntax.add_term(term);
                    self.finite(term, body.typ, input.calls.max(body.calls))?
                } else {
                    self.node(
                        term,
                        body.typ,
                        input.nodes + body.nodes + 1,
                        input.depth.max(body.depth),
                        input.calls.max(body.calls),
                    )?
                }
            }
            Finish::SplitStart(left, right, body, env) => {
                let pair = pop();
                let left_type = self.typ(0, 1, left.typ)?;
                let right_type = self.typ(0, 1, right.typ)?;
                let pair_type = self.syntax.add_type(syn::Type::Pair(left_type, right_type));
                self.same(pair_type, pair.typ, b"direct form split type differs")?;
                let left_bind = syn::Bind {
                    name: name(0, 1, &left.name)?,
                    multiplicity: multiplicity(left.mult),
                    typ: left_type,
                };
                let right_bind = syn::Bind {
                    name: name(0, 1, &right.name)?,
                    multiplicity: multiplicity(right.mult),
                    typ: right_type,
                };
                let env = env.add(left.name, &left_bind).add(right.name, &right_bind);
                tasks.push(Task::Finish(Finish::SplitEnd(left_bind, right_bind, pair)));
                tasks.push(Task::Expression(body, env));
                return Ok(());
            }
            Finish::SplitEnd(left, right, pair) => {
                let body = pop();
                let term = self
                    .syntax
                    .add_term(syn::Term::Unpair(pair.term, left, right, body.term));
                self.finite(term, body.typ, pair.calls.max(body.calls))?
            }
            Finish::OrbitSeed(count, turns, binding, body, env) => {
                let seed = pop();
                let typ = self.typ(0, 1, binding.typ)?;
                self.same(typ, seed.typ, b"direct form orbit seed type differs")?;
                let bind = syn::Bind {
                    name: name(0, 1, &binding.name)?,
                    typ,
                    multiplicity: multiplicity(binding.mult),
                };
                let next = env.clone().add(binding.name, &bind);
                tasks.push(Task::Finish(Finish::OrbitBody(
                    count, turns, bind, seed, env,
                )));
                tasks.push(Task::Expression(body, next));
                return Ok(());
            }
            Finish::OrbitBody(count, turns, bind, seed, env) => {
                let body = pop();
                if let Some(turns) = turns {
                    tasks.push(Task::Finish(Finish::OrbitTurns(count, bind, seed, body)));
                    tasks.push(Task::Expression(turns, env));
                    return Ok(());
                }
                self.orbit(count, None, seed, bind, body)?
            }
            Finish::OrbitTurns(count, bind, seed, body) => {
                self.orbit(count, Some(pop()), seed, bind, body)?
            }
            Finish::Call(requested, count) => {
                let mut args = values.split_off(values.len() - count);
                let target = self.build_in(trail, &requested)?;
                if !target.direct {
                    return Err(named(b"form requires explicit use = ", &requested));
                }
                Self::arity(&target, &requested, args.len())?;
                if target.arity == 0 {
                    let typ = self.syntax.add_type(syn::Type::Unit);
                    args.push(self.node(syn::Term::Unit, typ, 1, 0, 0)?);
                }
                let nodes =
                    target.nodes + args.iter().map(|value| value.nodes).sum::<usize>() + args.len();
                node_limit(nodes)?;
                let term = self.apply(&target, &args)?;
                Core {
                    term,
                    typ: target.function.arrow.out,
                    nodes,
                    depth: max_depth(&args),
                    calls: target.calls.max(max_calls(&args)),
                }
            }
            Finish::UseArgs(value, env) => {
                let count = value.caps.len() + 1;
                let args = values.split_off(values.len() - count);
                let target = self.build_in(trail, &value.name)?;
                Self::arity(&target, &value.name, args.len())?;
                let typ = self.typ(0, 1, value.binding.typ)?;
                self.same(
                    target.function.arrow.out,
                    typ,
                    [b"use result type differs = ".as_slice(), &value.name].concat(),
                )?;
                let bind = syn::Bind {
                    name: name(0, 1, &value.binding.name)?,
                    multiplicity: multiplicity(value.binding.mult),
                    typ,
                };
                let env = env.add(value.binding.name, &bind);
                tasks.push(Task::Finish(Finish::UseBody(target, bind, args)));
                tasks.push(Task::Expression(value.body, env));
                return Ok(());
            }
            Finish::UseBody(target, bind, args) => {
                let body = pop();
                let nodes = target.nodes
                    + body.nodes
                    + args.len()
                    + 1
                    + args.iter().map(|value| value.nodes).sum::<usize>();
                node_limit(nodes)?;
                let used = self.apply(&target, &args)?;
                self.node(
                    syn::Term::Let(bind, used, body.term),
                    body.typ,
                    nodes,
                    body.depth.max(max_depth(&args)),
                    target.calls.max(body.calls).max(max_calls(&args)),
                )?
            }
            Finish::FlowLocal(owner, rest, index, env, host, declared, line, column) => {
                let input = pop();
                let typ = if let Some(declared) = declared {
                    let typ = self.typ(line, column, declared)?;
                    self.same(
                        typ,
                        input.typ,
                        located(line, column, b"direct pure function local type differs").0,
                    )?;
                    typ
                } else {
                    input.typ
                };
                let bind = syn::Bind {
                    name: name(line, column, &host)?,
                    multiplicity: ct::Multiplicity::Many,
                    typ,
                };
                let env = env.add(host, &bind);
                tasks.push(Task::Finish(Finish::LetEnd(bind, input, false)));
                tasks.push(Task::Flow(owner, rest, index, env));
                return Ok(());
            }
        };
        values.push(result);
        Ok(())
    }
}
