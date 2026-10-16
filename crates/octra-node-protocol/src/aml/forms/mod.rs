// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_form direct elaboration. Core checking and evidence construction remain
//! explicit; this module does not grant source or deployment admission.
use super::{
    ast,
    core::{self, functions, syntax as syn, term, types as ct},
    effects, evidence, limits, types,
};
use num_bigint::BigInt;
use std::{collections::BTreeMap, sync::Arc};
mod expression;
mod flow;
mod inference;
mod link;
mod modes;
mod operations;
mod source_check;
mod task;
mod typing;
pub use link::{link, Linked};
use task::{Finish, Task};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub Vec<u8>);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn error(reason: impl AsRef<[u8]>) -> Error {
    Error(reason.as_ref().to_vec())
}
fn located(line: usize, column: usize, reason: impl AsRef<[u8]>) -> Error {
    error(
        [
            format!("line {line} column {column}: ").as_bytes(),
            reason.as_ref(),
        ]
        .concat(),
    )
}
fn named(prefix: &[u8], name: &[u8]) -> Error {
    error([prefix, name].concat())
}
fn name(line: usize, column: usize, value: &[u8]) -> Result<syn::Name> {
    syn::Name::new(value).ok_or_else(|| {
        located(
            line,
            column,
            [b"name is invalid = ".as_slice(), value].concat(),
        )
    })
}
fn multiplicity(value: ast::Mult) -> ct::Multiplicity {
    match value {
        ast::Mult::Once => ct::Multiplicity::One,
        ast::Mult::Many => ct::Multiplicity::Many,
    }
}
#[derive(Clone, Debug)]
pub struct Core {
    pub term: syn::TermId,
    pub typ: syn::TypeId,
    pub nodes: usize,
    pub depth: usize,
    pub calls: usize,
}
#[derive(Clone, Debug)]
pub struct Checked {
    pub function: functions::Function,
    pub nodes: usize,
    pub arity: usize,
    pub calls: usize,
    pub direct: bool,
}
#[derive(Clone, Default)]
struct Env(Arc<Vec<(ast::Name, syn::Name, syn::TypeId)>>);
impl Env {
    fn add(mut self, host: ast::Name, bind: &syn::Bind) -> Self {
        Arc::make_mut(&mut self.0).push((host, bind.name.clone(), bind.typ));
        self
    }
    fn find(&self, name: &[u8]) -> Option<&(ast::Name, syn::Name, syn::TypeId)> {
        self.0.iter().rev().find(|(found, _, _)| found == name)
    }
}
pub struct Elaborator<'a> {
    ast: &'a ast::Ast,
    host: ast::Nodes,
    syntax: syn::Syntax,
    types: ct::Types,
    terms: term::Terms,
    cache: BTreeMap<ast::Name, Checked>,
}
impl<'a> Elaborator<'a> {
    pub fn new(ast: &'a ast::Ast) -> Self {
        Self {
            ast,
            host: ast.nodes.type_arena(),
            syntax: syn::Syntax::default(),
            types: ct::Types::default(),
            terms: term::Terms::default(),
            cache: BTreeMap::new(),
        }
    }
    pub fn syntax(&self) -> &syn::Syntax {
        &self.syntax
    }
    pub fn core_types(&self) -> &ct::Types {
        &self.types
    }
    pub fn core_terms(&self) -> &term::Terms {
        &self.terms
    }
    pub fn cached(&self) -> &BTreeMap<ast::Name, Checked> {
        &self.cache
    }
    fn same(
        &self,
        expected: syn::TypeId,
        actual: syn::TypeId,
        reason: impl AsRef<[u8]>,
    ) -> Result<()> {
        if self.syntax.same_type(expected, actual) {
            Ok(())
        } else {
            Err(error(reason))
        }
    }
    fn node(
        &mut self,
        term: syn::Term,
        typ: syn::TypeId,
        nodes: usize,
        depth: usize,
        calls: usize,
    ) -> Result<Core> {
        node_limit(nodes)?;
        Ok(Core {
            term: self.syntax.add_term(term),
            typ,
            nodes,
            depth,
            calls,
        })
    }
    fn finite(&self, term: syn::TermId, typ: syn::TypeId, calls: usize) -> Result<Core> {
        let stat = core::finite::stat(&self.syntax, term).map_err(|failure| match failure {
            core::finite::Error::Nodes(actual) => error(format!(
                "direct form node limit = {} actual = {actual}",
                core::rule::LOCAL.get(core::rule::Field::TermNodes)
            )),
            core::finite::Error::Depth(actual) => error(format!(
                "direct form depth limit = {} actual = {actual}",
                core::rule::LOCAL.get(core::rule::Field::TermDepth)
            )),
        })?;
        node_limit(stat.nodes)?;
        Ok(Core {
            term,
            typ,
            nodes: stat.nodes,
            depth: stat.depth,
            calls,
        })
    }
    fn binding(&mut self, line: usize, column: usize, value: &ast::Binding) -> Result<syn::Bind> {
        let name = name(line, column, &value.name)?;
        let typ = self.typ(line, column, value.typ)?;
        Ok(syn::Bind {
            name,
            typ,
            multiplicity: multiplicity(value.mult),
        })
    }
    fn declared(&self, name: &[u8]) -> bool {
        self.ast.contract.forms.iter().any(|form| form.name == name)
            || self
                .ast
                .contract
                .functions
                .iter()
                .any(|function| function.name == name)
    }
    pub fn build(&mut self, name: &[u8]) -> Result<Checked> {
        self.build_in(&[], name)
    }
    fn build_in(&mut self, trail: &[ast::Name], requested: &[u8]) -> Result<Checked> {
        if trail.iter().any(|name| name == requested) {
            return Err(named(b"direct form recursion is forbidden = ", requested));
        }
        if let Some(checked) = self.cache.get(requested) {
            call_depth(trail.len() + checked.calls)?;
            return Ok(checked.clone());
        }
        if trail.len() >= limits::CALL_DEPTH {
            return Err(depth_error(trail.len() + 1));
        }
        let (line, column, params, ret, mode, marks, limit, source) = if let Some(form) = self
            .ast
            .contract
            .forms
            .iter()
            .find(|form| form.name == requested)
        {
            (
                form.line,
                form.column,
                form.params.clone(),
                form.ret,
                form.mult,
                form.marks.clone(),
                form.limit.clone(),
                task::Source::Expression(form.body),
            )
        } else if let Some(function) = self
            .ast
            .contract
            .functions
            .iter()
            .find(|function| function.name == requested)
        {
            let line = types::block_line(&self.ast.nodes, &function.body);
            if !function.pure
                || function.payable
                || function.nonreentrant
                || function.params.iter().any(|param| param.refine.is_some())
            {
                return Err(located(
                    line,
                    1,
                    [
                        b"function cannot enter a direct form = ".as_slice(),
                        requested,
                    ]
                    .concat(),
                ));
            }
            let params = function
                .params
                .iter()
                .map(|param| ast::Binding {
                    name: param.name.clone(),
                    typ: param.typ,
                    mult: ast::Mult::Many,
                })
                .collect();
            (
                line,
                1,
                params,
                function.ret,
                ast::Mult::Many,
                vec![],
                None,
                task::Source::Block(Arc::new(task::Owner {
                    name: requested.to_vec(),
                    line,
                    body: function.body.clone().into(),
                })),
            )
        } else {
            return Err(named(b"direct form function is absent = ", requested));
        };
        let mut values = vec![];
        for value in &params {
            values.push(self.binding(line, column, value)?);
        }
        let (caps, arg) = if let Some((arg, caps)) = values.split_last() {
            (caps.to_vec(), arg.clone())
        } else {
            let typ = self.syntax.add_type(syn::Type::Unit);
            (
                vec![],
                syn::Bind {
                    name: syn::Name::slot(core::Natural::from_u32(0).expect("zero slot")),
                    multiplicity: ct::Multiplicity::Many,
                    typ,
                },
            )
        };
        let out = self.typ(line, column, ret)?;
        // The native initial parameter environment chooses the first duplicate;
        // duplicate declarations are diagnosed only after elaborating the body.
        let env = Env(Arc::new(
            values
                .iter()
                .rev()
                .map(|bind| (bind.name.text().to_vec(), bind.name.clone(), bind.typ))
                .collect(),
        ));
        let mut next = trail.to_vec();
        next.push(requested.to_vec());
        let body = match source {
            task::Source::Expression(id) => self.run(&next, Task::Expression(id, env))?,
            task::Source::Block(owner) => {
                self.run(&next, Task::Flow(owner.clone(), owner.body.clone(), 0, env))?
            }
        };
        self.same(
            out,
            body.typ,
            located(
                line,
                column,
                [b"direct form result type differs = ".as_slice(), requested].concat(),
            )
            .0,
        )?;
        let mut arrow = functions::Arrow::new(multiplicity(mode), caps, arg, out);
        arrow.effects = marks.iter().map(|mark| mark.atom).collect();
        arrow.limit = limit.map(|value| core::limit::Limit {
            steps: value.steps,
            depth: value.depth,
            work: value.work,
        });
        let function = functions::Function {
            name: name(line, column, requested)?,
            arrow,
            body: body.term,
        };
        functions::valid(&self.syntax, &mut self.types, &mut self.terms, &function).map_err(
            |failure| {
                let reason = if let functions::Error::Check(failure) = failure {
                    self.check_text(&function.arrow.values(), function.body, &failure)
                } else {
                    failure.text(&self.types)
                };
                located(line, column, reason)
            },
        )?;
        let direct = functions::direct(&self.syntax, &mut self.types, &function);
        let checked = Checked {
            function,
            direct,
            nodes: body.nodes,
            arity: params.len(),
            calls: body.calls + 1,
        };
        self.cache.insert(requested.to_vec(), checked.clone());
        Ok(checked)
    }
    fn check_text(
        &self,
        inputs: &[syn::Bind],
        root: syn::TermId,
        failure: &core::check::Error,
    ) -> Vec<u8> {
        let names = core::lower::names(&self.syntax, inputs, root).unwrap_or_default();
        failure.text_named(&self.types, |id| {
            names
                .iter()
                .find(|(found, _)| *found == id)
                .map(|(_, name)| name.clone())
        })
    }
    fn run(&mut self, trail: &[ast::Name], root: Task) -> Result<Core> {
        let mut tasks = vec![root];
        let mut values = vec![];
        while let Some(task) = tasks.pop() {
            match task {
                Task::Expression(id, env) => self.expression(id, env, &mut tasks, &mut values)?,
                Task::Flow(owner, body, index, env) => {
                    self.flow(owner, body, index, env, &mut tasks)?;
                }
                Task::Finish(finish) => self.finish(trail, finish, &mut tasks, &mut values)?,
            }
        }
        Ok(values.pop().expect("elaborated direct root"))
    }
    pub fn strict(
        &mut self,
        line: usize,
        column: usize,
        values: &[(ast::Name, ast::TypeId)],
        root: ast::ExprId,
    ) -> Result<(Vec<syn::Bind>, Core)> {
        let mut inputs = vec![];
        let mut env = Env::default();
        for (host, typ) in values {
            if let Ok(typ) = self.typ(line, column, *typ) {
                let bind = syn::Bind {
                    name: name(line, column, host)?,
                    multiplicity: ct::Multiplicity::Many,
                    typ,
                };
                env = env.add(host.clone(), &bind);
                inputs.push(bind);
            }
        }
        // Oct_form.strict starts a separate build cache; inference/checking must
        // not add ordinary callees to the linker's direct-entry set.
        let cache = std::mem::take(&mut self.cache);
        let value = self.run(&[], Task::Expression(root, env));
        self.cache = cache;
        let value = value?;
        Ok((inputs, value))
    }
    pub fn check_term(
        &mut self,
        line: usize,
        column: usize,
        values: &[(ast::Name, ast::TypeId)],
        root: ast::ExprId,
    ) -> Result<()> {
        let (inputs, value) = self.strict(line, column, values, root)?;
        let program = core::lower::program(
            &self.syntax,
            &mut self.types,
            &mut self.terms,
            &inputs,
            value.term,
        )
        .map_err(|failure| located(line, column, failure.text()))?;
        core::check::check_in(&mut self.types, &self.terms, &program.inputs, program.term)
            .map_err(|failure| {
                located(line, column, self.check_text(&inputs, value.term, &failure))
            })?;
        Ok(())
    }
    pub fn evidence(&mut self, form: &ast::Form, checked: &Checked) -> Result<evidence::Evidence> {
        let mut binds = vec![];
        for mark in &form.marks {
            let target = match mark.atom {
                ast::Atom::Read(_) | ast::Atom::Write(_) => {
                    effects::Target::State(mark.target.clone())
                }
                ast::Atom::Emit(_) => effects::Target::Event(mark.target.clone()),
                ast::Atom::Fail(_) => effects::Target::Fault(mark.target.clone()),
                ast::Atom::Close(_) => {
                    return Err(located(
                        form.line,
                        form.column,
                        b"direct form close target is unsupported",
                    ))
                }
            };
            binds.push(effects::Bind::new(mark.atom, target));
        }
        let entries = effects::Registry::make(self.ast, &binds)
            .map_err(|failure| located(form.line, form.column, failure.text(&self.types)))?;
        let program = core::lower::program(
            &self.syntax,
            &mut self.types,
            &mut self.terms,
            &checked.function.arrow.values(),
            checked.function.body,
        )
        .map_err(|failure| located(form.line, form.column, failure.text()))?;
        let sealed = entries
            .seal(&mut self.types, &self.terms, &program)
            .map_err(|failure| located(form.line, form.column, failure.text(&self.types)))?;
        evidence::Evidence::make(sealed)
            .map_err(|failure| located(form.line, form.column, failure.text()))
    }
}
fn node_limit(nodes: usize) -> Result<()> {
    let maximum = core::rule::LOCAL.get(core::rule::Field::TermNodes) as usize;
    if nodes <= maximum {
        Ok(())
    } else {
        Err(error(format!(
            "direct form node limit = {maximum} actual = {nodes}"
        )))
    }
}
fn depth_error(actual: usize) -> Error {
    error(format!(
        "direct form call depth max = {} actual = {actual}",
        limits::CALL_DEPTH
    ))
}
fn call_depth(actual: usize) -> Result<()> {
    if actual <= limits::CALL_DEPTH {
        Ok(())
    } else {
        Err(depth_error(actual))
    }
}
fn max_depth(values: &[Core]) -> usize {
    values.iter().map(|value| value.depth).max().unwrap_or(0)
}
fn max_calls(values: &[Core]) -> usize {
    values.iter().map(|value| value.calls).max().unwrap_or(0)
}
