// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_raw expansion into named syntax. Types/binders and child terms are
//! evaluated in native order; the trace retains each raw-node occurrence.
use super::super::{
    braid, data, declaration, functions, index, loom, orbit, quant, record, rift,
    rule::{Field, LOCAL},
    spec,
    syntax::{self, Name, Syntax, Term, TermId},
    term::Terms,
    types::{Multiplicity, Types},
    wake, weave, Natural,
};
use super::{
    ast::{Ast, Bind, Data, Expr, ExprId, Form, Quantifier, Shape},
    Stage,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub stage: Stage,
    pub message: Vec<u8>,
    pub shape: Option<ShapeFailure>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeFailure {
    Depth(usize, usize),
    Nodes(usize, usize),
}
impl Failure {
    fn new(stage: Stage, message: impl AsRef<[u8]>) -> Self {
        Self {
            stage,
            message: message.as_ref().to_vec(),
            shape: None,
        }
    }
}
pub type Result<T> = std::result::Result<T, Failure>;
#[derive(Clone, Debug)]
pub struct Trace {
    pub term: TermId,
    pub nodes: Vec<TermId>,
}
/// Data/shape identities come from checked declarations. Function registration
/// follows declaration order and includes any generated specialization.
pub struct Context<'a> {
    pub data: &'a [Data],
    pub shapes: &'a [Shape],
    pub forms: &'a [Form],
    pub functions: Vec<functions::Function>,
    pub types: Types,
    pub terms: Terms,
}
impl<'a> Context<'a> {
    pub fn new(data: &'a [Data], shapes: &'a [Shape], forms: &'a [Form]) -> Self {
        Self {
            data,
            shapes,
            forms,
            functions: Vec::new(),
            types: Types::default(),
            terms: Terms::default(),
        }
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    fn typ(
        &mut self,
        ast: &mut Ast,
        env: &index::Env,
        id: declaration::TypeId,
    ) -> Result<syntax::TypeId> {
        ast.declarations
            .typ_in(env, &ast.indices, &mut ast.syntax, id)
            .map_err(|error| Failure::new(Stage::Declaration, error.text()))
    }
    fn bind(&mut self, ast: &mut Ast, env: &index::Env, bind: &Bind) -> Result<syntax::Bind> {
        let typ = self.typ(ast, env, bind.typ)?;
        Ok(syntax::Bind {
            name: bind.name.clone(),
            multiplicity: bind.multiplicity,
            typ,
        })
    }
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::unused_self)]
    fn index(&self, ast: &Ast, env: &index::Env, id: index::IndexId) -> Result<Natural> {
        ast.indices
            .eval(env, id)
            .map_err(|error| Failure::new(Stage::Index, error.text()))
    }
    fn data_decl(&self, id: usize) -> Result<data::Decl> {
        self.data
            .get(id)
            .map(|item| item.elaborated.clone())
            .ok_or_else(|| Failure::new(Stage::Data, b"raw data declaration absent"))
    }
    fn record_decl(&self, id: usize) -> Result<record::Decl> {
        self.shapes
            .get(id)
            .map(|item| item.elaborated.clone())
            .ok_or_else(|| Failure::new(Stage::Record, b"raw shape declaration absent"))
    }
    pub fn expand(&mut self, ast: &mut Ast, env: &index::Env, root: ExprId) -> Result<Trace> {
        shape(ast, root)?;
        let mut nodes = Vec::new();
        let term = self.term(ast, env, root, &mut nodes)?;
        Ok(Trace { term, nodes })
    }
    fn terms(
        &mut self,
        ast: &mut Ast,
        env: &index::Env,
        values: &[ExprId],
        trace: &mut Vec<TermId>,
    ) -> Result<Vec<TermId>> {
        values
            .iter()
            .map(|value| self.term(ast, env, *value, trace))
            .collect()
    }
    fn term(
        &mut self,
        ast: &mut Ast,
        env: &index::Env,
        id: ExprId,
        trace: &mut Vec<TermId>,
    ) -> Result<TermId> {
        let value = ast.expression(id).value.clone();
        let built = match value {
            Expr::Syn(root) => return Ok(copy_trace(&mut ast.syntax, root, trace)),
            Expr::Unit => Term::Unit,
            Expr::Bool(value) => Term::Bool(value),
            Expr::Int(value) => Term::Int(value),
            Expr::Bytes(value) => Term::Bytes(value),
            Expr::Var(name) => Term::Var(name),
            Expr::Vec(raw, values) => {
                let typ = self.typ(ast, env, raw)?;
                let values = self.terms(ast, env, &values, trace)?;
                Term::Vec(typ, values)
            }
            Expr::Seq(cap, raw, values) => {
                let cap = self.index(ast, env, cap)?;
                let typ = self.typ(ast, env, raw)?;
                let values = self.terms(ast, env, &values, trace)?;
                Term::Seq(cap, typ, values)
            }
            Expr::Let(bind, value, body) => {
                let bind = self.bind(ast, env, &bind)?;
                let value = self.term(ast, env, value, trace)?;
                let body = self.term(ast, env, body, trace)?;
                Term::Let(bind, value, body)
            }
            Expr::If(guard, yes, no) => {
                let guard = self.term(ast, env, guard, trace)?;
                let yes = self.term(ast, env, yes, trace)?;
                let no = self.term(ast, env, no, trace)?;
                Term::If(guard, yes, no)
            }
            Expr::Pair(left, right) => Term::Pair(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Unpair(value, left, right, body) => {
                let value = self.term(ast, env, value, trace)?;
                let left = self.bind(ast, env, &left)?;
                let right = self.bind(ast, env, &right)?;
                let body = self.term(ast, env, body, trace)?;
                Term::Unpair(value, left, right, body)
            }
            Expr::Fst(value) => Term::Fst(self.term(ast, env, value, trace)?),
            Expr::Snd(value) => Term::Snd(self.term(ast, env, value, trace)?),
            Expr::Inl(value, raw) => {
                let value = self.term(ast, env, value, trace)?;
                let typ = self.typ(ast, env, raw)?;
                Term::Inl(value, typ)
            }
            Expr::Inr(raw, value) => {
                let typ = self.typ(ast, env, raw)?;
                let value = self.term(ast, env, value, trace)?;
                Term::Inr(typ, value)
            }
            Expr::Case(value, left, yes, right, no) => {
                let value = self.term(ast, env, value, trace)?;
                let left = self.bind(ast, env, &left)?;
                let yes = self.term(ast, env, yes, trace)?;
                let right = self.bind(ast, env, &right)?;
                let no = self.term(ast, env, no, trace)?;
                Term::Case(value, left, yes, right, no)
            }
            Expr::Act(atom, value) => Term::Act(atom, self.term(ast, env, value, trace)?),
            Expr::Add(left, right) => Term::Add(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Sub(left, right) => Term::Sub(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Mul(left, right) => Term::Mul(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Div(left, right) => Term::Div(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Mod(left, right) => Term::Mod(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Neg(value) => Term::Neg(self.term(ast, env, value, trace)?),
            Expr::Abs(value) => Term::Abs(self.term(ast, env, value, trace)?),
            Expr::Fit(raw, value) => {
                let typ = self.typ(ast, env, raw)?;
                Term::Fit(typ, self.term(ast, env, value, trace)?)
            }
            Expr::Wide(value) => Term::Wide(self.term(ast, env, value, trace)?),
            Expr::Length(value) => Term::Length(self.term(ast, env, value, trace)?),
            Expr::Eq(raw, left, right) => {
                let typ = self.typ(ast, env, raw)?;
                let left = self.term(ast, env, left, trace)?;
                let right = self.term(ast, env, right, trace)?;
                Term::Eq(typ, left, right)
            }
            Expr::Cmp(relation, left, right) => Term::Cmp(
                relation,
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Cat(left, right) => Term::Cat(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Take(index, value) => Term::Take(index, self.term(ast, env, value, trace)?),
            Expr::Drop(index, value) => Term::Drop(index, self.term(ast, env, value, trace)?),
            Expr::Vcat(left, right) => Term::Vcat(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::At(index, value) => Term::At(index, self.term(ast, env, value, trace)?),
            Expr::Uncons(value) => Term::Uncons(self.term(ast, env, value, trace)?),
            Expr::Fold(vector, seed, item, state, body) => {
                let vector = self.term(ast, env, vector, trace)?;
                let seed = self.term(ast, env, seed, trace)?;
                let item = self.bind(ast, env, &item)?;
                let state = self.bind(ast, env, &state)?;
                let body = self.term(ast, env, body, trace)?;
                Term::Vfold(vector, seed, syntax::Fold { item, state, body })
            }
            Expr::Step(left, right) => Term::Step(
                self.term(ast, env, left, trace)?,
                self.term(ast, env, right, trace)?,
            ),
            Expr::Close(value) => Term::Close(self.term(ast, env, value, trace)?),
            Expr::DataMake(decl, name, value) => {
                let value = self.term(ast, env, value, trace)?;
                let result = self
                    .data_decl(decl)?
                    .make(&mut ast.syntax, &name, value)
                    .map_err(|error| Failure::new(Stage::Data, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::DataCase(decl, value, arms) => {
                let value = self.term(ast, env, value, trace)?;
                let mut values = Vec::new();
                for (name, bind, body) in arms {
                    let bind = self.bind(ast, env, &bind)?;
                    let body = self.term(ast, env, body, trace)?;
                    values.push(data::Arm::new(name, bind, body));
                }
                let result = self
                    .data_decl(decl)?
                    .case(&mut ast.syntax, value, &values)
                    .map_err(|error| Failure::new(Stage::Data, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::RecordMake(decl, items) => {
                let mut values = Vec::new();
                for (name, value) in items {
                    values.push(record::Item::new(name, self.term(ast, env, value, trace)?));
                }
                let result = self
                    .record_decl(decl)?
                    .make(&mut ast.syntax, &values)
                    .map_err(|error| Failure::new(Stage::Record, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::RecordSplit(decl, value, picks, body) => {
                let value = self.term(ast, env, value, trace)?;
                let mut values = Vec::new();
                for (name, bind) in picks {
                    values.push(record::Pick::new(name, self.bind(ast, env, &bind)?));
                }
                let body = self.term(ast, env, body, trace)?;
                let result = self
                    .record_decl(decl)?
                    .split(&mut ast.syntax, value, &values, body)
                    .map_err(|error| Failure::new(Stage::Record, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Quant(mode, source, item, body) => {
                let source = self.term(ast, env, source, trace)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let mode = match mode {
                    Quantifier::Every => quant::Mode::Every,
                    Quantifier::Any => quant::Mode::Any,
                    Quantifier::Count => quant::Mode::Count,
                    Quantifier::Sum => quant::Mode::Sum,
                };
                let result = quant::make(&mut ast.syntax, mode, source, &item, body)
                    .map_err(|error| Failure::new(Stage::Quantifier, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Weave(count, out, source, item, body) => {
                let count = self.index(ast, env, count)?;
                let out = self.typ(ast, env, out)?;
                let source = self.term(ast, env, source, trace)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let result = weave::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    out,
                    source,
                    &item,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Weave, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Braid(count, out, left, right, first, second, body) => {
                let count = self.index(ast, env, count)?;
                let out = self.typ(ast, env, out)?;
                let left = self.term(ast, env, left, trace)?;
                let right = self.term(ast, env, right, trace)?;
                let first = self.bind(ast, env, &first)?;
                let second = self.bind(ast, env, &second)?;
                let body = self.term(ast, env, body, trace)?;
                let result = braid::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    out,
                    left,
                    right,
                    &first,
                    &second,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Braid, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Loom(count, out, item, body) => {
                let count = self.index(ast, env, count)?;
                let out = self.typ(ast, env, out)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let result = loom::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    out,
                    &item,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Loom, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Orbit(count, seed, item, body) => {
                let count = self.index(ast, env, count)?;
                let seed = self.term(ast, env, seed, trace)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let result = orbit::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    seed,
                    &item,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Orbit, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::OrbitTo(count, turns, seed, item, body) => {
                let count = self.index(ast, env, count)?;
                let turns = self.term(ast, env, turns, trace)?;
                let seed = self.term(ast, env, seed, trace)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let result = orbit::upto(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    turns,
                    seed,
                    &item,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Orbit, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Wake(count, seed, item, body) => {
                let count = self.index(ast, env, count)?;
                let seed = self.term(ast, env, seed, trace)?;
                let item = self.bind(ast, env, &item)?;
                let body = self.term(ast, env, body, trace)?;
                let result = wake::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    count,
                    seed,
                    &item,
                    body,
                )
                .map_err(|error| Failure::new(Stage::Wake, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::Rift(cut, rest, elem, source) => {
                let cut = self.index(ast, env, cut)?;
                let rest = self.index(ast, env, rest)?;
                let elem = self.typ(ast, env, elem)?;
                let source = self.term(ast, env, source, trace)?;
                let result = rift::make(
                    &mut ast.syntax,
                    &mut self.types,
                    &mut self.terms,
                    cut,
                    rest,
                    elem,
                    source,
                )
                .map_err(|error| Failure::new(Stage::Rift, error.text(&self.types)))?;
                trace.push(result);
                return Ok(result);
            }
            Expr::DirectCall(form, values, slot) => {
                let raw = self
                    .forms
                    .get(form)
                    .ok_or_else(|| Failure::new(Stage::Function, b"raw direct form absent"))?;
                let function = functions::find(&self.functions, &raw.name)
                    .cloned()
                    .ok_or_else(|| {
                        Failure::new(
                            Stage::Function,
                            functions::Error::Function(raw.name.clone()).text(&self.types),
                        )
                    })?;
                let trace_start = trace.len();
                let values = self.terms(ast, env, &values, trace)?;
                let applied = functions::apply(&mut ast.syntax, &function, &values)
                    .map_err(|error| Failure::new(Stage::Function, error.text(&self.types)))?;
                let bind = syntax::Bind {
                    name: Name::dslot(slot),
                    multiplicity: Multiplicity::Many,
                    typ: function.arrow.out,
                };
                let value = ast.syntax.add_term(Term::Var(bind.name.clone()));
                let result = ast.syntax.add_term(Term::Let(bind, applied, value));
                trace.truncate(trace_start);
                return Ok(copy_trace(&mut ast.syntax, result, trace));
            }
        };
        let result = ast.syntax.add_term(built);
        trace.push(result);
        Ok(result)
    }
}
impl spec::Elaborator for Context<'_> {
    fn elaborate(
        &mut self,
        ast: &mut Ast,
        env: &index::Env,
        body: ExprId,
    ) -> std::result::Result<TermId, Vec<u8>> {
        self.expand(ast, env, body)
            .map(|value| value.term)
            .map_err(|error| error.message)
    }
}

pub(super) fn children(value: &Expr) -> Vec<ExprId> {
    match value {
        Expr::Syn(_)
        | Expr::Unit
        | Expr::Bool(_)
        | Expr::Int(_)
        | Expr::Bytes(_)
        | Expr::Var(_) => Vec::new(),
        Expr::Vec(_, values) | Expr::Seq(_, _, values) | Expr::DirectCall(_, values, _) => {
            values.iter().rev().copied().collect()
        }
        Expr::Let(_, left, right)
        | Expr::Pair(left, right)
        | Expr::Add(left, right)
        | Expr::Sub(left, right)
        | Expr::Mul(left, right)
        | Expr::Div(left, right)
        | Expr::Mod(left, right)
        | Expr::Eq(_, left, right)
        | Expr::Cmp(_, left, right)
        | Expr::Cat(left, right)
        | Expr::Vcat(left, right)
        | Expr::Step(left, right)
        | Expr::Unpair(left, _, _, right)
        | Expr::RecordSplit(_, left, _, right)
        | Expr::Quant(_, left, _, right)
        | Expr::Weave(_, _, left, _, right)
        | Expr::Orbit(_, left, _, right)
        | Expr::Wake(_, left, _, right) => vec![*left, *right],
        Expr::If(first, second, third)
        | Expr::Case(first, _, second, _, third)
        | Expr::Fold(first, second, _, _, third)
        | Expr::Braid(_, _, first, second, _, _, third)
        | Expr::OrbitTo(_, first, second, _, third) => vec![*first, *second, *third],
        Expr::Fst(value)
        | Expr::Snd(value)
        | Expr::Inl(value, _)
        | Expr::Inr(_, value)
        | Expr::Act(_, value)
        | Expr::Neg(value)
        | Expr::Abs(value)
        | Expr::Fit(_, value)
        | Expr::Wide(value)
        | Expr::Length(value)
        | Expr::Take(_, value)
        | Expr::Drop(_, value)
        | Expr::At(_, value)
        | Expr::Uncons(value)
        | Expr::Close(value)
        | Expr::DataMake(_, _, value)
        | Expr::Loom(_, _, _, value)
        | Expr::Rift(_, _, _, value) => vec![*value],
        Expr::DataCase(_, value, arms) => std::iter::once(*value)
            .chain(arms.iter().rev().map(|(_, _, body)| *body))
            .collect(),
        Expr::RecordMake(_, values) => values.iter().rev().map(|(_, value)| *value).collect(),
    }
}
fn shape(ast: &Ast, root: ExprId) -> Result<()> {
    enum Source {
        Raw(ExprId),
        Named(TermId),
    }
    let max_depth = LOCAL.get(Field::TermDepth) as usize;
    let max_nodes = LOCAL.get(Field::TermNodes) as usize;
    let mut pending = vec![(0usize, Source::Raw(root))];
    let mut nodes = 0;
    while let Some((depth, source)) = pending.pop() {
        if let Source::Raw(id) = &source {
            if let Expr::Syn(id) = ast.expression(*id).value {
                pending.push((depth, Source::Named(id)));
                continue;
            }
        }
        if depth > max_depth {
            let mut error = Failure::new(
                Stage::Lower,
                format!("raw term depth limit = {max_depth} actual = {depth}"),
            );
            error.shape = Some(ShapeFailure::Depth(max_depth, depth));
            return Err(error);
        }
        if nodes == max_nodes {
            let mut error = Failure::new(
                Stage::Lower,
                format!("raw term nodes limit = {max_nodes} actual = {}", nodes + 1),
            );
            error.shape = Some(ShapeFailure::Nodes(max_nodes, nodes + 1));
            return Err(error);
        }
        nodes += 1;
        match source {
            Source::Raw(id) => pending.extend(
                children(&ast.expression(id).value)
                    .into_iter()
                    .rev()
                    .map(|id| (depth + 1, Source::Raw(id))),
            ),
            Source::Named(id) => {
                let term = ast.syntax.term(id);
                let mut children = term.children();
                if matches!(term, Term::Vec(..) | Term::Seq(..)) {
                    children.reverse();
                }
                pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|id| (depth + 1, Source::Named(id))),
                );
            }
        }
    }
    Ok(())
}
fn copy_trace(syntax: &mut Syntax, root: TermId, trace: &mut Vec<TermId>) -> TermId {
    enum Job {
        Visit(TermId),
        Build(Term, usize),
    }
    let mut pending = vec![Job::Visit(root)];
    let mut values = Vec::new();
    while let Some(job) = pending.pop() {
        match job {
            Job::Visit(id) => {
                let term = syntax.term(id).clone();
                let children = term.children();
                pending.push(Job::Build(term, children.len()));
                pending.extend(children.into_iter().rev().map(Job::Visit));
            }
            Job::Build(term, count) => {
                let children = values.split_off(values.len() - count);
                let mut children = children.into_iter();
                let term = term.map_terms(|_| {
                    children
                        .next()
                        .expect("one copied child per original child")
                });
                let id = syntax.add_term(term);
                trace.push(id);
                values.push(id);
            }
        }
    }
    values.pop().expect("copied source root")
}
