// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Interleaved C_parse elaboration and diagnostic origins. Raw grammar remains
//! separately available; only this path constructs a native source program.
use super::super::{
    check, fhe, functions, hfhe, hpar, limit::Limit, lower, poly, spec, syntax as syn, term, types,
};
use super::{
    ast, declaration, elaborate, BigInt, Bind, Body, BodyId, Cause, Error, Expr, ExprId, Field,
    Form, IndexId, Multiplicity, Name, Natural, Parsed, Parser, Result, Span, Stage, TypeId, Veil,
    LOCAL,
};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
};
#[derive(Clone, Debug)]
pub struct CheckedVeil {
    pub name: Name,
    pub info: fhe::Info,
    pub parameter: fhe::Parameter,
    pub host: fhe::Host,
    pub stage: Option<hfhe::Info>,
    pub link: Option<hpar::Link>,
}
#[derive(Clone, Debug)]
struct FormMarks {
    sequence: Vec<Option<Span>>,
    root: Option<Span>,
}
#[derive(Clone, Debug)]
struct Instance {
    name: Name,
    types: Vec<poly::Actual>,
    sizes: Vec<Natural>,
    function: functions::Function,
}
#[derive(Default)]
pub(super) struct State {
    functions: Vec<functions::Function>,
    instances: Vec<Instance>,
    bodies: functions::Bodies,
    expressions: BTreeMap<ExprId, (syn::TermId, Vec<Option<Span>>)>,
    flows: BTreeMap<BodyId, (functions::BodyId, Vec<Option<Span>>)>,
    marks: BTreeMap<Name, FormMarks>,
    types: types::Types,
    terms: term::Terms,
    veils: Vec<CheckedVeil>,
}
impl State {
    fn functions(&self) -> Vec<functions::Function> {
        let mut instances = self.instances.iter().collect::<Vec<_>>();
        instances.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| poly::compare_actuals(&self.types, &left.types, &right.types))
                .then_with(|| left.sizes.cmp(&right.sizes))
        });
        self.functions
            .iter()
            .cloned()
            .chain(instances.into_iter().map(|item| item.function.clone()))
            .collect()
    }
}
pub struct Program {
    pub(super) parsed: Parsed,
    pub(super) state: State,
}
pub struct Lowered {
    pub program: term::Program,
    pub types: types::Types,
    pub terms: term::Terms,
}
pub struct Compiled {
    pub lowered: Lowered,
    pub checked: check::Checked,
    pub origins: Origins,
}
#[derive(Clone, Debug)]
pub struct Origins {
    pub marks: Vec<Option<Span>>,
    pub span: Span,
    pub veils: usize,
    pub veil_depth: Natural,
}
impl Origins {
    pub fn machine_source(&self) -> super::super::machine::Source<'_> {
        super::super::machine::Source {
            marks: &self.marks,
            span: self.span,
            veils: self.veils,
            veil_depth: self.veil_depth,
        }
    }
}
impl Program {
    pub fn parsed(&self) -> &Parsed {
        &self.parsed
    }
    pub fn into_lowered(mut self) -> Result<Lowered> {
        let program = self.lower()?;
        Ok(Lowered {
            program,
            types: self.state.types,
            terms: self.state.terms,
        })
    }
    pub fn into_compiled(mut self) -> Result<Compiled> {
        let (program, checked) = self.compile()?;
        let source = self.machine_source();
        let origins = Origins {
            marks: source.marks.to_vec(),
            span: source.span,
            veils: source.veils,
            veil_depth: source.veil_depth,
        };
        Ok(Compiled {
            lowered: Lowered {
                program,
                types: self.state.types,
                terms: self.state.terms,
            },
            checked,
            origins,
        })
    }
    pub fn name(&self) -> &Name {
        &self.parsed.name
    }
    pub fn types(&self) -> &types::Types {
        &self.state.types
    }
    pub fn terms(&self) -> &term::Terms {
        &self.state.terms
    }
    pub fn body(&self) -> (&functions::Bodies, functions::BodyId) {
        (&self.state.bodies, self.state.flows[&self.parsed.body].0)
    }
    pub fn veils(&self) -> &[CheckedVeil] {
        &self.state.veils
    }
    pub fn body_span(&self) -> Span {
        self.parsed.body_span
    }
    pub fn veil_count(&self) -> usize {
        self.state.veils.len()
    }
    pub fn veil_depth(&self) -> Natural {
        self.state
            .veils
            .iter()
            .map(|veil| veil.info.peak())
            .max()
            .unwrap_or_else(|| Natural::from_u32(0).expect("zero veil depth"))
    }
    pub fn forms(&self) -> Vec<functions::Function> {
        self.state.functions()
    }
    pub fn declarations(&self) -> &[ast::Form] {
        &self.parsed.forms
    }
    pub fn perms(&self) -> &super::super::perm::Set {
        &self.parsed.perms
    }
    pub fn dtypes(&self) -> Vec<(&BigInt, &super::super::data::Decl)> {
        self.parsed
            .data
            .iter()
            .map(|item| (&item.code, &item.elaborated))
            .collect()
    }
    pub fn rtypes(&self) -> Vec<(&BigInt, &super::super::record::Decl)> {
        self.parsed
            .shapes
            .iter()
            .map(|item| (&item.code, &item.elaborated))
            .collect()
    }
    pub fn res(&self, core: &Limit) -> Limit {
        core.maximum(&Limit::level(BigInt::from(self.veil_depth().get())))
    }
    pub fn body_marks(&self) -> &[Option<Span>] {
        &self.state.flows[&self.parsed.body].1
    }
    pub fn machine_source(&self) -> super::super::machine::Source<'_> {
        super::super::machine::Source {
            marks: self.body_marks(),
            span: self.body_span(),
            veils: self.veil_count(),
            veil_depth: self.veil_depth(),
        }
    }
    pub fn binds(&mut self) -> std::result::Result<Vec<syn::Bind>, declaration::Error> {
        self.parsed.ast.declarations.binds_in(
            &self.parsed.sizes,
            &self.parsed.ast.indices,
            &mut self.parsed.ast.syntax,
            &self.parsed.inputs,
        )
    }
    pub fn lower(&mut self) -> Result<term::Program> {
        let inputs = self.binds().map_err(|error| Error {
            cause: Cause::Semantic(Stage::Declaration, error.text()),
            span: self.parsed.body_span,
        })?;
        let functions = self.state.functions();
        let root = self.state.flows[&self.parsed.body].0;
        let result = functions::lower(
            &mut self.parsed.ast.syntax,
            &mut self.state.types,
            &mut self.state.terms,
            &inputs,
            &self.state.bodies,
            &functions,
            root,
        );
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if !matches!(error, functions::Error::Low(_)) {
                    for function in &functions {
                        if let Err(error) = functions::valid(
                            &self.parsed.ast.syntax,
                            &mut self.state.types,
                            &mut self.state.terms,
                            function,
                        ) {
                            let marks = self.state.marks.get(&function.name);
                            let span = marks
                                .and_then(|marks| marks.root)
                                .unwrap_or(self.parsed.body_span);
                            if let functions::Error::Check(_) = &error {
                                let values = function.arrow.values();
                                if let Ok(program) = lower::program(
                                    &self.parsed.ast.syntax,
                                    &mut self.state.types,
                                    &mut self.state.terms,
                                    &values,
                                    function.body,
                                ) {
                                    if let Err(failure) = check::check_in_located(
                                        &mut self.state.types,
                                        &self.state.terms,
                                        &program.inputs,
                                        program.term,
                                    ) {
                                        let names = lower::names(
                                            &self.parsed.ast.syntax,
                                            &values,
                                            function.body,
                                        )
                                        .unwrap_or_default();
                                        let span = marked_failure_span(
                                            span,
                                            marks
                                                .map_or(&[][..], |marks| marks.sequence.as_slice()),
                                            &self.state.terms,
                                            program.term,
                                            failure.term,
                                        );
                                        return Err(Error {
                                            cause: Cause::Semantic(
                                                Stage::Check,
                                                failure.error.text_named(&self.state.types, |id| {
                                                    names
                                                        .iter()
                                                        .find(|(key, _)| *key == id)
                                                        .map(|(_, name)| name.clone())
                                                }),
                                            ),
                                            span,
                                        });
                                    }
                                }
                            }
                            return Err(Error {
                                cause: Cause::Semantic(
                                    Stage::Function,
                                    error.text(&self.state.types),
                                ),
                                span,
                            });
                        }
                    }
                }
                let (stage, text) = match error {
                    functions::Error::Low(error) => (Stage::Lower, error.text()),
                    error => (Stage::Function, error.text(&self.state.types)),
                };
                Err(Error {
                    cause: Cause::Semantic(stage, text),
                    span: self.parsed.body_span,
                })
            }
        }
    }
    pub fn compile(&mut self) -> Result<(term::Program, check::Checked)> {
        let program = self.lower()?;
        let inputs = self.binds().unwrap_or_default();
        let functions = self.state.functions();
        let root = self.state.flows[&self.parsed.body].0;
        let names = functions::names(
            &mut self.parsed.ast.syntax,
            &mut self.state.types,
            &mut self.state.terms,
            &inputs,
            &self.state.bodies,
            &functions,
            root,
        )
        .unwrap_or_default();
        let mut checked = check::check_in_located(
            &mut self.state.types,
            &self.state.terms,
            &program.inputs,
            program.term,
        )
        .map_err(|failure| {
            let span = marked_failure_span(
                self.parsed.body_span,
                self.body_marks(),
                &self.state.terms,
                program.term,
                failure.term,
            );
            Error {
                cause: Cause::Semantic(
                    Stage::Check,
                    failure.error.text_named(&self.state.types, |id| {
                        names
                            .iter()
                            .find(|(key, _)| *key == id)
                            .map(|(_, name)| name.clone())
                    }),
                ),
                span,
            }
        })?;
        self.parsed
            .perms
            .check_info(checked.info())
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Permission, error.text(&self.state.types)),
                span: self.parsed.body_span,
            })?;
        let peak = self
            .state
            .veils
            .iter()
            .map(|veil| veil.info.peak())
            .max()
            .map_or(0, crate::aml::ast::Natural::get);
        checked.raise_resources(&Limit::level(BigInt::from(peak)));
        Ok((program, checked))
    }
    pub fn check(&mut self) -> Result<check::Checked> {
        self.compile().map(|(_, checked)| checked)
    }
}
impl Parser {
    fn raw_expand(&mut self, root: ExprId, span: Span) -> Result<elaborate::Trace> {
        let state = self.native.as_mut().expect("checked parser");
        let mut context = elaborate::Context::new(&self.data, &self.shapes, &self.forms);
        context.functions = state.functions();
        context.types = std::mem::take(&mut state.types);
        context.terms = std::mem::take(&mut state.terms);
        let result = context.expand(&mut self.ast, &self.sizes, root);
        state.types = context.types;
        state.terms = context.terms;
        result.map_err(|error| Error {
            cause: match error.shape {
                Some(elaborate::ShapeFailure::Depth(limit, actual)) => Cause::Depth(limit, actual),
                Some(elaborate::ShapeFailure::Nodes(limit, actual)) => Cause::Nodes(limit, actual),
                None => Cause::Semantic(error.stage, error.message),
            },
            span,
        })
    }
    pub(super) fn expr(&mut self, depth: usize) -> Result<ExprId> {
        let first = self.span();
        let start = self.marks.len();
        let root = self.expression(depth)?;
        if self.native.is_some() {
            let whole = self.joined(first);
            let trace = self.raw_expand(root, first)?;
            let marks = origin_marks(
                &self.ast.syntax,
                whole,
                &trace.nodes,
                &self.marks[start..],
                trace.term,
            );
            self.marks.truncate(start);
            self.marks.extend_from_slice(&marks);
            self.native
                .as_mut()
                .expect("checked parser")
                .expressions
                .insert(root, (trace.term, marks));
        }
        Ok(root)
    }
    fn named_bind(&mut self, bind: &Bind, span: Span) -> Result<syn::Bind> {
        let typ = self.checked_type(bind.typ, span)?;
        Ok(syn::Bind {
            name: bind.name.clone(),
            multiplicity: bind.multiplicity,
            typ,
        })
    }
    pub(super) fn native_form(&mut self, form: &Form, span: Span, start: usize) -> Result<()> {
        if self.native.is_none() {
            return Ok(());
        }
        if form.polymorphic() {
            poly::Function::from_form(form).map_err(|error| Error {
                cause: match error {
                    poly::Error::Spec(error) => Cause::Semantic(
                        Stage::Instance,
                        error.text(&self.native.as_ref().expect("checked parser").types),
                    ),
                    error => Cause::Semantic(
                        Stage::Polymorphic,
                        error.text(&self.native.as_ref().expect("checked parser").types),
                    ),
                },
                span,
            })?;
        } else if form.specialized() {
            spec::Function::from_form(form).map_err(|error| Error {
                cause: Cause::Semantic(
                    Stage::Instance,
                    error.text(&self.native.as_ref().expect("checked parser").types),
                ),
                span,
            })?;
        } else {
            let trace = self.raw_expand(form.body, span)?;
            let out = self.checked_type(form.output, span)?;
            let caps = form
                .captures
                .iter()
                .map(|bind| self.named_bind(bind, span))
                .collect::<Result<Vec<_>>>()?;
            let arg = self.named_bind(&form.argument, span)?;
            let function = functions::Function {
                name: form.name.clone(),
                arrow: functions::Arrow {
                    multiplicity: form.multiplicity,
                    caps,
                    arg,
                    out,
                    effects: form.effects.clone(),
                    limit: form.limit.clone(),
                },
                body: trace.term,
            };
            let spread = spread(&self.ast.syntax, trace.term, Some(form.body_span));
            let raw = &self.marks[start..];
            let sequence = if raw.len() == spread.len() && raw.iter().all(Option::is_some) {
                raw.to_vec()
            } else {
                spread
            };
            let state = self.native.as_mut().expect("checked parser");
            state.functions.push(function);
            state.marks.insert(
                form.name.clone(),
                FormMarks {
                    sequence,
                    root: Some(form.body_span),
                },
            );
            return Ok(());
        }
        self.native.as_mut().expect("checked parser").marks.insert(
            form.name.clone(),
            FormMarks {
                sequence: self.marks[start..].to_vec(),
                root: Some(form.body_span),
            },
        );
        Ok(())
    }
    pub(super) fn native_direct(
        &mut self,
        index: usize,
        values: &[ExprId],
        first: Span,
    ) -> Result<ExprId> {
        let mut args = Vec::new();
        for value in values {
            args.push(self.raw_expand(*value, first)?.term);
        }
        let form = &self.forms[index];
        let state = self.native.as_ref().expect("checked parser");
        let function = functions::find(&state.functions, &form.name)
            .expect("parsed monomorphic direct form")
            .clone();
        let applied =
            functions::apply(&mut self.ast.syntax, &function, &args).map_err(|error| Error {
                cause: Cause::Semantic(Stage::Function, error.text(&state.types)),
                span: first,
            })?;
        let id = Natural::new(&BigInt::from(self.nodes)).ok_or_else(|| Error {
            cause: Cause::Nodes(LOCAL.get(Field::TermNodes) as usize, self.nodes),
            span: first,
        })?;
        let bind = syn::Bind {
            name: Name::dslot(id),
            multiplicity: Multiplicity::Many,
            typ: function.arrow.out,
        };
        let result = self.ast.syntax.add_term(syn::Term::Var(bind.name.clone()));
        let term = self
            .ast
            .syntax
            .add_term(syn::Term::Let(bind, applied, result));
        self.put(Expr::Syn(term), Some(first))
    }
    pub(super) fn native_instance(
        &mut self,
        name: &Name,
        type_args: &[TypeId],
        size_args: &[IndexId],
    ) -> Result<Name> {
        if self.native.is_none() {
            return Ok(name.clone());
        }
        let Some(index) = self.form_find(name) else {
            return Ok(name.clone());
        };
        let form = self.forms[index].clone();
        if !form.polymorphic() && !form.specialized() {
            return Ok(name.clone());
        }
        let span = self.span();
        let state = self.native.as_mut().expect("checked parser");
        let actuals = if form.polymorphic() {
            let function = poly::Function::from_form(&form).map_err(|error| Error {
                cause: Cause::Semantic(Stage::Polymorphic, error.text(&state.types)),
                span,
            })?;
            poly::actuals(
                &mut self.ast,
                &mut state.types,
                &self.sizes,
                function.parameters(),
                type_args,
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Polymorphic, error.text(&state.types)),
                span,
            })?
        } else {
            Vec::new()
        };
        let sizes = spec::args(&self.ast, &self.sizes, size_args).map_err(|error| Error {
            cause: Cause::Semantic(Stage::Instance, error.text(&state.types)),
            span,
        })?;
        if let Some(instance) = state.instances.iter().find(|instance| {
            instance.name == *name
                && instance.sizes == sizes
                && poly::compare_actuals(&state.types, &instance.types, &actuals) == Ordering::Equal
        }) {
            return Ok(instance.function.name.clone());
        }
        let maximum = LOCAL.get(Field::Inputs) as usize;
        if state.instances.len() >= maximum {
            return Err(Error {
                cause: Cause::Semantic(
                    Stage::Function,
                    functions::Error::Functions(maximum, state.instances.len() + 1)
                        .text(&state.types),
                ),
                span,
            });
        }
        let generated = Name::dslot(
            Natural::new(&BigInt::from(state.instances.len()))
                .expect("bounded generated form count"),
        );
        let mut context = elaborate::Context::new(&self.data, &self.shapes, &self.forms);
        context.functions = state.functions();
        let function = if form.polymorphic() {
            let item = poly::Function::from_form(&form).map_err(|error| Error {
                cause: Cause::Semantic(Stage::Polymorphic, error.text(&state.types)),
                span,
            })?;
            poly::mono(
                &mut self.ast,
                &mut state.types,
                &mut state.terms,
                &self.sizes,
                generated.clone(),
                &item,
                &actuals,
                &sizes,
                &mut context,
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Polymorphic, error.text(&state.types)),
                span,
            })?
        } else {
            let item = spec::Function::from_form(&form).map_err(|error| Error {
                cause: Cause::Semantic(Stage::Instance, error.text(&state.types)),
                span,
            })?;
            spec::mono(
                &mut self.ast,
                &mut state.types,
                &mut state.terms,
                &self.sizes,
                generated.clone(),
                &item,
                &sizes,
                &mut context,
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Instance, error.text(&state.types)),
                span,
            })?
        };
        let sequence = spread(&self.ast.syntax, function.body, Some(form.body_span));
        state.marks.insert(
            generated.clone(),
            FormMarks {
                sequence,
                root: Some(form.body_span),
            },
        );
        state.instances.push(Instance {
            name: name.clone(),
            types: actuals,
            sizes,
            function,
        });
        Ok(generated)
    }
    pub(super) fn native_body(&mut self, id: BodyId) -> Result<()> {
        if self.native.is_none() {
            return Ok(());
        }
        let located = self.ast.body(id).clone();
        let at = located.mark;
        let bind = match &located.value {
            Body::Let(bind, _, _) | Body::Use { result: bind, .. } => {
                Some(self.named_bind(bind, at.unwrap_or(self.span()))?)
            }
            _ => None,
        };
        let state = self.native.as_mut().expect("checked parser");
        let get_expr = |id: &ExprId| {
            state
                .expressions
                .get(id)
                .expect("interleaved expression")
                .clone()
        };
        let get_flow = |id: &BodyId| state.flows.get(id).expect("interleaved flow").clone();
        let (body, mut marks) = match located.value {
            Body::Ret(value) => {
                let (value, marks) = get_expr(&value);
                (functions::Body::Ret(value), marks)
            }
            Body::Let(_, value, rest) => {
                let (value, mut marks) = get_expr(&value);
                let (rest, following) = get_flow(&rest);
                marks.extend(following);
                marks.push(at);
                (
                    functions::Body::Let(bind.expect("let bind"), value, rest),
                    marks,
                )
            }
            Body::If(guard, yes, no) => {
                let (guard, mut marks) = get_expr(&guard);
                let (yes, ymarks) = get_flow(&yes);
                let (no, nmarks) = get_flow(&no);
                marks.extend(ymarks);
                marks.extend(nmarks);
                marks.push(at);
                (functions::Body::If(guard, yes, no), marks)
            }
            Body::Use {
                name,
                captures,
                argument,
                rest,
                ..
            } => {
                let mut terms = Vec::new();
                let mut marks = Vec::new();
                for value in captures {
                    let (value, sequence) = get_expr(&value);
                    terms.push(value);
                    marks.extend(sequence);
                }
                let (argument, sequence) = get_expr(&argument);
                marks.extend(sequence);
                if let Some(form) = state.marks.get(&name) {
                    marks.extend_from_slice(&form.sequence);
                }
                marks.extend(std::iter::repeat_n(at, terms.len() + 1));
                let (rest, sequence) = get_flow(&rest);
                marks.extend(sequence);
                marks.push(at);
                (
                    functions::Body::Call(bind.expect("call bind"), name, terms, argument, rest),
                    marks,
                )
            }
        };
        // Ret has no synthetic flow node; other branch roots are already in the
        // sequence above. Keep the buffer owned by its actor-free source parse.
        let body = state.bodies.add(body);
        state.flows.insert(id, (body, std::mem::take(&mut marks)));
        Ok(())
    }
    pub(super) fn native_veil(&mut self, veil: &Veil, span: Span) -> Result<()> {
        if self.native.is_none() {
            return Ok(());
        }
        let fhe_error = |error: fhe::Error| Error {
            cause: Cause::Semantic(Stage::Fhe, error.text()),
            span,
        };
        let config = fhe::Config::new(&veil.depth, &veil.add, &veil.multiply, &veil.renew)
            .map_err(fhe_error)?;
        let profile = fhe::Profile::new(&[(veil.key.clone(), config)]).map_err(fhe_error)?;
        let inputs = veil
            .inputs
            .iter()
            .map(|input| {
                fhe::Input::new(
                    input.name.clone(),
                    input.key.clone(),
                    input.remaining.clone(),
                )
            })
            .collect::<Vec<_>>();
        let environment = fhe::Environment::new(&profile, &inputs).map_err(fhe_error)?;
        let parameters = veil
            .parameters
            .iter()
            .map(|(id, room)| fhe::Parameter::new(id, &veil.key, room))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(fhe_error)?;
        let catalog = fhe::Catalog::new(&parameters).map_err(fhe_error)?;
        let (terms, root) = fhe::Terms::from_ast(&self.ast, veil.body);
        let (info, parameter, stage, link) = if veil.staged {
            let inputs = veil
                .inputs
                .iter()
                .map(|input| {
                    let (terms, slots, query) = input.state.as_ref().expect("staged input state");
                    hfhe::Input::new(
                        input.name.clone(),
                        terms.clone(),
                        slots.clone(),
                        query.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let link = hpar::check_catalog(
                &hpar::production_catalog(),
                &catalog,
                &profile,
                &environment,
                &inputs,
                &terms,
                root,
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Hpar, error.text()),
                span,
            })?;
            (
                link.fhe().clone(),
                link.parameter(),
                Some(link.hfhe()),
                Some(link),
            )
        } else {
            let info = fhe::check(&profile, &environment, &terms, root).map_err(fhe_error)?;
            let parameter = catalog.params(&info).map_err(fhe_error)?;
            (info, parameter, None, None)
        };
        let host = fhe::host(&profile, &environment, &terms, root).map_err(fhe_error)?;
        self.native
            .as_mut()
            .expect("checked parser")
            .veils
            .push(CheckedVeil {
                name: veil.name.clone(),
                info,
                parameter,
                host,
                stage,
                link,
            });
        Ok(())
    }
}
fn named_order(syntax: &syn::Syntax, root: syn::TermId) -> Vec<syn::TermId> {
    let mut out = Vec::new();
    let mut pending = vec![(root, false)];
    while let Some((id, done)) = pending.pop() {
        if done {
            out.push(id);
        } else {
            pending.push((id, true));
            pending.extend(
                syntax
                    .term(id)
                    .children()
                    .into_iter()
                    .rev()
                    .map(|id| (id, false)),
            );
        }
    }
    out
}
fn spread(syntax: &syn::Syntax, root: syn::TermId, mark: Option<Span>) -> Vec<Option<Span>> {
    vec![mark; named_order(syntax, root).len()]
}
fn origin_marks(
    syntax: &syn::Syntax,
    whole: Span,
    trace: &[syn::TermId],
    marks: &[Option<Span>],
    root: syn::TermId,
) -> Vec<Option<Span>> {
    if trace.len() != marks.len() {
        return spread(syntax, root, Some(whole));
    }
    // OCaml's nullary KUnit constructor has one physical identity, including
    // generated units. Other constructors retain their occurrence identities.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Key {
        Unit,
        Node(syn::TermId),
    }
    let key = |id| {
        if matches!(syntax.term(id), syn::Term::Unit) {
            Key::Unit
        } else {
            Key::Node(id)
        }
    };
    let mut origins: BTreeMap<Key, VecDeque<Span>> = BTreeMap::new();
    for (id, mark) in trace.iter().zip(marks) {
        origins
            .entry(key(*id))
            .or_default()
            .push_back(mark.unwrap_or(whole));
    }
    let mut out = Vec::new();
    let mut pending = vec![(root, whole, false)];
    while let Some((id, parent, done)) = pending.pop() {
        if done {
            out.push(Some(parent));
            continue;
        }
        let mark = origins
            .get_mut(&key(id))
            .and_then(|values| {
                let value = values.pop_front()?;
                values.push_back(value);
                Some(value)
            })
            .unwrap_or(parent);
        pending.push((id, mark, true));
        pending.extend(
            syntax
                .term(id)
                .children()
                .into_iter()
                .rev()
                .map(|id| (id, mark, false)),
        );
    }
    out
}
fn marked_failure_span(
    default: Span,
    marks: &[Option<Span>],
    terms: &term::Terms,
    root: term::TermId,
    failed: Option<term::TermId>,
) -> Span {
    let Some(failed) = failed else { return default };
    let mut at = 0;
    let mut pending = vec![(root, false)];
    while let Some((id, done)) = pending.pop() {
        if done {
            if id == failed {
                if let Some(Some(mark)) = marks.get(at) {
                    return *mark;
                }
            }
            at += 1;
        } else {
            pending.push((id, true));
            pending.extend(
                terms
                    .get(id)
                    .children()
                    .into_iter()
                    .rev()
                    .map(|id| (id, false)),
            );
        }
    }
    default
}
