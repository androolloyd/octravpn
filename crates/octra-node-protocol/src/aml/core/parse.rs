// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Standalone C_parse source frontend. Located raw syntax is kept distinct from
//! elaboration, specialization, core checking and proof-bound compilation.
//! Public source callers must bound concurrent parses; each parse owns a
//! dedicated stack to support the adopted 4096-level native syntax profile.
pub mod ast;
pub mod elaborate;
mod error;
mod expressions;
mod heads;
mod native;
mod types;
mod veil;
use super::{
    declaration::{self, Input, Type as Decl, TypeId},
    index::{self, Env, IndexId},
    lexer::{self, Form as Expected, Item, Span, Symbol as S, Token as T, Word as W},
    rule::{Field, LOCAL},
    syntax::Name,
    types::Multiplicity,
    Effects, Natural,
};
pub use ast::Parsed;
use ast::{
    Ast, Bind, Body, BodyId, Data, Expr, ExprId, Fhe, FheId, FheInput, Form, Kind, Law, Located,
    Permission, Quantifier, Shape, Veil,
};
pub use error::{Cause, Error, Stage};
pub use native::{CheckedVeil, Compiled, Lowered, Origins, Program};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, Error>;
struct Parser {
    items: Vec<Item>,
    at: usize,
    nodes: usize,
    ast: Ast,
    sizes: Env,
    inputs: Vec<Input>,
    input_spans: Vec<Span>,
    forms: Vec<Form>,
    data: Vec<Data>,
    shapes: Vec<Shape>,
    permissions: Vec<(BigInt, Permission)>,
    perms: super::perm::Set,
    veils: Vec<Veil>,
    kinds: Vec<(Name, Kind)>,
    marks: Vec<Option<Span>>,
    native: Option<native::State>,
}
impl Parser {
    fn token(&self) -> &T {
        &self.items[self.at].token
    }
    fn span(&self) -> Span {
        self.items[self.at].span
    }
    fn previous(&self) -> Span {
        self.items[self.at.saturating_sub(1)].span
    }
    fn joined(&self, first: Span) -> Span {
        Span {
            first: first.first,
            last: self.previous().last,
        }
    }
    fn is(&self, form: Expected) -> bool {
        self.token().form() == form
    }
    fn word_is(&self, word: W) -> bool {
        self.is(Expected::Word(word))
    }
    fn symbol_is(&self, symbol: S) -> bool {
        self.is(Expected::Symbol(symbol))
    }
    fn named_is(&self, word: &[u8]) -> bool {
        matches!(self.token(),T::Ident(name) if name==word)
    }
    fn next(&mut self) {
        self.at += 1;
    }
    fn error(&self, cause: Cause) -> Error {
        Error {
            cause,
            span: self.span(),
        }
    }
    fn semantic(&self, stage: Stage, detail: impl AsRef<[u8]>) -> Error {
        self.error(Cause::Semantic(stage, detail.as_ref().to_vec()))
    }
    fn need(&self, forms: &[Expected]) -> Error {
        self.error(match self.token() {
            T::Hold(value) => Cause::Held(*value),
            actual => Cause::Need(forms.to_vec(), actual.form()),
        })
    }
    fn take(&mut self, form: Expected) -> Result<()> {
        if self.is(form) {
            self.next();
            Ok(())
        } else {
            Err(self.need(&[form]))
        }
    }
    fn word(&mut self, word: W) -> Result<()> {
        self.take(Expected::Word(word))
    }
    fn symbol(&mut self, symbol: S) -> Result<()> {
        self.take(Expected::Symbol(symbol))
    }
    fn separator(&mut self, separator: S, close: S) -> Result<bool> {
        if self.symbol_is(separator) {
            self.next();
            Ok(true)
        } else if self.symbol_is(close) {
            self.next();
            Ok(false)
        } else {
            Err(self.need(&[Expected::Symbol(separator), Expected::Symbol(close)]))
        }
    }
    fn named(&mut self, name: &[u8]) -> Result<()> {
        match self.token() {
            T::Ident(actual) if actual == name => {
                self.next();
                Ok(())
            }
            T::Ident(actual) => Err(self.error(Cause::Word(name.to_vec(), actual.clone()))),
            _ => Err(self.need(&[Expected::Ident])),
        }
    }
    fn name(&mut self, size: bool) -> Result<Name> {
        let T::Ident(raw) = self.token() else {
            return Err(self.need(&[Expected::Ident]));
        };
        let raw = raw.clone();
        let name = Name::new(&raw).ok_or_else(|| {
            self.error(if size {
                Cause::SizeName(raw)
            } else {
                Cause::Name(raw)
            })
        })?;
        self.next();
        Ok(name)
    }
    fn natural(&mut self) -> Result<BigInt> {
        let T::Natural(value) = self.token() else {
            return Err(self.need(&[Expected::Natural]));
        };
        let value = value.clone();
        self.next();
        Ok(value)
    }
    fn multiplicity(&mut self) -> Result<Multiplicity> {
        let value = match self.token() {
            T::Word(W::Erase) => Multiplicity::Zero,
            T::Word(W::Once) => Multiplicity::One,
            T::Word(W::Many) => Multiplicity::Many,
            _ => {
                return Err(self.need(&[
                    Expected::Word(W::Erase),
                    Expected::Word(W::Once),
                    Expected::Word(W::Many),
                ]))
            }
        };
        self.next();
        Ok(value)
    }
    fn guard(&self, depth: usize) -> Result<()> {
        let maximum = LOCAL.get(Field::TermDepth) as usize;
        if depth > maximum {
            Err(self.error(Cause::Depth(maximum, depth)))
        } else {
            Ok(())
        }
    }
    fn node(&mut self) -> Result<()> {
        let maximum = LOCAL.get(Field::TermNodes) as usize;
        self.nodes += 1;
        if self.nodes > maximum {
            Err(self.error(Cause::Nodes(maximum, self.nodes)))
        } else {
            Ok(())
        }
    }
    fn put(&mut self, value: Expr, first: Option<Span>) -> Result<ExprId> {
        self.node()?;
        let id = ExprId(self.ast.expressions.len());
        let mark = first.map(|first| self.joined(first));
        self.ast.expressions.push(Located { value, mark });
        self.marks.push(mark);
        Ok(id)
    }
    fn body_put(&mut self, value: Body, first: Option<Span>, counted: bool) -> Result<BodyId> {
        if counted {
            self.node()?;
        }
        let id = BodyId(self.ast.bodies.len());
        let mark = first.map(|first| self.joined(first));
        self.ast.bodies.push(Located { value, mark });
        if counted {
            self.marks.push(mark);
        }
        self.native_body(id)?;
        Ok(id)
    }
    fn fhe_put(&mut self, value: Fhe) -> Result<FheId> {
        self.node()?;
        let id = FheId(self.ast.private.len());
        self.ast.private.push(Located { value, mark: None });
        self.marks.push(None);
        Ok(id)
    }
    fn data_find(&self, name: &Name) -> Option<usize> {
        self.data.iter().position(|item| &item.name == name)
    }
    fn shape_find(&self, name: &Name) -> Option<usize> {
        self.shapes.iter().position(|item| &item.name == name)
    }
    fn form_find(&self, name: &Name) -> Option<usize> {
        self.forms.iter().position(|item| &item.name == name)
    }
    fn checked_type(&mut self, typ: TypeId, span: Span) -> Result<super::syntax::TypeId> {
        self.ast
            .declarations
            .typ_in(&self.sizes, &self.ast.indices, &mut self.ast.syntax, typ)
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Declaration, error.text()),
                span,
            })
    }
    fn bind(&mut self, checked: bool) -> Result<Bind> {
        let mark = self.span();
        let multiplicity = self.multiplicity()?;
        let name = self.name(false)?;
        self.symbol(S::Colon)?;
        let typ = self.typ()?;
        if checked {
            self.checked_type(typ, mark)?;
        }
        Ok(Bind {
            name,
            multiplicity,
            typ,
        })
    }
    fn input(&mut self) -> Result<()> {
        self.word(W::Input)?;
        let mark = self.span();
        let bind = self.bind(true)?;
        self.inputs
            .push(Input::new(bind.name.text(), bind.multiplicity, bind.typ));
        self.input_spans.push(mark);
        Ok(())
    }
}

/// Parse the entire standalone grammar into located raw syntax. This API grants
/// no execution or compilation authority: callers must still elaborate all
/// raw constructs and specializations, then perform native core validation.
pub fn syntax(source: &[u8]) -> Result<Parsed> {
    source_owner(source, false).map(|(parsed, _)| parsed)
}
pub fn parse(source: &[u8]) -> Result<Program> {
    let (parsed, state) = source_owner(source, true)?;
    Ok(Program {
        parsed,
        state: state.expect("native parser state"),
    })
}
pub fn source(bytes: &[u8]) -> Result<Lowered> {
    parse(bytes)?
        .into_compiled()
        .map(|compiled| compiled.lowered)
}
fn source_owner(source: &[u8], checked: bool) -> Result<(Parsed, Option<native::State>)> {
    // Native permits 4096 nested term levels. Own the corresponding recursion
    // stack rather than consuming a Tokio worker or an embedder's small stack.
    // The source remains borrowed; all returned arenas are owned and flat.
    std::thread::scope(|scope| {
        let unavailable = |reason: &[u8]| {
            let position = lexer::Position {
                offset: 0,
                line: 1,
                column: 1,
            };
            Error {
                cause: Cause::Unavailable(reason.to_vec()),
                span: Span {
                    first: position,
                    last: position,
                },
            }
        };
        let owner = std::thread::Builder::new()
            .name("aml-source".to_owned())
            .stack_size(128 * 1024 * 1024)
            .spawn_scoped(scope, move || source_parts(source, checked))
            .map_err(|_| unavailable(b"AML source parser worker unavailable"))?;
        owner
            .join()
            .map_err(|_| unavailable(b"AML source parser worker failed"))?
    })
}
fn source_parts(source: &[u8], checked: bool) -> Result<(Parsed, Option<native::State>)> {
    let items = lexer::scan(source).map_err(|error| Error {
        span: error.span,
        cause: Cause::Lex(error),
    })?;
    for item in &items {
        if let T::Hold(value) = item.token {
            return Err(Error {
                cause: Cause::Held(value),
                span: item.span,
            });
        }
    }
    let mut state = Parser {
        items,
        at: 0,
        nodes: 0,
        ast: Ast::default(),
        sizes: Env::default(),
        inputs: Vec::new(),
        input_spans: Vec::new(),
        forms: Vec::new(),
        data: Vec::new(),
        shapes: Vec::new(),
        permissions: Vec::new(),
        perms: super::perm::Set::default(),
        veils: Vec::new(),
        kinds: Vec::new(),
        marks: Vec::new(),
        native: checked.then(native::State::default),
    };
    let first = state.span();
    state.word(W::Program)?;
    let name = state.name(false)?;
    state.symbol(S::Lbrace)?;
    if state.symbol_is(S::Rbrace) {
        return Err(state.error(Cause::Empty));
    }
    state.heads()?;
    state.declarations()?;
    state.forms()?;
    let body_first = state.span();
    let body = state.flow(0)?;
    let body_span = state.joined(body_first);
    let last = state.span();
    state.symbol(S::Rbrace)?;
    state.take(Expected::Eof)?;
    if let Err(error) = state.ast.declarations.binds_in(
        &state.sizes,
        &state.ast.indices,
        &mut state.ast.syntax,
        &state.inputs,
    ) {
        let mark = match &error {
            declaration::Error::Dup(name) => state
                .inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| &input.name == name)
                .nth(1)
                .map(|(at, _)| state.input_spans[at]),
            declaration::Error::Name(name) | declaration::Error::Mode(name, _) => state
                .inputs
                .iter()
                .position(|input| &input.name == name)
                .map(|at| state.input_spans[at]),
            _ => None,
        }
        .unwrap_or(body_span);
        return Err(Error {
            cause: Cause::Semantic(Stage::Declaration, error.text()),
            span: mark,
        });
    }
    let native = state.native.take();
    Ok((
        Parsed {
            perms: state.perms,
            name,
            ast: state.ast,
            sizes: state.sizes,
            inputs: state.inputs,
            input_spans: state.input_spans,
            forms: state.forms,
            data: state.data,
            shapes: state.shapes,
            permissions: state.permissions,
            veils: state.veils,
            body,
            body_span,
            span: Span {
                first: first.first,
                last: last.last,
            },
        },
        native,
    ))
}
