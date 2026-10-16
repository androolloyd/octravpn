// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::{data, limit::Limit, record, Atom};
use super::{
    index, BTreeSet, BigInt, Bind, Cause, Data, Effects, Error, Expected, Field, Form, Kind, Law,
    Name, Natural, Parser, Permission, Result, Shape, Stage, Zero, LOCAL, S, T, W,
};
impl Parser {
    pub(super) fn heads(&mut self) -> Result<()> {
        loop {
            match self.token() {
                T::Word(W::Size | W::Measure) => {
                    let mark = self.span();
                    let literal = self.word_is(W::Size);
                    self.next();
                    let name = self.name(true)?;
                    self.symbol(S::Eq)?;
                    let term = if literal {
                        let value = self.natural()?;
                        self.index_lit(value)?
                    } else {
                        self.index()?
                    };
                    self.sizes =
                        self.sizes
                            .put(&self.ast.indices, name, term)
                            .map_err(|error| Error {
                                cause: match error {
                                    index::Error::Dup(name) => Cause::SizeDuplicate(name),
                                    error => Cause::Semantic(Stage::Index, error.text()),
                                },
                                span: mark,
                            })?;
                }
                T::Word(W::Law) => {
                    let mark = self.span();
                    self.next();
                    let left = self.index()?;
                    let relation = self.index_relation()?;
                    let right = self.index()?;
                    self.ast
                        .indices
                        .hold(&self.sizes, relation, left, right)
                        .map_err(|error| Error {
                            cause: Cause::Semantic(Stage::Index, error.text()),
                            span: mark,
                        })?;
                }
                T::Word(W::Input) => self.input()?,
                T::Ident(_) if self.named_is(b"veil") => return Ok(()),
                T::Word(W::Data | W::Shape | W::Permit | W::Form | W::Term) => return Ok(()),
                _ => {
                    return Err(self.need(&[
                        Expected::Word(W::Size),
                        Expected::Word(W::Measure),
                        Expected::Word(W::Law),
                        Expected::Word(W::Input),
                        Expected::Word(W::Data),
                        Expected::Word(W::Shape),
                        Expected::Word(W::Permit),
                        Expected::Word(W::Form),
                        Expected::Ident,
                        Expected::Word(W::Term),
                    ]))
                }
            }
        }
    }
    pub(super) fn declarations(&mut self) -> Result<()> {
        loop {
            match self.token() {
                T::Word(W::Data) => self.data_declaration(false)?,
                T::Word(W::Shape) => self.data_declaration(true)?,
                T::Word(W::Input) => self.input()?,
                T::Word(W::Permit) => self.permission()?,
                T::Ident(_) if self.named_is(b"veil") => self.veil()?,
                T::Word(W::Form | W::Term) => return Ok(()),
                _ => {
                    return Err(self.need(&[
                        Expected::Word(W::Data),
                        Expected::Word(W::Shape),
                        Expected::Word(W::Input),
                        Expected::Word(W::Permit),
                        Expected::Ident,
                        Expected::Word(W::Form),
                        Expected::Word(W::Term),
                    ]))
                }
            }
        }
    }
    fn index_relation(&mut self) -> Result<index::Relation> {
        if self.symbol_is(S::Eq) {
            self.next();
            Ok(index::Relation::Eq)
        } else if self.symbol_is(S::Le) {
            self.next();
            Ok(index::Relation::Le)
        } else {
            Err(self.need(&[Expected::Symbol(S::Eq), Expected::Symbol(S::Le)]))
        }
    }
    fn permission(&mut self) -> Result<()> {
        let mark = self.span();
        self.next();
        self.word(W::Cap)?;
        self.symbol(S::Lbrack)?;
        let kind = self.natural()?;
        self.symbol(S::Rbrack)?;
        self.symbol(S::Eq)?;
        let policy = if self.word_is(W::Step) {
            self.next();
            if self.symbol_is(S::Plus) {
                self.next();
                self.word(W::Close)?;
                Permission::Both
            } else {
                Permission::Step
            }
        } else if self.word_is(W::Close) {
            self.next();
            Permission::Close
        } else {
            return Err(self.need(&[Expected::Word(W::Step), Expected::Word(W::Close)]));
        };
        self.perms = self.perms.add(&kind, policy).map_err(|error| Error {
            cause: Cause::Semantic(
                Stage::Permission,
                error.text(&super::super::types::Types::default()),
            ),
            span: mark,
        })?;
        self.permissions.push((kind, policy));
        Ok(())
    }
    fn data_declaration(&mut self, shape: bool) -> Result<()> {
        let mark = self.span();
        self.next();
        let name = self.name(false)?;
        if self.data_find(&name).is_some() || self.shape_find(&name).is_some() {
            return Err(Error {
                cause: if shape {
                    Cause::ShapeDuplicate(name.text().to_vec())
                } else {
                    Cause::DataDuplicate(name.text().to_vec())
                },
                span: mark,
            });
        }
        self.word(W::Tag)?;
        let tag_mark = self.span();
        let code = self.natural()?;
        let tag_width = LOCAL.get(Field::Tag) as usize;
        if code < BigInt::zero() || code >= (BigInt::from(1) << tag_width) {
            return Err(Error {
                cause: Cause::Tag(code),
                span: tag_mark,
            });
        }
        let bits = (0..tag_width)
            .map(|bit| code.bit(bit as u64))
            .collect::<Vec<_>>();
        if self.data.iter().any(|item| item.code == code)
            || self.shapes.iter().any(|item| item.code == code)
        {
            return Err(Error {
                cause: Cause::TagDuplicate(code),
                span: tag_mark,
            });
        }
        self.symbol(S::Eq)?;
        let mut fields = Vec::new();
        if shape {
            self.symbol(S::Lbrace)?;
        }
        loop {
            let field = self.name(false)?;
            if shape {
                self.symbol(S::Colon)?;
            } else {
                self.symbol(S::Lparen)?;
            }
            let type_mark = self.span();
            let raw = self.typ()?;
            let typ = self.checked_type(raw, type_mark)?;
            if !shape {
                self.symbol(S::Rparen)?;
            }
            fields.push((field, typ));
            if shape {
                if self.separator(S::Comma, S::Rbrace)? {
                    continue;
                }
            } else if self.symbol_is(S::Bar) {
                self.next();
                continue;
            }
            break;
        }
        let types = super::super::types::Types::default();
        if shape {
            let elaborated = record::Decl::new(
                &mut self.ast.syntax,
                &bits,
                name.clone(),
                fields
                    .iter()
                    .map(|(name, typ)| record::Field::new(name.clone(), *typ))
                    .collect(),
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Record, error.text(&types)),
                span: mark,
            })?;
            self.shapes.push(Shape {
                name,
                code,
                fields,
                typ: elaborated.typ(),
                span: self.joined(mark),
                elaborated,
            });
        } else {
            let elaborated = data::Decl::new(
                &mut self.ast.syntax,
                &bits,
                name.clone(),
                fields
                    .iter()
                    .map(|(name, typ)| data::Constructor::new(name.clone(), *typ))
                    .collect(),
            )
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Data, error.text(&types)),
                span: mark,
            })?;
            self.data.push(Data {
                name,
                code,
                constructors: fields,
                typ: elaborated.typ(),
                span: self.joined(mark),
                elaborated,
            });
        }
        Ok(())
    }
    fn captures(&mut self, checked: bool) -> Result<Vec<Bind>> {
        self.symbol(S::Lbrack)?;
        let mut values = Vec::new();
        if self.symbol_is(S::Rbrack) {
            self.next();
            return Ok(values);
        }
        loop {
            values.push(self.bind(checked)?);
            if self.symbol_is(S::Comma) {
                self.next();
                if self.symbol_is(S::Rbrack) {
                    self.next();
                    return Ok(values);
                }
            } else if self.symbol_is(S::Rbrack) {
                self.next();
                return Ok(values);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrack)]));
            }
        }
    }
    fn form_sizes(&mut self) -> Result<Vec<Name>> {
        self.next();
        self.symbol(S::Lbrack)?;
        let mut values = Vec::new();
        loop {
            values.push(self.name(true)?);
            if self.symbol_is(S::Comma) {
                self.next();
            } else if self.symbol_is(S::Rbrack) {
                self.next();
                return Ok(values);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrack)]));
            }
        }
    }
    fn form_kinds(&mut self) -> Result<Vec<(Name, Kind)>> {
        self.next();
        self.symbol(S::Lbrack)?;
        let mut values = Vec::new();
        loop {
            let name = self.name(false)?;
            self.symbol(S::Colon)?;
            let kind = if self.word_is(W::Data) {
                Kind::Data
            } else if self.word_is(W::Res) {
                Kind::Resource
            } else {
                return Err(self.need(&[Expected::Word(W::Data), Expected::Word(W::Res)]));
            };
            self.next();
            values.push((name, kind));
            if self.symbol_is(S::Comma) {
                self.next();
            } else if self.symbol_is(S::Rbrack) {
                self.next();
                return Ok(values);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrack)]));
            }
        }
    }
    fn form_laws(&mut self) -> Result<Vec<Law>> {
        self.next();
        self.symbol(S::Lbrack)?;
        let mut laws = Vec::new();
        loop {
            let left = self.index()?;
            let relation = self.index_relation()?;
            let right = self.index()?;
            laws.push(Law {
                relation,
                left,
                right,
            });
            if self.symbol_is(S::Comma) {
                self.next();
            } else if self.symbol_is(S::Rbrack) {
                let maximum = LOCAL.get(Field::Inputs) as usize;
                if laws.len() > maximum {
                    return Err(self.semantic(
                        Stage::Instance,
                        format!("form law count limit = {maximum} actual = {}", laws.len()),
                    ));
                }
                self.next();
                return Ok(laws);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrack)]));
            }
        }
    }
    fn marks(&mut self) -> Result<Effects> {
        self.word(W::Marks)?;
        self.symbol(S::Lbrace)?;
        let mut effects = Effects::new();
        if self.symbol_is(S::Rbrace) {
            self.next();
            return Ok(effects);
        }
        loop {
            let mark = self.span();
            let word = match self.token() {
                T::Word(word @ (W::Read | W::Write | W::Emit | W::Fail | W::Close)) => *word,
                _ => {
                    return Err(self.need(&[
                        Expected::Word(W::Read),
                        Expected::Word(W::Write),
                        Expected::Word(W::Emit),
                        Expected::Word(W::Fail),
                        Expected::Word(W::Close),
                    ]))
                }
            };
            self.next();
            self.symbol(S::Lbrack)?;
            let number_mark = self.span();
            let raw = self.natural()?;
            let kind = Natural::new(&raw).ok_or(Error {
                cause: Cause::MarkNatural(raw),
                span: number_mark,
            })?;
            self.symbol(S::Rbrack)?;
            let atom = match word {
                W::Read => Atom::Read(kind),
                W::Write => Atom::Write(kind),
                W::Emit => Atom::Emit(kind),
                W::Fail => Atom::Fail(kind),
                _ => Atom::Close(kind),
            };
            if !effects.insert(atom) {
                return Err(Error {
                    cause: Cause::MarkDuplicate(super::super::atom_text(atom)),
                    span: mark,
                });
            }
            if self.symbol_is(S::Comma) {
                self.next();
                if self.symbol_is(S::Rbrace) {
                    self.next();
                    return Ok(effects);
                }
            } else if self.symbol_is(S::Rbrace) {
                self.next();
                return Ok(effects);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrace)]));
            }
        }
    }
    fn axis(&mut self, word: W) -> Result<BigInt> {
        self.word(word)?;
        self.symbol(S::Lbrack)?;
        let mark = self.span();
        let raw = self.natural()?;
        if Natural::new(&raw).is_none() {
            return Err(Error {
                cause: Cause::UnderNatural(raw),
                span: mark,
            });
        }
        self.symbol(S::Rbrack)?;
        Ok(raw)
    }
    fn under(&mut self) -> Result<Limit> {
        self.word(W::Under)?;
        self.symbol(S::Lbrace)?;
        let steps = self.axis(W::Steps)?;
        self.symbol(S::Comma)?;
        let depth = self.axis(W::Depth)?;
        self.symbol(S::Comma)?;
        let work = self.axis(W::Work)?;
        self.symbol(S::Rbrace)?;
        Ok(Limit { steps, depth, work })
    }
    fn form(&mut self) -> Result<Form> {
        let span = self.span();
        self.next();
        let name = self.name(false)?;
        let kinds = if self.word_is(W::Kind) {
            self.form_kinds()?
        } else {
            Vec::new()
        };
        let sizes = if self.word_is(W::Size) {
            self.form_sizes()?
        } else {
            Vec::new()
        };
        let laws = if !sizes.is_empty() && self.word_is(W::Law) {
            self.form_laws()?
        } else {
            Vec::new()
        };
        self.kinds.clone_from(&kinds);
        let checked = kinds.is_empty() && sizes.is_empty();
        let captures = self.captures(checked)?;
        self.symbol(S::Lparen)?;
        let argument = self.bind(checked)?;
        self.symbol(S::Rparen)?;
        self.symbol(S::Thin)?;
        self.symbol(S::Lbrack)?;
        let multiplicity = self.multiplicity()?;
        self.symbol(S::Rbrack)?;
        let output_mark = self.span();
        let output = self.typ()?;
        let effects = self.marks()?;
        let limit = if self.word_is(W::Under) {
            Some(self.under()?)
        } else {
            None
        };
        self.symbol(S::Eq)?;
        let body_first = self.span();
        let body_marks_start = self.marks.len();
        let body = self.expression(0)?;
        let body_span = self.joined(body_first);
        self.kinds.clear();
        if checked && self.native.is_none() {
            self.checked_type(output, output_mark)?;
        } else if !checked && self.native.is_none() {
            let maximum = LOCAL.get(Field::Inputs) as usize;
            if sizes.len() > maximum {
                return Err(self.semantic(
                    Stage::Instance,
                    format!("form size count limit = {maximum} actual = {}", sizes.len()),
                ));
            }
            let mut names = BTreeSet::new();
            for value in sizes
                .iter()
                .chain(captures.iter().map(|bind| &bind.name))
                .chain(std::iter::once(&argument.name))
            {
                if !names.insert(value) {
                    return Err(Error {
                        cause: Cause::Semantic(
                            Stage::Instance,
                            [b"duplicate form binder = ", value.text()].concat(),
                        ),
                        span: output_mark,
                    });
                }
            }
            if kinds.len() > maximum {
                return Err(Error {
                    cause: Cause::Semantic(
                        Stage::Polymorphic,
                        format!("form kind count limit = {maximum} actual = {}", kinds.len())
                            .into_bytes(),
                    ),
                    span: output_mark,
                });
            }
            let mut names = BTreeSet::new();
            for value in kinds
                .iter()
                .map(|(name, _)| name)
                .chain(sizes.iter())
                .chain(captures.iter().map(|bind| &bind.name))
                .chain(std::iter::once(&argument.name))
            {
                if !names.insert(value) {
                    return Err(Error {
                        cause: Cause::Semantic(
                            Stage::Polymorphic,
                            [b"duplicate form kind binder = ", value.text()].concat(),
                        ),
                        span: output_mark,
                    });
                }
            }
        }
        let form = Form {
            name,
            kinds,
            sizes,
            laws,
            captures,
            argument,
            multiplicity,
            output,
            effects,
            limit,
            body,
            body_span,
            span: self.joined(span),
        };
        self.native_form(&form, output_mark, body_marks_start)?;
        Ok(form)
    }
    pub(super) fn forms(&mut self) -> Result<()> {
        loop {
            if self.word_is(W::Term) {
                self.next();
                return Ok(());
            }
            if !self.word_is(W::Form) {
                return Err(self.need(&[Expected::Word(W::Form), Expected::Word(W::Term)]));
            }
            let mark = self.span();
            let form = self.form()?;
            if self.form_find(&form.name).is_some() {
                return Err(Error {
                    cause: Cause::Semantic(
                        Stage::Function,
                        [b"duplicate name = ", form.name.text()].concat(),
                    ),
                    span: mark,
                });
            }
            self.forms.push(form);
        }
    }
}
