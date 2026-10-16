// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::{syntax::Atom, term::Relation};
use super::{
    BigInt, Body, BodyId, Cause, Decl, Error, Expected, Expr, ExprId, Field, Form, Located,
    Multiplicity, Name, Natural, Parser, Quantifier, Result, Span, Stage, TypeId, LOCAL, S, T, W,
};
impl Parser {
    pub(super) fn expression(&mut self, depth: usize) -> Result<ExprId> {
        self.guard(depth)?;
        match self.token() {
            T::Word(W::Let) => {
                let first = self.span();
                self.next();
                let bind = self.bind(false)?;
                self.symbol(S::Eq)?;
                let value = self.expression(depth + 1)?;
                self.word(W::In)?;
                let body = self.expression(depth + 1)?;
                self.put(Expr::Let(bind, value, body), Some(first))
            }
            T::Word(W::Split) => self.split(depth),
            T::Word(W::If) => {
                let first = self.span();
                self.next();
                let guard = self.expression(depth + 1)?;
                self.word(W::Then)?;
                let yes = self.expression(depth + 1)?;
                self.word(W::Else)?;
                let no = self.expression(depth + 1)?;
                self.put(Expr::If(guard, yes, no), Some(first))
            }
            T::Word(W::Case) => self.case(depth),
            T::Word(W::Fold) => {
                self.next();
                let source = self.expression(depth + 1)?;
                self.word(W::From)?;
                let seed = self.expression(depth + 1)?;
                self.word(W::With)?;
                let item = self.bind(false)?;
                self.symbol(S::Comma)?;
                let state = self.bind(false)?;
                self.symbol(S::Arrow)?;
                let body = self.expression(depth + 1)?;
                self.put(Expr::Fold(source, seed, item, state, body), None)
            }
            T::Word(word @ (W::Every | W::Any | W::Count | W::Total)) => {
                let mode = match word {
                    W::Every => Quantifier::Every,
                    W::Any => Quantifier::Any,
                    W::Count => Quantifier::Count,
                    _ => Quantifier::Sum,
                };
                self.next();
                let source = self.expression(depth + 1)?;
                self.word(W::With)?;
                let item = self.bind(false)?;
                self.symbol(S::Arrow)?;
                let body = self.expression(depth + 1)?;
                self.put(Expr::Quant(mode, source, item, body), None)
            }
            T::Word(W::Weave | W::Braid | W::Loom) => self.weave(depth),
            T::Word(W::Orbit | W::Wake) => self.orbit(depth),
            T::Word(W::Rift) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let cut = self.index()?;
                self.symbol(S::Comma)?;
                let rest = self.index()?;
                self.symbol(S::Comma)?;
                let elem = self.typ()?;
                self.symbol(S::Rbrack)?;
                self.symbol(S::Lparen)?;
                let value = self.expression(depth + 1)?;
                self.symbol(S::Rparen)?;
                self.put(Expr::Rift(cut, rest, elem, value), None)
            }
            _ => self.order(depth),
        }
    }
    fn split(&mut self, depth: usize) -> Result<ExprId> {
        let first = self.span();
        self.next();
        let value = self.expression(depth + 1)?;
        self.word(W::As)?;
        if matches!(self.token(), T::Ident(_)) {
            let mark = self.span();
            let name = self.name(false)?;
            let index = self.shape_find(&name).ok_or_else(|| Error {
                cause: Cause::ShapeName(name.text().to_vec()),
                span: mark,
            })?;
            self.symbol(S::Lbrace)?;
            let mut fields = Vec::new();
            loop {
                let name = self.name(false)?;
                self.symbol(S::Arrow)?;
                let bind = self.bind(false)?;
                fields.push((name, bind));
                if !self.separator(S::Comma, S::Rbrace)? {
                    break;
                }
            }
            self.word(W::In)?;
            let body = self.expression(depth + 1)?;
            self.put(Expr::RecordSplit(index, value, fields, body), Some(first))
        } else {
            let left = self.bind(false)?;
            self.symbol(S::Comma)?;
            let right = self.bind(false)?;
            self.word(W::In)?;
            let body = self.expression(depth + 1)?;
            self.put(Expr::Unpair(value, left, right, body), Some(first))
        }
    }
    fn case(&mut self, depth: usize) -> Result<ExprId> {
        self.next();
        let value = self.expression(depth + 1)?;
        if self.word_is(W::Of) {
            self.next();
            self.word(W::Good)?;
            let left = self.bind(false)?;
            self.symbol(S::Arrow)?;
            let yes = self.expression(depth + 1)?;
            self.symbol(S::Bar)?;
            self.word(W::Bad)?;
            let right = self.bind(false)?;
            self.symbol(S::Arrow)?;
            let no = self.expression(depth + 1)?;
            self.put(Expr::Case(value, left, yes, right, no), None)
        } else if self.word_is(W::As) {
            self.next();
            let mark = self.span();
            let name = self.name(false)?;
            let index = self.data_find(&name).ok_or_else(|| Error {
                cause: Cause::DataName(name.text().to_vec()),
                span: mark,
            })?;
            self.word(W::Of)?;
            self.symbol(S::Lbrace)?;
            let mut arms = Vec::new();
            loop {
                let name = self.name(false)?;
                let bind = self.bind(false)?;
                self.symbol(S::Arrow)?;
                let body = self.expression(depth + 1)?;
                arms.push((name, bind, body));
                if !self.separator(S::Bar, S::Rbrace)? {
                    break;
                }
            }
            self.put(Expr::DataCase(index, value, arms), None)
        } else {
            Err(self.need(&[Expected::Word(W::Of), Expected::Word(W::As)]))
        }
    }
    fn weave(&mut self, depth: usize) -> Result<ExprId> {
        let T::Word(word) = self.token().clone() else {
            unreachable!()
        };
        self.next();
        self.symbol(S::Lbrack)?;
        let count = self.index()?;
        self.symbol(S::Comma)?;
        let out = self.typ()?;
        self.symbol(S::Rbrack)?;
        let left = if word == W::Loom {
            None
        } else {
            Some(self.expression(depth + 1)?)
        };
        let right = if word == W::Braid {
            self.symbol(S::Comma)?;
            Some(self.expression(depth + 1)?)
        } else {
            None
        };
        self.word(W::With)?;
        let first = self.bind(false)?;
        let second = if word == W::Braid {
            self.symbol(S::Comma)?;
            Some(self.bind(false)?)
        } else {
            None
        };
        self.symbol(S::Arrow)?;
        let body = self.expression(depth + 1)?;
        self.put(
            match (word, left, right, second) {
                (W::Weave, Some(source), _, _) => Expr::Weave(count, out, source, first, body),
                (W::Braid, Some(left), Some(right), Some(second)) => {
                    Expr::Braid(count, out, left, right, first, second, body)
                }
                _ => Expr::Loom(count, out, first, body),
            },
            None,
        )
    }
    fn orbit(&mut self, depth: usize) -> Result<ExprId> {
        let wake = self.word_is(W::Wake);
        self.next();
        self.symbol(S::Lbrack)?;
        let count = self.index()?;
        if !wake && !self.symbol_is(S::Comma) && !self.symbol_is(S::Rbrack) {
            return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rbrack)]));
        }
        let turns = if !wake && self.symbol_is(S::Comma) {
            self.next();
            Some(self.expression(depth + 1)?)
        } else {
            None
        };
        self.symbol(S::Rbrack)?;
        self.word(W::From)?;
        let seed = self.expression(depth + 1)?;
        self.word(W::With)?;
        let item = self.bind(false)?;
        self.symbol(S::Arrow)?;
        let body = self.expression(depth + 1)?;
        self.put(
            if wake {
                Expr::Wake(count, seed, item, body)
            } else if let Some(turns) = turns {
                Expr::OrbitTo(count, turns, seed, item, body)
            } else {
                Expr::Orbit(count, seed, item, body)
            },
            None,
        )
    }
    fn order(&mut self, depth: usize) -> Result<ExprId> {
        let first = self.span();
        let left = self.additive(depth)?;
        let relation = match self.token() {
            T::Symbol(symbol @ (S::EqEq | S::Ne | S::Lt | S::Le | S::Gt | S::Ge)) => *symbol,
            _ => return Ok(left),
        };
        self.next();
        let right = self.additive(depth + 1)?;
        if matches!(relation, S::EqEq | S::Ne) {
            let typ = self.ast.declarations.push(Decl::Int);
            let same = self.put(Expr::Eq(typ, left, right), Some(first))?;
            if relation == S::EqEq {
                Ok(same)
            } else {
                let typ = self.ast.declarations.push(Decl::Bool);
                let value = ExprId(self.ast.expressions.len());
                // Native != adds its literal without a separate parser node or
                // origin mark; the equality itself still consumes one node.
                self.ast.expressions.push(Located {
                    value: Expr::Bool(false),
                    mark: None,
                });
                self.put(Expr::Eq(typ, same, value), Some(first))
            }
        } else {
            let relation = match relation {
                S::Lt => Relation::Lt,
                S::Le => Relation::Le,
                S::Gt => Relation::Gt,
                _ => Relation::Ge,
            };
            self.put(Expr::Cmp(relation, left, right), Some(first))
        }
    }
    fn additive(&mut self, depth: usize) -> Result<ExprId> {
        let first = self.span();
        let mut left = self.product(depth)?;
        loop {
            let plus = self.symbol_is(S::Plus);
            let minus = self.symbol_is(S::Minus);
            if !plus && !minus {
                return Ok(left);
            }
            self.next();
            let right = self.product(depth + 1)?;
            left = self.put(
                if plus {
                    Expr::Add(left, right)
                } else {
                    Expr::Sub(left, right)
                },
                Some(first),
            )?;
        }
    }
    fn product(&mut self, depth: usize) -> Result<ExprId> {
        let first = self.span();
        let mut left = self.atom(depth)?;
        loop {
            let symbol = match self.token() {
                T::Symbol(symbol @ (S::Star | S::Slash | S::Percent)) => *symbol,
                _ => return Ok(left),
            };
            self.next();
            let right = self.atom(depth + 1)?;
            left = self.put(
                match symbol {
                    S::Star => Expr::Mul(left, right),
                    S::Slash => Expr::Div(left, right),
                    _ => Expr::Mod(left, right),
                },
                Some(first),
            )?;
        }
    }
    fn items(
        &mut self,
        depth: usize,
        close: S,
        trailing: bool,
        checked: bool,
    ) -> Result<Vec<ExprId>> {
        let mut values = Vec::new();
        if self.symbol_is(close) {
            self.next();
            return Ok(values);
        }
        loop {
            values.push(if checked {
                self.expr(depth + 1)?
            } else {
                self.expression(depth + 1)?
            });
            if self.symbol_is(S::Comma) {
                self.next();
                if self.symbol_is(close) {
                    if !trailing {
                        return Err(self.need(&[
                            Expected::Natural,
                            Expected::Ident,
                            Expected::Symbol(S::Lparen),
                        ]));
                    }
                    self.next();
                    return Ok(values);
                }
            } else if self.symbol_is(close) {
                self.next();
                return Ok(values);
            } else {
                return Err(self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(close)]));
            }
        }
    }
    fn atom(&mut self, depth: usize) -> Result<ExprId> {
        self.guard(depth)?;
        let first = self.span();
        let value = match self.token().clone() {
            T::Natural(value) => {
                self.next();
                Expr::Int(value)
            }
            T::Symbol(S::Minus) => {
                self.next();
                if let T::Natural(value) = self.token().clone() {
                    self.next();
                    Expr::Int(-value)
                } else {
                    Expr::Neg(self.atom(depth + 1)?)
                }
            }
            T::Hex(value) => {
                self.next();
                Expr::Bytes(value)
            }
            T::Word(W::True) => {
                self.next();
                Expr::Bool(true)
            }
            T::Word(W::False) => {
                self.next();
                Expr::Bool(false)
            }
            T::Word(W::Unit) => {
                self.next();
                Expr::Unit
            }
            T::Ident(_) => {
                let name = self.name(false)?;
                if self.symbol_is(S::Lparen) {
                    return self.direct(depth, first, name);
                }
                Expr::Var(name)
            }
            T::Symbol(S::Lparen) => {
                self.next();
                if self.symbol_is(S::Rparen) {
                    self.next();
                    Expr::Unit
                } else {
                    let left = self.expression(depth + 1)?;
                    if self.symbol_is(S::Comma) {
                        self.next();
                        let right = self.expression(depth + 1)?;
                        self.symbol(S::Rparen)?;
                        Expr::Pair(left, right)
                    } else if self.symbol_is(S::Rparen) {
                        self.next();
                        return Ok(left);
                    } else {
                        return Err(
                            self.need(&[Expected::Symbol(S::Comma), Expected::Symbol(S::Rparen)])
                        );
                    }
                }
            }
            T::Word(word @ (W::Vec | W::Seq)) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let count = if word == W::Seq {
                    let count = self.index()?;
                    self.symbol(S::Comma)?;
                    Some(count)
                } else {
                    None
                };
                let typ = self.typ()?;
                self.symbol(S::Rbrack)?;
                self.symbol(S::Lparen)?;
                let items = self.items(depth, S::Rparen, word == W::Vec, false)?;
                if let Some(count) = count {
                    Expr::Seq(count, typ, items)
                } else {
                    Expr::Vec(typ, items)
                }
            }
            T::Word(W::Make) => return self.make(depth),
            T::Word(word @ (W::Fst | W::Snd | W::Uncons | W::Abs | W::Wide | W::Length)) => {
                self.next();
                self.symbol(S::Lparen)?;
                let value = self.expression(depth + 1)?;
                self.symbol(S::Rparen)?;
                match word {
                    W::Fst => Expr::Fst(value),
                    W::Snd => Expr::Snd(value),
                    W::Uncons => Expr::Uncons(value),
                    W::Abs => Expr::Abs(value),
                    W::Wide => Expr::Wide(value),
                    _ => Expr::Length(value),
                }
            }
            T::Word(word @ (W::Cat | W::Vcat | W::Step)) => {
                self.next();
                self.symbol(S::Lparen)?;
                let left = self.expression(depth + 1)?;
                self.symbol(S::Comma)?;
                let right = self.expression(depth + 1)?;
                self.symbol(S::Rparen)?;
                match word {
                    W::Cat => Expr::Cat(left, right),
                    W::Vcat => Expr::Vcat(left, right),
                    _ => Expr::Step(left, right),
                }
            }
            T::Word(word @ (W::Fit | W::Good | W::Bad | W::Equal)) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let typ = self.typ()?;
                self.symbol(S::Rbrack)?;
                self.symbol(S::Lparen)?;
                let value = self.expression(depth + 1)?;
                let value = if word == W::Equal {
                    self.symbol(S::Comma)?;
                    let right = self.expression(depth + 1)?;
                    Expr::Eq(typ, value, right)
                } else {
                    match word {
                        W::Fit => Expr::Fit(typ, value),
                        W::Good => Expr::Inl(value, typ),
                        _ => Expr::Inr(typ, value),
                    }
                };
                self.symbol(S::Rparen)?;
                value
            }
            T::Word(
                word @ (W::Take
                | W::Drop
                | W::At
                | W::Read
                | W::Write
                | W::Emit
                | W::Fail
                | W::Close),
            ) => {
                self.next();
                if word == W::Close && !self.symbol_is(S::Lbrack) {
                    self.symbol(S::Lparen)?;
                    let value = self.expression(depth + 1)?;
                    self.symbol(S::Rparen)?;
                    Expr::Close(value)
                } else {
                    self.symbol(S::Lbrack)?;
                    let index = self.natural()?;
                    self.symbol(S::Rbrack)?;
                    self.symbol(S::Lparen)?;
                    let value = self.expression(depth + 1)?;
                    self.symbol(S::Rparen)?;
                    match word {
                        W::Take => Expr::Take(index, value),
                        W::Drop => Expr::Drop(index, value),
                        W::At => Expr::At(index, value),
                        _ => Expr::Act(
                            match word {
                                W::Read => Atom::Read(index),
                                W::Write => Atom::Write(index),
                                W::Emit => Atom::Emit(index),
                                W::Fail => Atom::Fail(index),
                                _ => Atom::Close(index),
                            },
                            value,
                        ),
                    }
                }
            }
            _ => {
                return Err(self.need(&[
                    Expected::Natural,
                    Expected::Hex,
                    Expected::Word(W::True),
                    Expected::Word(W::False),
                    Expected::Word(W::Unit),
                    Expected::Ident,
                    Expected::Symbol(S::Lparen),
                    Expected::Word(W::Vec),
                    Expected::Word(W::Seq),
                    Expected::Word(W::Make),
                    Expected::Word(W::Fst),
                    Expected::Word(W::Snd),
                    Expected::Word(W::Equal),
                    Expected::Word(W::Good),
                    Expected::Word(W::Bad),
                    Expected::Word(W::Read),
                    Expected::Word(W::Write),
                    Expected::Word(W::Emit),
                    Expected::Word(W::Fail),
                    Expected::Word(W::Cat),
                    Expected::Word(W::Take),
                    Expected::Word(W::Drop),
                    Expected::Word(W::Vcat),
                    Expected::Word(W::At),
                    Expected::Word(W::Uncons),
                    Expected::Word(W::Step),
                    Expected::Word(W::Close),
                    Expected::Word(W::Abs),
                    Expected::Word(W::Fit),
                    Expected::Word(W::Wide),
                    Expected::Word(W::Length),
                ]))
            }
        };
        self.put(value, Some(first))
    }
    fn make(&mut self, depth: usize) -> Result<ExprId> {
        let mark = self.span();
        self.next();
        let name = self.name(false)?;
        if let Some(index) = self.data_find(&name) {
            let ctor = self.name(false)?;
            self.symbol(S::Lparen)?;
            let payload = self.expression(depth + 1)?;
            self.symbol(S::Rparen)?;
            self.put(Expr::DataMake(index, ctor, payload), None)
        } else if let Some(index) = self.shape_find(&name) {
            self.symbol(S::Lbrace)?;
            let mut fields = Vec::new();
            loop {
                let name = self.name(false)?;
                self.symbol(S::Eq)?;
                let value = self.expression(depth + 1)?;
                fields.push((name, value));
                if !self.separator(S::Comma, S::Rbrace)? {
                    break;
                }
            }
            self.put(Expr::RecordMake(index, fields), None)
        } else {
            Err(Error {
                cause: Cause::DataName(name.text().to_vec()),
                span: mark,
            })
        }
    }
    fn direct(&mut self, depth: usize, first: Span, name: Name) -> Result<ExprId> {
        let types = super::super::types::Types::default();
        let Some(index) = self.form_find(&name) else {
            return Err(Error {
                cause: Cause::Semantic(
                    Stage::Function,
                    super::super::functions::Error::Function(name).text(&types),
                ),
                span: first,
            });
        };
        let form = self.forms[index].clone();
        let direct = !form.polymorphic()
            && !form.specialized()
            && form.effects.is_empty()
            && form
                .captures
                .iter()
                .chain(std::iter::once(&form.argument))
                .all(|bind| bind.multiplicity == Multiplicity::Many)
            && self.raw_data(form.output);
        if !direct {
            return Err(Error {
                cause: Cause::Semantic(
                    Stage::Function,
                    super::super::functions::Error::Direct(name).text(&types),
                ),
                span: first,
            });
        }
        self.next();
        let values = self.items(depth, S::Rparen, true, false)?;
        if self.native.is_some() {
            return self.native_direct(index, &values, first);
        }
        if values.len() != form.captures.len() + 1 {
            return Err(Error {
                cause: Cause::Semantic(
                    Stage::Function,
                    super::super::functions::Error::Arity(
                        name,
                        form.captures.len() + 1,
                        values.len(),
                    )
                    .text(&types),
                ),
                span: first,
            });
        }
        let slot = Natural::new(&BigInt::from(self.nodes)).ok_or_else(|| Error {
            cause: Cause::Nodes(LOCAL.get(Field::TermNodes) as usize, self.nodes),
            span: first,
        })?;
        self.put(Expr::DirectCall(index, values, slot), Some(first))
    }
    fn raw_data(&mut self, typ: TypeId) -> bool {
        let Ok(typ) = self.checked_type(typ, self.span()) else {
            return false;
        };
        let mut types = super::super::types::Types::default();
        super::super::lower::typ(&self.ast.syntax, &mut types, typ)
            .is_ok_and(|typ| types.kind(typ) == super::super::types::Kind::Data)
    }
    pub(super) fn flow(&mut self, depth: usize) -> Result<BodyId> {
        self.guard(depth)?;
        let first = self.span();
        if self.word_is(W::Let) {
            self.next();
            let bind = self.bind(true)?;
            self.symbol(S::Eq)?;
            let value = self.expr(depth + 1)?;
            self.word(W::In)?;
            let rest = self.flow(depth + 1)?;
            self.body_put(Body::Let(bind, value, rest), Some(first), true)
        } else if self.word_is(W::If) {
            self.next();
            let guard = self.expr(depth + 1)?;
            self.word(W::Then)?;
            let yes = self.flow(depth + 1)?;
            self.word(W::Else)?;
            let no = self.flow(depth + 1)?;
            self.body_put(Body::If(guard, yes, no), Some(first), true)
        } else if self.word_is(W::Use) {
            self.use_form(depth)
        } else {
            let value = self.expr(depth)?;
            self.body_put(Body::Ret(value), None, false)
        }
    }
    fn use_form(&mut self, depth: usize) -> Result<BodyId> {
        let first = self.span();
        self.next();
        let name = self.name(false)?;
        let form = self.form_find(&name).map(|index| self.forms[index].clone());
        let mut types = Vec::new();
        let mut sizes = Vec::new();
        if form.as_ref().is_some_and(Form::polymorphic) {
            self.word(W::Kind)?;
            self.symbol(S::Lbrack)?;
            loop {
                types.push(self.typ()?);
                if !self.separator(S::Comma, S::Rbrack)? {
                    break;
                }
            }
        }
        if form.as_ref().is_some_and(|form| {
            form.specialized() && !form.polymorphic() || form.polymorphic() && self.word_is(W::Size)
        }) {
            self.word(W::Size)?;
            self.symbol(S::Lbrack)?;
            loop {
                sizes.push(self.index()?);
                if !self.separator(S::Comma, S::Rbrack)? {
                    break;
                }
            }
        }
        self.symbol(S::Lbrack)?;
        let captures = self.items(depth, S::Rbrack, true, true)?;
        self.symbol(S::Lparen)?;
        let argument = self.expr(depth + 1)?;
        self.symbol(S::Rparen)?;
        self.word(W::As)?;
        let result = self.bind(true)?;
        let name = self.native_instance(&name, &types, &sizes)?;
        self.word(W::In)?;
        let rest = self.flow(depth + 1)?;
        self.body_put(
            Body::Use {
                name,
                types,
                sizes,
                captures,
                argument,
                result,
                rest,
            },
            Some(first),
            true,
        )
    }
}
