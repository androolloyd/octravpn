// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::super::types::Sign;
use super::{
    index, BigInt, Cause, Decl, Error, Expected, IndexId, Parser, Result, Stage, TypeId, S, T, W,
};
impl Parser {
    pub(super) fn index_lit(&mut self, value: BigInt) -> Result<IndexId> {
        self.ast
            .indices
            .lit(&value)
            .ok_or_else(|| self.semantic(Stage::Index, index::Error::Nat(value).text()))
    }
    pub(super) fn index(&mut self) -> Result<IndexId> {
        let mut left = self.index_product()?;
        loop {
            let add = self.symbol_is(S::Plus);
            let sub = self.symbol_is(S::Minus);
            if !add && !sub {
                return Ok(left);
            }
            self.next();
            let right = self.index_product()?;
            left = if add {
                self.ast.indices.add(left, right)
            } else {
                self.ast.indices.sub(left, right)
            };
        }
    }
    fn index_product(&mut self) -> Result<IndexId> {
        let mut left = self.index_atom()?;
        while self.symbol_is(S::Star) {
            self.next();
            let right = self.index_atom()?;
            left = self.ast.indices.mul(left, right);
        }
        Ok(left)
    }
    fn index_atom(&mut self) -> Result<IndexId> {
        match self.token().clone() {
            T::Natural(value) => {
                self.next();
                self.index_lit(value)
            }
            T::Ident(_) => {
                let name = self.name(true)?;
                Ok(self.ast.indices.var(name))
            }
            T::Word(W::Max) => {
                self.next();
                self.symbol(S::Lparen)?;
                let left = self.index()?;
                self.symbol(S::Comma)?;
                let right = self.index()?;
                self.symbol(S::Rparen)?;
                Ok(self.ast.indices.max(left, right))
            }
            T::Symbol(S::Lparen) => {
                self.next();
                let value = self.index()?;
                self.symbol(S::Rparen)?;
                Ok(value)
            }
            _ => Err(self.need(&[
                Expected::Natural,
                Expected::Ident,
                Expected::Word(W::Max),
                Expected::Symbol(S::Lparen),
            ])),
        }
    }
    pub(super) fn typ(&mut self) -> Result<TypeId> {
        // C_decl products associate right; collect first so an unparenthesized
        // product cannot exhaust the host stack before native type preflight.
        let mut items = vec![self.type_atom()?];
        while self.symbol_is(S::Star) {
            self.next();
            items.push(self.type_atom()?);
        }
        let mut value = items.pop().expect("one type atom");
        while let Some(left) = items.pop() {
            value = self.ast.declarations.push(Decl::Pair(left, value));
        }
        Ok(value)
    }
    fn type_atom(&mut self) -> Result<TypeId> {
        let value = match self.token().clone() {
            T::Word(W::Unit) => {
                self.next();
                Decl::Unit
            }
            T::Word(W::Bool) => {
                self.next();
                Decl::Bool
            }
            T::Word(W::Int) => {
                self.next();
                Decl::Int
            }
            T::Word(word @ (W::Sint | W::Uint | W::Bytes)) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let index = self.index()?;
                self.symbol(S::Rbrack)?;
                match word {
                    W::Sint => Decl::Num(Sign::Signed, index),
                    W::Uint => Decl::Num(Sign::Unsigned, index),
                    _ => Decl::Bytes(index),
                }
            }
            T::Word(word @ (W::Vec | W::Seq)) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let index = self.index()?;
                self.symbol(S::Comma)?;
                let item = self.typ()?;
                self.symbol(S::Rbrack)?;
                if word == W::Vec {
                    Decl::Vec(index, item)
                } else {
                    Decl::Seq(index, item)
                }
            }
            T::Word(W::Cap) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let kind = self.natural()?;
                self.symbol(S::Rbrack)?;
                Decl::Cap(kind)
            }
            T::Word(W::Result) => {
                self.next();
                self.symbol(S::Lbrack)?;
                let good = self.typ()?;
                self.symbol(S::Comma)?;
                let bad = self.typ()?;
                self.symbol(S::Rbrack)?;
                Decl::Result(good, bad)
            }
            T::Ident(_) => {
                let mark = self.span();
                let name = self.name(false)?;
                if self.kinds.iter().any(|(key, _)| key == &name) {
                    Decl::Var(name)
                } else if let Some(at) = self.data_find(&name) {
                    Decl::Exact(self.data[at].typ)
                } else if let Some(at) = self.shape_find(&name) {
                    Decl::Exact(self.shapes[at].typ)
                } else {
                    return Err(Error {
                        cause: Cause::DataName(name.text().to_vec()),
                        span: mark,
                    });
                }
            }
            T::Symbol(S::Lparen) => {
                self.next();
                let value = self.typ()?;
                self.symbol(S::Rparen)?;
                return Ok(value);
            }
            _ => {
                return Err(self.need(&[
                    Expected::Word(W::Unit),
                    Expected::Word(W::Bool),
                    Expected::Word(W::Int),
                    Expected::Word(W::Sint),
                    Expected::Word(W::Uint),
                    Expected::Word(W::Bytes),
                    Expected::Word(W::Vec),
                    Expected::Word(W::Seq),
                    Expected::Word(W::Cap),
                    Expected::Word(W::Result),
                    Expected::Ident,
                    Expected::Symbol(S::Lparen),
                ]))
            }
        };
        Ok(self.ast.declarations.push(value))
    }
}
