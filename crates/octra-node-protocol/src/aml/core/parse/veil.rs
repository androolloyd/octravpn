// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    BigInt, Cause, Error, Expected, Fhe, FheId, FheInput, Parser, Result, Stage, Veil, S, T, W,
};
impl Parser {
    fn index_value(&mut self) -> Result<BigInt> {
        let mark = self.span();
        let term = self.index()?;
        self.ast
            .indices
            .eval(&self.sizes, term)
            .map(|value| BigInt::from(value.get()))
            .map_err(|error| Error {
                cause: Cause::Semantic(Stage::Index, error.text()),
                span: mark,
            })
    }
    fn named_index(&mut self, name: &[u8]) -> Result<BigInt> {
        self.named(name)?;
        self.symbol(S::Lbrack)?;
        let value = self.index_value()?;
        self.symbol(S::Rbrack)?;
        Ok(value)
    }
    fn word_index(&mut self, name: W) -> Result<BigInt> {
        self.word(name)?;
        self.symbol(S::Lbrack)?;
        let value = self.index_value()?;
        self.symbol(S::Rbrack)?;
        Ok(value)
    }
    fn private_expression(&mut self, depth: usize) -> Result<FheId> {
        let mut left = self.private_product(depth)?;
        while self.symbol_is(S::Plus) {
            self.next();
            let right = self.private_product(depth + 1)?;
            left = self.fhe_put(Fhe::Add(left, right))?;
        }
        Ok(left)
    }
    fn private_product(&mut self, depth: usize) -> Result<FheId> {
        let mut left = self.private_atom(depth)?;
        while self.symbol_is(S::Star) {
            self.next();
            let right = self.private_atom(depth + 1)?;
            left = self.fhe_put(Fhe::Mul(left, right))?;
        }
        Ok(left)
    }
    fn private_atom(&mut self, depth: usize) -> Result<FheId> {
        self.guard(depth)?;
        if self.named_is(b"renew") {
            self.next();
            self.symbol(S::Lparen)?;
            let value = self.private_expression(depth + 1)?;
            self.symbol(S::Rparen)?;
            self.fhe_put(Fhe::Renew(value))
        } else if self.named_is(b"trim") {
            self.next();
            self.symbol(S::Lbrack)?;
            let remaining = self.index_value()?;
            self.symbol(S::Rbrack)?;
            self.symbol(S::Lparen)?;
            let value = self.private_expression(depth + 1)?;
            self.symbol(S::Rparen)?;
            self.fhe_put(Fhe::Trim(remaining, value))
        } else if matches!(self.token(), T::Ident(_)) {
            let name = self.name(false)?;
            self.fhe_put(Fhe::Var(name))
        } else if self.symbol_is(S::Lparen) {
            self.next();
            let value = self.private_expression(depth + 1)?;
            self.symbol(S::Rparen)?;
            Ok(value)
        } else {
            Err(self.need(&[Expected::Ident, Expected::Symbol(S::Lparen)]))
        }
    }
    fn veil_input(&mut self, staged: bool) -> Result<FheInput> {
        self.next();
        let name = self.name(false)?;
        self.symbol(S::Colon)?;
        self.named(b"enc")?;
        self.symbol(S::Lbrack)?;
        let key = self.index_value()?;
        self.symbol(S::Comma)?;
        let remaining = self.index_value()?;
        self.symbol(S::Rbrack)?;
        let state = if staged {
            self.named(b"state")?;
            self.symbol(S::Lbrace)?;
            let terms = self.named_index(b"terms")?;
            self.symbol(S::Comma)?;
            let slots = self.named_index(b"slots")?;
            self.symbol(S::Comma)?;
            let query = self.named_index(b"query")?;
            self.symbol(S::Rbrace)?;
            Some((terms, slots, query))
        } else {
            None
        };
        Ok(FheInput {
            name,
            key,
            remaining,
            state,
        })
    }
    pub(super) fn veil(&mut self) -> Result<()> {
        let mark = self.span();
        self.named(b"veil")?;
        let name = self.name(false)?;
        if self.veils.iter().any(|item| item.name == name) {
            return Err(Error {
                cause: Cause::VeilDuplicate(name.text().to_vec()),
                span: mark,
            });
        }
        let key = self.named_index(b"key")?;
        let depth = self.word_index(W::Depth)?;
        self.word(W::Under)?;
        self.symbol(S::Lbrace)?;
        let add = self.named_index(b"add")?;
        self.symbol(S::Comma)?;
        let multiply = self.named_index(b"mul")?;
        self.symbol(S::Comma)?;
        let renew = self.named_index(b"renew")?;
        self.symbol(S::Rbrace)?;
        let staged = if self.named_is(b"stage") {
            self.next();
            self.symbol(S::Lbrack)?;
            self.named(b"prod")?;
            self.symbol(S::Rbrack)?;
            true
        } else {
            false
        };
        self.symbol(S::Lbrace)?;
        let mut parameters = Vec::new();
        let mut inputs = Vec::new();
        loop {
            if self.named_is(b"param") {
                let parameter_span = self.span();
                self.next();
                self.symbol(S::Lbrack)?;
                let id = self.index_value()?;
                self.symbol(S::Rbrack)?;
                let room = self.named_index(b"room")?;
                // Native validates each parameter before parsing the following
                // veil item, ahead of configuration and environment checks.
                super::super::fhe::Parameter::new(&id, &key, &room).map_err(|error| Error {
                    cause: Cause::Semantic(Stage::Fhe, error.text()),
                    span: parameter_span,
                })?;
                parameters.push((id, room));
            } else if self.word_is(W::Input) {
                inputs.push(self.veil_input(staged)?);
            } else if self.word_is(W::Term) {
                self.next();
                break;
            } else {
                return Err(self.need(&[
                    Expected::Ident,
                    Expected::Word(W::Input),
                    Expected::Word(W::Term),
                ]));
            }
        }
        let body = self.private_expression(0)?;
        self.symbol(S::Rbrace)?;
        let veil = Veil {
            name,
            key,
            depth,
            add,
            multiply,
            renew,
            staged,
            parameters,
            inputs,
            body,
            span: self.joined(mark),
        };
        self.native_veil(&veil, mark)?;
        self.veils.push(veil);
        Ok(())
    }
}
