// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native expression precedence, direct forms, calls and storage paths.
use super::{
    limits, Atom, BinOp, Binding, Expr, ExprId, Mult, Name, Natural, Parser, Result, UnOp, Use, S,
    T, W,
};
fn infix(token: &T) -> Option<(usize, BinOp)> {
    Some(match token {
        T::Symbol(S::Or) => (1, BinOp::Or),
        T::Symbol(S::And) => (2, BinOp::And),
        T::Symbol(S::EqEq) => (3, BinOp::Eq),
        T::Symbol(S::BangEq) => (3, BinOp::Neq),
        T::Symbol(S::Lt) => (4, BinOp::Lt),
        T::Symbol(S::Gt) => (4, BinOp::Gt),
        T::Symbol(S::LtEq) => (4, BinOp::Le),
        T::Symbol(S::GtEq) => (4, BinOp::Ge),
        T::Symbol(S::Plus) => (5, BinOp::Add),
        T::Symbol(S::Minus) => (5, BinOp::Sub),
        T::Symbol(S::Star) => (6, BinOp::Mul),
        T::Symbol(S::Slash) => (6, BinOp::Div),
        T::Symbol(S::Percent) => (6, BinOp::Mod),
        _ => return None,
    })
}
fn starts(token: &T) -> bool {
    matches!(
        token,
        T::Word(
            W::Let
                | W::If
                | W::True
                | W::False
                | W::Caller
                | W::Origin
                | W::Epoch
                | W::EpochTime
                | W::Value
                | W::TreeHash
                | W::NodeId
                | W::TxHash
                | W::SelfAddr
                | W::None_
                | W::Some_
                | W::Unwrap
                | W::IsSome
                | W::Balance
                | W::Self_
                | W::Emit
        ) | T::Symbol(S::Minus | S::Bang | S::LBracket | S::LParen)
            | T::Ident(_)
            | T::Integer(_)
            | T::String(_)
    )
}
impl Parser<'_> {
    pub(super) fn expr(&mut self) -> Result<ExprId> {
        self.expr_bp(0, 1)
    }
    fn expr_bp(&mut self, depth: usize, minimum: usize) -> Result<ExprId> {
        if depth > limits::PARSER_DEPTH {
            return Err(self.error("expression nesting exceeds limit"));
        }
        let mut left = self.prefix(depth)?;
        loop {
            let token = self.token()?;
            if token == T::Symbol(S::Question) && minimum <= 1 {
                self.eat();
                let yes = self.expr_bp(depth + 1, 1)?;
                self.expect(T::Symbol(S::Colon))?;
                let no = self.expr_bp(depth + 1, 1)?;
                left = self.nodes.expr(Expr::Ternary(left, yes, no));
            } else if let Some((power, op)) = infix(&token).filter(|(power, _)| *power >= minimum) {
                self.eat();
                let right = self.expr_bp(depth + 1, power + 1)?;
                left = self.nodes.expr(Expr::Binop(op, left, right));
            } else {
                return Ok(left);
            }
        }
    }
    fn prefix(&mut self, mut depth: usize) -> Result<ExprId> {
        let mut ops = vec![];
        loop {
            match self.token()? {
                T::Symbol(S::Minus) => ops.push(UnOp::Neg),
                T::Symbol(S::Bang) => ops.push(UnOp::Not),
                _ => break,
            }
            self.eat();
            if !self.prior {
                depth += 1;
            }
        }
        let mut value = self.prefix_remainder(depth)?;
        for op in ops.into_iter().rev() {
            value = self.nodes.expr(Expr::Unop(op, value));
        }
        Ok(value)
    }
    fn prefix_remainder(&mut self, depth: usize) -> Result<ExprId> {
        if self.prior {
            return self.primary();
        }
        match self.token()? {
            T::Word(W::Let) => {
                self.eat();
                let binding = self.binding()?;
                self.expect(T::Symbol(S::Eq))?;
                let value = self.expr_bp(depth + 1, 1)?;
                self.expect(T::Word(W::In))?;
                let body = self.expr_bp(depth + 1, 1)?;
                Ok(self.nodes.expr(Expr::Let(binding, value, body)))
            }
            T::Word(W::If) => {
                self.eat();
                let guard = self.expr_bp(depth + 1, 1)?;
                self.word(b"then")?;
                let yes = self.expr_bp(depth + 1, 1)?;
                self.expect(T::Word(W::Else))?;
                let no = self.expr_bp(depth + 1, 1)?;
                Ok(self.nodes.expr(Expr::Ternary(guard, yes, no)))
            }
            T::Ident(name) if name == b"split" => self.split(depth),
            T::Ident(name) if name == b"orbit" || name == b"equal" => {
                self.eat();
                if !self.is(T::Symbol(S::LBracket))? {
                    return self.named_remainder(name);
                }
                self.eat();
                if name == b"equal" {
                    let typ = self.typ()?;
                    self.expect(T::Symbol(S::RBracket))?;
                    self.expect(T::Symbol(S::LParen))?;
                    let left = self.expr_bp(depth + 1, 1)?;
                    self.expect(T::Symbol(S::Comma))?;
                    let right = self.expr_bp(depth + 1, 1)?;
                    self.expect(T::Symbol(S::RParen))?;
                    Ok(self.nodes.expr(Expr::Equal(typ, left, right)))
                } else {
                    let count = self.natural(b"expected orbit cap")?;
                    let turns = if self.is(T::Symbol(S::Comma))? {
                        self.eat();
                        Some(self.expr_bp(depth + 1, 1)?)
                    } else {
                        None
                    };
                    self.expect(T::Symbol(S::RBracket))?;
                    self.word(b"from")?;
                    let seed = self.expr_bp(depth + 1, 1)?;
                    self.word(b"with")?;
                    let binding = self.binding()?;
                    self.expect(T::Symbol(S::FatArrow))?;
                    let body = self.expr_bp(depth + 1, 1)?;
                    Ok(self
                        .nodes
                        .expr(Expr::Orbit(count, turns, seed, binding, body)))
                }
            }
            _ => self.primary(),
        }
    }
    fn split(&mut self, depth: usize) -> Result<ExprId> {
        self.eat();
        let value = if self.is(T::Symbol(S::LParen))? {
            let args = self.args()?;
            if !matches!(self.stream.peek()?, T::Ident(name) if name == b"as") {
                return Ok(self.nodes.expr(Expr::Call(b"split".to_vec(), args)));
            }
            match args.as_slice() {
                [value] => *value,
                _ => self.nodes.expr(Expr::Tuple(args)),
            }
        } else if starts(self.stream.peek()?) {
            self.expr_bp(depth + 1, 1)?
        } else {
            return self.named_remainder(b"split".to_vec());
        };
        self.word(b"as")?;
        let left = self.binding()?;
        self.expect(T::Symbol(S::Comma))?;
        let right = self.binding()?;
        self.expect(T::Word(W::In))?;
        let body = self.expr_bp(depth + 1, 1)?;
        Ok(self.nodes.expr(Expr::Split(value, left, right, body)))
    }
    pub(super) fn multiplicity(&mut self) -> Result<Mult> {
        let mult = match self.stream.peek()? {
            T::Ident(name) if name == b"many" => Mult::Many,
            T::Ident(name) if name == b"once" => Mult::Once,
            _ => return Err(self.error("expected many or once")),
        };
        self.eat();
        Ok(mult)
    }
    pub(super) fn binding(&mut self) -> Result<Binding> {
        let mult = self.multiplicity()?;
        let name = self.ident()?;
        self.expect(T::Symbol(S::Colon))?;
        let typ = self.typ()?;
        Ok(Binding { name, mult, typ })
    }
    fn primary(&mut self) -> Result<ExprId> {
        let expr = match self.token()? {
            T::Integer(number) => {
                self.eat();
                Expr::Int(number)
            }
            T::String(raw) => {
                self.eat();
                Expr::String(raw)
            }
            T::Word(W::True | W::False) => {
                let value = self.is(T::Word(W::True))?;
                self.eat();
                Expr::Bool(value)
            }
            T::Word(
                word @ (W::Caller | W::Origin | W::TreeHash | W::NodeId | W::TxHash | W::SelfAddr),
            ) => {
                self.eat();
                match word {
                    W::Caller => Expr::Caller,
                    W::Origin => Expr::Origin,
                    W::TreeHash => Expr::TreeHash,
                    W::NodeId => Expr::NodeId,
                    W::TxHash => Expr::TxHash,
                    W::SelfAddr => Expr::SelfAddr,
                    _ => unreachable!(),
                }
            }
            T::Word(W::Epoch | W::EpochTime | W::Value | W::Balance) => {
                if self.prior {
                    let word = self.token()?;
                    self.eat();
                    let expr = match word {
                        T::Word(W::Epoch) => Expr::Epoch,
                        T::Word(W::EpochTime) => Expr::EpochTime,
                        T::Word(W::Value) => Expr::Value,
                        _ => {
                            self.expect(T::Symbol(S::LParen))?;
                            let value = self.expr()?;
                            self.expect(T::Symbol(S::RParen))?;
                            Expr::Balance(value)
                        }
                    };
                    return Ok(self.nodes.expr(expr));
                }
                let name = self.ident()?;
                return self.named_remainder(name);
            }
            T::Word(W::None_) => {
                self.eat();
                if self.is(T::Symbol(S::LParen))? {
                    self.eat();
                    self.expect(T::Symbol(S::RParen))?;
                }
                Expr::Call(b"none".to_vec(), vec![])
            }
            T::Word(word @ (W::Some_ | W::Unwrap | W::IsSome)) => {
                self.eat();
                self.expect(T::Symbol(S::LParen))?;
                let value = self.expr()?;
                self.expect(T::Symbol(S::RParen))?;
                Expr::Call(
                    match word {
                        W::Some_ => b"some".to_vec(),
                        W::Unwrap => b"unwrap".to_vec(),
                        _ => b"is_some_opt".to_vec(),
                    },
                    vec![value],
                )
            }
            T::Word(W::Self_) => {
                self.eat();
                self.expect(T::Symbol(S::Dot))?;
                let field = self.ident()?;
                let keys = self.indices()?;
                if self.is(T::Symbol(S::Dot))? {
                    self.eat();
                    let first = self.ident()?;
                    let fields = self.storage_path(first)?;
                    Expr::StoragePath(field, keys, fields)
                } else if keys.is_empty() {
                    Expr::Field(field)
                } else {
                    Expr::Index(field, keys)
                }
            }
            T::Symbol(S::LBracket) => {
                self.eat();
                Expr::Array(self.items(S::RBracket)?)
            }
            T::Symbol(S::LParen) => {
                self.eat();
                let first = self.expr()?;
                if !self.is(T::Symbol(S::Comma))? {
                    self.expect(T::Symbol(S::RParen))?;
                    return Ok(first);
                }
                self.eat();
                let mut values = vec![first];
                loop {
                    values.push(self.expr()?);
                    match self.token()? {
                        T::Symbol(S::Comma) => self.eat(),
                        T::Symbol(S::RParen) => {
                            self.eat();
                            break;
                        }
                        _ => return Err(self.error("expected , or ) in tuple")),
                    }
                }
                Expr::Tuple(values)
            }
            T::Ident(name) if !self.prior && name == b"use" => {
                self.eat();
                if self.stream.peek()?.identifier().is_none() {
                    return self.named_remainder(name);
                }
                let name = self.ident()?;
                self.expect(T::Symbol(S::LBracket))?;
                let caps = self.items(S::RBracket)?;
                self.expect(T::Symbol(S::LParen))?;
                let arg = self.expr()?;
                self.expect(T::Symbol(S::RParen))?;
                self.word(b"as")?;
                let binding = self.binding()?;
                self.expect(T::Word(W::In))?;
                let body = self.expr()?;
                Expr::Use(Use {
                    name,
                    caps,
                    arg,
                    binding,
                    body,
                })
            }
            T::Ident(name)
                if !self.prior && matches!(name.as_slice(), b"write" | b"read" | b"fail") =>
            {
                self.eat();
                if !self.is(T::Symbol(S::LBracket))? {
                    return self.named_remainder(name);
                }
                return self.action(match name.as_slice() {
                    b"write" => Atom::Write,
                    b"read" => Atom::Read,
                    _ => Atom::Fail,
                });
            }
            T::Word(W::Emit) if !self.prior => {
                self.eat();
                return self.action(Atom::Emit);
            }
            T::Ident(name) => {
                self.eat();
                return self.named_remainder(name);
            }
            _ => return Err(self.error("expected expression")),
        };
        Ok(self.nodes.expr(expr))
    }
    fn action(&mut self, make: fn(Natural) -> Atom) -> Result<ExprId> {
        self.expect(T::Symbol(S::LBracket))?;
        let kind = self.natural(b"expected effect atom")?;
        self.expect(T::Symbol(S::RBracket))?;
        self.expect(T::Symbol(S::LParen))?;
        let value = self.expr()?;
        self.expect(T::Symbol(S::RParen))?;
        Ok(self.nodes.expr(Expr::Action(make(kind), value)))
    }
    pub(super) fn named_remainder(&mut self, name: Name) -> Result<ExprId> {
        let expr = match self.token()? {
            T::Symbol(S::LParen) => Expr::Call(name, self.args()?),
            T::Symbol(S::Dot) => {
                self.eat();
                Expr::EnumVariant(name, self.ident()?)
            }
            _ => Expr::Var(name),
        };
        Ok(self.nodes.expr(expr))
    }
    pub(super) fn indices(&mut self) -> Result<Vec<ExprId>> {
        let mut out = vec![];
        while self.is(T::Symbol(S::LBracket))? {
            self.eat();
            out.push(self.expr()?);
            self.expect(T::Symbol(S::RBracket))?;
        }
        Ok(out)
    }
    pub(super) fn storage_path(&mut self, first: Name) -> Result<Vec<Name>> {
        let mut out = vec![first];
        while self.is(T::Symbol(S::Dot))? {
            self.eat();
            out.push(self.ident()?);
        }
        Ok(out)
    }
    pub(super) fn args(&mut self) -> Result<Vec<ExprId>> {
        self.expect(T::Symbol(S::LParen))?;
        self.items(S::RParen)
    }
    fn items(&mut self, close: S) -> Result<Vec<ExprId>> {
        let mut out = vec![];
        loop {
            if self.is(T::Symbol(close))? {
                self.eat();
                return Ok(out);
            }
            if !out.is_empty() {
                self.expect(T::Symbol(S::Comma))?;
            }
            out.push(self.expr()?);
        }
    }
}
