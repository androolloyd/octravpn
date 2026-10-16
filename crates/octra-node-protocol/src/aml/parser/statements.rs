// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Located imperative statements and native storage-update desugaring.
use super::{BinOp, Expr, Parser, Result, Stmt, StmtId, S, T, W};
impl Parser<'_> {
    pub(super) fn block(&mut self) -> Result<Vec<StmtId>> {
        self.expect(T::Symbol(S::LBrace))?;
        let mut statements = vec![];
        loop {
            if self.is(T::Symbol(S::RBrace))? {
                self.eat();
                return Ok(statements);
            }
            statements.push(self.statement()?);
        }
    }
    fn statement(&mut self) -> Result<StmtId> {
        let token = self.token()?;
        let (line, column) = self.stream.location();
        let stmt = match token {
            T::Word(W::Let) => {
                self.eat();
                if self.is(T::Symbol(S::LParen))? {
                    self.eat();
                    let mut names = vec![];
                    loop {
                        let name = self.ident()?;
                        if !self.prior && names.contains(&name) {
                            return Err(self.error(
                                [b"duplicate tuple binding name = ".as_slice(), &name].concat(),
                            ));
                        }
                        names.push(name);
                        match self.token()? {
                            T::Symbol(S::Comma) => self.eat(),
                            T::Symbol(S::RParen) => {
                                self.eat();
                                break;
                            }
                            _ => return Err(self.error("expected , or ) in tuple destructuring")),
                        }
                    }
                    self.expect(T::Symbol(S::Eq))?;
                    Stmt::LetTuple(names, self.expr()?)
                } else {
                    let name = self.ident()?;
                    let typ = if self.is(T::Symbol(S::Colon))? {
                        self.eat();
                        Some(self.typ()?)
                    } else {
                        None
                    };
                    self.expect(T::Symbol(S::Eq))?;
                    Stmt::Let(name, typ, self.expr()?)
                }
            }
            T::Word(W::Return) => {
                self.eat();
                let value = if matches!(
                    self.stream.peek()?,
                    T::Newline | T::Eof | T::Symbol(S::RBrace)
                ) {
                    None
                } else {
                    Some(self.expr()?)
                };
                Stmt::Return(value)
            }
            T::Word(W::Assert) => {
                self.eat();
                Stmt::Assert(self.expr()?)
            }
            T::Word(W::Require) => {
                self.eat();
                self.expect(T::Symbol(S::LParen))?;
                let condition = self.expr()?;
                self.expect(T::Symbol(S::Comma))?;
                let message = self.expr()?;
                self.expect(T::Symbol(S::RParen))?;
                Stmt::Require(condition, message)
            }
            T::Word(W::Emit) => {
                self.eat();
                let name = self.ident()?;
                Stmt::Emit(name, self.args()?)
            }
            T::Word(W::Revert) => {
                self.eat();
                let name = self.ident()?;
                Stmt::RevertError(name, self.args()?)
            }
            T::Word(W::If) => self.if_statement()?,
            T::Word(W::While) => {
                self.eat();
                let condition = self.expr()?;
                Stmt::While(condition, self.block()?)
            }
            T::Word(W::For) => {
                self.eat();
                let name = self.ident()?;
                self.expect(T::Word(W::In))?;
                if self.is(T::Word(W::Self_))? {
                    self.eat();
                    self.expect(T::Symbol(S::Dot))?;
                    let field = self.ident()?;
                    Stmt::ForEach(name, field, self.block()?)
                } else {
                    let start = self.expr()?;
                    self.expect(T::Symbol(S::DotDot))?;
                    let end = self.expr()?;
                    Stmt::For(name, start, end, self.block()?)
                }
            }
            T::Word(W::Match) => {
                self.eat();
                let value = self.expr()?;
                self.expect(T::Symbol(S::LBrace))?;
                let mut arms = vec![];
                loop {
                    if self.is(T::Symbol(S::RBrace))? {
                        self.eat();
                        break;
                    }
                    let name = self.ident()?;
                    self.expect(T::Symbol(S::Dot))?;
                    let variant = self.ident()?;
                    self.expect(T::Symbol(S::FatArrow))?;
                    let body = if self.is(T::Symbol(S::LBrace))? {
                        self.block()?
                    } else {
                        vec![self.statement()?]
                    };
                    arms.push((name, variant, body));
                }
                Stmt::Match(value, arms)
            }
            T::Word(W::Self_) => self.self_statement()?,
            T::Ident(name) if name == b"log" => {
                self.eat();
                Stmt::Emit(b"Log".to_vec(), self.args()?)
            }
            T::Ident(_) => self.ident_statement()?,
            T::Word(W::Epoch | W::EpochTime | W::Value | W::Balance) if !self.prior => {
                self.ident_statement()?
            }
            _ => return Err(self.error("expected statement")),
        };
        let stmt = self.nodes.stmt(stmt);
        if self.prior {
            Ok(stmt)
        } else {
            Ok(self.nodes.stmt(Stmt::Located(line, column, stmt)))
        }
    }
    fn if_statement(&mut self) -> Result<Stmt> {
        let mut arms = vec![];
        let mut otherwise = loop {
            self.eat();
            let condition = self.expr()?;
            let body = self.block()?;
            arms.push((condition, body));
            if !self.is(T::Word(W::Else))? {
                break None;
            }
            self.eat();
            if !self.is(T::Word(W::If))? {
                break Some(self.block()?);
            }
        };
        while let Some((condition, body)) = arms.pop() {
            let statement = Stmt::If(condition, body, otherwise);
            if arms.is_empty() {
                return Ok(statement);
            }
            otherwise = Some(vec![self.nodes.stmt(statement)]);
        }
        unreachable!("if statement has an arm")
    }
    fn compound(&mut self) -> Result<Option<BinOp>> {
        let op = match self.stream.peek()? {
            T::Symbol(S::PlusEq) => BinOp::Add,
            T::Symbol(S::MinusEq) => BinOp::Sub,
            T::Symbol(S::StarEq) => BinOp::Mul,
            T::Symbol(S::SlashEq) => BinOp::Div,
            _ => return Ok(None),
        };
        self.eat();
        Ok(Some(op))
    }
    fn self_statement(&mut self) -> Result<Stmt> {
        self.eat();
        self.expect(T::Symbol(S::Dot))?;
        let field = self.ident()?;
        let keys = if self.is(T::Symbol(S::LBracket))? {
            Some(self.indices()?)
        } else {
            None
        };
        if self.is(T::Symbol(S::Dot))? {
            self.eat();
            let first = self.ident()?;
            if keys.is_none() && self.is(T::Symbol(S::LParen))? {
                return Ok(Stmt::FieldCall(field, first, self.args()?));
            }
            let path = self.storage_path(first)?;
            let op = self.compound()?;
            if op.is_none() {
                self.expect(T::Symbol(S::Eq))?;
            }
            let value = self.expr()?;
            return Ok(match op {
                Some(op) => {
                    let keys = keys.unwrap_or_default();
                    if self.prior {
                        let left = self.nodes.expr(Expr::StoragePath(
                            field.clone(),
                            keys.clone(),
                            path.clone(),
                        ));
                        let value = self.nodes.expr(Expr::Binop(op, left, value));
                        Stmt::StoragePathSet(field, keys, path, value)
                    } else {
                        Stmt::StoragePathUpdate(field, keys, path, op, value)
                    }
                }
                None => Stmt::StoragePathSet(field, keys.unwrap_or_default(), path, value),
            });
        }
        if let Some(keys) = keys {
            let op = self.compound()?;
            if op.is_none() {
                self.expect(T::Symbol(S::Eq))?;
            }
            let value = self.expr()?;
            return Ok(match op {
                Some(op) => {
                    if self.prior {
                        let left = self.nodes.expr(Expr::Index(field.clone(), keys.clone()));
                        let value = self.nodes.expr(Expr::Binop(op, left, value));
                        Stmt::IndexSet(field, keys, value)
                    } else {
                        Stmt::IndexUpdate(field, keys, op, value)
                    }
                }
                None => Stmt::IndexSet(field, keys, value),
            });
        }
        if self.is(T::Symbol(S::Eq))? {
            self.eat();
            return Ok(Stmt::FieldSet(field, self.expr()?));
        }
        if let Some(op) = self.compound()? {
            let right = self.expr()?;
            let left = self.nodes.expr(Expr::Field(field.clone()));
            let value = self.nodes.expr(Expr::Binop(op, left, right));
            return Ok(Stmt::FieldSet(field, value));
        }
        Err(self.error("expected =, [ or . after self.field"))
    }
    fn ident_statement(&mut self) -> Result<Stmt> {
        let name = self.ident()?;
        if self.is(T::Symbol(S::Eq))? {
            self.eat();
            return Ok(Stmt::Assign(name, self.expr()?));
        }
        if let Some(op) = self.compound()? {
            let right = self.expr()?;
            let left = self.nodes.expr(Expr::Var(name.clone()));
            let value = self.nodes.expr(Expr::Binop(op, left, right));
            return Ok(Stmt::Assign(name, value));
        }
        if self.is(T::Symbol(S::LParen))? {
            let args = self.args()?;
            return Ok(Stmt::Expr(self.nodes.expr(Expr::Call(name, args))));
        }
        Err(self.error("expected = or ( after identifier"))
    }
}
