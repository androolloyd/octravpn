// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Oct_parse grammar over byte strings and flat syntax arenas.
use super::{
    ast::{
        Ast, Atom, BinOp, Binding, Const, Contract, Declaration, Enum, ErrorDef, Event, Expr,
        ExprId, Form, FormMark, Function, Import, Interface, InterfaceMethod, Invariant, Limit,
        Mult, Name, Natural, Nodes, Param, Refinement, StateField, Stmt, StmtId, Struct, Type,
        TypeId, UnOp, Use, Visibility,
    },
    lexer::{self, Stream, Symbol as S, Token as T, Word as W},
    limits,
};
use num_traits::ToPrimitive;
mod declarations;
mod expressions;
mod statements;
mod types;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Lex(lexer::Error),
    Parse(lexer::Error),
    Native(Vec<u8>),
}
impl From<lexer::Error> for Error {
    fn from(value: lexer::Error) -> Self {
        Self::Lex(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lex(error) | Self::Parse(error) => std::fmt::Display::fmt(error, f),
            Self::Native(reason) => f.write_str(&String::from_utf8_lossy(reason)),
        }
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
struct Parser<'a> {
    prior: bool,
    stream: Stream<'a>,
    nodes: Nodes,
}
impl Parser<'_> {
    fn token(&mut self) -> Result<T> {
        Ok(self.stream.peek()?.clone())
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn is(&mut self, token: T) -> Result<bool> {
        Ok(self.stream.peek()? == &token)
    }
    fn eat(&mut self) {
        self.stream.eat();
    }
    // Keep the native owned-input interface and its diagnostic/arena ownership.
    #[allow(clippy::needless_pass_by_value)]
    fn expect(&mut self, token: T) -> Result<()> {
        self.stream.expect(&token).map_err(Into::into)
    }
    fn error(&self, message: impl AsRef<[u8]>) -> Error {
        let (line, column) = self.stream.location();
        Error::Parse(lexer::Error {
            message: message.as_ref().to_vec(),
            line,
            column,
        })
    }
    fn ident(&mut self) -> Result<Name> {
        match self.stream.peek()?.identifier() {
            Some(name) => {
                let name = name.to_vec();
                self.eat();
                Ok(name)
            }
            None => Err(self.error("expected identifier")),
        }
    }
    fn word(&mut self, word: &[u8]) -> Result<()> {
        if matches!(self.stream.peek()?, T::Ident(name) if name == word) {
            self.eat();
            Ok(())
        } else {
            Err(self.error([b"expected ".as_slice(), word].concat()))
        }
    }
    fn ast_int(&mut self, expected: &[u8]) -> Result<i64> {
        if self.prior {
            let T::Integer(value) = self.token()? else {
                return Err(self.error(expected));
            };
            self.eat();
            return value
                .to_i64()
                .filter(|value| (-(1_i64 << 62)..(1_i64 << 62)).contains(value))
                .ok_or_else(|| Error::Native(b"Z.Overflow".to_vec()));
        }
        match self.stream.peek()? {
            T::Integer(value) => match value.to_u32().filter(|value| *value <= limits::AST_INT) {
                Some(value) => {
                    self.eat();
                    Ok(i64::from(value))
                }
                None => Err(self.error("integer exceeds portable range")),
            },
            _ => Err(self.error(expected)),
        }
    }
    fn natural(&mut self, expected: &[u8]) -> Result<Natural> {
        let value = match self.stream.peek()? {
            T::Integer(value) => Natural::new(value),
            _ => return Err(self.error(expected)),
        };
        self.eat();
        value.ok_or_else(|| self.error("natural exceeds fixed range"))
    }
    // Keep the explicit ordered native tuple/field projection at this boundary.
    #[allow(clippy::type_complexity)]
    fn params(&mut self) -> Result<Vec<Param>> {
        self.expect(T::Symbol(S::LParen))?;
        let mut params: Vec<Param> = vec![];
        loop {
            if self.is(T::Symbol(S::RParen))? {
                self.eat();
                return Ok(params);
            }
            if !params.is_empty() {
                self.expect(T::Symbol(S::Comma))?;
            }
            let name = self.ident()?;
            if !self.prior && params.iter().any(|param| param.name == name) {
                return Err(self.error([b"duplicate parameter name = ".as_slice(), &name].concat()));
            }
            self.expect(T::Symbol(S::Colon))?;
            let typ = self.typ()?;
            let refine = if self.is(T::Word(W::Where))? {
                self.eat();
                let refine_name = self.ident()?;
                if !self.prior && refine_name != name {
                    return Err(self.error("refinement parameter differs"));
                }
                let token = self.token()?;
                let (make, expected): (fn(Name, i64) -> Refinement, &[u8]) = match token {
                    T::Symbol(S::Gt) => (Refinement::Gt, b"expected integer after >"),
                    T::Symbol(S::GtEq) => (Refinement::Ge, b"expected integer after >="),
                    T::Symbol(S::Lt) => (Refinement::Lt, b"expected integer after <"),
                    T::Symbol(S::LtEq) => (Refinement::Le, b"expected integer after <="),
                    T::Symbol(S::BangEq) => (Refinement::Neq, b"expected integer after !="),
                    _ => return Err(self.error("expected comparison operator in where clause")),
                };
                self.eat();
                Some(make(name.clone(), self.ast_int(expected)?))
            } else {
                None
            };
            params.push(Param { name, typ, refine });
        }
    }
}
pub fn syntax(source: &[u8]) -> Result<Ast> {
    syntax_mode(source, false)
}
/// Frozen Prior_parse: retain its original grammar, cursor diagnostics,
/// unlocated statements, trailing-source behavior and absence of Oct_scope.
pub fn prior(source: &[u8]) -> Result<Ast> {
    syntax_mode(source, true)
}
fn syntax_mode(source: &[u8], prior: bool) -> Result<Ast> {
    let mut parser = Parser {
        prior,
        stream: if prior {
            Stream::prior(source)
        } else {
            Stream::new(source)
        },
        nodes: Nodes::default(),
    };
    let contract = parser.contract()?;
    if !prior && !parser.is(T::Eof)? {
        return Err(parser.error("trailing source after declaration"));
    }
    Ok(Ast {
        contract,
        nodes: parser.nodes,
    })
}
pub fn parse(source: &[u8]) -> Result<Ast> {
    parse_with(source, |_, _| None)
}
pub fn parse_with(
    source: &[u8],
    mut resolve_import: impl FnMut(&[Name], &[u8]) -> Option<Ast>,
) -> Result<Ast> {
    let mut ast = syntax(source)?;
    for import in ast.contract.imports.clone() {
        if let Some(imported) = resolve_import(&import.names, &import.path) {
            ast.prepend_import(imported);
        }
    }
    Ok(super::scope::resolve(ast))
}
