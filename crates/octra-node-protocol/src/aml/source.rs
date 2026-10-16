// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native Aml_source.owns selection between source and prior/forms syntax.
use super::lexer::{Error, Stream, Symbol as S, Token as T, Word as W};
mod compile;
pub use compile::{compile, compile_ast, compile_multi, CompileError, Compiled};
fn modifier(token: &T) -> bool {
    matches!(
        token,
        T::Word(W::Fn | W::View | W::Pure | W::Public | W::Private | W::Internal | W::Payable)
    )
}
fn scan(source: &[u8]) -> Result<bool, Error> {
    let mut stream = Stream::new(source);
    let (mut braces, mut parens, mut brackets) = (0usize, 0usize, 0usize);
    let (mut before, mut prior) = (T::Eof, T::Eof);
    loop {
        let token = stream.peek()?.clone();
        stream.eat();
        let next = stream.peek()?;
        let outer = braces == 1 && parens == 0 && brackets == 0;
        let owned = match &token {
            T::Word(W::Contract | W::Interface | W::Import | W::Implements) => braces == 0,
            T::Symbol(S::LBrace) => {
                outer
                    && (prior == T::Word(W::State)
                        || matches!(
                            (&before, &prior),
                            (T::Word(W::Struct | W::Enum), T::Ident(_))
                        ))
            }
            T::Symbol(S::LParen) => {
                outer
                    && (prior == T::Word(W::Constructor)
                        || matches!(before, T::Word(W::Event | W::Fn | W::Error))
                            && prior.identifier().is_some())
            }
            T::Symbol(S::Colon) => {
                outer && matches!((&before, &prior), (T::Word(W::Const), T::Ident(_)))
            }
            T::Symbol(S::Eq) => {
                outer
                    && (matches!((&before, &prior), (T::Word(W::Const), T::Ident(_)))
                        || matches!((&before, &prior), (T::Ident(name), T::Ident(_)) if name == b"invariant"))
            }
            T::Word(W::Public) => {
                outer && (modifier(next) || matches!(next, T::Ident(name) if name == b"main"))
            }
            T::Word(W::View | W::Pure | W::Private | W::Internal | W::Payable) => {
                outer && modifier(next)
            }
            _ => false,
        };
        if owned {
            return Ok(true);
        }
        match token {
            T::Eof => return Ok(false),
            T::Symbol(S::LBrace) => braces += 1,
            T::Symbol(S::RBrace) => braces = braces.saturating_sub(1),
            T::Symbol(S::LParen) => parens += 1,
            T::Symbol(S::RParen) => parens = parens.saturating_sub(1),
            T::Symbol(S::LBracket) => brackets += 1,
            T::Symbol(S::RBracket) => brackets = brackets.saturating_sub(1),
            _ => (),
        }
        before = prior;
        prior = token;
    }
}
pub fn owns(source: &[u8]) -> bool {
    scan(source).unwrap_or(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    Forms,
    Source,
}
pub fn body_empty(ast: &super::ast::Contract) -> bool {
    use super::ast::Declaration;
    match ast.declaration {
        Declaration::Interface => ast.interfaces.is_empty(),
        Declaration::Program | Declaration::Contract => {
            ast.structs.is_empty()
                && ast.enums.is_empty()
                && ast.consts.is_empty()
                && ast.invariants.is_empty()
                && ast.state.is_empty()
                && ast.events.is_empty()
                && ast.errors.is_empty()
                && ast.constructor.is_none()
                && ast.functions.is_empty()
                && ast.forms.is_empty()
        }
    }
}
pub fn shape(syntax: Syntax, ast: &super::ast::Contract) -> Result<(), Vec<u8>> {
    use super::limits;
    if syntax != Syntax::Source {
        return Ok(());
    }
    let error = if ast.imports.len() > limits::IMPORTS {
        Some("Program import count exceeds compiler limit")
    } else if ast
        .imports
        .iter()
        .map(|item| item.names.len())
        .sum::<usize>()
        > limits::IMPORT_NAMES
    {
        Some("Program import name count exceeds compiler limit")
    } else if ast.interfaces.len() > limits::INTERFACES {
        Some("Program interface count exceeds compiler limit")
    } else if ast
        .interfaces
        .iter()
        .map(|item| item.methods.len())
        .sum::<usize>()
        > limits::INTERFACE_METHODS
    {
        Some("Program interface method count exceeds compiler limit")
    } else {
        None
    };
    if let Some(error) = error {
        return Err(error.as_bytes().to_vec());
    }
    let mut seen = std::collections::BTreeSet::new();
    for interface in &ast.interfaces {
        if !seen.insert(&interface.name) {
            return Err([b"duplicate interface name = ".as_slice(), &interface.name].concat());
        }
    }
    Ok(())
}
pub fn diagnostic(
    source: Option<&[u8]>,
    line: i64,
    column: Option<i64>,
    message: &[u8],
) -> Vec<u8> {
    let mut out = vec![];
    if let Some(source) = source {
        out.extend(b"source = ");
        out.extend(source);
        out.push(b' ');
    }
    if line >= 1 {
        out.extend(format!("line {line}").as_bytes());
        if let Some(column) = column {
            out.extend(format!(" column {column}").as_bytes());
        }
        out.extend(b": ");
    }
    out.extend(message);
    out
}
