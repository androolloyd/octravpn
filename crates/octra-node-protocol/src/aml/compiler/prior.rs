// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Frozen Prior_compile entry points. AST/report fields shared with newer
//! compilers are projected only after the frozen parser has selected the AST.
pub use super::protocol::Interfaces;
use super::{emit_prior, protocol, Output, Result, SourceMode};
pub fn compile(raw: &[u8]) -> Result<Output> {
    let ast = match super::super::parser::prior(raw) {
        Ok(ast) => ast,
        Err(error) => return protocol::legacy_caught(error.into()),
    };
    protocol::prior_ast(&ast, Interfaces::Strict, SourceMode::Single, raw)
}
pub fn compile_program(raw: &[u8]) -> Result<Output> {
    let ast = match super::super::parser::prior(raw) {
        Ok(ast) => ast,
        Err(error) => return protocol::legacy_caught(error.into()),
    };
    if ast.contract.declaration != super::super::ast::Declaration::Program {
        return Ok(Output::failure(b"Program declaration required"));
    }
    // The single-source entry catches parser/generator exceptions outside
    // emit_program. Only normally returned results receive Prior's facts-first
    // projection; the multi-source entry catches before emit_program instead.
    protocol::prior_program_ast(&ast, raw)
}
pub fn compile_multi(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    interfaces: Interfaces,
) -> Result<Output> {
    protocol::prior_multi(resolver, main, interfaces, false)
}
pub fn compile_program_multi(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    interfaces: Interfaces,
) -> Result<Output> {
    emit_prior(protocol::prior_multi(resolver, main, interfaces, true)?)
}
