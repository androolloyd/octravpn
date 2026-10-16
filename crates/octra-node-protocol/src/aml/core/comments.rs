// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_comments byte-position-preserving erasure and unclosed-comment diagnostic.
pub use super::lexer::{Position, Span as Error};
pub fn erase(input: &[u8]) -> Result<Vec<u8>, Error> {
    super::lexer::erase_comments(input)
}
pub fn text(error: Error) -> Vec<u8> {
    format!(
        "comment is not closed line = {} column = {} offset = {}",
        error.first.line, error.first.column, error.first.offset
    )
    .into_bytes()
}
