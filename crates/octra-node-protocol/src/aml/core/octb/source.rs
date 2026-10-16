// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_octb source entry points retain the arenas used by the checked
//! machine image and every subsequent bytecode or diagnostic type/value ID.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::super::{eval::Values, feed::Feed, machine, types::Types};
use super::{finish, Error, Image};

#[derive(Clone, Debug)]
pub struct SourceImage {
    pub types: Types,
    pub values: Values,
    pub image: Image,
}

#[derive(Clone, Debug)]
pub struct SourceFailure {
    pub error: Error,
    pub types: Types,
    pub values: Values,
}
impl SourceFailure {
    pub fn text(&self) -> Vec<u8> {
        self.error.text(&self.types, &self.values)
    }
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for SourceFailure {}

/// Parse and check the entire source program, then construct and verify its
/// machine image before OCTB register lowering and exact-image decoding.
pub fn compile(source: &[u8]) -> Result<SourceImage, SourceFailure> {
    finish_source(machine::compile_source(source))
}

/// Source validation precedes feed attachment and evaluation. Machine source
/// compilation rehomes feed values into the image's retained value arena.
pub fn compile_feed(source: &[u8], feed: &Feed) -> Result<SourceImage, SourceFailure> {
    finish_source(machine::compile_source_feed(source, feed))
}

fn finish_source(
    result: Result<machine::SourceImage, machine::SourceFailure>,
) -> Result<SourceImage, SourceFailure> {
    let machine::SourceImage {
        mut types,
        mut values,
        image,
    } = result.map_err(|failure| SourceFailure {
        error: Error::Mach(failure.error),
        types: failure.types,
        values: failure.values,
    })?;
    match finish(&mut types, &mut values, image) {
        Ok(image) => Ok(SourceImage {
            types,
            values,
            image,
        }),
        Err(error) => Err(SourceFailure {
            error,
            types,
            values,
        }),
    }
}
