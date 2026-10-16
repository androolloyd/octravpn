// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native C_mach source ownership. Parsing and source checking precede machine
//! evaluation; their checked resources and source marks are retained unchanged.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::super::{eval::Values, feed::Feed, parse, types::Types};
use super::{image, Error, Image, TreeId, Trees};

/// A source image keeps every type and value ID in the arenas that created it.
#[derive(Clone, Debug)]
pub struct SourceImage {
    pub types: Types,
    pub values: Values,
    pub image: Image,
}

/// Diagnostic ownership preserves the typed error without dangling arena IDs.
#[derive(Clone, Debug)]
pub struct SourceFailure {
    pub error: Error,
    pub types: Types,
    pub values: Values,
}
impl SourceFailure {
    fn source(error: Error, values: Values) -> Self {
        Self {
            error,
            types: Types::default(),
            values,
        }
    }
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

/// C_mach.source runs C_parse.parse and C_parse.compile before any machine
/// profile restriction or evaluation. This also retains private veil bounds.
pub fn source(source_text: &[u8]) -> Result<parse::Compiled, Error> {
    parse::parse(source_text)
        .and_then(parse::Program::into_compiled)
        .map_err(Error::Source)
}

pub fn source_tree(source: &parse::Compiled, trees: &mut Trees) -> Result<TreeId, Error> {
    let (tree, consumed) = trees
        .from_marks(
            &source.lowered.terms,
            source.lowered.program.term,
            &source.origins.marks,
        )
        .ok_or(Error::Map)?;
    if consumed != source.origins.marks.len() {
        return Err(Error::Map);
    }
    Ok(tree)
}

pub fn compile_source(source_text: &[u8]) -> Result<SourceImage, SourceFailure> {
    compile_source_with(source_text, None)
}

/// The feed is rehomed from its canonical AF1 bytes into the image's value
/// arena. A feed created in another request cannot introduce foreign value IDs.
pub fn compile_source_feed(source_text: &[u8], feed: &Feed) -> Result<SourceImage, SourceFailure> {
    compile_source_with(source_text, Some(feed))
}

fn compile_source_with(
    source_text: &[u8],
    feed: Option<&Feed>,
) -> Result<SourceImage, SourceFailure> {
    let parse::Compiled {
        lowered:
            parse::Lowered {
                program,
                mut types,
                mut terms,
            },
        checked,
        origins,
    } = source(source_text).map_err(|error| SourceFailure::source(error, Values::default()))?;
    let mut values = Values::default();
    let info = checked.info();
    let source = origins.machine_source();
    let result = match feed {
        None => image::compile_checked(&mut types, &terms, &mut values, &program, source, info),
        Some(feed) => match Feed::decode(&mut values, feed.encode()) {
            Err(error) => Err(Error::Feed(error)),
            Ok(feed) => image::compile_feed_checked(
                &mut types,
                &mut terms,
                &mut values,
                &program,
                source,
                info,
                &feed,
            ),
        },
    };
    match result {
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
