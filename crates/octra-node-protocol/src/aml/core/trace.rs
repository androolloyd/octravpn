// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_trace's closed-literal two-step trace and structural replay.
// Preserve the native structured diagnostic payloads and their existing API.
#![allow(clippy::result_large_err)]
use super::{emit, eval::Values, lexer::Span, machine::Literal, types::Types};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Load(Literal),
    Stop,
}
#[derive(Clone, Debug)]
pub struct Frame {
    pub pc: i64,
    pub operation: Operation,
    pub register: Option<Literal>,
    pub effort: i64,
    pub halted: bool,
    pub span: Span,
}
#[derive(Clone, Debug)]
pub struct Trace {
    artifact: emit::SourceImage,
    frames: Vec<Frame>,
    result: Literal,
}
impl Trace {
    pub fn types(&self) -> &Types {
        &self.artifact.types
    }
    pub fn values(&self) -> &Values {
        &self.artifact.values
    }
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
    pub fn result(&self) -> &Literal {
        &self.result
    }
    pub fn octb(&self) -> &[u8] {
        &self.artifact.image.octb
    }
}
#[derive(Clone, Debug)]
pub enum Error {
    Emit(emit::SourceFailure),
    Shape,
    Result,
}
impl Error {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Emit(error) => error.text(),
            Self::Shape => b"trace shape is invalid".to_vec(),
            Self::Result => b"trace result differs from compiler result".to_vec(),
        }
    }
}
pub fn replay(frames: &[Frame]) -> Result<Literal, Error> {
    let [first, final_frame] = frames else {
        return Err(Error::Shape);
    };
    let (Operation::Load(value), Some(loaded), Some(final_value)) =
        (&first.operation, &first.register, &final_frame.register)
    else {
        return Err(Error::Shape);
    };
    if first.pc == 0
        && first.effort == 1
        && !first.halted
        && final_frame.pc == 1
        && final_frame.operation == Operation::Stop
        && final_frame.effort == 2
        && final_frame.halted
        && value.equal(loaded)
        && loaded.equal(final_value)
    {
        Ok(final_value.clone())
    } else {
        Err(Error::Shape)
    }
}
pub fn make(source: &[u8]) -> Result<Trace, Error> {
    let artifact = emit::compile_source(source).map_err(Error::Emit)?;
    let result = artifact.image.lit.clone();
    let span = artifact.image.span;
    let frames = vec![
        Frame {
            pc: 0,
            operation: Operation::Load(result.clone()),
            register: Some(result.clone()),
            effort: 1,
            halted: false,
            span,
        },
        Frame {
            pc: 1,
            operation: Operation::Stop,
            register: Some(result),
            effort: 2,
            halted: true,
            span,
        },
    ];
    let result = replay(&frames)?;
    if !result.equal(&artifact.image.lit) {
        return Err(Error::Result);
    }
    Ok(Trace {
        artifact,
        frames,
        result,
    })
}
