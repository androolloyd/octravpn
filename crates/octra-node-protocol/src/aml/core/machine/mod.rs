// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! C_mach machine representations. Layout/projection is separate from machine
//! lowering, replay, instruction generation and code-bound evidence checking.
use super::{result::Record, Natural};
use num_bigint::BigInt;
use std::sync::Arc;
mod code;
mod flow;
mod image;
mod location;
mod lower;
mod projection;
mod replay;
mod shape;
mod source;
mod tree;
mod value;
pub use code::{Code, CodeId, Codes, Operation};
pub use image::{compile, compile_feed, Emission, Error, Image, Source};
pub use location::{Location, LocationId, Locations, Tag as LocationTag};
pub use projection::{atoms, literal, value};
pub use replay::Replay;
pub use shape::{Shape, ShapeId, Shapes};
pub use source::{
    compile_source, compile_source_feed, source, source_tree, SourceFailure, SourceImage,
};
pub use tree::{Tree, TreeId, Trees};
#[derive(Clone, Debug)]
pub enum Literal {
    Bool(bool),
    Int(Arc<BigInt>),
    Bytes(Arc<[u8]>),
    Data(Record),
    Cap(Natural, Natural),
}
impl PartialEq for Literal {
    fn eq(&self, right: &Self) -> bool {
        self.equal(right)
    }
}
impl Eq for Literal {}
impl Literal {
    pub fn equal(&self, right: &Self) -> bool {
        match (self, right) {
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Bytes(left), Self::Bytes(right)) => left == right,
            (Self::Data(left), Self::Data(right)) => left.equal(right),
            (Self::Cap(lk, li), Self::Cap(rk, ri)) => lk == rk && li == ri,
            _ => false,
        }
    }
}
