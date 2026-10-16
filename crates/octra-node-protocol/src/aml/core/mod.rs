// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent AML core foundations. These do not create proof or admission
//! authority; checking, lowering and evidence construction are separate stages.
pub mod arena;
pub mod bin;
pub mod braid;
pub mod certificate;
pub mod check;
pub mod comments;
pub mod crypt;
pub mod data;
pub mod debug;
pub mod declaration;
pub mod emit;
pub mod entropy;
pub mod eval;
pub mod feed;
pub mod fhe;
pub mod field;
pub mod finite;
pub mod flow;
pub mod folio;
pub mod functions;
pub mod graph;
pub mod hfhe;
pub mod hpar;
pub mod index;
pub mod lexer;
pub mod limit;
pub(crate) mod list;
pub mod loom;
pub mod lower;
pub mod machine;
pub mod maps;
pub mod octb;
pub mod orbit;
pub mod parse;
pub mod path;
pub mod perm;
pub mod poly;
pub mod print;
pub mod program_codec;
pub mod project;
pub mod project_file;
pub mod project_image;
pub mod quant;
pub mod record;
pub mod res;
pub mod result;
pub mod rift;
pub mod root;
pub mod rule;
pub mod seal;
pub mod session;
pub mod sha;
pub mod source_binary;
pub mod source_certificate;
pub mod spec;
pub mod syntax;
pub mod term;
pub mod text;
pub mod trace;
pub mod turn;
pub mod types;
pub mod vm;
pub mod wake;
pub mod weave;
pub use super::ast::{Atom, Natural};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::BTreeSet;
pub type Effects = BTreeSet<Atom>;
impl Natural {
    pub const MAX: u32 = rule::LOCAL.get(rule::Field::Nat) as u32;
    pub const STR_MAX: usize = rule::LOCAL.get(rule::Field::Str) as usize;
    pub fn zero() -> Self {
        Self::from_u32(0).expect("fixed core zero")
    }
    pub fn one() -> Self {
        Self::from_u32(1).expect("fixed core one")
    }
    pub fn to_bigint(self) -> BigInt {
        BigInt::from(self.get())
    }
    pub fn text(self) -> Vec<u8> {
        self.get().to_string().into_bytes()
    }
    pub fn from_u32(value: u32) -> Option<Self> {
        Self::new(&BigInt::from(value))
    }
    pub fn checked_add(self, right: Self) -> Option<Self> {
        Self::from_u32(self.get().checked_add(right.get())?)
    }
    pub fn checked_sub(self, right: Self) -> Option<Self> {
        Self::from_u32(self.get().checked_sub(right.get())?)
    }
    pub fn byte(value: &BigInt) -> Option<u8> {
        value.to_u8()
    }
}
pub fn atom_text(atom: Atom) -> Vec<u8> {
    let (name, id): (&[u8], Natural) = match atom {
        Atom::Read(id) => (b"read", id),
        Atom::Write(id) => (b"write", id),
        Atom::Emit(id) => (b"emit", id),
        Atom::Fail(id) => (b"fail", id),
        Atom::Close(id) => (b"close", id),
    };
    [name, b"<", id.get().to_string().as_bytes(), b">"].concat()
}
pub fn effects_text(effects: &Effects) -> Vec<u8> {
    let mut out = text::Text::default();
    out.add(b"{");
    for (index, atom) in effects.iter().enumerate() {
        if out.full() {
            break;
        }
        if index > 0 {
            out.add(b",");
        }
        out.add(&atom_text(*atom));
    }
    if !out.full() {
        out.add(b"}");
    }
    out.finish()
}
