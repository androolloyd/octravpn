// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Rust arena adapter errors. Native recursive constructors have no dangling
//! reference case; these checks do not replace native type checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Type,
    Term,
    SyntaxType,
    SyntaxTerm,
    Index,
    Declaration,
    RawExpr,
    RawBody,
    Fhe,
    FunctionBody,
    Value,
    BinaryCode,
    MachineShape,
    MachineCode,
}
impl Kind {
    fn text(self) -> &'static str {
        match self {
            Self::Type => "core type",
            Self::Term => "core term",
            Self::SyntaxType => "syntax type",
            Self::SyntaxTerm => "syntax term",
            Self::Index => "index",
            Self::Declaration => "declaration type",
            Self::RawExpr => "raw expression",
            Self::RawBody => "raw body",
            Self::Fhe => "FHE term",
            Self::FunctionBody => "function body",
            Self::Value => "core value",
            Self::BinaryCode => "binary code",
            Self::MachineShape => "machine shape",
            Self::MachineCode => "machine code",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub kind: Kind,
    pub index: usize,
    pub length: usize,
}
impl Reference {
    pub fn text(&self) -> Vec<u8> {
        format!(
            "{} reference is absent index = {} length = {}",
            self.kind.text(),
            self.index,
            self.length
        )
        .into_bytes()
    }
}
impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for Reference {}
