// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted AML source frontend and checks. These do not provide deployment
//! authority; admission still requires the complete independent compiler path.
pub mod abi;
pub mod ast;
pub mod call;
pub mod check;
pub mod compiler;
pub mod core;
pub mod effects;
pub mod emit;
pub mod evidence;
pub mod facts;
pub mod forms;
pub mod generate;
pub mod lexer;
pub mod limits;
pub mod parser;
pub mod rpc;
pub mod scope;
pub mod source;
pub mod types;
pub mod verify;
