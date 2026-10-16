// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Program_limits and the C_rule.local natural bound.
pub const PARSER_DEPTH: usize = 128;
pub const AST_INT: u32 = 1_073_741_823;
pub const NATURAL: u32 = 1_000_000;
pub const IMPORTS: usize = 256;
pub const IMPORT_NAMES: usize = 256;
pub const INTERFACES: usize = 256;
pub const INTERFACE_METHODS: usize = 4_096;
pub const FUNCTIONS: usize = 256;
pub const INTERNAL_CALLS: usize = 4_096;
pub const EXTERNAL_CALLS: usize = 1_024;
pub const CALL_DEPTH: usize = 64;
pub const INSTRUCTIONS: usize = 65_536;
pub const FACTS: usize = 4_096;
pub const FLOW_STEPS: usize = 1_048_576;
