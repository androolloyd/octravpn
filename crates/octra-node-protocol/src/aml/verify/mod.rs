// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_verify's advisory AST safety report. Native report fields, including
//! `verified`, describe these heuristics; they do not certify a Coq proof run.
use super::ast::{
    Ast, BinOp, Binding, Expr, ExprId, Function, Mult, Name, Nodes, Param, Stmt, StmtId, Type,
    TypeId, UnOp, Visibility,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
mod analysis;
mod calls;
mod findings;
mod invariants;
mod json;
mod text;
pub use text::expression_text;
pub const SCHEMA: &[u8] = b"aml_safety_report_v1";
pub const ENGINE: &[u8] = b"aml_ast_verifier";
pub const PROOF_MODEL: &[u8] = b"formal/coq/aml_value_safety_model.v";
pub const PROOF_GATE: &[u8] = b"scripts/check_aml_formal.sh";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}
impl Severity {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Error => b"error",
            Self::Warning => b"warning",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: &'static str,
    pub program_name: Name,
    pub function_name: Option<Name>,
    pub state_field: Option<Name>,
    pub parameter: Option<Name>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub name: Name,
    pub visibility: Visibility,
    pub direct_calls: Vec<Name>,
    pub direct_writes: Vec<Name>,
    pub transitive_writes: Vec<Name>,
    pub value_writes: Vec<Name>,
    pub signed_params: Vec<Name>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invariant {
    pub code: Name,
    pub kind: Option<&'static str>,
    pub status: &'static str,
    pub expression: Option<Vec<u8>>,
    pub message: Vec<u8>,
    pub fields: Vec<Name>,
    pub functions: Vec<Name>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub program_name: Name,
    pub findings: Vec<Finding>,
    pub summaries: Vec<Summary>,
    pub invariants: Vec<Invariant>,
}
impl Report {
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    }
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }
    pub fn code_count(&self, code: &str) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.code == code)
            .count()
    }
    pub fn safety_level(&self) -> &'static [u8] {
        if self.has_errors() {
            b"error"
        } else if self.count(Severity::Warning) > 0 {
            b"warning"
        } else {
            b"safe"
        }
    }
}
struct Analysis<'a> {
    ast: &'a Ast,
    host: Nodes,
}
#[derive(Clone, Default)]
struct Env(Arc<Vec<(Name, TypeId)>>);
impl Env {
    fn add(mut self, name: Name, typ: TypeId) -> Self {
        Arc::make_mut(&mut self.0).insert(0, (name, typ));
        self
    }
    fn set(mut self, name: Name, typ: TypeId) -> Self {
        let values = Arc::make_mut(&mut self.0);
        if let Some(index) = values.iter().position(|(found, _)| found == &name) {
            values.remove(index);
        }
        values.insert(0, (name, typ));
        self
    }
    fn find(&self, name: &[u8]) -> Option<TypeId> {
        self.0
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, typ)| *typ)
    }
}
fn uniq(values: impl IntoIterator<Item = Name>) -> Vec<Name> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
fn contains(value: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || value
            .windows(needle.len())
            .any(|value| value.eq_ignore_ascii_case(needle))
}
fn any(value: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| contains(value, needle))
}
fn value_name(name: &[u8]) -> bool {
    any(
        name,
        &[
            b"amount",
            b"amt",
            b"value",
            b"supply",
            b"balance",
            b"reserve",
            b"deposit",
            b"withdraw",
            b"allowance",
            b"grant",
            b"liquidity",
            b"fee",
            b"lp",
        ],
    )
}
fn value_field(name: &[u8]) -> bool {
    any(
        name,
        &[
            b"balance",
            b"balances",
            b"reserve",
            b"reserves",
            b"deposit",
            b"deposits",
            b"allowance",
            b"allowances",
            b"grant",
            b"grants",
            b"total_supply",
            b"liquidity",
            b"lp",
        ],
    )
}
fn value_function(name: &[u8]) -> bool {
    any(
        name,
        &[
            b"transfer",
            b"pull",
            b"withdraw",
            b"deposit",
            b"mint",
            b"burn",
            b"swap",
            b"grant",
            b"approve",
            b"pay",
            b"claim",
        ],
    )
}
fn unsigned(typ: &Type) -> bool {
    matches!(typ, Type::U64 | Type::U128 | Type::U256)
}
fn blocks(nodes: &Nodes, roots: &[StmtId]) -> Vec<StmtId> {
    let mut pending: Vec<_> = roots.iter().copied().rev().collect();
    let mut out = vec![];
    while let Some(mut id) = pending.pop() {
        while let Stmt::Located(_, _, child) = nodes.statement(id) {
            id = *child;
        }
        out.push(id);
        let mut statement = nodes.statement(id).clone();
        let mut children = vec![];
        statement.blocks(&mut |body| children.extend(body.iter().copied()));
        pending.extend(children.into_iter().rev());
    }
    out
}
impl Analysis<'_> {
    fn base_type(&self, mut typ: TypeId) -> TypeId {
        while let Type::Map(_, value) = self.host.typ(typ) {
            typ = *value;
        }
        typ
    }
    fn field_type(&self, name: &[u8]) -> Option<TypeId> {
        self.ast
            .contract
            .state
            .iter()
            .find(|field| field.name == name)
            .map(|field| self.base_type(field.typ))
    }
    fn value_storage(&self, name: &[u8]) -> bool {
        value_field(name) && self.field_type(name).is_some()
    }
}
pub fn verify_ast(ast: &Ast) -> Report {
    let program_name = if ast.contract.name.is_empty() {
        b"interface".to_vec()
    } else {
        ast.contract.name.clone()
    };
    let functions: Vec<_> = ast
        .contract
        .functions
        .iter()
        .chain(ast.contract.constructor.iter())
        .collect();
    let mut analysis = Analysis {
        ast,
        host: ast.nodes.type_arena(),
    };
    let mut findings = analysis.state_findings(&program_name);
    let summaries = calls::summarize(&analysis, &functions);
    let (invariant_findings, mut invariants) =
        invariants::derived(&analysis, &program_name, &functions, &summaries);
    invariants.extend(invariants::declared(ast, &invariants));
    for function in functions {
        findings.extend(analysis.function_findings(&program_name, function));
    }
    findings.extend(invariant_findings);
    Report {
        program_name,
        findings,
        summaries,
        invariants,
    }
}
pub fn verify_source(source: &[u8]) -> Result<Report, super::parser::Error> {
    super::parser::parse(source).map(|ast| verify_ast(&ast))
}
