// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    calls, contains, expression_text, findings, Analysis, Ast, BinOp, Expr, ExprId, Finding,
    Function, Invariant, Name, Nodes, Severity, Summary,
};
pub(super) fn derived(
    analysis: &Analysis<'_>,
    program: &[u8],
    functions: &[&Function],
    summaries: &[Summary],
) -> (Vec<Finding>, Vec<Invariant>) {
    let balances: Vec<_> = analysis
        .ast
        .contract
        .state
        .iter()
        .filter(|field| contains(&field.name, b"balance"))
        .map(|field| field.name.clone())
        .collect();
    let supply: Vec<_> = analysis
        .ast
        .contract
        .state
        .iter()
        .filter(|field| contains(&field.name, b"total_supply") || field.name == b"supply")
        .map(|field| field.name.clone())
        .collect();
    let mut fields = balances.clone();
    fields.extend(supply.clone());
    if balances.is_empty() || supply.is_empty() {
        return (
            vec![],
            vec![Invariant {
                code: b"supply_balance_conservation".to_vec(),
                kind: Some("derived"),
                status: "not_applicable",
                expression: None,
                message: b"program does not expose both balance and supply storage".to_vec(),
                fields,
                functions: vec![],
            }],
        );
    }
    let mut risky = vec![];
    for summary in summaries {
        let writes_balance = summary
            .transitive_writes
            .iter()
            .any(|name| balances.contains(name));
        let writes_supply = summary
            .transitive_writes
            .iter()
            .any(|name| supply.contains(name));
        if !writes_balance && !writes_supply {
            continue;
        }
        let Some(function) = functions
            .iter()
            .find(|function| function.name == summary.name)
        else {
            continue;
        };
        let writes = calls::direct_writes(&analysis.ast.nodes, &function.body);
        let direct_balance_count: usize = balances
            .iter()
            .map(|field| writes.iter().filter(|name| *name == field).count())
            .sum();
        if writes_balance && (writes_supply || direct_balance_count == 2) {
            continue;
        }
        risky.push(summary.name.clone());
    }
    let pass = risky.is_empty();
    let findings = risky
        .iter()
        .map(|name| {
            findings::finding(
                program,
                Some(name),
                Severity::Warning,
                "supply_invariant_unproven",
                "balance and supply conservation is not proven for this function",
                None,
                None,
            )
        })
        .collect();
    let invariant = Invariant {
        code: b"supply_balance_conservation".to_vec(),
        kind: Some("derived"),
        status: if pass { "pass" } else { "warning" },
        expression: None,
        message: if pass {
            b"balance and supply write pattern looks conserved".to_vec()
        } else {
            b"some functions update balances or supply without a proven matching conservation update".to_vec()
        },
        fields,
        functions: risky,
    };
    (findings, vec![invariant])
}
fn field_name(nodes: &Nodes, id: ExprId) -> Option<&[u8]> {
    match nodes.expression(id) {
        Expr::Var(name) | Expr::Field(name) => Some(name),
        _ => None,
    }
}
fn invariant_kind(nodes: &Nodes, id: ExprId) -> Option<(Name, Name)> {
    match nodes.expression(id) {
        Expr::Binop(BinOp::Eq, left, right) => {
            let pair = match nodes.expression(*left) {
                Expr::Call(name, args) if name == b"sum" && args.len() == 1 => {
                    Some((args[0], *right))
                }
                _ => match nodes.expression(*right) {
                    Expr::Call(name, args) if name == b"sum" && args.len() == 1 => {
                        Some((args[0], *left))
                    }
                    _ => None,
                },
            }?;
            let balance = field_name(nodes, pair.0)?;
            let supply = field_name(nodes, pair.1)?;
            (contains(balance, b"balance")
                && (contains(supply, b"total_supply") || supply == b"supply"))
                .then(|| (balance.to_vec(), supply.to_vec()))
        }
        Expr::String(value) if contains(value, b"sum(") && contains(value, b"total_supply") => {
            Some((b"balances".to_vec(), b"total_supply".to_vec()))
        }
        _ => None,
    }
}
pub(super) fn declared(ast: &Ast, derived: &[Invariant]) -> Vec<Invariant> {
    ast.contract
        .invariants
        .iter()
        .map(|item| {
            let (status, fields, kind) =
                if let Some((balance, supply)) = invariant_kind(&ast.nodes, item.expr) {
                    let status = match derived
                        .iter()
                        .find(|invariant| invariant.code == b"supply_balance_conservation")
                        .map(|invariant| invariant.status)
                    {
                        Some("pass") => "pass",
                        Some("warning") => "warning",
                        _ => "declared",
                    };
                    (status, vec![balance, supply], "declared_supply_balance")
                } else {
                    ("declared", vec![], "declared")
                };
            let message = match ast.nodes.expression(item.expr) {
                Expr::String(value) => value.clone(),
                _ => expression_text(&ast.nodes, item.expr),
            };
            Invariant {
                code: [b"declared:".as_slice(), &item.name].concat(),
                kind: Some(kind),
                status,
                expression: Some(message.clone()),
                message,
                fields,
                functions: vec![],
            }
        })
        .collect()
}
