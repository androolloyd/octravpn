// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    unsigned, value_field, value_function, value_name, Analysis, Arc, Env, Expr, ExprId, Finding,
    Function, Param, Severity, Stmt, StmtId, Type, Visibility,
};
pub(super) fn finding(
    program: &[u8],
    function: Option<&[u8]>,
    severity: Severity,
    code: &'static str,
    message: &'static str,
    field: Option<&[u8]>,
    parameter: Option<&[u8]>,
) -> Finding {
    Finding {
        severity,
        code,
        message,
        program_name: program.to_vec(),
        function_name: function.map(<[u8]>::to_vec),
        state_field: field.map(<[u8]>::to_vec),
        parameter: parameter.map(<[u8]>::to_vec),
    }
}
enum Task {
    Block(Arc<[StmtId]>, usize, Env),
    Next(Arc<[StmtId]>, usize),
    Statement(StmtId, Env),
    Discard,
}
impl Analysis<'_> {
    pub(super) fn state_findings(&self, program: &[u8]) -> Vec<Finding> {
        self.ast
            .contract
            .state
            .iter()
            .filter(|field| {
                value_field(&field.name)
                    && matches!(self.host.typ(self.base_type(field.typ)), Type::Int)
            })
            .map(|field| {
                finding(
                    program,
                    None,
                    Severity::Error,
                    "signed_value_storage",
                    "value-like storage uses signed int",
                    Some(&field.name),
                    None,
                )
            })
            .collect()
    }
    fn parameter_finding(
        &self,
        program: &[u8],
        function: &Function,
        param: &Param,
    ) -> Option<Finding> {
        let value_like = value_name(&param.name) || value_function(&function.name);
        if function.visibility == Visibility::Public
            && value_like
            && matches!(self.host.typ(param.typ), Type::Int)
        {
            Some(finding(
                program,
                Some(&function.name),
                Severity::Error,
                "signed_value_parameter",
                "value-moving public parameter uses signed int",
                None,
                Some(&param.name),
            ))
        } else if function.visibility == Visibility::Public
            && value_like
            && unsigned(self.host.typ(param.typ))
            && !function.name.eq_ignore_ascii_case(b"grant")
            && !function.name.eq_ignore_ascii_case(b"approve")
            && !self.positive(&param.name, &function.body)
        {
            Some(finding(
                program,
                Some(&function.name),
                Severity::Warning,
                "unsigned_parameter_without_positive_guard",
                "unsigned value parameter allows zero unless guarded",
                None,
                Some(&param.name),
            ))
        } else {
            None
        }
    }
    fn statement_finding(
        &self,
        program: &[u8],
        function: &Function,
        mut id: StmtId,
    ) -> Option<Finding> {
        while let Stmt::Located(_, _, child) = self.ast.nodes.statement(id) {
            id = *child;
        }
        let message = match self.ast.nodes.statement(id) {
            Stmt::Expr(value) if matches!(self.ast.nodes.expression(*value), Expr::Call(name, _) if name == b"transfer") => {
                Some("transfer result is not checked")
            }
            Stmt::Let(name, _, value)
                if matches!(self.ast.nodes.expression(*value), Expr::Call(name, _) if name == b"transfer")
                    && !self.checks_var(name, &function.body) =>
            {
                Some("transfer result is assigned but not required")
            }
            _ => None,
        }?;
        Some(finding(
            program,
            Some(&function.name),
            Severity::Warning,
            "unchecked_transfer_result",
            message,
            None,
            None,
        ))
    }
    fn write_findings(
        &mut self,
        program: &[u8],
        function: &Function,
        env: &Env,
        field: &[u8],
        expr: ExprId,
    ) -> Vec<Finding> {
        let mut findings = vec![];
        if self.value_storage(field) {
            if let Some(source) = self.signed_source(env, expr) {
                findings.push(finding(
                    program,
                    Some(&function.name),
                    Severity::Error,
                    "signed_value_flow",
                    "signed value can flow into value-like storage",
                    Some(field),
                    Some(&source),
                ));
            }
            if self
                .field_type(field)
                .is_some_and(|typ| unsigned(self.host.typ(typ)))
                && self.unproven_arithmetic(env, &function.body, expr)
            {
                findings.push(finding(
                    program,
                    Some(&function.name),
                    Severity::Error,
                    "unsigned_arithmetic_range_not_proven",
                    "unsigned arithmetic result can exceed the declared range",
                    Some(field),
                    None,
                ));
            }
        }
        findings
    }
    fn flow_findings(&mut self, program: &[u8], function: &Function) -> Vec<Finding> {
        let env = Env(Arc::new(
            function
                .params
                .iter()
                .map(|param| (param.name.clone(), param.typ))
                .collect(),
        ));
        let mut pending = vec![Task::Block(function.body.clone().into(), 0, env)];
        let mut findings = vec![];
        let mut values = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Block(body, index, env) => {
                    if let Some(id) = body.get(index).copied() {
                        pending.push(Task::Next(body, index + 1));
                        pending.push(Task::Statement(id, env));
                    } else {
                        values.push(env);
                    }
                }
                Task::Next(body, index) => pending.push(Task::Block(
                    body,
                    index,
                    values.pop().expect("safety statement environment"),
                )),
                Task::Discard => {
                    values.pop().expect("safety nested environment");
                }
                Task::Statement(mut id, mut env) => {
                    while let Stmt::Located(_, _, child) = self.ast.nodes.statement(id) {
                        id = *child;
                    }
                    let mut nested = vec![];
                    match self.ast.nodes.statement(id).clone() {
                        Stmt::Let(name, declared, expr) => {
                            let typ = declared.or_else(|| self.expression_type(&env, expr));
                            if let Some(typ) = typ {
                                env = env.add(name, typ);
                            }
                        }
                        Stmt::Assign(name, expr) => {
                            if let Some(typ) = self.expression_type(&env, expr) {
                                env = env.set(name, typ);
                            }
                        }
                        Stmt::FieldSet(field, expr)
                        | Stmt::IndexSet(field, _, expr)
                        | Stmt::StoragePathSet(field, _, _, expr)
                        | Stmt::IndexFieldSet(field, _, _, expr)
                        | Stmt::IndexUpdate(field, _, _, expr)
                        | Stmt::StoragePathUpdate(field, _, _, _, expr) => findings
                            .extend(self.write_findings(program, function, &env, &field, expr)),
                        Stmt::LetTuple(names, expr) => {
                            if let Some(typ) = self.expression_type(&env, expr) {
                                for name in names {
                                    env = env.set(name, typ);
                                }
                            }
                        }
                        mut statement => statement.blocks(&mut |body| nested.push(body.clone())),
                    }
                    values.push(env.clone());
                    for body in nested.into_iter().rev() {
                        pending.push(Task::Discard);
                        pending.push(Task::Block(body.into(), 0, env.clone()));
                    }
                }
            }
        }
        values.pop().expect("safety function environment");
        findings
    }
    pub(super) fn function_findings(
        &mut self,
        program: &[u8],
        function: &Function,
    ) -> Vec<Finding> {
        let mut findings: Vec<_> = function
            .params
            .iter()
            .filter_map(|param| self.parameter_finding(program, function, param))
            .collect();
        findings.extend(
            function
                .body
                .iter()
                .filter_map(|id| self.statement_finding(program, function, *id)),
        );
        findings.extend(self.flow_findings(program, function));
        findings
    }
}
