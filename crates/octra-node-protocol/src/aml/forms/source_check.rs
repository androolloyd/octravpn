// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, error, types, Arc, Elaborator, Result};
type Values = Arc<Vec<(ast::Name, ast::TypeId)>>;
fn put(mut values: Values, name: ast::Name, typ: ast::TypeId) -> Values {
    let values_mut = Arc::make_mut(&mut values);
    values_mut.retain(|(found, _)| found != &name);
    values_mut.insert(0, (name, typ));
    values
}
enum Task {
    Block(Arc<[ast::StmtId]>, usize, usize, usize, Values),
    Next(Arc<[ast::StmtId]>, usize, usize, usize),
    Statement(ast::StmtId, usize, usize, Values),
    Discard,
}
impl Elaborator<'_> {
    pub(super) fn check_expression(
        &mut self,
        line: usize,
        column: usize,
        values: &[(ast::Name, ast::TypeId)],
        root: ast::ExprId,
    ) -> Result<()> {
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            let mut expr = self.ast.nodes.expression(id).clone();
            match &expr {
                ast::Expr::Use(_)
                | ast::Expr::Equal(..)
                | ast::Expr::Let(..)
                | ast::Expr::Split(..)
                | ast::Expr::Orbit(..) => self.check_term(line, column, values, id)?,
                ast::Expr::Action(..) => {
                    return Err(error(b"effect atoms are available only in form bodies"))
                }
                _ => {
                    let mut children = vec![];
                    expr.map_exprs(&mut |id| {
                        children.push(id);
                        id
                    });
                    pending.extend(children.into_iter().rev());
                }
            }
        }
        Ok(())
    }
    pub(super) fn check_function(&mut self, function: &ast::Function) -> Result<()> {
        let env = Arc::new(
            function
                .params
                .iter()
                .map(|param| (param.name.clone(), param.typ))
                .collect(),
        );
        let line = types::block_line(&self.ast.nodes, &function.body);
        let mut pending = vec![Task::Block(function.body.clone().into(), 0, line, 1, env)];
        let mut values = vec![];
        while let Some(task) = pending.pop() {
            match task {
                Task::Block(body, index, line, column, env) => {
                    if let Some(id) = body.get(index).copied() {
                        pending.push(Task::Next(body, index + 1, line, column));
                        pending.push(Task::Statement(id, line, column, env));
                    } else {
                        values.push(env);
                    }
                }
                Task::Next(body, index, line, column) => {
                    let env = values.pop().expect("statement host environment");
                    pending.push(Task::Block(body, index, line, column, env));
                }
                Task::Discard => {
                    values.pop().expect("nested host environment");
                }
                Task::Statement(mut id, mut line, mut column, mut env) => {
                    while let ast::Stmt::Located(next_line, next_column, child) =
                        self.ast.nodes.statement(id)
                    {
                        (line, column, id) = (*next_line, *next_column, *child);
                    }
                    let mut nested: Vec<(Vec<ast::StmtId>, Values)> = vec![];
                    match self.ast.nodes.statement(id).clone() {
                        ast::Stmt::Let(name, declared, input) => {
                            self.check_expression(line, column, &env, input)?;
                            let local = declared.or_else(|| self.infer(line, column, &env, input));
                            if let Some(typ) = local {
                                env = put(env, name, typ);
                            }
                        }
                        ast::Stmt::If(guard, yes, no) => {
                            self.check_expression(line, column, &env, guard)?;
                            nested.push((yes, env.clone()));
                            if let Some(no) = no {
                                nested.push((no, env.clone()));
                            }
                        }
                        ast::Stmt::While(guard, body) => {
                            self.check_expression(line, column, &env, guard)?;
                            nested.push((body, env.clone()));
                        }
                        ast::Stmt::For(name, first, last, body) => {
                            self.check_expression(line, column, &env, first)?;
                            self.check_expression(line, column, &env, last)?;
                            let integer = self.host.intern(ast::Type::Int);
                            nested.push((body, put(env.clone(), name, integer)));
                        }
                        ast::Stmt::ForEach(_, _, body) => nested.push((body, env.clone())),
                        ast::Stmt::Match(value, arms) => {
                            self.check_expression(line, column, &env, value)?;
                            nested.extend(arms.into_iter().map(|(_, _, body)| (body, env.clone())));
                        }
                        mut statement => {
                            let mut expressions = vec![];
                            statement.map_exprs(&mut |id| {
                                expressions.push(id);
                                id
                            });
                            for expression in expressions {
                                self.check_expression(line, column, &env, expression)?;
                            }
                        }
                    }
                    values.push(env);
                    for (body, env) in nested.into_iter().rev() {
                        pending.push(Task::Discard);
                        pending.push(Task::Block(body.into(), 0, line, column, env));
                    }
                }
            }
        }
        values.pop().expect("checked function environment");
        Ok(())
    }
}
