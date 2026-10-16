// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, located, task, Arc, Elaborator, Env, Finish, Result, Task};
impl Elaborator<'_> {
    // Keep this operation on the shared native checker/host method interface.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(super) fn flow(
        &mut self,
        owner: Arc<task::Owner>,
        body: Arc<[ast::StmtId]>,
        index: usize,
        env: Env,
        tasks: &mut Vec<Task>,
    ) -> Result<()> {
        let Some(mut id) = body.get(index).copied() else {
            return Err(located(
                owner.line,
                1,
                [
                    b"direct pure function body is empty = ".as_slice(),
                    &owner.name,
                ]
                .concat(),
            ));
        };
        let (mut line, mut column) = (owner.line, 1);
        while let ast::Stmt::Located(next_line, next_column, child) = self.ast.nodes.statement(id) {
            (line, column, id) = (*next_line, *next_column, *child);
        }
        let single = index + 1 == body.len();
        match self.ast.nodes.statement(id) {
            ast::Stmt::Return(Some(value)) if single => tasks.push(Task::Expression(*value, env)),
            ast::Stmt::If(guard, yes, no)
                if (single && no.is_some()) || (!single && no.is_none()) =>
            {
                tasks.push(Task::Finish(Finish::Branch(Some((line, column)))));
                if let Some(no) = no {
                    tasks.push(Task::Flow(owner.clone(), no.clone().into(), 0, env.clone()));
                } else {
                    tasks.push(Task::Flow(owner.clone(), body, index + 1, env.clone()));
                }
                tasks.push(Task::Flow(owner, yes.clone().into(), 0, env.clone()));
                tasks.push(Task::Expression(*guard, env));
            }
            ast::Stmt::Let(name, declared, input) if !single => {
                tasks.push(Task::Finish(Finish::FlowLocal(
                    owner,
                    body,
                    index + 1,
                    env.clone(),
                    name.clone(),
                    *declared,
                    line,
                    column,
                )));
                tasks.push(Task::Expression(*input, env));
            }
            _ => {
                return Err(located(
                    line,
                    column,
                    [
                        b"direct pure function body is unsupported = ".as_slice(),
                        &owner.name,
                    ]
                    .concat(),
                ))
            }
        }
        Ok(())
    }
}
