// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native statement checks; branch locals never escape their block.
use super::{invalid, Checker, Env, ExprId, Result, Stmt, StmtId, Type};
struct Frame {
    body: std::vec::IntoIter<StmtId>,
    env: Env,
}
impl Checker<'_> {
    // Continuation frames own their iterators, including newly produced bodies.
    #[allow(clippy::unnecessary_to_owned)]
    pub(super) fn block(&mut self, env: Env, body: &[StmtId]) -> Result<()> {
        let mut frames = vec![Frame {
            body: body.to_vec().into_iter(),
            env,
        }];
        while let Some(frame) = frames.last_mut() {
            let Some(id) = frame.body.next() else {
                frames.pop();
                continue;
            };
            let mut stmt = self.nodes.statement(id).clone();
            while let Stmt::Located(_, _, inner) = stmt {
                stmt = self.nodes.statement(inner).clone();
            }
            let children = self.statement(&mut frame.env, stmt)?;
            for (body, env) in children.into_iter().rev() {
                frames.push(Frame {
                    body: body.into_iter(),
                    env,
                });
            }
        }
        Ok(())
    }
    fn statement(&mut self, env: &mut Env, stmt: Stmt) -> Result<Vec<(Vec<StmtId>, Env)>> {
        match stmt {
            Stmt::Let(name, annotation, value) => {
                let actual = self.infer(env, value)?;
                let typ = annotation.unwrap_or(actual);
                self.require(b"local initializer type differs", typ, actual)?;
                env.add(name, typ);
            }
            Stmt::LetTuple(names, value) => {
                let actual = self.infer(env, value)?;
                match self.nodes.typ(actual) {
                    Type::Tuple(types) if names.len() == types.len() => {
                        for (name, typ) in names.into_iter().zip(types) {
                            env.add(name, *typ);
                        }
                    }
                    Type::Tuple(types) => {
                        return Err(invalid(format!(
                            "tuple binding count differs expected = {} actual = {}",
                            names.len(),
                            types.len()
                        )))
                    }
                    typ => {
                        return Err(invalid(
                            [
                                b"tuple binding type differs actual = ".as_slice(),
                                typ.name(),
                            ]
                            .concat(),
                        ))
                    }
                }
            }
            Stmt::Assign(name, value) => {
                let expected = env.local(&name).ok_or_else(|| {
                    invalid([b"variable is undefined name = ".as_slice(), &name].concat())
                })?;
                let actual = self.infer(env, value)?;
                self.require(b"assignment type differs", expected, actual)?;
            }
            Stmt::FieldSet(name, value) => {
                let expected = self.field(&name)?;
                let actual = self.infer(env, value)?;
                self.require(b"state assignment type differs", expected, actual)?;
            }
            Stmt::IndexSet(name, keys, value) => {
                let expected = self.state_index(env, &name, &keys)?;
                let actual = self.infer(env, value)?;
                self.require(b"indexed assignment type differs", expected, actual)?;
            }
            Stmt::IndexUpdate(name, keys, op, value) => {
                let expected = self.state_index(env, &name, &keys)?;
                let left = self.state_index(env, &name, &keys)?;
                let right = self.infer(env, value)?;
                let actual = self.binary(op, left, right, None, Some(value))?;
                self.require(b"indexed update type differs", expected, actual)?;
            }
            Stmt::Return(Some(value)) => {
                if self.nodes.typ(env.ret) == &Type::Void {
                    return Err(invalid("void function cannot return a value"));
                }
                let actual = self.infer(env, value)?;
                self.require(b"return type differs", env.ret, actual)?;
            }
            Stmt::Return(None) => {
                if self.nodes.typ(env.ret) != &Type::Void {
                    return Err(invalid(
                        [
                            b"return value is required type = ".as_slice(),
                            self.nodes.typ(env.ret).name(),
                        ]
                        .concat(),
                    ));
                }
            }
            Stmt::Assert(value) => {
                let boolean = self.nodes.intern(Type::Bool);
                let actual = self.infer(env, value)?;
                self.require(b"assert condition type differs", boolean, actual)?;
            }
            Stmt::Require(guard, message) => {
                let boolean = self.nodes.intern(Type::Bool);
                let actual = self.infer(env, guard)?;
                self.require(b"require condition type differs", boolean, actual)?;
                self.infer(env, message)?;
            }
            Stmt::Emit(name, values) => {
                let mut types = vec![];
                for value in values {
                    types.push(self.infer(env, value)?);
                }
                if let Some(event) = self.contract.events.iter().find(|event| event.name == name) {
                    if event.fields.len() != types.len() {
                        return Err(invalid(
                            [b"event argument count differs event = ".as_slice(), &name].concat(),
                        ));
                    }
                    for ((_, expected, _), actual) in event.fields.iter().zip(types) {
                        self.require(
                            &[b"event argument type differs event = ".as_slice(), &name].concat(),
                            *expected,
                            actual,
                        )?;
                    }
                }
            }
            Stmt::If(guard, yes, no) => {
                let boolean = self.nodes.intern(Type::Bool);
                let actual = self.infer(env, guard)?;
                self.require(b"if condition type differs", boolean, actual)?;
                let mut children = vec![(yes, env.clone())];
                if let Some(no) = no {
                    children.push((no, env.clone()));
                }
                return Ok(children);
            }
            Stmt::While(guard, body) => {
                let boolean = self.nodes.intern(Type::Bool);
                let actual = self.infer(env, guard)?;
                self.require(b"while condition type differs", boolean, actual)?;
                return Ok(vec![(body, env.clone())]);
            }
            Stmt::For(name, first, last, body) => {
                let integer = self.nodes.intern(Type::Int);
                let first = self.infer(env, first)?;
                self.require(b"range start type differs", integer, first)?;
                let last = self.infer(env, last)?;
                self.require(b"range end type differs", integer, last)?;
                let mut child = env.clone();
                child.add(name, integer);
                return Ok(vec![(body, child)]);
            }
            Stmt::FieldCall(name, method, values) => {
                self.field_call(env, &name, &method, &values)?;
            }
            Stmt::StoragePathSet(name, keys, path, value) => {
                let expected = self.storage_path(env, &name, &keys, &path)?;
                let actual = self.infer(env, value)?;
                self.require(b"storage path assignment type differs", expected, actual)?;
            }
            Stmt::StoragePathUpdate(name, keys, path, op, value) => {
                let expected = self.storage_path(env, &name, &keys, &path)?;
                let left = self.storage_path(env, &name, &keys, &path)?;
                let right = self.infer(env, value)?;
                let actual = self.binary(op, left, right, None, Some(value))?;
                self.require(b"storage path update type differs", expected, actual)?;
            }
            Stmt::IndexFieldSet(name, keys, field, value) => {
                let expected = self.storage_path(env, &name, &keys, &[field])?;
                let actual = self.infer(env, value)?;
                self.require(b"storage path assignment type differs", expected, actual)?;
            }
            Stmt::ForEach(name, field, body) => {
                let field_type = self.field(&field)?;
                let Type::List(typ) = self.nodes.typ(field_type) else {
                    return Err(invalid(
                        [b"field is not a list name = ".as_slice(), &field].concat(),
                    ));
                };
                let mut child = env.clone();
                child.add(name, *typ);
                return Ok(vec![(body, child)]);
            }
            Stmt::Match(value, arms) => {
                self.infer(env, value)?;
                return Ok(arms
                    .into_iter()
                    .map(|(_, _, body)| (body, env.clone()))
                    .collect());
            }
            Stmt::Expr(value) => {
                self.infer(env, value)?;
            }
            Stmt::RevertError(_, values) => {
                for value in values {
                    self.infer(env, value)?;
                }
            }
            Stmt::Located(..) => unreachable!("statement locations were peeled"),
        }
        Ok(vec![])
    }
    fn field_call(
        &mut self,
        env: &Env,
        name: &[u8],
        method: &[u8],
        values: &[ExprId],
    ) -> Result<()> {
        let field = self.field(name)?;
        let Type::List(item_type) = self.nodes.typ(field) else {
            return Err(invalid(
                [b"field is not a list name = ".as_slice(), name].concat(),
            ));
        };
        match (method, values) {
            (b"push", [value]) => {
                let expected = *item_type;
                let actual = self.infer(env, *value)?;
                self.require(b"list item type differs", expected, actual)
            }
            (b"delete", [value]) => {
                let integer = self.nodes.intern(Type::Int);
                let actual = self.infer(env, *value)?;
                self.require(b"list index type differs", integer, actual)
            }
            (b"len" | b"pop", []) => Ok(()),
            (b"push" | b"delete" | b"len" | b"pop", _) => Err(invalid(
                [
                    b"list method argument count differs method = ".as_slice(),
                    method,
                ]
                .concat(),
            )),
            _ => Err(invalid(
                [b"list method is undefined name = ".as_slice(), method].concat(),
            )),
        }
    }
}
