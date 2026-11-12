// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{ast, ct, located, syn, BigInt, Elaborator, Result};
impl Elaborator<'_> {
    pub(super) fn typ(
        &mut self,
        line: usize,
        column: usize,
        root: ast::TypeId,
    ) -> Result<syn::TypeId> {
        enum Task {
            Visit(ast::TypeId),
            Pair(ast::TypeId),
        }
        let mut tasks = vec![Task::Visit(root)];
        let mut values = vec![];
        while let Some(task) = tasks.pop() {
            let (id, typ) = match task {
                Task::Visit(id) => {
                    if let Some(value) = self.host_to_core.get(&id) {
                        values.push(*value);
                        continue;
                    }
                    let typ = match self.host.typ(id) {
                        ast::Type::Void => syn::Type::Unit,
                        ast::Type::Int => syn::Type::Int,
                        ast::Type::Bool => syn::Type::Bool,
                        ast::Type::Bytes32 => syn::Type::Bytes(BigInt::from(32)),
                        ast::Type::U64 => syn::Type::Num(ct::Sign::Unsigned, BigInt::from(64)),
                        ast::Type::U128 => syn::Type::Num(ct::Sign::Unsigned, BigInt::from(128)),
                        ast::Type::U256 => syn::Type::Num(ct::Sign::Unsigned, BigInt::from(256)),
                        ast::Type::Tuple(items) if items.len() == 2 => {
                            tasks.push(Task::Pair(id));
                            tasks.push(Task::Visit(items[1]));
                            tasks.push(Task::Visit(items[0]));
                            continue;
                        }
                        value => {
                            return Err(located(
                                line,
                                column,
                                [
                                    b"direct form type is unsupported = ".as_slice(),
                                    value.name(),
                                ]
                                .concat(),
                            ))
                        }
                    };
                    (id, typ)
                }
                Task::Pair(id) => {
                    let right = values.pop().expect("direct right type");
                    let left = values.pop().expect("direct left type");
                    (id, syn::Type::Pair(left, right))
                }
            };
            let value = self.syntax.add_type(typ);
            self.host_to_core.insert(id, value);
            values.push(value);
        }
        Ok(values.pop().expect("direct type"))
    }
}
