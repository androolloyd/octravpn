// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native advisory host inference. Failed strict elaboration falls back to this
//! syntactic projection; neither path grants effect or bytecode authority.
use super::{ast, ct, syn, types, Arc, BigInt, Elaborator};
type Values = Arc<Vec<(ast::Name, ast::TypeId)>>;
fn bind(mut values: Values, name: ast::Name, typ: ast::TypeId) -> Values {
    Arc::make_mut(&mut values).insert(0, (name, typ));
    values
}
enum Task {
    Visit(ast::ExprId, Values),
    Numeric(ast::BinOp),
    Tuple(usize),
    List,
    Let(ast::Binding, ast::ExprId, Values),
    OrbitTurns(ast::Natural, ast::ExprId, ast::Binding, ast::ExprId, Values),
    OrbitSeed(ast::Binding, ast::ExprId, Values),
    OrbitBody(ast::TypeId),
    Branch,
}
impl Elaborator<'_> {
    fn host_type(&mut self, root: syn::TypeId) -> Option<ast::TypeId> {
        enum Task {
            Visit(syn::TypeId),
            Pair(syn::TypeId),
        }
        let mut tasks = vec![Task::Visit(root)];
        let mut values = vec![];
        while let Some(task) = tasks.pop() {
            let (id, typ) = match task {
                Task::Visit(id) => {
                    if let Some(value) = self.core_to_host.get(&id) {
                        values.push((*value)?);
                        continue;
                    }
                    let typ = match self.syntax.typ(id) {
                        syn::Type::Int => ast::Type::Int,
                        syn::Type::Bool => ast::Type::Bool,
                        syn::Type::Bytes(size) if size == &BigInt::from(32) => ast::Type::Bytes32,
                        syn::Type::Num(ct::Sign::Unsigned, bits) if bits == &BigInt::from(64) => {
                            ast::Type::U64
                        }
                        syn::Type::Num(ct::Sign::Unsigned, bits) if bits == &BigInt::from(128) => {
                            ast::Type::U128
                        }
                        syn::Type::Num(ct::Sign::Unsigned, bits) if bits == &BigInt::from(256) => {
                            ast::Type::U256
                        }
                        syn::Type::Pair(left, right) => {
                            tasks.push(Task::Pair(id));
                            tasks.push(Task::Visit(*right));
                            tasks.push(Task::Visit(*left));
                            continue;
                        }
                        _ => {
                            self.core_to_host.insert(id, None);
                            return None;
                        }
                    };
                    (id, typ)
                }
                Task::Pair(id) => {
                    let right = values.pop().expect("host right type");
                    let left = values.pop().expect("host left type");
                    (id, ast::Type::Tuple(vec![left, right]))
                }
            };
            let value = self.host.intern(typ);
            self.core_to_host.insert(id, Some(value));
            values.push(value);
        }
        values.pop()
    }
    pub(super) fn infer(
        &mut self,
        line: usize,
        column: usize,
        env: &[(ast::Name, ast::TypeId)],
        root: ast::ExprId,
    ) -> Option<ast::TypeId> {
        if env.iter().any(|(name, typ)| {
            self.typ(line, column, *typ).is_ok() && syn::Name::new(name).is_none()
        }) {
            return self.host_infer(env, root);
        }
        let names = super::super::scope::references(&self.ast.nodes, [root], |_| true);
        let used: Vec<_> = names
            .iter()
            .filter_map(|name| env.iter().find(|(found, _)| found == name).cloned())
            .collect();
        match self.strict(line, column, &used, root) {
            Ok((_, value)) => {
                let host = self.host_type(value.typ)?;
                self.host_to_core.insert(host, value.typ);
                Some(host)
            }
            Err(_) => self.host_infer(env, root),
        }
    }
    fn host_infer(
        &mut self,
        env: &[(ast::Name, ast::TypeId)],
        root: ast::ExprId,
    ) -> Option<ast::TypeId> {
        use ast::{BinOp as B, Expr as E};
        let mut tasks = vec![Task::Visit(root, Arc::new(env.to_vec()))];
        let mut values: Vec<Option<ast::TypeId>> = vec![];
        while let Some(task) = tasks.pop() {
            let value = match task {
                Task::Visit(id, env) => match self.ast.nodes.expression(id) {
                    E::Int(_) | E::Epoch | E::EpochTime | E::Value | E::Balance(_) => {
                        Some(self.host.intern(ast::Type::Int))
                    }
                    E::Bool(_)
                    | E::Equal(..)
                    | E::Binop(
                        B::Eq | B::Neq | B::Lt | B::Gt | B::Le | B::Ge | B::And | B::Or,
                        _,
                        _,
                    ) => Some(self.host.intern(ast::Type::Bool)),
                    E::String(_) | E::TreeHash | E::NodeId | E::TxHash => {
                        Some(self.host.intern(ast::Type::String))
                    }
                    E::Caller | E::Origin | E::SelfAddr => {
                        Some(self.host.intern(ast::Type::Address))
                    }
                    E::Var(name) => env
                        .iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, typ)| *typ)
                        .or_else(|| {
                            self.ast
                                .contract
                                .consts
                                .iter()
                                .find(|item| &item.name == name)
                                .map(|item| item.typ)
                        }),
                    E::Field(name) => self
                        .ast
                        .contract
                        .state
                        .iter()
                        .find(|field| &field.name == name)
                        .map(|field| field.typ),
                    E::Index(name, _) => self
                        .ast
                        .contract
                        .state
                        .iter()
                        .find(|field| &field.name == name)
                        .and_then(|field| match self.host.typ(field.typ) {
                            ast::Type::Map(_, typ) | ast::Type::List(typ) => Some(*typ),
                            _ => None,
                        }),
                    E::Binop(op, left, right) => {
                        tasks.push(Task::Numeric(*op));
                        tasks.push(Task::Visit(*left, env.clone()));
                        tasks.push(Task::Visit(*right, env));
                        continue;
                    }
                    E::Unop(_, value) | E::Action(_, value) => {
                        tasks.push(Task::Visit(*value, env));
                        continue;
                    }
                    E::Call(name, _) => self
                        .ast
                        .contract
                        .functions
                        .iter()
                        .find(|function| &function.name == name)
                        .map(|function| function.ret)
                        .or_else(|| {
                            self.ast
                                .contract
                                .forms
                                .iter()
                                .find(|form| &form.name == name)
                                .map(|form| form.ret)
                        }),
                    E::Array(items) if items.is_empty() => {
                        let void = self.host.intern(ast::Type::Void);
                        Some(self.host.intern(ast::Type::List(void)))
                    }
                    E::Array(items) => {
                        tasks.push(Task::List);
                        tasks.push(Task::Visit(items[0], env));
                        continue;
                    }
                    E::Tuple(items) => {
                        tasks.push(Task::Tuple(items.len()));
                        tasks.extend(items.iter().rev().map(|id| Task::Visit(*id, env.clone())));
                        continue;
                    }
                    E::Let(binding, input, body) => {
                        tasks.push(Task::Let(binding.clone(), *body, env.clone()));
                        tasks.push(Task::Visit(*input, env));
                        continue;
                    }
                    E::Split(_, left, right, body) => {
                        let env = bind(
                            bind(env, left.name.clone(), left.typ),
                            right.name.clone(),
                            right.typ,
                        );
                        tasks.push(Task::Visit(*body, env));
                        continue;
                    }
                    E::Orbit(count, turns, seed, binding, body) => {
                        if let Some(turns) = turns {
                            tasks.push(Task::OrbitTurns(
                                *count,
                                *seed,
                                binding.clone(),
                                *body,
                                env.clone(),
                            ));
                            tasks.push(Task::Visit(*turns, env));
                        } else {
                            tasks.push(Task::OrbitSeed(binding.clone(), *body, env.clone()));
                            tasks.push(Task::Visit(*seed, env));
                        }
                        continue;
                    }
                    E::Ternary(_, yes, no) => {
                        tasks.push(Task::Branch);
                        tasks.push(Task::Visit(*no, env.clone()));
                        tasks.push(Task::Visit(*yes, env));
                        continue;
                    }
                    E::Use(value) => {
                        tasks.push(Task::Visit(
                            value.body,
                            bind(env, value.binding.name.clone(), value.binding.typ),
                        ));
                        continue;
                    }
                    E::StoragePath(..)
                    | E::FieldProp(..)
                    | E::IndexField(..)
                    | E::EnumVariant(..) => None,
                },
                Task::Numeric(op) => {
                    let left = values.pop().expect("host left operand");
                    let right = values.pop().expect("host right operand");
                    match (left, right) {
                        (Some(left), Some(right)) => {
                            let (left, right) = (self.host.typ(left), self.host.typ(right));
                            let typ = if op == B::Add && (types::text(left) || types::text(right)) {
                                Some(ast::Type::String)
                            } else if types::numeric(left) && types::numeric(right) {
                                Some(types::numeric_result(left, right))
                            } else {
                                None
                            };
                            typ.map(|typ| self.host.intern(typ))
                        }
                        _ => None,
                    }
                }
                Task::List => {
                    let typ = values.pop().expect("host list item");
                    typ.map(|typ| self.host.intern(ast::Type::List(typ)))
                }
                Task::Tuple(count) => {
                    let items = values.split_off(values.len() - count);
                    items
                        .into_iter()
                        .collect::<Option<Vec<_>>>()
                        .map(|items| self.host.intern(ast::Type::Tuple(items)))
                }
                Task::Let(binding, body, env) => {
                    let actual = values.pop().expect("host local input");
                    if actual
                        .is_some_and(|actual| types::compatible(&self.host, binding.typ, actual))
                    {
                        tasks.push(Task::Visit(body, bind(env, binding.name, binding.typ)));
                        continue;
                    }
                    None
                }
                Task::OrbitTurns(_count, seed, binding, body, env) => {
                    let turns = values.pop().expect("host orbit turns");
                    if turns.is_some_and(|typ| matches!(self.host.typ(typ), ast::Type::Int)) {
                        tasks.push(Task::OrbitSeed(binding, body, env.clone()));
                        tasks.push(Task::Visit(seed, env));
                        continue;
                    }
                    None
                }
                Task::OrbitSeed(binding, body, env) => {
                    let actual = values.pop().expect("host orbit seed");
                    if actual
                        .is_some_and(|actual| types::compatible(&self.host, binding.typ, actual))
                    {
                        tasks.push(Task::OrbitBody(binding.typ));
                        tasks.push(Task::Visit(body, bind(env, binding.name, binding.typ)));
                        continue;
                    }
                    None
                }
                Task::OrbitBody(declared) => values
                    .pop()
                    .expect("host orbit body")
                    .filter(|actual| types::compatible(&self.host, declared, *actual))
                    .map(|_| declared),
                Task::Branch => {
                    let no = values.pop().expect("host no branch");
                    let yes = values.pop().expect("host yes branch");
                    match (yes, no) {
                        (Some(yes), Some(no)) if types::compatible(&self.host, yes, no) => {
                            Some(yes)
                        }
                        _ => None,
                    }
                }
            };
            values.push(value);
        }
        values.pop().expect("host inferred root")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_type_graph_converts_once_per_node() {
        let mut ast = crate::aml::parser::parse(b"contract Graph {}").unwrap();
        let mut host = ast.nodes.intern(ast::Type::Int);
        for _ in 0..64 {
            host = ast.nodes.intern(ast::Type::Tuple(vec![host, host]));
        }
        let mut elaborator = Elaborator::new(&ast);
        let core = elaborator.typ(0, 1, host).unwrap();
        assert_eq!(elaborator.host_to_core.len(), 65);
        assert_eq!(elaborator.host_type(core), Some(host));
        assert_eq!(elaborator.core_to_host.len(), 65);
        assert_eq!(elaborator.typ(0, 1, host).unwrap(), core);
    }

    #[test]
    fn inference_selects_first_used_binding_and_ignores_unused_locals() {
        let mut ast = crate::aml::parser::parse(b"contract Locals {}").unwrap();
        let int = ast.nodes.intern(ast::Type::Int);
        let boolean = ast.nodes.intern(ast::Type::Bool);
        let value = ast.nodes.expr(ast::Expr::Var(b"value".to_vec()));
        let env = vec![
            (b"value".to_vec(), int),
            (b"unused".to_vec(), boolean),
            (b"value".to_vec(), boolean),
        ];
        let mut elaborator = Elaborator::new(&ast);
        assert_eq!(elaborator.infer(0, 1, &env, value), Some(int));
    }
}
