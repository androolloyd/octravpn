// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Oct_check validation. Direct AML forms have a separate elaborator.
use super::{
    ast::{
        Ast, BinOp, Binding, Contract, Expr, ExprId, Name, Nodes, Stmt, StmtId, Type, TypeId, UnOp,
    },
    types,
};
use std::sync::Arc;
mod calls;
mod expressions;
mod statements;
pub(crate) use calls::builtin;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub Vec<u8>);
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}
impl std::error::Error for Invalid {}
type Result<T> = std::result::Result<T, Invalid>;
fn invalid(message: impl AsRef<[u8]>) -> Invalid {
    Invalid(message.as_ref().to_vec())
}
#[derive(Clone)]
struct Env {
    locals: Arc<Vec<(Name, TypeId)>>,
    ret: TypeId,
    active: Arc<Vec<Name>>,
}
impl Env {
    fn root(ret: TypeId) -> Self {
        Self {
            locals: Arc::new(vec![]),
            ret,
            active: Arc::new(vec![]),
        }
    }
    fn add(&mut self, name: Name, typ: TypeId) {
        Arc::make_mut(&mut self.locals).push((name, typ));
    }
    fn local(&self, name: &[u8]) -> Option<TypeId> {
        self.locals
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, typ)| *typ)
    }
}
struct Checker<'a> {
    contract: &'a Contract,
    nodes: &'a mut Nodes,
}
impl Checker<'_> {
    fn require(&self, context: &[u8], expected: TypeId, actual: TypeId) -> Result<()> {
        if types::compatible(self.nodes, expected, actual) {
            Ok(())
        } else {
            Err(invalid(
                [
                    context,
                    b" expected = ",
                    self.nodes.typ(expected).name(),
                    b" actual = ",
                    self.nodes.typ(actual).name(),
                ]
                .concat(),
            ))
        }
    }
    fn field(&self, name: &[u8]) -> Result<TypeId> {
        self.contract
            .state
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.typ)
            .ok_or_else(|| invalid([b"state field is undefined name = ".as_slice(), name].concat()))
    }
    fn state_index(&mut self, env: &Env, name: &[u8], keys: &[ExprId]) -> Result<TypeId> {
        let mut typ = self.field(name)?;
        for key in keys {
            let (expected, value) = match self.nodes.typ(typ) {
                Type::Map(key, value) => (*key, *value),
                _ => return Err(invalid("indexed value is not a map")),
            };
            let actual = self.infer(env, *key)?;
            self.require(b"map key type differs", expected, actual)?;
            typ = value;
        }
        Ok(typ)
    }
    fn struct_path(&self, mut typ: TypeId, path: &[Name]) -> Option<TypeId> {
        for name in path {
            let Type::Struct(structure) = self.nodes.typ(typ) else {
                return None;
            };
            let structure = self
                .contract
                .structs
                .iter()
                .find(|item| item.name == *structure)?;
            typ = structure.fields.iter().find(|(field, _)| field == name)?.1;
        }
        Some(typ)
    }
    fn storage_path(
        &mut self,
        env: &Env,
        field: &[u8],
        keys: &[ExprId],
        path: &[Name],
    ) -> Result<TypeId> {
        let base = self.state_index(env, field, keys)?;
        if let Some((last, parent)) = path.split_last() {
            if last == b"length"
                && self
                    .struct_path(base, parent)
                    .is_some_and(|typ| matches!(self.nodes.typ(typ), Type::List(_) | Type::Map(..)))
            {
                return Ok(self.nodes.intern(Type::Int));
            }
        }
        self.struct_path(base, path).ok_or_else(|| {
            let mut message =
                [b"storage path is undefined name = ".as_slice(), field, b"."].concat();
            for (index, name) in path.iter().enumerate() {
                if index != 0 {
                    message.push(b'.');
                }
                message.extend(name);
            }
            invalid(message)
        })
    }
}
pub fn check(ast: &mut Ast) -> Result<()> {
    let returns = types::Returns::new(&ast.nodes);
    let contract = &ast.contract;
    let mut checker = Checker {
        contract,
        nodes: &mut ast.nodes,
    };
    let void = checker.nodes.intern(Type::Void);
    for constant in &contract.consts {
        let mut env = Env::root(void);
        Arc::make_mut(&mut env.active).push(constant.name.clone());
        let actual = checker.infer(&env, constant.value)?;
        if checker.nodes.typ(constant.typ) != &Type::Void {
            checker.require(b"constant type differs", constant.typ, actual)?;
        }
    }
    if let Some(function) = &contract.constructor {
        let mut env = Env::root(void);
        for param in &function.params {
            env.add(param.name.clone(), param.typ);
        }
        checker.block(env, &function.body)?;
    }
    for function in &contract.functions {
        if checker.nodes.typ(function.ret) != &Type::Void && !returns.block(&function.body) {
            return Err(invalid(
                [
                    b"function return is not total function = ".as_slice(),
                    &function.name,
                    b" type = ",
                    checker.nodes.typ(function.ret).name(),
                ]
                .concat(),
            ));
        }
        let mut env = Env::root(function.ret);
        for param in &function.params {
            env.add(param.name.clone(), param.typ);
        }
        checker.block(env, &function.body)?;
    }
    Ok(())
}
