// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_gen environment. The full generator is separate from typed-source checks.
use super::{
    ast::{
        Ast, BinOp, Binding, Contract, Declaration, Expr, ExprId, Function, Name, Nodes, Param,
        Refinement, Stmt, StmtId, Type, TypeId, UnOp, Visibility,
    },
    emit::{Emitter, Error, Result},
    source::Syntax,
    types,
};
use std::{collections::BTreeMap, sync::Arc};
mod depth;
mod entries;
mod expressions;
mod inference;
mod lists;
mod options;
mod protocol_inference;
mod statements;
mod storage;
mod writes;
pub use entries::{generate, imperative, linked, prior, protocol, Generated};
#[derive(Clone, Debug)]
pub struct Local {
    pub name: Name,
    pub register: u8,
    pub typ: TypeId,
}
pub struct Generator<'a> {
    pub contract: &'a Contract,
    pub nodes: &'a mut Nodes,
    pub code: Emitter,
    pub loops: bool,
    pub locals: Arc<Vec<Local>>,
    pub loop_regs: Vec<u8>,
    pub function_labels: BTreeMap<Name, u32>,
    pub forms: Vec<Name>,
    pub direct: Vec<Name>,
    pub has_payable: bool,
    pub in_nonreentrant: bool,
    pub function_direct: bool,
    pub function_return: TypeId,
}
impl<'a> Generator<'a> {
    pub(crate) fn prior(ast: &'a mut Ast) -> Self {
        let mut generator = Self::protocol(ast, false, false);
        generator.code = Emitter::prior();
        generator
    }
    /// Historical Oct_emit state uses its own inference and storage namespace.
    pub(crate) fn protocol(ast: &'a mut Ast, loops: bool, checked: bool) -> Self {
        let mut generator = Self::new(ast, Syntax::Forms, loops, vec![]);
        generator.forms.clear();
        generator.code = Emitter::protocol(checked);
        generator
    }
    pub fn new(ast: &'a mut Ast, syntax: Syntax, loops: bool, direct: Vec<Name>) -> Self {
        let function_return = ast.nodes.intern(Type::Void);
        let forms = ast
            .contract
            .forms
            .iter()
            .map(|form| form.name.clone())
            .collect();
        let has_payable = ast
            .contract
            .functions
            .iter()
            .any(|function| function.payable);
        Self {
            contract: &ast.contract,
            nodes: &mut ast.nodes,
            code: Emitter::new(syntax),
            loops,
            locals: Arc::new(vec![]),
            loop_regs: vec![],
            function_labels: BTreeMap::new(),
            forms,
            direct,
            has_payable,
            in_nonreentrant: false,
            function_direct: false,
            function_return,
        }
    }
    pub fn require_type(&self, context: &[u8], expected: TypeId, actual: TypeId) -> Result<()> {
        if types::compatible(self.nodes, expected, actual) {
            Ok(())
        } else {
            Err(self.code.located_error(
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
    pub fn is_form(&self, name: &[u8]) -> bool {
        self.forms.iter().any(|form| form == name)
    }
    pub fn is_direct(&self, name: &[u8]) -> bool {
        self.direct.iter().any(|entry| entry == name)
    }
    pub fn local(&self, name: &[u8]) -> Option<&Local> {
        self.locals.iter().rev().find(|local| local.name == name)
    }
    pub fn bind(&mut self, name: Name, register: u8, typ: TypeId) {
        Arc::make_mut(&mut self.locals).push(Local {
            name,
            register,
            typ,
        });
    }
    pub fn integer_storage(&self, typ: TypeId) -> bool {
        match self.nodes.typ(typ) {
            Type::Int | Type::U64 | Type::U128 | Type::U256 | Type::Enum(_) => true,
            Type::Struct(name) => self.contract.enums.iter().any(|item| item.name == *name),
            _ => false,
        }
    }
    pub fn typed_storage(&self, typ: TypeId) -> bool {
        self.contract.declaration == Declaration::Program
            && matches!(
                self.nodes.typ(typ),
                Type::Int
                    | Type::Bool
                    | Type::String
                    | Type::Address
                    | Type::Bytes
                    | Type::Bytes32
                    | Type::U64
                    | Type::U128
                    | Type::U256
            )
    }
    pub fn map_value(&self, mut typ: TypeId) -> TypeId {
        while let Type::Map(_, value) = self.nodes.typ(typ) {
            typ = *value;
        }
        typ
    }
    pub fn struct_path(&self, mut typ: TypeId, path: &[Name]) -> Option<TypeId> {
        for segment in path {
            let Type::Struct(name) = self.nodes.typ(typ) else {
                return None;
            };
            let structure = self
                .contract
                .structs
                .iter()
                .find(|item| item.name == *name)?;
            typ = structure.fields.iter().find(|(name, _)| name == segment)?.1;
        }
        Some(typ)
    }
    pub fn storage_base(&self, field: &[u8], indexed: bool) -> Option<TypeId> {
        let typ = self
            .contract
            .state
            .iter()
            .find(|item| item.name == field)?
            .typ;
        Some(if indexed { self.map_value(typ) } else { typ })
    }
    pub fn storage_length(&self, field: &[u8], indexed: bool, path: &[Name]) -> Option<Vec<Name>> {
        let (last, prefix) = path.split_last()?;
        if last != b"length" {
            return None;
        }
        let typ = self.struct_path(self.storage_base(field, indexed)?, prefix)?;
        matches!(self.nodes.typ(typ), Type::List(_) | Type::Map(..)).then(|| prefix.to_vec())
    }
    pub fn storage_type(&mut self, field: &[u8], indexed: bool, path: &[Name]) -> Option<TypeId> {
        if self.storage_length(field, indexed, path).is_some() {
            Some(self.nodes.intern(Type::Int))
        } else {
            self.struct_path(self.storage_base(field, indexed)?, path)
        }
    }
    pub fn storage_loaded(&mut self, register: u8, typ: TypeId) -> Result<u8> {
        if self.integer_storage(typ) {
            self.code.int_from_storage(register)
        } else if self.nodes.typ(typ) == &Type::Bool {
            self.code.bool_from_storage(register)
        } else {
            Ok(register)
        }
    }
    pub fn enum_index(&self, name: &[u8], variant: &[u8]) -> Result<usize> {
        let enumeration = self
            .contract
            .enums
            .iter()
            .find(|item| item.name == name)
            .ok_or_else(|| {
                self.code
                    .error([b"unknown enum: ".as_slice(), name].concat())
            })?;
        enumeration
            .variants
            .iter()
            .position(|item| item == variant)
            .ok_or_else(|| {
                self.code
                    .error([b"unknown variant: ".as_slice(), name, b".", variant].concat())
            })
    }
}
pub fn storage_path_name(field: &[u8], path: &[Name]) -> Vec<u8> {
    let mut out = field.to_vec();
    for segment in path {
        out.push(b'.');
        out.extend(segment);
    }
    out
}
pub fn check_interfaces(ast: &Ast) -> Result<()> {
    let error = |message: Vec<u8>| Error::Invalid {
        message,
        line: 0,
        column: 0,
    };
    for name in &ast.contract.implements {
        let interface = ast
            .contract
            .interfaces
            .iter()
            .find(|interface| interface.name == *name)
            .ok_or_else(|| error([b"unknown interface: ".as_slice(), name].concat()))?;
        for method in &interface.methods {
            let function = ast
                .contract
                .functions
                .iter()
                .find(|function| function.name == method.name)
                .ok_or_else(|| {
                    error(
                        [
                            b"contract ".as_slice(),
                            &ast.contract.name,
                            b" implements ",
                            name,
                            b" but missing method: ",
                            &method.name,
                        ]
                        .concat(),
                    )
                })?;
            let prefix = [name.as_slice(), b".", &method.name].concat();
            if method.params.len() != function.params.len() {
                return Err(error(
                    [
                        prefix.as_slice(),
                        format!(
                            ": expected {} params, got {}",
                            method.params.len(),
                            function.params.len()
                        )
                        .as_bytes(),
                    ]
                    .concat(),
                ));
            }
            for (expected, actual) in method.params.iter().zip(&function.params) {
                if expected.typ != actual.typ {
                    return Err(error(
                        [
                            prefix.as_slice(),
                            b": param '",
                            &actual.name,
                            b"' type mismatch: expected ",
                            ast.nodes.typ(expected.typ).name(),
                            b", got ",
                            ast.nodes.typ(actual.typ).name(),
                        ]
                        .concat(),
                    ));
                }
            }
            if method.ret != function.ret {
                return Err(error(
                    [
                        prefix.as_slice(),
                        b": return type mismatch: expected ",
                        ast.nodes.typ(method.ret).name(),
                        b", got ",
                        ast.nodes.typ(function.ret).name(),
                    ]
                    .concat(),
                ));
            }
            if function.visibility != Visibility::Public {
                return Err(error([prefix.as_slice(), b" must be public"].concat()));
            }
        }
    }
    Ok(())
}
