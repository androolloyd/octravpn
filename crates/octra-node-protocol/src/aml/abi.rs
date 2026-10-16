// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Adopted Ocs01 ABI projection and Program static-storage kinds.
use super::ast::{Ast, Declaration, Name, Nodes, Type, TypeId, Visibility};
use crate::octb::StorageKind;
use num_bigint::BigInt;
mod encode;
mod source;
pub use encode::encode;
pub use source::{encode as encode_source, type_name};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argument {
    Bytes,
    Text,
    Credits,
    Flag,
    Account,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    pub inputs: Vec<Argument>,
    pub outputs: Vec<Argument>,
    pub effort: BigInt,
    pub pure: bool,
    pub payable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abi {
    pub functions: Vec<(Name, Function)>,
    pub events: Vec<(Name, Vec<(Name, Argument)>)>,
}
fn argument(typ: &Type) -> Argument {
    match typ {
        Type::Int => Argument::Credits,
        Type::Bool => Argument::Flag,
        Type::String => Argument::Text,
        Type::Address => Argument::Account,
        _ => Argument::Bytes,
    }
}
pub fn of_ast(ast: &Ast) -> Abi {
    Abi {
        functions: ast
            .contract
            .functions
            .iter()
            .filter(|function| function.visibility == Visibility::Public)
            .map(|function| {
                (
                    function.name.clone(),
                    Function {
                        inputs: function
                            .params
                            .iter()
                            .map(|param| argument(ast.nodes.typ(param.typ)))
                            .collect(),
                        outputs: vec![argument(ast.nodes.typ(function.ret))],
                        effort: BigInt::from(100),
                        pure: function.view || function.pure,
                        payable: function.payable,
                    },
                )
            })
            .collect(),
        events: ast
            .contract
            .events
            .iter()
            .map(|event| {
                (
                    event.name.clone(),
                    event
                        .fields
                        .iter()
                        .map(|(name, typ, _)| (name.clone(), argument(ast.nodes.typ(*typ))))
                        .collect(),
                )
            })
            .collect(),
    }
}
pub fn storage_kinds(ast: &Ast) -> Vec<(Name, StorageKind)> {
    if ast.contract.declaration != Declaration::Program {
        return vec![];
    }
    ast.contract
        .state
        .iter()
        .filter_map(|field| {
            let kind = match ast.nodes.typ(field.typ) {
                Type::Int => StorageKind::Int,
                Type::Bool => StorageKind::Bool,
                Type::String => StorageKind::String,
                Type::Bytes => StorageKind::Bytes,
                Type::Bytes32 => StorageKind::Bytes32,
                Type::U64 => StorageKind::U64,
                Type::U128 => StorageKind::U128,
                Type::U256 => StorageKind::U256,
                Type::Address => StorageKind::Addr,
                Type::Enum(name) if ast.contract.enums.iter().any(|item| item.name == *name) => {
                    StorageKind::Int
                }
                _ => return None,
            };
            Some((field.name.clone(), kind))
        })
        .collect()
}
