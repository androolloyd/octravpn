// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_compile AST-to-flow-facts projection. These are declarations for policy
//! completion and type-flow checking, not an admission result.
use super::{
    ast::{Ast, Nodes, Param, Type, TypeId},
    limits,
    source::Syntax,
};
use crate::octb::{
    program::{Call, Capability, Entry, Facts, Kind, Xcall},
    Instruction,
};
use std::collections::{BTreeMap, BTreeSet};
pub fn kind(typ: &Type) -> Kind {
    match typ {
        Type::Int => Kind::Int,
        Type::Bool => Kind::Bool,
        Type::String => Kind::String,
        Type::Address => Kind::Addr,
        Type::Bytes => Kind::Bytes,
        Type::Bytes32 => Kind::Bytes32,
        Type::U64 => Kind::U64,
        Type::U128 => Kind::U128,
        Type::U256 => Kind::U256,
        Type::Cipher => Kind::Cipher,
        Type::PubKey => Kind::PubKey,
        Type::Map(..)
        | Type::List(_)
        | Type::Struct(_)
        | Type::Enum(_)
        | Type::Option(_)
        | Type::Tuple(_)
        | Type::Void => Kind::Unknown,
    }
}
fn source_kind(nodes: &Nodes, syntax: Syntax, typ: TypeId) -> Kind {
    match nodes.typ(typ) {
        Type::Option(_) if syntax == Syntax::Source => Kind::String,
        typ => kind(typ),
    }
}
fn params(nodes: &Nodes, syntax: Syntax, params: &[Param]) -> Vec<(i64, Kind)> {
    params
        .iter()
        .enumerate()
        .map(|(index, param)| (1001 + index as i64, source_kind(nodes, syntax, param.typ)))
        .collect()
}
pub fn of_ast(ast: &Ast, code: &[Instruction], syntax: Syntax) -> Facts {
    let labels: BTreeMap<_, _> = code
        .iter()
        .enumerate()
        .filter_map(|(pc, op)| match op {
            Instruction::Jdest(label) => Some((i64::from(*label), pc as i64)),
            _ => None,
        })
        .collect();
    let root = ast
        .contract
        .constructor
        .as_ref()
        .map_or_else(Vec::new, |constructor| {
            params(&ast.nodes, syntax, &constructor.params)
        });
    let storage = ast
        .contract
        .state
        .iter()
        .filter_map(|field| {
            let kind = kind(ast.nodes.typ(field.typ));
            matches!(
                kind,
                Kind::Int
                    | Kind::Bool
                    | Kind::String
                    | Kind::Bytes
                    | Kind::Bytes32
                    | Kind::U64
                    | Kind::U128
                    | Kind::U256
                    | Kind::Addr
            )
            .then(|| (field.name.clone(), kind))
        })
        .collect();
    let mut functions = BTreeMap::new();
    let mut entries = vec![];
    for (index, function) in ast.contract.functions.iter().enumerate() {
        let label = 200 + index as i64 * 100;
        functions.insert(label, function);
        if let Some(target) = labels.get(&label) {
            entries.push(Entry {
                target: *target,
                memory: params(&ast.nodes, syntax, &function.params),
                effects: vec![],
            });
        }
    }
    let targets: BTreeSet<_> = entries.iter().map(|entry| entry.target).collect();
    let mut owner = None;
    let mut calls = vec![];
    for (pc, op) in code.iter().enumerate() {
        let pc = pc as i64;
        if targets.contains(&pc) {
            owner = Some(pc);
        }
        if let Instruction::CallInt(_, label) = op {
            let label = i64::from(*label);
            if let (Some(target), Some(owner), Some(function)) =
                (labels.get(&label), owner, functions.get(&label))
            {
                calls.push(Call {
                    owner,
                    pc,
                    target: *target,
                    kind: source_kind(&ast.nodes, syntax, function.ret),
                });
            }
        }
    }
    Facts {
        root,
        storage,
        entries,
        calls,
        xcalls: vec![],
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct External {
    pub method: Vec<u8>,
    pub inputs: Vec<Kind>,
    pub output: Kind,
    pub capabilities: Vec<Capability>,
}
pub fn attach_xcalls(
    code: &[Instruction],
    facts: &Facts,
    specs: &[External],
) -> Result<Facts, &'static str> {
    let pcs: Vec<_> = code
        .iter()
        .enumerate()
        .filter_map(|(pc, op)| matches!(op, Instruction::Xcall(..)).then_some(pc as i64))
        .collect();
    if specs.len() > limits::EXTERNAL_CALLS {
        return Err("external ABI limit exceeded");
    }
    if pcs.len() != specs.len() {
        return Err("external ABI count does not match XCALL count");
    }
    let mut facts = facts.clone();
    facts.xcalls = pcs
        .into_iter()
        .zip(specs)
        .map(|(pc, spec)| Xcall {
            pc,
            method: spec.method.clone(),
            inputs: spec.inputs.clone(),
            output: spec.output,
            capabilities: spec.capabilities.clone(),
        })
        .collect();
    Ok(facts)
}
