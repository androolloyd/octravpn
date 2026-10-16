// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Shared legacy OCTB dispatcher, parameters and method declarations.
use crate::octb::Value;
use octra_node_protocol::{
    circle_wasm::{Error, Execution, Method},
    native_json::Document,
    octb::{Instruction as I, Value as Constant},
};
fn program_error(error: crate::program::Error) -> Error {
    match error {
        crate::program::Error::Rejected(reason) => Error::Rejected(reason),
        crate::program::Error::Unavailable(reason) => Error::Unavailable(reason.into_bytes()),
    }
}

pub(crate) fn methods(code: &[I]) -> Vec<Method> {
    let Some(entry) = code.iter().position(|op| matches!(op, I::Jdest(100))) else {
        return vec![];
    };
    let mut labels = std::collections::BTreeMap::new();
    for (index, op) in code.iter().enumerate() {
        if let I::Jdest(label) = op {
            labels.insert(*label, index);
        }
    }
    let mut methods = vec![];
    for pc in entry + 1..code.len() {
        match (&code[pc], code.get(pc + 1), code.get(pc + 2)) {
            (I::Ldi(_, name), Some(I::Eq(..)), Some(I::Jif(_, label))) => {
                if let Constant::Str(name) = name.as_ref() {
                    let view = labels.get(label).is_none_or(|target| {
                        for (pc, op) in code.iter().enumerate().skip(*target) {
                            match op {
                                I::Sstore(..)
                                | I::Sstorek(..)
                                | I::Sdel(..)
                                | I::Sdelk(..)
                                | I::Transfer(..) => return false,
                                I::Stop() | I::Revert() => break,
                                I::Jdest(_) if pc > *target => break,
                                _ => (),
                            }
                        }
                        true
                    });
                    methods.push(Method {
                        name: name.to_vec(),
                        view,
                        execution: Execution::Standard,
                    });
                }
            }
            (I::Stop() | I::Revert(), _, _) => break,
            _ => (),
        }
    }
    methods
}

pub(crate) fn arity(code: &[I], method: &[u8]) -> Option<usize> {
    let entry = code.iter().position(|op| matches!(op, I::Jdest(100)))?;
    for pc in entry + 1..code.len() {
        match (&code[pc], code.get(pc + 1), code.get(pc + 2)) {
            (I::Ldi(_, name), Some(I::Eq(..)), Some(I::Jif(_, target)))
                if matches!(name.as_ref(), Constant::Str(name) if name.as_ref() == method)
                    && *target > 0
                    && (*target as usize) < code.len() =>
            {
                return Some(
                    code[*target as usize + 1..]
                        .iter()
                        .take_while(|op| matches!(op, I::Mload(_, index) if *index >= 1001))
                        .count(),
                );
            }
            (I::Stop() | I::Revert(), _, _) => break,
            _ => (),
        }
    }
    None
}

pub(crate) fn seed_values(machine: &mut crate::octb::Machine, method: &[u8], values: Vec<Value>) {
    machine.memory.insert(999, Value::string(b"call".to_vec()));
    machine.memory.insert(1000, Value::string(method.to_vec()));
    for (index, value) in values.into_iter().enumerate() {
        machine.memory.insert(1001 + index as i64, value);
    }
}

/// Contract.extract_method_target over code whose jumps have been fixed.
pub(crate) fn method_target(code: &[I], method: &[u8]) -> Option<usize> {
    let entry = code.iter().position(|op| matches!(op, I::Jdest(100)))?;
    for pc in entry + 1..code.len() {
        match (&code[pc], code.get(pc + 1), code.get(pc + 2)) {
            (I::Ldi(_, name), Some(I::Eq(..)), Some(I::Jif(_, target))) if matches!(name.as_ref(),Constant::Str(name) if name.as_ref()==method) => {
                return Some(*target as usize)
            }
            (I::Revert() | I::Stop(), _, _) => return None,
            _ => (),
        }
    }
    None
}
pub(crate) fn runtime_parameters(
    admitted: &octra_node_protocol::octb::admission::Admitted,
    code: &[I],
    method: &[u8],
    params: &Document,
) -> Result<Vec<Value>, Error> {
    let target =
        method_target(code, method).ok_or_else(|| Error::Rejected(b"method not found".to_vec()))?;
    crate::program::input::parse(admitted, target, params).map_err(program_error)
}
pub(crate) fn storage_kinds(
    admitted: &octra_node_protocol::octb::admission::Admitted,
    calls: bool,
) -> std::collections::BTreeMap<Vec<u8>, octra_node_protocol::octb::StorageKind> {
    if calls {
        crate::program::input::storage_kinds(admitted)
    } else {
        std::collections::BTreeMap::default()
    }
}

pub(crate) fn dispatcher(code: &[I], method: &[u8]) -> Option<usize> {
    let entry = code.iter().position(|op| matches!(op, I::Jdest(100)))?;
    for pc in entry + 1..code.len() {
        match &code[pc] {
            I::Ldi(_, value) if matches!(value.as_ref(), Constant::Str(name) if name.as_ref() == method) => {
                if matches!(code.get(pc + 1), Some(I::Eq(..)))
                    && matches!(code.get(pc + 2), Some(I::Jif(..)))
                {
                    return Some(entry);
                }
            }
            I::Revert() | I::Stop() => return None,
            _ => (),
        }
    }
    None
}
