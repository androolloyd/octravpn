// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_compile's existing ABI projection uses OCaml `%S` quoting.
use super::{Abi, Argument, Declaration};
use crate::native_exception::quoted;
fn kind(argument: Argument) -> &'static [u8] {
    match argument {
        Argument::Credits => b"int",
        Argument::Flag => b"bool",
        Argument::Text => b"string",
        Argument::Account => b"address",
        Argument::Bytes => b"bytes",
    }
}
fn boolean(out: &mut Vec<u8>, value: bool) {
    out.extend_from_slice(if value { b"true" } else { b"false" });
}
pub fn encode(declaration: Declaration, abi: &Abi) -> Vec<u8> {
    let mut out = b"{\"declaration\":".to_vec();
    quoted(&mut out, declaration.name());
    out.extend_from_slice(b",\"functions\":[");
    for (index, (name, function)) in abi.functions.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        quoted(&mut out, name);
        out.extend_from_slice(b",\"inputs\":[");
        for (index, input) in function.inputs.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            quoted(&mut out, kind(*input));
        }
        out.extend_from_slice(b"],\"output\":");
        quoted(
            &mut out,
            match function.outputs.as_slice() {
                [output] => kind(*output),
                _ => b"void",
            },
        );
        out.extend_from_slice(b",\"view\":");
        boolean(&mut out, function.pure);
        out.extend_from_slice(b",\"payable\":");
        boolean(&mut out, function.payable);
        out.push(b'}');
    }
    out.extend_from_slice(b"],\"events\":[");
    for (index, (name, fields)) in abi.events.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"name\":");
        quoted(&mut out, name);
        out.extend_from_slice(b",\"fields\":[");
        for (index, (name, field)) in fields.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            out.extend_from_slice(b"{\"name\":");
            quoted(&mut out, name);
            out.extend_from_slice(b",\"type\":");
            quoted(&mut out, kind(*field));
            out.push(b'}');
        }
        out.extend_from_slice(b"]}");
    }
    out.extend_from_slice(b"]}");
    out
}
