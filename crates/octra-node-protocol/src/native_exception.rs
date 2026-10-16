// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! OCaml 4.14 `%S` / Printexc string arguments preserve arbitrary byte strings.
//! Unlike JSON or Rust debug strings, non-ASCII bytes use decimal escapes.
pub fn quoted(out: &mut Vec<u8>, raw: &[u8]) {
    out.push(b'"');
    for &byte in raw {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            8 => out.extend_from_slice(b"\\b"),
            32..=126 => out.push(byte),
            _ => out.extend_from_slice(&[
                b'\\',
                b'0' + byte / 100,
                b'0' + (byte / 10) % 10,
                b'0' + byte % 10,
            ]),
        }
    }
    out.push(b'"');
}
pub fn string_argument(constructor: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = constructor.to_vec();
    out.push(b'(');
    quoted(&mut out, message);
    out.push(b')');
    out
}
