// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    json_string, octb, Document, Engine, Error, Output, ReadError, ReadMode, Result, STANDARD,
};
pub(super) fn optional(out: &mut Vec<u8>, name: &[u8], raw: &[u8]) -> Result<()> {
    if raw.is_empty() {
        return Ok(());
    }
    let doc = match Document::parse_native(raw, ReadMode::Safe) {
        Ok(doc) => doc,
        Err(ReadError::Json { .. }) => return Ok(()),
        Err(ReadError::Unavailable(error)) => return Err(Error::unavailable(error)),
    };
    let raw = doc.write(doc.root(), false).map_err(Error::unavailable)?;
    out.push(b',');
    json_string(out, name);
    out.push(b':');
    out.extend_from_slice(&raw);
    Ok(())
}
pub fn compiled(result: &Output, deploy_payload: Option<&[u8]>) -> Result<Vec<u8>> {
    if let Some(error) = &result.error {
        return Err(Error::compile(error));
    }
    let executable = result
        .program_envelope
        .as_deref()
        .unwrap_or(&result.bytecode);
    let disasm = match octb::admission::decode(&result.bytecode, false) {
        Ok(admitted) => octb::assembler::emit(admitted.code()).map_err(Error::unavailable)?,
        Err(error) if error.is_operational() => return Err(Error::unavailable(error)),
        Err(_) => vec![],
    };
    let mut out = b"{\"bytecode\":".to_vec();
    json_string(&mut out, STANDARD.encode(executable).as_bytes());
    out.extend_from_slice(
        format!(
            ",\"size\":{},\"instructions\":{},\"abi\":",
            executable.len(),
            result.instructions
        )
        .as_bytes(),
    );
    json_string(&mut out, &result.abi_json);
    out.extend_from_slice(b",\"version\":");
    json_string(&mut out, &result.version);
    out.extend_from_slice(b",\"disasm\":");
    json_string(&mut out, &disasm);
    for (name, raw) in [
        (
            b"program_envelope".as_slice(),
            result.program_envelope.as_deref(),
        ),
        (b"deploy_payload", deploy_payload),
    ] {
        if let Some(raw) = raw {
            out.push(b',');
            json_string(&mut out, name);
            out.push(b':');
            json_string(&mut out, STANDARD.encode(raw).as_bytes());
        }
    }
    optional(&mut out, b"verification", &result.verification_json)?;
    optional(&mut out, b"certificate", &result.certificate_json)?;
    out.push(b'}');
    Ok(out)
}
