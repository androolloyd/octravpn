// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{verify, CompileError, Facts, Result, SourceMode};
use crate::{
    native_json::{Document, ReadError, ReadMode, Value},
    transaction::json_string,
};
use sha2::{Digest, Sha256};
fn hash(value: &[u8]) -> Vec<u8> {
    hex::encode(Sha256::digest(value)).into_bytes()
}
pub fn ordered_sources<'a>(sources: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Vec<u8> {
    let mut sources: Vec<_> = sources.into_iter().collect();
    sources.sort_by(|left, right| left.0.cmp(right.0));
    let mut out = vec![b'['];
    for (index, (path, body)) in sources.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(b"{\"path\":");
        json_string(&mut out, path);
        out.extend_from_slice(b",\"source_hash\":");
        json_string(&mut out, &hash(body));
        out.push(b'}');
    }
    out.push(b']');
    out
}
pub fn certificate(
    version: &[u8],
    declaration: &[u8],
    mode: SourceMode,
    source_material: &[u8],
    bytecode: &[u8],
    verification: &[u8],
) -> Vec<u8> {
    let mut out = b"{\"schema\":\"aml_bytecode_certificate_v1\",\"compiler\":\"octra_aml\",\"compiler_version\":".to_vec();
    json_string(&mut out, version);
    out.extend_from_slice(b",\"declaration\":");
    json_string(&mut out, declaration);
    out.extend_from_slice(b",\"verification_schema\":");
    json_string(&mut out, verify::SCHEMA);
    out.extend_from_slice(b",\"source_mode\":");
    json_string(&mut out, mode.text());
    out.extend_from_slice(b",\"source_hash\":");
    json_string(&mut out, &hash(source_material));
    out.extend_from_slice(b",\"bytecode_hash\":");
    json_string(&mut out, &hash(bytecode));
    out.extend_from_slice(b",\"verification_hash\":");
    json_string(&mut out, &hash(verification));
    out.push(b'}');
    out
}
pub fn program_certificate(raw: &[u8], effects: &[Vec<u8>], facts: &Facts) -> Result<Vec<u8>> {
    let doc = Document::parse_native(raw, ReadMode::Safe).map_err(|error| match error {
        ReadError::Unavailable(error) => CompileError::Unavailable(error.to_string().into_bytes()),
        ReadError::Json { .. } => CompileError::Invalid(b"invalid program certificate".to_vec()),
    })?;
    let Value::Object(fields) = doc.root() else {
        return Err(CompileError::Invalid(
            b"program certificate must be an object".to_vec(),
        ));
    };
    let mut out = b"{\"schema\":\"aml_bytecode_certificate_v2\",\"effects\":[".to_vec();
    for (index, effect) in effects.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        json_string(&mut out, effect);
    }
    out.extend_from_slice(b"],\"facts_hash\":");
    json_string(&mut out, &facts.hash());
    out.extend_from_slice(b",\"facts\":");
    out.extend(facts.json());
    for (key, id) in fields {
        if key == b"schema" || key == b"effects" || key == b"facts" {
            continue;
        }
        out.push(b',');
        json_string(&mut out, key);
        out.push(b':');
        let value = doc.get(*id).expect("certificate JSON field");
        out.extend(
            doc.write(value, false)
                .map_err(|error| CompileError::Unavailable(error.to_string().into_bytes()))?,
        );
    }
    out.push(b'}');
    Ok(out)
}
