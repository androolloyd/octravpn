// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Typed Program certificate and control-flow admission.
mod facts;
mod flow;
mod policy;
use crate::{
    native_json::{Document, Value},
    octb::{
        admission::{self, Admitted},
        Error, Image,
    },
    program_attestation::{self, field, text},
    program_trust::Keys,
    program_wire::Envelope,
};
pub use facts::{Call, Capability, Entry, Facts, Kind, Xcall};
use sha2::{Digest, Sha256};
use std::sync::Arc;
fn error(message: impl Into<String>) -> Error {
    Error::Message(message.into())
}
fn require(condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(error(message))
    }
}
fn digest(value: Option<&[u8]>) -> bool {
    value.is_some_and(|v| {
        v.len() == 64
            && v.iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    })
}
fn policy_error(error_value: policy::Error) -> Error {
    match error_value {
        policy::Error::Certificate => error("invalid program certificate"),
        policy::Error::Policy(reason) => error(reason),
    }
}
/// Complete transitive entry effects before constructing a Program certificate.
/// These declarations still require policy verification and typed admission.
pub fn complete_effects(code: &[super::Instruction], facts: &Facts) -> Result<Facts, Error> {
    policy::complete(code, facts).map_err(policy_error)
}
pub fn effect_names(code: &[super::Instruction], facts: &Facts) -> Result<Vec<Vec<u8>>, Error> {
    policy::effects(code, facts).map_err(policy_error)
}
pub(crate) fn check_facts(
    code: Vec<super::Instruction>,
    point_ops: bool,
    facts: Facts,
) -> Result<Admitted, Error> {
    let mut admitted = admission::program_code(code, point_ops)?;
    flow::check(admitted.code(), &facts, 1_048_576)
        .map_err(|failure| error(format!("Program type flow: {failure}")))?;
    admitted.facts = Some(Arc::new(facts));
    Ok(admitted)
}
fn certificate(
    raw_code: &[u8],
    code: &[super::Instruction],
    raw: &[u8],
    trusted: Option<&Keys>,
) -> Result<(Facts, Vec<u8>), Error> {
    let doc = Document::parse(raw).map_err(|e| match e {
        crate::native_json::Error::Allocation => Error::Allocation,
        crate::native_json::Error::Syntax(_) => error("invalid program certificate"),
    })?;
    require(
        matches!(doc.root(), Value::Object(_)),
        "program certificate must be an object",
    )?;
    let get = |name: &[u8]| text(&doc, doc.root(), name);
    require(
        get(b"schema") == Some(b"aml_bytecode_certificate_v2"),
        "program certificate schema mismatch",
    )?;
    require(
        get(b"declaration") == Some(b"program"),
        "program certificate declaration mismatch",
    )?;
    require(
        get(b"bytecode_hash") == Some(hex::encode(Sha256::digest(raw_code)).as_bytes()),
        "program certificate bytecode mismatch",
    )?;
    require(
        get(b"compiler") == Some(b"octra_aml")
            && get(b"compiler_version").is_some_and(|v| !v.is_empty())
            && matches!(get(b"source_mode"), Some(b"single" | b"multi"))
            && digest(get(b"source_hash"))
            && digest(get(b"verification_hash")),
        "program certificate provenance mismatch",
    )?;
    if let Some(trusted) = trusted {
        program_attestation::verify(trusted, &doc).map_err(|e| match e {
            program_attestation::Error::Allocation => Error::Allocation,
            _ => error(format!("program compiler attestation: {e}")),
        })?;
    }
    let facts = field(&doc, doc.root(), b"facts")
        .and_then(|v| Facts::parse(&doc, v))
        .ok_or_else(|| error("program certificate facts mismatch"))?;
    let effects = field(&doc, doc.root(), b"effects")
        .and_then(|v| facts::strings(&doc, v))
        .ok_or_else(|| error("program certificate effects mismatch"))?;
    policy::verify(code, &facts, &effects).map_err(|e| match e {
        policy::Error::Certificate => error("invalid program certificate"),
        policy::Error::Policy(reason) => error(format!("program effect policy: {reason}")),
    })?;
    require(
        get(b"facts_hash") == Some(facts.hash().as_slice()),
        "program certificate facts hash mismatch",
    )?;
    Ok((
        facts,
        get(b"compiler_version")
            .ok_or_else(|| error("program certificate provenance mismatch"))?
            .to_vec(),
    ))
}
fn decode_with(raw: &[u8], point_ops: bool, trusted: Option<&Keys>) -> Result<Admitted, Error> {
    let envelope = Envelope::decode(raw).map_err(|e| error(e.to_string()))?;
    let code = Image::decode(&envelope.code, point_ops)?.code;
    let (facts, version) = certificate(&envelope.code, &code, &envelope.cert, trusted)?;
    let mut admitted = admission::program_code(code, point_ops)?;
    flow::check(admitted.code(), &facts, 1_048_576)
        .map_err(|e| error(format!("Program type flow: {e}")))?;
    admitted.facts = Some(Arc::new(facts));
    admitted.compiler_version = Some(version);
    Ok(admitted)
}
pub fn decode(raw: &[u8], point_ops: bool, trusted: &Keys) -> Result<Admitted, Error> {
    decode_with(raw, point_ops, Some(trusted))
}
/// For a source package independently recompiled by the node, or reloading an
/// authenticated stored program with native admission="source" metadata. It
/// must not bypass attestation on an opaque deployment envelope or user flag.
pub fn decode_source(raw: &[u8], point_ops: bool) -> Result<Admitted, Error> {
    decode_with(raw, point_ops, None)
}
pub fn decode_deploy(raw: &[u8], point_ops: bool, trusted: &Keys) -> Result<Admitted, Error> {
    if raw.starts_with(b"OCPG") {
        decode(raw, point_ops, trusted)
    } else {
        admission::decode(raw, point_ops)
    }
}
