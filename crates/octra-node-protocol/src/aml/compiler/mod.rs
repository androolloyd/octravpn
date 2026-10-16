// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Source/preview Oct_compile reports, certificates and Program envelopes.
//! Protocol/prior emission is a separate path, never an alias for Source.
use super::{
    abi, facts,
    source::{self, CompileError, Compiled, Syntax},
    verify,
};
use crate::{
    octb::{
        self,
        program::{self, Facts},
    },
    program_wire::Envelope,
};
use std::collections::BTreeMap;
mod certificate;
pub mod package;
pub mod prior;
pub mod protocol;
pub use certificate::{certificate, ordered_sources, program_certificate};
pub const LANG_VERSION: &[u8] = b"1.0 Rehovot";
pub const SOURCE_VERSION: &[u8] = b"2.0 AML-preview";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Source,
    Preview,
}
impl Version {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Source => LANG_VERSION,
            Self::Preview => SOURCE_VERSION,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiMode {
    Existing,
    Source,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMode {
    Single,
    Multi,
}
impl SourceMode {
    pub fn text(self) -> &'static [u8] {
        match self {
            Self::Single => b"single",
            Self::Multi => b"multi",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Output {
    pub bytecode: Vec<u8>,
    pub abi_json: Vec<u8>,
    pub instructions: usize,
    pub error: Option<Vec<u8>>,
    pub version: Vec<u8>,
    pub verification_json: Vec<u8>,
    pub certificate_json: Vec<u8>,
    pub program_envelope: Option<Vec<u8>>,
    pub program_facts: Option<Facts>,
}
impl Output {
    pub fn failure(reason: impl AsRef<[u8]>) -> Self {
        Self {
            bytecode: vec![],
            abi_json: vec![],
            instructions: 0,
            error: Some(reason.as_ref().to_vec()),
            version: LANG_VERSION.to_vec(),
            verification_json: vec![],
            certificate_json: vec![],
            program_envelope: None,
            program_facts: None,
        }
    }
}
type Result<T> = std::result::Result<T, CompileError>;
fn caught(error: CompileError) -> Result<Output> {
    match error {
        CompileError::Unavailable(_) => Err(error),
        _ => Ok(Output::failure(error.text())),
    }
}
fn bytecode_error(error: octb::Error, prefix: &[u8]) -> Result<Output> {
    if error.is_operational() {
        Err(error.into())
    } else {
        Ok(Output::failure(
            [prefix, error.to_string().as_bytes()].concat(),
        ))
    }
}
pub fn source_result(
    compiled: &Compiled,
    version: Version,
    abi_mode: AbiMode,
    syntax: Syntax,
    mode: SourceMode,
    material: &[u8],
) -> Output {
    let verification_json = verify::verify_ast(&compiled.ast).json();
    let certificate_json = certificate(
        version.text(),
        compiled.declaration.name(),
        mode,
        material,
        &compiled.octb,
        &verification_json,
    );
    let program_facts = facts::of_ast(&compiled.ast, &compiled.code, syntax);
    let abi_json = match abi_mode {
        AbiMode::Existing => abi::encode(compiled.declaration, &abi::of_ast(&compiled.ast)),
        AbiMode::Source => abi::encode_source(&compiled.ast),
    };
    Output {
        bytecode: compiled.octb.clone(),
        abi_json,
        instructions: compiled.code.len(),
        error: None,
        version: version.text().to_vec(),
        verification_json,
        certificate_json,
        program_envelope: None,
        program_facts: Some(program_facts),
    }
}
pub fn emit_program_with_facts(result: Output, facts: &Facts) -> Result<Output> {
    emit_program_with_facts_at(result, facts, true)
}
fn emit_program_with_facts_at(
    mut result: Output,
    facts: &Facts,
    point_ops: bool,
) -> Result<Output> {
    if result.error.is_some() {
        return Ok(result);
    }
    let code = match octb::Image::decode(&result.bytecode, point_ops) {
        Ok(image) => image.code,
        Err(error) => return bytecode_error(error, b"Program bytecode: "),
    };
    let facts = match program::complete_effects(&code, facts) {
        Ok(facts) => facts,
        Err(error) => return bytecode_error(error, b"Program effect policy: "),
    };
    let effects = match program::effect_names(&code, &facts) {
        Ok(effects) => effects,
        Err(error) => return bytecode_error(error, b"Program effect policy: "),
    };
    if let Err(error) = program::check_facts(code, point_ops, facts.clone()) {
        return bytecode_error(error, b"Program admission: ");
    }
    let certificate = match program_certificate(&result.certificate_json, &effects, &facts) {
        Ok(certificate) => certificate,
        Err(error) => return caught(error),
    };
    let envelope = match (Envelope {
        code: result.bytecode.clone(),
        cert: certificate.clone(),
    })
    .encode()
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return Ok(Output::failure(
                [
                    b"Program envelope: ".as_slice(),
                    error.to_string().as_bytes(),
                ]
                .concat(),
            ))
        }
    };
    result.certificate_json = certificate;
    result.program_envelope = Some(envelope);
    Ok(result)
}
pub fn emit_program(result: Output) -> Result<Output> {
    if result.error.is_some() {
        return Ok(result);
    }
    let Some(facts) = result.program_facts.clone() else {
        return Ok(Output::failure(b"Program facts missing"));
    };
    emit_program_with_facts(result, &facts)
}
fn emit_prior(result: Output) -> Result<Output> {
    // Prior_compile checks for facts before consulting result.error. Its
    // historical "Program facts missing" projection is intentionally retained.
    let Some(facts) = result.program_facts.clone() else {
        return Ok(Output::failure(b"Program facts missing"));
    };
    emit_program_with_facts_at(result, &facts, false)
}
pub fn attest_program(
    mut result: Output,
    key_id: &[u8],
    private_key: &ed25519_dalek::SigningKey,
) -> Result<Output> {
    if result.error.is_some() {
        return Ok(result);
    }
    if result.program_envelope.is_none() {
        return Ok(Output::failure(b"Program envelope missing"));
    }
    let certificate =
        match crate::program_attestation::attach(key_id, private_key, &result.certificate_json) {
            Ok(certificate) => certificate,
            Err(crate::program_attestation::Error::Allocation) => {
                return Err(CompileError::Unavailable(
                    b"program attestation allocation unavailable".to_vec(),
                ))
            }
            Err(error) => return Ok(Output::failure(error.to_string())),
        };
    let envelope = match (Envelope {
        code: result.bytecode.clone(),
        cert: certificate.clone(),
    })
    .encode()
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return Ok(Output::failure(
                [
                    b"Program envelope: ".as_slice(),
                    error.to_string().as_bytes(),
                ]
                .concat(),
            ))
        }
    };
    result.certificate_json = certificate;
    result.program_envelope = Some(envelope);
    Ok(result)
}
pub fn compile_source(
    mut resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    loops: bool,
    version: Version,
) -> Result<Output> {
    let mut sources = BTreeMap::new();
    let compiled = source::compile_multi(
        |path| {
            let body = resolver(path)?;
            sources.insert(path.to_vec(), body.clone());
            Some(body)
        },
        main,
        Syntax::Source,
        loops,
    );
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(error) => return caught(error),
    };
    if compiled.declaration != super::ast::Declaration::Program {
        return Ok(Output::failure(b"Program declaration required"));
    }
    let material = ordered_sources(
        sources
            .iter()
            .map(|(path, body)| (path.as_slice(), body.as_slice())),
    );
    emit_program(source_result(
        &compiled,
        version,
        AbiMode::Source,
        Syntax::Source,
        SourceMode::Multi,
        &material,
    ))
}
