//! Explicit local source-to-binary tooling for the existing Legacy VM.
//!
//! A source declaration does not grant typed Program authority. This route
//! preserves the adopted emitter and binary admission, and never emits OCPS or
//! OCPG. Its certificate describes a reproducible build, not a trusted signer.
use super::{Artifact, Error, Result};
use octra_node_protocol::{
    aml::{
        compiler::{self, AbiMode, SourceMode, Version},
        source::{self, Syntax},
    },
    program_trust::Keys,
};

pub fn legacy(source: &[u8], loops: bool, point_ops: bool) -> Result<serde_json::Value> {
    if source.len() > 1_048_576 {
        return Err(Error::rejected("source exceeds compile limit"));
    }
    let compiled = source::compile(source, Syntax::Source, loops).map_err(|error| match error {
        source::CompileError::Unavailable(reason) => {
            Error::unavailable(String::from_utf8_lossy(&reason))
        }
        other => Error::rejected(other.text()),
    })?;
    let admitted = Artifact::binary(&compiled.octb, point_ops, &Keys::default())?;
    if admitted.admitted().facts().is_some() || admitted.admission() != b"binary" {
        return Err(Error::rejected("expected Legacy binary admission"));
    }
    let result = compiler::source_result(
        &compiled,
        Version::Source,
        AbiMode::Source,
        Syntax::Source,
        SourceMode::Single,
        source,
    );
    let response =
        octra_node_protocol::aml::rpc::compiled(&result, None).map_err(Error::unavailable)?;
    let mut report: serde_json::Value =
        serde_json::from_slice(&response).map_err(Error::unavailable)?;
    report["target_admission"] = "legacy-binary".into();
    report["typed_admission"] = false.into();
    Ok(report)
}
