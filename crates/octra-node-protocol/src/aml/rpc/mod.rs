// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Contract_rpc compilation and address projections. Transport, concurrency
//! limits and epoch rule capture belong to the node's RPC host.
use super::{
    ast::Declaration,
    compiler::{self, package, AbiMode, Output, SourceMode, Version},
    parser, source,
};
use crate::{
    native_json::{Document, ReadError, ReadMode, Value},
    octb,
    transaction::{decode_base64, json_string},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::BTreeMap;
mod files;
mod response;
pub mod verification;
pub use files::{validate, File};
pub use response::compiled;

pub use crate::rpc::Fault;
use crate::rpc::{param, require_address, require_string};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rpc(Fault),
    Unavailable(Vec<u8>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let raw = match self {
            Self::Rpc(fault) => &fault.message,
            Self::Unavailable(reason) => reason,
        };
        write!(f, "{}", String::from_utf8_lossy(raw))
    }
}
impl std::error::Error for Error {}
impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::Rpc(fault)
    }
}
impl Error {
    fn invalid(reason: impl AsRef<[u8]>) -> Self {
        Self::Rpc(Fault::invalid(reason))
    }
    fn compile(reason: impl AsRef<[u8]>) -> Self {
        Self::Rpc(Fault::new(-32000, reason))
    }
    fn unavailable(reason: impl std::fmt::Display) -> Self {
        Self::Unavailable(reason.to_string().into_bytes())
    }
}
impl From<source::CompileError> for Error {
    fn from(error: source::CompileError) -> Self {
        match error {
            source::CompileError::Unavailable(reason) => Self::Unavailable(reason),
            other => Self::compile(other.text()),
        }
    }
}
impl From<package::Error> for Error {
    fn from(error: package::Error) -> Self {
        match error {
            package::Error::Unavailable(reason) => Self::Unavailable(reason),
            other @ package::Error::Rejected(_) => Self::compile(other.to_string()),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    pub compiler: package::CompilerMode,
    pub point_ops: bool,
    pub loops: bool,
}
impl Rules {
    /// Native Program_read_rpc.compile_at selection for an RPC epoch. Stateful
    /// deployment admission independently captures its authenticated rule fold.
    pub fn at(chain: &[u8], epoch: i64) -> Self {
        use crate::{
            rules::{self, Rule},
            transaction::RuleMode,
        };
        Self {
            compiler: package::CompilerMode::for_rules(
                rules::at(chain, Rule::ProgramSource, epoch),
                rules::at(chain, Rule::FheWork, epoch),
            ),
            point_ops: rules::at(chain, Rule::Standard, epoch) == RuleMode::Active,
            loops: rules::at(chain, Rule::ProofExecution, epoch) == RuleMode::Active,
        }
    }
    fn syntax(self) -> source::Syntax {
        match self.compiler {
            package::CompilerMode::Protocol => source::Syntax::Forms,
            _ => source::Syntax::Source,
        }
    }
}
fn is_program(raw: &[u8]) -> bool {
    parser::parse(raw).is_ok_and(|ast| ast.contract.declaration == Declaration::Program)
}
pub fn single(source: &[u8], rules: Rules) -> Result<Vec<u8>> {
    validate(source, None, None)?;
    if is_program(source) {
        let built = package::compile_at(
            b"main.aml",
            vec![crate::program_wire::Source {
                path: b"main.aml".to_vec(),
                body: source.to_vec(),
            }],
            rules.compiler,
            rules.point_ops,
            rules.loops,
        )?;
        compiled(&built.result, Some(&built.package))
    } else {
        let compiled_source = source::compile(source, rules.syntax(), rules.loops)?;
        let result = compiler::source_result(
            &compiled_source,
            Version::Source,
            AbiMode::Source,
            rules.syntax(),
            SourceMode::Single,
            source,
        );
        compiled(&result, None)
    }
}
pub fn single_params(doc: &Document, params: &Value, rules: Rules) -> Result<Vec<u8>> {
    let source = require_string(doc, params, 0, "source")?;
    match param(doc, params, 1) {
        None | Some(Value::Bool(_)) => single(source, rules),
        _ => Err(Error::invalid("program must be boolean")),
    }
}
pub fn assembly_params(doc: &Document, params: &Value) -> Result<Vec<u8>> {
    let source = require_string(doc, params, 0, "source")?;
    if source.len() > 1_048_576 {
        return Err(Error::invalid(b"assembly source exceeds compile limit"));
    }
    let encoded = octb::assembler::compile(source).map_err(|failure| match failure {
        octb::assembler::Failure::Exception(reason) => {
            Error::compile([b"compile error: ".as_slice(), &reason].concat())
        }
        octb::assembler::Failure::Rejected(error) => Error::compile(error.to_string()),
        octb::assembler::Failure::Unavailable(error) => Error::unavailable(error),
    })?;
    let mut out = b"{\"bytecode\":".to_vec();
    json_string(&mut out, STANDARD.encode(&encoded.bytes).as_bytes());
    out.extend_from_slice(
        format!(
            ",\"size\":{},\"instructions\":{}}}",
            encoded.bytes.len(),
            encoded.instructions
        )
        .as_bytes(),
    );
    Ok(out)
}
pub fn multi(doc: &Document, object: Option<&Value>, rules: Rules) -> Result<Vec<u8>> {
    let Some(object) = object else {
        return Err(Error::invalid("expected {files, main}"));
    };
    if !matches!(object, Value::Object(_)) {
        return Err(Error::invalid("expected object"));
    }
    if !matches!(doc.field(object, b"program"), None | Some(Value::Bool(_))) {
        return Err(Error::invalid("program must be boolean"));
    }
    let items = match doc.field(object, b"files") {
        Some(Value::List(items)) => items.as_slice(),
        _ => &[],
    };
    let files = files::read(doc, items)?;
    validate(b"", Some(&files), None)?;
    let main = match doc.field(object, b"main") {
        Some(Value::String(main)) => main.as_slice(),
        _ => b"main.aml",
    };
    let sources: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_slice(), file.source.as_slice()))
        .collect();
    if sources.get(main).is_some_and(|raw| is_program(raw)) {
        let built = package::compile_at(
            main,
            files
                .into_iter()
                .map(|file| crate::program_wire::Source {
                    path: file.path,
                    body: file.source,
                })
                .collect(),
            rules.compiler,
            rules.point_ops,
            rules.loops,
        )?;
        return compiled(&built.result, Some(&built.package));
    }
    let compiled_source = source::compile_multi(
        |path| sources.get(path).map(|raw| raw.to_vec()),
        main,
        rules.syntax(),
        rules.loops,
    )?;
    let material = compiler::ordered_sources(sources.iter().map(|(path, raw)| (*path, *raw)));
    let result = compiler::source_result(
        &compiled_source,
        Version::Source,
        AbiMode::Source,
        rules.syntax(),
        SourceMode::Multi,
        &material,
    );
    compiled(&result, None)
}
pub fn multi_params(doc: &Document, params: &Value, rules: Rules) -> Result<Vec<u8>> {
    multi(doc, param(doc, params, 0), rules)
}
pub fn compute_address_params(doc: &Document, params: &Value) -> Result<Vec<u8>> {
    let encoded = require_string(doc, params, 0, "bytecode_b64");
    let deployer = require_address(doc, params, 1, "deployer");
    // Native tuple evaluation computes both arguments, but returns the first
    // error in bytecode/deployer order without decoding either artifact.
    let encoded = encoded?;
    let deployer = deployer?;
    let nonce = match param(doc, params, 2) {
        Some(Value::Int(value)) => value.get(),
        _ => 0,
    };
    let raw = decode_base64(encoded).map_err(|error| {
        Error::compile(
            [
                b"error: ".as_slice(),
                &crate::native_exception::string_argument(
                    b"Invalid_argument",
                    error.to_string().as_bytes(),
                ),
            ]
            .concat(),
        )
    })?;
    let mut out = b"{\"address\":".to_vec();
    json_string(&mut out, &crate::contract::address(&raw, deployer, nonce));
    out.extend_from_slice(b",\"deployer\":");
    json_string(&mut out, deployer);
    out.extend_from_slice(format!(",\"nonce\":{nonce}}}").as_bytes());
    Ok(out)
}
