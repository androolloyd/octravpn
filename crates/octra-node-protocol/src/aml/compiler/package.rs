// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Rule-selected OCPS compilation and independent source admission.
use super::{
    compile_source, prior, program, protocol, AbiMode, BTreeMap, CompileError, Output, Version,
};
use crate::{
    octb::admission,
    program_wire::{self, Package, Source},
};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerMode {
    Protocol,
    Source,
    Preview,
}
impl CompilerMode {
    pub fn for_rules(
        source: crate::transaction::RuleMode,
        preview: crate::transaction::RuleMode,
    ) -> Self {
        use crate::transaction::RuleMode;
        match source {
            RuleMode::Prior => Self::Protocol,
            RuleMode::Active if preview == RuleMode::Active => Self::Preview,
            RuleMode::Active => Self::Source,
        }
    }
}
impl From<Version> for CompilerMode {
    fn from(version: Version) -> Self {
        match version {
            Version::Source => Self::Source,
            Version::Preview => Self::Preview,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Rejected(Vec<u8>),
    Unavailable(Vec<u8>),
}
impl Error {
    pub fn reason(&self) -> &[u8] {
        match self {
            Self::Rejected(reason) | Self::Unavailable(reason) => reason,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.reason()))
    }
}
impl std::error::Error for Error {}
impl From<program_wire::Error> for Error {
    fn from(error: program_wire::Error) -> Self {
        Self::Rejected(error.to_string().into_bytes())
    }
}
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug)]
pub struct Built {
    pub package: Vec<u8>,
    pub envelope: Vec<u8>,
    pub result: Output,
}
#[derive(Clone, Debug)]
pub struct AdmittedSource {
    envelope: Vec<u8>,
    program: admission::Admitted,
}
impl AdmittedSource {
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn program(&self) -> &admission::Admitted {
        &self.program
    }
    pub fn into_parts(self) -> (Vec<u8>, admission::Admitted) {
        (self.envelope, self.program)
    }
}
fn admitted(envelope: &[u8], point_ops: bool) -> Result<admission::Admitted> {
    program::decode_source(envelope, point_ops).map_err(|error| {
        if error.is_operational() {
            Error::Unavailable(error.to_string().into_bytes())
        } else {
            Error::Rejected(
                [
                    b"Program admission failed: ".as_slice(),
                    error.to_string().as_bytes(),
                ]
                .concat(),
            )
        }
    })
}
fn build(
    mut package: Package,
    compiler: CompilerMode,
    point_ops: bool,
    loops: bool,
    described: bool,
) -> Result<Built> {
    let sources: BTreeMap<_, _> = package
        .sources
        .iter()
        .map(|source| (source.path.as_slice(), source.body.as_slice()))
        .collect();
    let mut used = BTreeSet::new();
    let resolver = |path: &[u8]| {
        let source = sources.get(path)?;
        used.insert(path.to_vec());
        Some(source.to_vec())
    };
    let result = match package.compiler_profile {
        1 => match compiler {
            CompilerMode::Source => compile_source(resolver, &package.main, loops, Version::Source),
            CompilerMode::Preview => {
                compile_source(resolver, &package.main, loops, Version::Preview)
            }
            CompilerMode::Protocol if point_ops => protocol::compile_program_multi(
                resolver,
                &package.main,
                protocol::Options {
                    loops,
                    checked: false,
                    abi: if described {
                        AbiMode::Source
                    } else {
                        AbiMode::Existing
                    },
                    interfaces: if described {
                        protocol::Interfaces::Strict
                    } else {
                        protocol::Interfaces::First
                    },
                },
            ),
            CompilerMode::Protocol => prior::compile_program_multi(
                resolver,
                &package.main,
                if described {
                    prior::Interfaces::Strict
                } else {
                    prior::Interfaces::First
                },
            ),
        },
        _ => Ok(Output::failure(b"unsupported Program compiler profile")),
    }
    .map_err(|error| match error {
        CompileError::Unavailable(reason) => Error::Unavailable(reason),
        other => Error::Rejected([b"Program compile failed: ".as_slice(), &other.text()].concat()),
    })?;
    if let Some(reason) = &result.error {
        return Err(Error::Rejected(
            [b"Program compile failed: ".as_slice(), reason].concat(),
        ));
    }
    let envelope = result
        .program_envelope
        .clone()
        .ok_or_else(|| Error::Rejected(b"Program envelope missing".to_vec()))?;
    if let Some(source) = package
        .sources
        .iter()
        .find(|source| !used.contains(&source.path))
    {
        return Err(Error::Rejected(
            [b"unused Program source: ".as_slice(), &source.path].concat(),
        ));
    }
    admitted(&envelope, point_ops)?;
    package.envelope.clone_from(&envelope);
    Ok(Built {
        package: package.encode()?,
        envelope,
        result,
    })
}
pub fn compile(
    main: &[u8],
    sources: Vec<Source>,
    version: Version,
    point_ops: bool,
    loops: bool,
) -> Result<Built> {
    compile_at(main, sources, version.into(), point_ops, loops)
}
pub fn compile_at(
    main: &[u8],
    sources: Vec<Source>,
    compiler: CompilerMode,
    point_ops: bool,
    loops: bool,
) -> Result<Built> {
    if compiler != CompilerMode::Protocol && !point_ops {
        return Err(Error::Rejected(
            b"unsupported Program compiler profile".to_vec(),
        ));
    }
    let sources = program_wire::normalize(main, sources)?;
    build(
        Package {
            compiler_profile: 1,
            main: main.to_vec(),
            sources,
            envelope: vec![],
        },
        compiler,
        point_ops,
        loops,
        true,
    )
}
pub fn admit_base64(
    encoded: &[u8],
    version: Version,
    point_ops: bool,
    loops: bool,
) -> Result<AdmittedSource> {
    admit_with(encoded, version.into(), point_ops, loops)
}
pub fn admit_with(
    encoded: &[u8],
    compiler: CompilerMode,
    point_ops: bool,
    loops: bool,
) -> Result<AdmittedSource> {
    if compiler != CompilerMode::Protocol && !point_ops {
        return Err(Error::Rejected(
            b"unsupported Program compiler profile".to_vec(),
        ));
    }
    let package = Package::decode_base64(encoded)?;
    let built = build(
        Package {
            envelope: vec![],
            ..package.clone()
        },
        compiler,
        point_ops,
        loops,
        false,
    );
    let built = if compiler == CompilerMode::Preview {
        match built {
            Ok(built) if built.envelope == package.envelope => built,
            Err(error @ Error::Unavailable(_)) => return Err(error),
            _ => build(
                Package {
                    envelope: vec![],
                    ..package.clone()
                },
                CompilerMode::Source,
                point_ops,
                loops,
                false,
            )?,
        }
    } else {
        built?
    };
    if built.envelope != package.envelope {
        return Err(Error::Rejected(
            b"Program source and envelope mismatch".to_vec(),
        ));
    }
    let program = admitted(&package.envelope, point_ops)?;
    Ok(AdmittedSource {
        envelope: package.envelope,
        program,
    })
}
pub fn admit_transition(encoded: &[u8], point_ops: bool, loops: bool) -> Result<AdmittedSource> {
    if !point_ops {
        return Err(Error::Rejected(
            b"unsupported Program compiler profile".to_vec(),
        ));
    }
    match admit_with(encoded, CompilerMode::Source, point_ops, loops) {
        Ok(admitted) => Ok(admitted),
        Err(error @ Error::Unavailable(_)) => Err(error),
        Err(source_error) => match admit_with(encoded, CompilerMode::Protocol, point_ops, loops) {
            Ok(admitted) => Ok(admitted),
            Err(error @ Error::Unavailable(_)) => Err(error),
            Err(_) => Err(source_error),
        },
    }
}
