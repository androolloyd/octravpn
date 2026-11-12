// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    compiler, package, source, AbiMode, BTreeMap, Error, Material, Output, Result, SourceMode,
    Version,
};
use crate::aml::compiler::{prior, protocol};
// Native bounded task/snapshot records remain inline without extra allocations.
#[allow(clippy::large_enum_variant)]
enum Attempt {
    Compiled(Output),
    Rejected(Vec<u8>),
}
pub(super) fn executable(result: &Output) -> &[u8] {
    result
        .program_envelope
        .as_deref()
        .unwrap_or(&result.bytecode)
}
fn sources(material: &Material) -> BTreeMap<&[u8], &[u8]> {
    let mut sources = BTreeMap::new();
    for file in material.files.iter().flatten() {
        sources.insert(file.path.as_slice(), file.source.as_slice());
    }
    sources.insert(material.main.as_slice(), material.source.as_slice());
    sources
}
fn packaged(
    material: &Material,
    mode: package::CompilerMode,
    points: bool,
    loops: bool,
) -> Result<Attempt> {
    let sources = sources(material)
        .into_iter()
        .map(|(path, body)| crate::program_wire::Source {
            path: path.to_vec(),
            body: body.to_vec(),
        })
        .collect();
    match package::compile_at_metered(&material.main, sources, mode, points, loops, points) {
        Ok(built) => Ok(Attempt::Compiled(built.result)),
        Err(package::Error::Rejected(reason)) => Ok(Attempt::Rejected(reason)),
        Err(package::Error::Unavailable(reason)) => Err(Error::Unavailable(reason)),
    }
}
fn surface(material: &Material, syntax: source::Syntax, loops: bool) -> Result<Attempt> {
    let compiled = if material.files.is_some() {
        let sources = sources(material);
        source::compile_multi_metered(
            |path| sources.get(path).map(|raw| raw.to_vec()),
            &material.main,
            syntax,
            loops,
            true,
            false,
        )
        .map(|compiled| {
            (
                compiled,
                SourceMode::Multi,
                compiler::ordered_sources(sources),
            )
        })
    } else {
        source::compile_metered(&material.source, syntax, loops, true)
            .map(|compiled| (compiled, SourceMode::Single, material.source.clone()))
    };
    match compiled {
        Ok((compiled, mode, bytes)) => {
            let result = compiler::source_result(
                &compiled,
                Version::Source,
                AbiMode::Source,
                syntax,
                mode,
                &bytes,
            );
            Ok(Attempt::Compiled(result))
        }
        Err(source::CompileError::Unavailable(reason)) => Err(Error::Unavailable(reason)),
        Err(error) => Ok(Attempt::Rejected(error.text())),
    }
}
fn protocol_result(material: &Material, historical: bool) -> Result<Attempt> {
    let result = if material.files.is_some() {
        let sources = sources(material);
        if historical {
            prior::compile_multi(
                |path| sources.get(path).map(|raw| raw.to_vec()),
                &material.main,
                prior::Interfaces::Strict,
            )
        } else {
            protocol::compile_multi(
                |path| sources.get(path).map(|raw| raw.to_vec()),
                &material.main,
                protocol::Options {
                    metered: true,
                    ..Default::default()
                },
                false,
            )
        }
    } else if historical {
        prior::compile(&material.source)
    } else {
        protocol::compile(
            &material.source,
            protocol::Options {
                metered: true,
                ..Default::default()
            },
        )
    };
    match result {
        Ok(mut result) => match result.error.take() {
            None => Ok(Attempt::Compiled(result)),
            Some(reason) => Ok(Attempt::Rejected(reason)),
        },
        Err(source::CompileError::Unavailable(reason)) => Err(Error::Unavailable(reason)),
        Err(error) => Ok(Attempt::Rejected(error.text())),
    }
}
pub(super) struct Candidate {
    pub code: Vec<u8>,
    pub result: Output,
}
pub(super) fn candidates(material: &Material, source_entry: bool) -> Result<Vec<Candidate>> {
    let attempts = if source_entry {
        let current = packaged(material, package::CompilerMode::Protocol, true, false)?;
        let source = packaged(material, package::CompilerMode::Source, true, false)?;
        let preview = packaged(material, package::CompilerMode::Preview, true, false)?;
        let prior = packaged(material, package::CompilerMode::Protocol, false, false)?;
        let scoped_protocol = packaged(material, package::CompilerMode::Protocol, true, true)?;
        let scoped_source = packaged(material, package::CompilerMode::Source, true, true)?;
        let scoped_preview = packaged(material, package::CompilerMode::Preview, true, true)?;
        vec![
            current,
            prior,
            source,
            preview,
            scoped_protocol,
            scoped_source,
            scoped_preview,
        ]
    } else {
        vec![
            surface(material, source::Syntax::Source, false)?,
            surface(material, source::Syntax::Forms, false)?,
            surface(material, source::Syntax::Source, true)?,
            surface(material, source::Syntax::Forms, true)?,
            protocol_result(material, false)?,
            protocol_result(material, true)?,
        ]
    };
    let first_error = attempts.first().and_then(|attempt| match attempt {
        Attempt::Rejected(reason) => Some(reason.clone()),
        Attempt::Compiled(_) => None,
    });
    let historical = (!source_entry)
        .then(|| attempts.last())
        .flatten()
        .and_then(|attempt| match attempt {
            Attempt::Compiled(result) => Some(result.clone()),
            Attempt::Rejected(_) => None,
        });
    let mut results = Vec::<Candidate>::new();
    for (index, attempt) in attempts.into_iter().enumerate() {
        if let Attempt::Compiled(result) = attempt {
            let code = if source_entry {
                executable(&result)
            } else {
                &result.bytecode
            };
            if source_entry || index < 4 || !results.iter().any(|row| row.code == *code) {
                results.push(Candidate {
                    code: code.to_vec(),
                    result,
                });
            }
        }
    }
    if !source_entry {
        let mut envelopes = Vec::new();
        for row in &results {
            let result = compiler::emit_program(row.result.clone())?;
            if let Some(code) = &result.program_envelope {
                envelopes.push(Candidate {
                    code: code.clone(),
                    result,
                });
            }
        }
        if let Some(historical) = historical {
            let result = compiler::emit_prior(historical)?;
            if let Some(code) = &result.program_envelope {
                envelopes.push(Candidate {
                    code: code.clone(),
                    result,
                });
            }
        }
        results.extend(envelopes);
    }
    let files = material.sources()?;
    let scope = crate::program_record::source::scope_check(&material.main, &files, true)
        .map_err(super::record_error)?;
    let checked = results
        .into_iter()
        .filter(|row| scope.matches(&row.result.bytecode))
        .collect::<Vec<_>>();
    if checked.is_empty() {
        Err(Error::compile(
            first_error.unwrap_or_else(|| b"compiler result is absent".to_vec()),
        ))
    } else {
        Ok(checked)
    }
}
