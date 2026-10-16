// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    compiler, package, source, AbiMode, BTreeMap, Error, Material, Output, Result, SourceMode,
    Version,
};
use crate::aml::compiler::protocol;
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
    match package::compile_at(&material.main, sources, mode, points, loops) {
        Ok(built) => Ok(Attempt::Compiled(built.result)),
        Err(package::Error::Rejected(reason)) => Ok(Attempt::Rejected(reason)),
        Err(package::Error::Unavailable(reason)) => Err(Error::Unavailable(reason)),
    }
}
fn surface(material: &Material, syntax: source::Syntax, loops: bool) -> Result<Attempt> {
    let compiled = if material.files.is_some() {
        let sources = sources(material);
        source::compile_multi(
            |path| sources.get(path).map(|raw| raw.to_vec()),
            &material.main,
            syntax,
            loops,
        )
        .map(|compiled| {
            (
                compiled,
                SourceMode::Multi,
                compiler::ordered_sources(sources),
            )
        })
    } else {
        source::compile(&material.source, syntax, loops)
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
fn historical(material: &Material) -> Result<Attempt> {
    let result = if material.files.is_some() {
        let sources = sources(material);
        protocol::compile_multi(
            |path| sources.get(path).map(|raw| raw.to_vec()),
            &material.main,
            protocol::Options::default(),
            false,
        )
    } else {
        protocol::compile(&material.source, protocol::Options::default())
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
pub(super) fn candidates(material: &Material, source_entry: bool) -> Result<Vec<Output>> {
    let attempts = if source_entry {
        // Preserve native evaluation order before applying its distinct result
        // order. All dialect attempts execute, even when an earlier one matches.
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
        let current = surface(material, source::Syntax::Source, false)?;
        let forms = surface(material, source::Syntax::Forms, false)?;
        let scoped = surface(material, source::Syntax::Source, true)?;
        let scoped_forms = surface(material, source::Syntax::Forms, true)?;
        let prior = historical(material)?;
        let mut attempts = vec![current, forms, scoped, scoped_forms];
        match &prior {
            Attempt::Compiled(result)
                if attempts.iter().any(
                    |attempt| matches!(attempt, Attempt::Compiled(other) if executable(other) == executable(result)),
                ) =>
            {
            }
            _ => attempts.push(prior),
        }
        attempts
    };
    let first_error = attempts.first().and_then(|attempt| match attempt {
        Attempt::Rejected(reason) => Some(reason.clone()),
        Attempt::Compiled(_) => None,
    });
    let results: Vec<_> = attempts
        .into_iter()
        .filter_map(|attempt| match attempt {
            Attempt::Compiled(result) => Some(result),
            Attempt::Rejected(_) => None,
        })
        .collect();
    if results.is_empty() {
        Err(Error::compile(
            first_error.unwrap_or_else(|| b"compiler result is absent".to_vec()),
        ))
    } else {
        Ok(results)
    }
}
