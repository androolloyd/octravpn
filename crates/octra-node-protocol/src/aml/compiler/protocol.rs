// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Oct_compile's historical Oct_emit pipeline, distinct from Aml_source.
//! The frozen Prior compiler remains a separate rule-selected implementation.
use super::super::{
    ast::{Ast, Declaration},
    check, emit, generate, limits, parser, scope,
};
use super::{
    emit_prior, emit_program, octb, ordered_sources, source, source_result, AbiMode, BTreeMap,
    CompileError, Compiled, Output, Result, SourceMode, Syntax, Version,
};
use std::{collections::BTreeSet, sync::Arc};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interfaces {
    Strict,
    First,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Language {
    Protocol,
    Prior,
}
fn parse(language: Language, raw: &[u8]) -> std::result::Result<Ast, parser::Error> {
    match language {
        Language::Protocol => parser::parse(raw),
        Language::Prior => parser::prior(raw),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub loops: bool,
    pub checked: bool,
    pub abi: AbiMode,
    pub interfaces: Interfaces,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            loops: false,
            checked: false,
            abi: AbiMode::Existing,
            interfaces: Interfaces::Strict,
        }
    }
}
pub(super) fn legacy_caught(error: CompileError) -> Result<Output> {
    match error {
        error @ CompileError::Unavailable(_) => Err(error),
        CompileError::Located { line, message, .. } => Ok(Output::failure(
            [format!("line {line}: ").as_bytes(), &message].concat(),
        )),
        CompileError::Invalid(reason) => Ok(Output::failure(reason)),
    }
}
fn emitted_error(error: emit::Error) -> Result<Output> {
    match error {
        emit::Error::Unavailable(reason) => {
            Err(CompileError::Unavailable(reason.as_bytes().to_vec()))
        }
        emit::Error::Invalid { line, message, .. } => Ok(Output::failure(
            [format!("line {line}: ").as_bytes(), &message].concat(),
        )),
        emit::Error::Failure(reason) => Ok(Output::failure(
            [
                b"compile error: ".as_slice(),
                &crate::native_exception::string_argument(b"Failure", &reason),
            ]
            .concat(),
        )),
    }
}
fn invalid(reason: impl AsRef<[u8]>) -> CompileError {
    CompileError::Invalid(reason.as_ref().to_vec())
}
fn failure(reason: &[u8]) -> CompileError {
    invalid(
        [
            b"compile error: ".as_slice(),
            &crate::native_exception::string_argument(b"Failure", reason),
        ]
        .concat(),
    )
}
fn require_shape(ast: &Ast) -> std::result::Result<(), CompileError> {
    let reason = if ast.contract.imports.len() > limits::IMPORTS {
        Some("Program import count exceeds compiler limit")
    } else if ast
        .contract
        .imports
        .iter()
        .map(|import| import.names.len())
        .sum::<usize>()
        > limits::IMPORT_NAMES
    {
        Some("Program import name count exceeds compiler limit")
    } else if ast.contract.interfaces.len() > limits::INTERFACES {
        Some("Program interface count exceeds compiler limit")
    } else if ast
        .contract
        .interfaces
        .iter()
        .map(|interface| interface.methods.len())
        .sum::<usize>()
        > limits::INTERFACE_METHODS
    {
        Some("Program interface method count exceeds compiler limit")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(invalid(reason));
    }
    let mut seen = BTreeSet::new();
    for interface in &ast.contract.interfaces {
        if !seen.insert(&interface.name) {
            return Err(invalid(
                [
                    b"Program interface is duplicated: ".as_slice(),
                    &interface.name,
                ]
                .concat(),
            ));
        }
    }
    Ok(())
}
pub fn compile_ast(
    ast: &Ast,
    options: Options,
    mode: SourceMode,
    material: &[u8],
) -> Result<Output> {
    compile_ast_mode(ast, options, mode, material, Language::Protocol)
}
pub(super) fn prior_ast(
    ast: &Ast,
    interfaces: Interfaces,
    mode: SourceMode,
    material: &[u8],
) -> Result<Output> {
    compile_ast_mode(
        ast,
        Options {
            interfaces,
            ..Options::default()
        },
        mode,
        material,
        Language::Prior,
    )
}
pub(super) fn prior_program_ast(ast: &Ast, material: &[u8]) -> Result<Output> {
    compile_ast_with(
        ast,
        Options::default(),
        SourceMode::Single,
        material,
        Language::Prior,
        emit_prior,
    )
}
fn compile_ast_mode(
    ast: &Ast,
    options: Options,
    mode: SourceMode,
    material: &[u8],
    language: Language,
) -> Result<Output> {
    compile_ast_with(ast, options, mode, material, language, Ok)
}
fn compile_ast_with(
    ast: &Ast,
    options: Options,
    mode: SourceMode,
    material: &[u8],
    language: Language,
    finish: fn(Output) -> Result<Output>,
) -> Result<Output> {
    let mut ast = ast.clone();
    if options.interfaces == Interfaces::Strict {
        if let Err(error) = require_shape(&ast) {
            return legacy_caught(error);
        }
    } else {
        let mut seen = BTreeSet::new();
        ast.contract
            .interfaces
            .retain(|interface| seen.insert(interface.name.clone()));
    }
    if options.loops {
        if let Err(reason) = scope::check_loops(&ast) {
            return Ok(Output::failure(reason));
        }
    }
    let program = ast.contract.declaration == Declaration::Program;
    if program && ast.contract.functions.len() > limits::FUNCTIONS {
        return finish(Output::failure(b"Program function limit exceeded"));
    }
    if program && options.checked && ast.contract.forms.is_empty() {
        if let Err(error) = check::check(&mut ast) {
            return Ok(Output::failure(
                [b"Program source type: ".as_slice(), &error.0].concat(),
            ));
        }
    }
    if !ast.contract.forms.is_empty() {
        if language == Language::Prior {
            return Err(CompileError::Unavailable(
                b"frozen Prior AST transport contains modern forms".to_vec(),
            ));
        }
        return match source::compile_ast(&ast, Syntax::Forms, options.loops) {
            Ok(compiled) => Ok(source_result(
                &compiled,
                Version::Source,
                options.abi,
                Syntax::Forms,
                mode,
                material,
            )),
            Err(error) => legacy_caught(error),
        };
    }
    let generated = match language {
        Language::Protocol => generate::protocol(&mut ast, options.loops, options.checked),
        Language::Prior => generate::prior(&mut ast),
    };
    let code = match generated {
        Ok(code) => code,
        Err(error) => return emitted_error(error),
    };
    if program && code.len() > limits::INSTRUCTIONS {
        return finish(Output::failure(b"Program instruction limit exceeded"));
    }
    let octb = match octb::encode(
        &code,
        &octb::Metadata::default(),
        language == Language::Protocol,
    ) {
        Ok(octb) => octb,
        Err(error) if error.is_operational() => return Err(error.into()),
        Err(error) => {
            return Ok(Output::failure(
                [b"compile error: ".as_slice(), error.to_string().as_bytes()].concat(),
            ))
        }
    };
    let compiled = Compiled {
        name: ast.contract.name.clone(),
        declaration: ast.contract.declaration,
        ast,
        code,
        octb,
    };
    finish(source_result(
        &compiled,
        Version::Source,
        options.abi,
        Syntax::Forms,
        mode,
        material,
    ))
}
pub fn compile(raw: &[u8], options: Options) -> Result<Output> {
    match parser::parse(raw) {
        Ok(ast) => compile_ast(&ast, options, SourceMode::Single, raw),
        Err(error) => legacy_caught(error.into()),
    }
}
pub fn compile_program(raw: &[u8], checked: bool) -> Result<Output> {
    let ast = match parser::parse(raw) {
        Ok(ast) => ast,
        Err(error) => return legacy_caught(error.into()),
    };
    if ast.contract.declaration != Declaration::Program {
        return Ok(Output::failure(b"Program declaration required"));
    }
    emit_program(compile_ast(
        &ast,
        Options {
            checked,
            ..Options::default()
        },
        SourceMode::Single,
        raw,
    )?)
}
struct Loader<R> {
    resolver: R,
    sources: BTreeMap<Vec<u8>, Arc<[u8]>>,
    parsed: BTreeMap<Vec<u8>, Arc<Ast>>,
    interfaces: Interfaces,
    language: Language,
}
impl<R: FnMut(&[u8]) -> Option<Vec<u8>>> Loader<R> {
    fn load(&mut self, path: &[u8]) -> Option<Arc<[u8]>> {
        if let Some(source) = self.sources.get(path) {
            return Some(source.clone());
        }
        let source: Arc<[u8]> = (self.resolver)(path)?.into();
        self.sources.insert(path.to_vec(), source.clone());
        Some(source)
    }
    fn imported(&mut self, path: &[u8]) -> std::result::Result<Arc<Ast>, CompileError> {
        if let Some(ast) = self.parsed.get(path) {
            return Ok(ast.clone());
        }
        let raw = self
            .load(path)
            .ok_or_else(|| failure(&[b"import not found: ".as_slice(), path].concat()))?;
        let ast = parse(self.language, &raw).map_err(CompileError::from)?;
        if self.interfaces == Interfaces::Strict {
            require_shape(&ast)?;
        }
        let ast = Arc::new(ast);
        self.parsed.insert(path.to_vec(), ast.clone());
        Ok(ast)
    }
}
fn merge<R: FnMut(&[u8]) -> Option<Vec<u8>>>(
    loader: &mut Loader<R>,
    main: &mut Ast,
) -> std::result::Result<(), CompileError> {
    let mut groups = vec![];
    let mut bindings = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for import in &main.contract.imports {
        if loader.interfaces == Interfaces::Strict && import.names.is_empty() {
            continue;
        }
        let parsed = loader.imported(&import.path)?;
        let mut selected = vec![];
        if loader.interfaces == Interfaces::Strict {
            for name in &import.names {
                let interface = parsed
                    .contract
                    .interfaces
                    .iter()
                    .find(|interface| &interface.name == name)
                    .ok_or_else(|| {
                        invalid(
                            [
                                b"Program interface ".as_slice(),
                                name,
                                b" is missing from ",
                                &import.path,
                            ]
                            .concat(),
                        )
                    })?;
                match bindings.get(name) {
                    None => {
                        bindings.insert(name.clone(), import.path.clone());
                        selected.push(interface.clone());
                    }
                    Some(path) if path == &import.path => (),
                    Some(_) => {
                        return Err(invalid(
                            [b"Program interface import is ambiguous: ".as_slice(), name].concat(),
                        ))
                    }
                }
            }
        } else {
            let requested: BTreeSet<_> = import.names.iter().collect();
            for interface in &parsed.contract.interfaces {
                if requested.contains(&interface.name) && seen.insert(interface.name.clone()) {
                    selected.push(interface.clone());
                }
            }
        }
        groups.push((parsed, selected));
    }
    for (parsed, selected) in groups.into_iter().rev() {
        main.prepend_interfaces(&parsed.nodes, selected);
    }
    Ok(())
}
pub fn compile_multi(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    options: Options,
    program_only: bool,
) -> Result<Output> {
    compile_multi_mode(resolver, main, options, program_only, Language::Protocol)
}
pub(super) fn prior_multi(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    interfaces: Interfaces,
    program_only: bool,
) -> Result<Output> {
    compile_multi_mode(
        resolver,
        main,
        Options {
            interfaces,
            ..Options::default()
        },
        program_only,
        Language::Prior,
    )
}
fn compile_multi_mode(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    options: Options,
    program_only: bool,
    language: Language,
) -> Result<Output> {
    let mut loader = Loader {
        resolver,
        sources: BTreeMap::new(),
        parsed: BTreeMap::new(),
        interfaces: options.interfaces,
        language,
    };
    let Some(raw) = loader.load(main) else {
        return legacy_caught(failure(&[b"file not found: ".as_slice(), main].concat()));
    };
    let mut ast = match parse(language, &raw) {
        Ok(ast) => ast,
        Err(error) => return legacy_caught(error.into()),
    };
    if options.interfaces == Interfaces::Strict {
        if let Err(error) = require_shape(&ast) {
            return legacy_caught(error);
        }
    }
    if program_only && ast.contract.declaration != Declaration::Program {
        return Ok(Output::failure(b"Program declaration required"));
    }
    if let Err(error) = merge(&mut loader, &mut ast) {
        return legacy_caught(error);
    }
    let material = ordered_sources(
        loader
            .sources
            .iter()
            .map(|(path, body)| (path.as_slice(), body.as_ref())),
    );
    compile_ast_mode(&ast, options, SourceMode::Multi, &material, language)
}
pub fn compile_program_multi(
    resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main: &[u8],
    options: Options,
) -> Result<Output> {
    emit_program(compile_multi(resolver, main, options, true)?)
}
