// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Aml_source composition through canonical bytecode and call-proof binding.
//! A compiled artifact is not a Program certificate or deployment admission.
use super::super::{abi, ast, call, emit, forms, generate, limits, parser, scope};
use super::{body_empty, diagnostic, shape, Syntax};
use crate::octb::{self, admission, Instruction, Metadata};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
#[derive(Clone, Debug)]
pub struct Compiled {
    pub name: ast::Name,
    pub declaration: ast::Declaration,
    pub ast: ast::Ast,
    pub code: Vec<Instruction>,
    pub octb: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    Invalid(Vec<u8>),
    Located {
        source: Option<Vec<u8>>,
        line: usize,
        column: Option<usize>,
        message: Vec<u8>,
    },
    Unavailable(Vec<u8>),
}
impl CompileError {
    pub fn text(&self) -> Vec<u8> {
        match self {
            Self::Invalid(reason) | Self::Unavailable(reason) => reason.clone(),
            Self::Located {
                source,
                line,
                column,
                message,
            } => diagnostic(
                source.as_deref(),
                *line as i64,
                column.map(|value| value as i64),
                message,
            ),
        }
    }
    fn source(mut self, path: &[u8]) -> Self {
        if let Self::Located { source, .. } = &mut self {
            *source = Some(path.to_vec());
        }
        self
    }
}
impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.text()))
    }
}
impl std::error::Error for CompileError {}
impl From<parser::Error> for CompileError {
    fn from(error: parser::Error) -> Self {
        let error = match error {
            parser::Error::Lex(error) | parser::Error::Parse(error) => error,
            parser::Error::Native(reason) => {
                return Self::Invalid([b"compile error: ".as_slice(), &reason].concat())
            }
        };
        Self::Located {
            source: None,
            line: error.line,
            column: Some(error.column),
            message: error.message,
        }
    }
}
impl From<emit::Error> for CompileError {
    fn from(error: emit::Error) -> Self {
        match error {
            emit::Error::Failure(reason) => Self::Invalid(reason),
            emit::Error::Invalid {
                message,
                line,
                column,
            } => Self::Located {
                source: None,
                line,
                column: (column > 0).then_some(column),
                message,
            },
            emit::Error::Unavailable(reason) => Self::Unavailable(reason.as_bytes().to_vec()),
        }
    }
}
impl From<octb::Error> for CompileError {
    fn from(error: octb::Error) -> Self {
        match error {
            octb::Error::Allocation => Self::Unavailable(error.to_string().into_bytes()),
            octb::Error::Message(reason) => Self::Invalid(reason.into_bytes()),
            octb::Error::InvalidArgument(reason) => Self::Invalid(reason.as_bytes().to_vec()),
        }
    }
}
type Result<T> = std::result::Result<T, CompileError>;
fn repeated(ast: &ast::Ast) -> Option<&[u8]> {
    let mut seen = BTreeSet::new();
    ast.contract
        .interfaces
        .iter()
        .find_map(|interface| (!seen.insert(&interface.name)).then_some(interface.name.as_slice()))
}
fn verifier_text(error: admission::VerificationError) -> Vec<u8> {
    use admission::VerificationError as E;
    match error {
        E::Register(pc, reg) => format!("register r{reg} is invalid at pc {pc}"),
        E::Span(pc, base, count) => format!("register span r{base}+{count} is invalid at pc {pc}"),
        E::Jump(dest) => format!("jump destination {dest} is absent"),
        E::Duplicate(dest) => format!("jump destination {dest} is repeated"),
        E::Count(count) => format!("instruction count {count} exceeds capacity"),
        E::Empty => "instruction stream is empty".to_owned(),
        E::Reserved(pc) => format!("storage key is reserved at pc {pc}"),
        E::CapabilityKind(pc, kind) => {
            format!("capability kind is invalid at pc {pc} kind = {kind}")
        }
    }
    .into_bytes()
}
pub fn compile_ast(ast: &ast::Ast, syntax: Syntax, loops: bool) -> Result<Compiled> {
    if loops {
        scope::check_loops(ast).map_err(CompileError::Invalid)?;
    }
    shape(syntax, &ast.contract).map_err(CompileError::Invalid)?;
    if let Some(name) = repeated(ast) {
        return Err(CompileError::Invalid(
            [b"duplicate interface name = ".as_slice(), name].concat(),
        ));
    }
    if body_empty(&ast.contract) {
        return Err(CompileError::Invalid(
            b"source declaration body is empty".to_vec(),
        ));
    }
    let program = ast.contract.declaration == ast::Declaration::Program;
    if program && ast.contract.functions.len() + ast.contract.forms.len() > limits::FUNCTIONS {
        return Err(CompileError::Invalid(
            b"program function count exceeds capacity".to_vec(),
        ));
    }
    let mut linked = forms::link(ast).map_err(|error| CompileError::Invalid(error.0))?;
    let generated = generate::linked(&mut linked, syntax, loops)?;
    if program && generated.code.len() > limits::INSTRUCTIONS {
        return Err(CompileError::Invalid(
            b"program instruction count exceeds capacity".to_vec(),
        ));
    }
    admission::verify_detailed(&generated.code)
        .map_err(|error| CompileError::Invalid(verifier_text(error)))?;
    let state = if program {
        abi::storage_kinds(&linked.ast)
    } else {
        vec![]
    };
    let mut metadata = Metadata {
        state: (!state.is_empty()).then_some(state),
        ..Metadata::default()
    };
    if !generated.seals.is_empty() {
        let image = octb::encode(&generated.code, &metadata, true)?;
        metadata.proof = Some(
            call::encode(&image, &generated.seals)
                .map_err(|error| CompileError::Invalid(error.text()))?,
        );
    }
    let octb = octb::encode(&generated.code, &metadata, true)?;
    if let Some(proof) = metadata.proof.take() {
        let image = octb::encode(&generated.code, &metadata, true)?;
        call::verify(&image, &generated.code, &proof)
            .map_err(|error| CompileError::Invalid(error.text()))?;
    }
    Ok(Compiled {
        name: linked.ast.contract.name.clone(),
        declaration: linked.ast.contract.declaration,
        ast: linked.ast,
        code: generated.code,
        octb,
    })
}
pub fn compile(source: &[u8], syntax: Syntax, loops: bool) -> Result<Compiled> {
    let ast = parser::parse(source)?;
    compile_ast(&ast, syntax, loops)
}
fn load(
    cache: &mut BTreeMap<Vec<u8>, Arc<[u8]>>,
    resolver: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
    path: &[u8],
) -> Result<Arc<[u8]>> {
    if let Some(source) = cache.get(path) {
        return Ok(source.clone());
    }
    let source: Arc<[u8]> = resolver(path)
        .ok_or_else(|| {
            CompileError::Invalid([b"source is absent path = ".as_slice(), path].concat())
        })?
        .into();
    cache.insert(path.to_vec(), source.clone());
    Ok(source)
}
fn parse(source: &[u8], path: &[u8], syntax: Syntax) -> Result<ast::Ast> {
    let ast = parser::parse(source).map_err(|error| CompileError::from(error).source(path))?;
    shape(syntax, &ast.contract).map_err(CompileError::Invalid)?;
    Ok(ast)
}
pub fn compile_multi(
    mut resolver: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    main_path: &[u8],
    syntax: Syntax,
    loops: bool,
) -> Result<Compiled> {
    let mut cache = BTreeMap::new();
    let source = load(&mut cache, &mut resolver, main_path)?;
    let mut main = parse(&source, main_path, syntax)?;
    let mut imported = vec![];
    for import in &main.contract.imports {
        let source = load(&mut cache, &mut resolver, &import.path)?;
        let parsed = parse(&source, &import.path, syntax)?;
        let mut selected = vec![];
        for name in &import.names {
            let interface = parsed
                .contract
                .interfaces
                .iter()
                .find(|interface| &interface.name == name)
                .ok_or_else(|| {
                    CompileError::Invalid(
                        [
                            b"source = ".as_slice(),
                            &import.path,
                            b" imported interface is absent name = ",
                            name,
                        ]
                        .concat(),
                    )
                })?;
            selected.push(interface.clone());
        }
        imported.push((parsed.nodes.type_arena(), selected));
    }
    for (nodes, interfaces) in imported.into_iter().rev() {
        main.prepend_interfaces(&nodes, interfaces);
    }
    compile_ast(&main, syntax, loops).map_err(|error| error.source(main_path))
}
