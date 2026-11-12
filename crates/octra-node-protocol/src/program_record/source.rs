//! Source publication binds declared compiler, scoped executable and report to
//! the currently deployed code. The publication path supplies owner authority.
use super::Record;
use crate::{
    aml::{
        self,
        compiler::{self, package, prior, protocol, AbiMode, Output, SourceMode, Version},
        source::{self, Syntax},
    },
    native_json::{Document, ReadError, ReadMode, Value},
    program_attestation,
    program_wire::{self, Envelope, Source},
    transaction::{decode_base64, json_string},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};

pub const SCHEMA: &[u8] = b"octra_program_source";
pub const MAX_BYTES: usize = 2_097_152;
pub const PROFILES: &[(&[u8], bool)] = &[
    (b"source", false),
    (b"forms", false),
    (b"source", true),
    (b"forms", true),
    (b"protocol", false),
    (b"historical", false),
    (b"package", false),
    (b"package_historical", false),
    (b"package_source", false),
    (b"package_preview", false),
    (b"package", true),
    (b"package_source", true),
    (b"package_preview", true),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sources {
    pub main: Vec<u8>,
    pub files: Vec<Source>,
    pub compiler: Vec<u8>,
    pub loops: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(Vec<u8>),
    Unavailable(Vec<u8>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Invalid(raw) | Self::Unavailable(raw)) = self;
        write!(f, "{}", String::from_utf8_lossy(raw))
    }
}
impl std::error::Error for Error {}
fn invalid(reason: &str) -> Error {
    Error::Invalid(reason.as_bytes().to_vec())
}
fn compiled(error: source::CompileError) -> Error {
    match error {
        source::CompileError::Unavailable(raw) => Error::Unavailable(raw),
        _ => invalid("program source compilation failed"),
    }
}
fn package_error(error: package::Error) -> Error {
    match error {
        package::Error::Unavailable(raw) => Error::Unavailable(raw),
        package::Error::Rejected(_) => invalid("program source compilation failed"),
    }
}
pub fn profile(compiler: &[u8], loops: bool) -> bool {
    matches!(
        compiler,
        b"source" | b"forms" | b"package" | b"package_source" | b"package_preview"
    ) || !loops
        && matches!(
            compiler,
            b"protocol" | b"historical" | b"package_historical"
        )
}
impl Sources {
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = b"{\"main\":".to_vec();
        json_string(&mut raw, &self.main);
        raw.extend_from_slice(b",\"files\":[");
        for (index, file) in self.files.iter().enumerate() {
            if index > 0 {
                raw.push(b',');
            }
            raw.extend_from_slice(b"{\"path\":");
            json_string(&mut raw, &file.path);
            raw.extend_from_slice(b",\"source\":");
            json_string(&mut raw, &file.body);
            raw.push(b'}');
        }
        raw.extend_from_slice(b"],\"compiler\":");
        json_string(&mut raw, &self.compiler);
        raw.extend_from_slice(b",\"loops\":");
        raw.extend_from_slice(if self.loops { b"true" } else { b"false" });
        raw.push(b'}');
        raw
    }
    pub fn decode(encoded: &[u8]) -> Result<Self, Error> {
        if encoded.len() > MAX_BYTES {
            return Err(invalid("program source payload too large"));
        }
        let raw = decode_base64(encoded).map_err(|_| invalid("program source payload invalid"))?;
        if STANDARD.encode(&raw).as_bytes() != encoded {
            return Err(invalid("program source encoding differs"));
        }
        let doc = Document::parse_native(&raw, ReadMode::Tree).map_err(|error| match error {
            ReadError::Unavailable(error) => Error::Unavailable(error.to_string().into_bytes()),
            ReadError::Json { .. } => invalid("program source payload invalid"),
        })?;
        let Value::Object(fields) = doc.root() else {
            return Err(invalid("program source payload invalid"));
        };
        let mut names: Vec<_> = fields.iter().map(|(name, _)| name.as_slice()).collect();
        names.sort_unstable();
        if names != [b"compiler".as_slice(), b"files", b"loops", b"main"] {
            return Err(invalid("program source payload invalid"));
        }
        let (
            Some(Value::String(main)),
            Some(Value::List(files)),
            Some(Value::String(compiler)),
            Some(Value::Bool(loops)),
        ) = (
            doc.field(doc.root(), b"main"),
            doc.field(doc.root(), b"files"),
            doc.field(doc.root(), b"compiler"),
            doc.field(doc.root(), b"loops"),
        )
        else {
            return Err(invalid("program source compiler invalid"));
        };
        if !profile(compiler, *loops) {
            return Err(invalid("program source compiler invalid"));
        }
        let mut sources = Vec::new();
        for id in files {
            let Some(value @ Value::Object(fields)) = doc.get(*id) else {
                return Err(invalid("program source file invalid"));
            };
            if fields.len() != 2 || fields[0].0 == fields[1].0 {
                return Err(invalid("program source file invalid"));
            }
            let (Some(Value::String(path)), Some(Value::String(body))) =
                (doc.field(value, b"path"), doc.field(value, b"source"))
            else {
                return Err(invalid("program source file invalid"));
            };
            sources.push(Source {
                path: path.clone(),
                body: body.clone(),
            });
        }
        let files = program_wire::normalize(main, sources)
            .map_err(|e| Error::Invalid(e.to_string().into_bytes()))?;
        Ok(Self {
            main: main.clone(),
            files,
            compiler: compiler.clone(),
            loops: *loops,
        })
    }
    pub fn text(&self) -> Vec<u8> {
        source_text(&self.main, &self.files)
    }
    pub fn fee(&self) -> BigInt {
        byte_fee(self.text().len())
    }
    pub fn compile(&self, metered: bool) -> Result<(Vec<u8>, Output), Error> {
        if !profile(&self.compiler, self.loops) {
            return Err(invalid("program source compiler invalid"));
        }
        let historical = matches!(
            self.compiler.as_slice(),
            b"historical" | b"package_historical"
        );
        if metered && historical {
            return Err(invalid("program source compilation failed"));
        }
        for file in &self.files {
            let ast = if historical {
                aml::parser::prior(&file.body)
            } else {
                aml::parser::parse(&file.body)
            }
            .map_err(|e| compiled(e.into()))?;
            aml::scope::check_consts(&ast)
                .map_err(|_| invalid("program source compilation failed"))?;
        }
        let resolver = |path: &[u8]| {
            self.files
                .iter()
                .find(|file| file.path == path)
                .map(|file| file.body.clone())
        };
        let body =
            resolver(&self.main).ok_or_else(|| invalid("program source compilation failed"))?;
        let single = self.main == b"main.aml" && self.files.len() == 1;
        let result = match self.compiler.as_slice() {
            b"package" | b"package_historical" | b"package_source" | b"package_preview" => {
                let mode = match self.compiler.as_slice() {
                    b"package_source" => package::CompilerMode::Source,
                    b"package_preview" => package::CompilerMode::Preview,
                    _ => package::CompilerMode::Protocol,
                };
                let built = package::compile_at_metered(
                    &self.main,
                    self.files.clone(),
                    mode,
                    !historical,
                    self.loops,
                    metered,
                )
                .map_err(package_error)?;
                return Ok((built.envelope, built.result));
            }
            b"protocol" => {
                let options = protocol::Options {
                    metered,
                    ..Default::default()
                };
                if single {
                    protocol::compile(&body, options)
                } else {
                    protocol::compile_multi(resolver, &self.main, options, false)
                }
            }
            b"historical" => {
                if single {
                    prior::compile(&body)
                } else {
                    prior::compile_multi(resolver, &self.main, prior::Interfaces::Strict)
                }
            }
            b"source" | b"forms" => {
                let syntax = if self.compiler == b"source" {
                    Syntax::Source
                } else {
                    Syntax::Forms
                };
                let value = if single {
                    source::compile_metered(&body, syntax, self.loops, metered)
                } else {
                    source::compile_multi_metered(
                        resolver, &self.main, syntax, self.loops, metered, false,
                    )
                }
                .map_err(compiled)?;
                let material = if single {
                    body
                } else {
                    compiler::ordered_sources(
                        self.files
                            .iter()
                            .map(|f| (f.path.as_slice(), f.body.as_slice())),
                    )
                };
                Ok(compiler::source_result(
                    &value,
                    Version::Source,
                    AbiMode::Source,
                    syntax,
                    if single {
                        SourceMode::Single
                    } else {
                        SourceMode::Multi
                    },
                    &material,
                ))
            }
            _ => return Err(invalid("program source compiler invalid")),
        }
        .map_err(compiled)?;
        if result.error.is_some() {
            return Err(invalid("program source compilation failed"));
        }
        Ok((result.bytecode.clone(), result))
    }
    pub fn verify(&self, metered: bool, exact: bool, stored: &[u8]) -> Result<Record, Error> {
        let (code, result) = self.compile(metered)?;
        if !scope_matches(&self.main, &self.files, metered, &result.bytecode)? {
            return Err(invalid("program source scope differs"));
        }
        let mut candidates = vec![(code, result.clone())];
        if !exact {
            let envelope = if self.compiler == b"historical" {
                compiler::emit_prior(result)
            } else {
                compiler::emit_program(result)
            }
            .map_err(compiled)?;
            if let Some(code) = &envelope.program_envelope {
                candidates.push((code.clone(), envelope));
            }
        }
        let stored_image = executable(stored)?;
        for (code, result) in candidates {
            let matching = code == stored
                || !exact
                    && match executable(&code) {
                        Ok(image) => image == stored_image,
                        Err(error @ Error::Unavailable(_)) => return Err(error),
                        Err(Error::Invalid(_)) => false,
                    };
            if matching {
                return Ok(make(&self.text(), stored, &result));
            }
        }
        Err(invalid("program source bytecode mismatch"))
    }
}
pub fn source_text(main: &[u8], files: &[Source]) -> Vec<u8> {
    if let [file] = files {
        if main == b"main.aml" && file.path == b"main.aml" {
            return file.body.clone();
        }
    }
    let mut raw = vec![b'{'];
    if main != b"main.aml" {
        raw.extend_from_slice(b"\"main\":");
        json_string(&mut raw, main);
        raw.extend_from_slice(b",\"files\":{");
    }
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            raw.push(b',');
        }
        json_string(&mut raw, &file.path);
        raw.push(b':');
        json_string(&mut raw, &file.body);
    }
    raw.push(b'}');
    if main != b"main.aml" {
        raw.push(b'}');
    }
    raw
}
pub fn byte_fee(bytes: usize) -> BigInt {
    BigInt::from(200_000) + BigInt::from(bytes.div_ceil(16))
}
pub fn make(source: &[u8], code: &[u8], result: &Output) -> Record {
    Record {
        source: source.to_vec(),
        abi: result.abi_json.clone(),
        report: (!result.verification_json.is_empty()).then(|| result.verification_json.clone()),
        certificate: (!result.certificate_json.is_empty()).then(|| result.certificate_json.clone()),
        code_hash: hex::encode(Sha256::digest(code)).into_bytes(),
    }
}
pub fn check(record: &Record) -> Result<(), Error> {
    if record.encode().len() > MAX_BYTES {
        Err(invalid("program record too large"))
    } else if !super::valid_hash(&record.code_hash) {
        Err(invalid("program record code hash invalid"))
    } else {
        Ok(())
    }
}
pub fn fee(record: &Record) -> BigInt {
    byte_fee(record.encode().len())
}
pub fn executable(raw: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    if !raw.starts_with(b"OCPG") {
        return Ok((raw.to_vec(), None));
    }
    let envelope = Envelope::decode(raw).map_err(|_| invalid("program bytecode invalid"))?;
    let document =
        Document::parse_native(&envelope.cert, ReadMode::Safe).map_err(|error| match error {
            ReadError::Unavailable(error) => Error::Unavailable(error.to_string().into_bytes()),
            ReadError::Json { .. } => invalid("program certificate invalid"),
        })?;
    let payload =
        program_attestation::payload(b"source-check", &document).map_err(|error| match error {
            program_attestation::Error::Allocation => {
                Error::Unavailable(error.to_string().into_bytes())
            }
            _ => invalid("program certificate invalid"),
        })?;
    Ok((envelope.code, Some(payload)))
}
pub enum Scope {
    Unchanged,
    Images(Vec<Vec<u8>>),
}
impl Scope {
    pub fn matches(&self, code: &[u8]) -> bool {
        match self {
            Self::Unchanged => true,
            Self::Images(images) => images.iter().any(|image| image == code),
        }
    }
}
pub fn scope_check(main: &[u8], files: &[Source], metered: bool) -> Result<Scope, Error> {
    let mut scoped = false;
    for file in files {
        match aml::parser::parse(&file.body) {
            Ok(ast) => scoped |= aml::scope::source_scope(&ast),
            Err(aml::parser::Error::Unavailable(reason)) => return Err(Error::Unavailable(reason)),
            Err(_) => scoped = true,
        }
    }
    if !scoped {
        return Ok(Scope::Unchanged);
    }
    let resolver = |path: &[u8]| {
        files
            .iter()
            .find(|file| file.path == path)
            .map(|file| file.body.clone())
    };
    let mut images = Vec::new();
    for syntax in [Syntax::Source, Syntax::Forms] {
        match source::compile_multi_metered(resolver, main, syntax, true, metered, false) {
            Ok(value) => images.push(value.octb),
            Err(source::CompileError::Unavailable(reason)) => {
                return Err(Error::Unavailable(reason))
            }
            Err(_) => (),
        }
    }
    match protocol::compile_multi(
        resolver,
        main,
        protocol::Options {
            metered,
            loops: true,
            ..Default::default()
        },
        false,
    ) {
        Ok(value) if value.error.is_none() => images.push(value.bytecode),
        Err(source::CompileError::Unavailable(reason)) => return Err(Error::Unavailable(reason)),
        _ => (),
    }
    Ok(Scope::Images(images))
}
pub fn scope_matches(
    main: &[u8],
    files: &[Source],
    metered: bool,
    code: &[u8],
) -> Result<bool, Error> {
    scope_check(main, files, metered).map(|scope| scope.matches(code))
}
pub fn record_scope(stored: &[u8], record: &Record) -> Result<(), Error> {
    let (main, files) = match Document::parse_native(&record.source, ReadMode::Tree) {
        Err(ReadError::Json { .. }) => (
            b"main.aml".to_vec(),
            vec![Source {
                path: b"main.aml".to_vec(),
                body: record.source.clone(),
            }],
        ),
        Err(ReadError::Unavailable(error)) => {
            return Err(Error::Unavailable(error.to_string().into_bytes()))
        }
        Ok(doc) => {
            let Value::Object(fields) = doc.root() else {
                return Err(invalid("program source record invalid"));
            };
            let (main, entries) = if fields.len() == 2 {
                match (
                    doc.field(doc.root(), b"main"),
                    doc.field(doc.root(), b"files"),
                ) {
                    (Some(Value::String(main)), Some(Value::Object(files))) => {
                        (main.clone(), files)
                    }
                    _ => (b"main.aml".to_vec(), fields),
                }
            } else {
                (b"main.aml".to_vec(), fields)
            };
            let mut files = Vec::new();
            for (path, id) in entries {
                let Some(Value::String(body)) = doc.get(*id) else {
                    return Err(invalid("program source record invalid"));
                };
                files.push(Source {
                    path: path.clone(),
                    body: body.clone(),
                });
            }
            (main, files)
        }
    };
    let files = program_wire::normalize(&main, files)
        .map_err(|e| Error::Invalid(e.to_string().into_bytes()))?;
    let (code, _) = executable(stored)?;
    if scope_matches(&main, &files, true, &code)? {
        Ok(())
    } else {
        Err(invalid("program source scope differs"))
    }
}
