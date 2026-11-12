//! Bounded c49 compiler/publication differential, separate from adopted fixtures.
use octra_node_protocol::{
    aml::{
        compiler::{self, protocol, AbiMode, Output, SourceMode, Version},
        parser, scope,
        source::{self, Syntax},
    },
    program_record::source::{self as records, Sources},
    program_wire::Source,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn error(reason: impl std::fmt::Display) -> Value {
    json!({"error":reason.to_string()})
}
fn output(value: &Output) -> Value {
    if let Some(reason) = &value.error {
        return error(String::from_utf8_lossy(reason));
    }
    json!({
        "bytecode":digest(&value.bytecode), "bytecode_size":value.bytecode.len(),
        "abi":digest(&value.abi_json), "verification":digest(&value.verification_json),
        "certificate":digest(&value.certificate_json), "instructions":value.instructions,
        "version":std::str::from_utf8(&value.version).unwrap(),
        "facts":value.program_facts.as_ref().map(|facts| digest(&facts.json())),
    })
}
fn run(input: &Value) -> Value {
    let raw = input["source"].as_str().unwrap().as_bytes();
    let metered = input["metered"].as_bool().unwrap_or(false);
    let loops = input["loops"].as_bool().unwrap_or(false);
    let profile = input["compiler"].as_str().unwrap_or("").as_bytes();
    match input["kind"].as_str().unwrap() {
        "compile" => {
            if profile == b"protocol" {
                return match protocol::compile(
                    raw,
                    protocol::Options {
                        metered,
                        ..Default::default()
                    },
                ) {
                    Ok(value) => output(&value),
                    Err(reason) => error(reason),
                };
            }
            let syntax = if profile == b"forms" {
                Syntax::Forms
            } else {
                Syntax::Source
            };
            match source::compile_metered(raw, syntax, loops, metered) {
                Ok(compiled) => output(&compiler::source_result(
                    &compiled,
                    Version::Source,
                    AbiMode::Source,
                    syntax,
                    SourceMode::Single,
                    raw,
                )),
                Err(reason) => error(reason),
            }
        }
        "publish" => {
            let sources = Sources {
                main: b"main.aml".to_vec(),
                files: vec![Source {
                    path: b"main.aml".to_vec(),
                    body: raw.to_vec(),
                }],
                compiler: profile.to_vec(),
                loops,
            };
            match sources.compile(metered) {
                Err(reason) => error(reason),
                Ok((code, compiled)) => {
                    let checked = |exact, stored: &[u8]| match sources
                        .verify(metered, exact, stored)
                    {
                        Err(reason) => error(reason),
                        Ok(record) => {
                            json!({"record":digest(&record.encode()),"fee":records::fee(&record).to_string(),"valid":match records::check(&record) {Ok(())=>Value::Bool(true),Err(reason)=>Value::String(reason.to_string())}})
                        }
                    };
                    json!({"compiled":output(&compiled),"code":digest(&code),"exact":checked(true,&code),"semantic":checked(false,&code),"damaged":checked(false,&[b"bad".as_slice(),&code].concat()),"encoded":digest(&sources.encode()),"fee":sources.fee().to_string()})
                }
            }
        }
        "scope" => {
            let ast = parser::parse(raw).unwrap();
            json!({"graph": match scope::check_consts(&ast) {Ok(())=>Value::Bool(true),Err(reason)=>Value::String(String::from_utf8(reason).unwrap())},"scoped":scope::source_scope(&ast)})
        }
        _ => panic!("unknown native fixture case"),
    }
}
#[test]
fn c49_compiler_bytes_metadata_metering_and_source_publication_match_native() {
    let report: Value =
        serde_json::from_str(include_str!("fixtures/candidate-compiler.json")).unwrap();
    assert_eq!(
        report["upstream_commit"],
        "c49de45cf49ebbc2e5c0697eb956cbcada5845e7"
    );
    let candidate: Value = serde_json::from_str(include_str!(
        "../../../docs/rust-node/source-map-candidate.json"
    ))
    .unwrap();
    assert_eq!(report["upstream_commit"], candidate["upstream_commit"]);
    for (path, expected) in report["source_sha256"].as_object().unwrap() {
        if let Some(committed) = candidate["files"].get(path) {
            assert_eq!(expected, committed, "native compiler source {path}");
        } else {
            // The source manifest excludes build recipes; this recipe supplies
            // the independently reconstructed source-stamp assertion above.
            assert_eq!(path, "lib/vm/dune");
        }
    }
    for (field, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/candidate-compiler-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/candidate-compiler-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[field], digest(raw), "{field}");
    }
    assert_eq!(
        report["source_stamp"].as_str().unwrap().as_bytes(),
        octra_node_protocol::program_record::SOURCE_STAMP
    );
    assert_eq!(report["compiled_modules"].as_array().unwrap().len(), 100);
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 101);
    for (index, case) in cases.iter().enumerate() {
        if let Some(path) = case["input"]["path"].as_str() {
            let local: &[u8] = match path {
                "program/main-v5.aml" => include_bytes!("../../../program/main-v5.aml"),
                "program/private-admin-factory.aml" => {
                    include_bytes!("../../../program/private-admin-factory.aml")
                }
                _ => panic!("unrecognized native compiler source"),
            };
            assert_eq!(
                case["input"]["source"].as_str().unwrap().as_bytes(),
                local,
                "stale native source {path}"
            );
        }
        assert_eq!(
            run(&case["input"]),
            case["expected"],
            "case {index} {}",
            case["input"]["label"]
        );
    }
}
