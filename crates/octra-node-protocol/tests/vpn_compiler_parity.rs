use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::aml::{
    compiler::{self, AbiMode, SourceMode, Version},
    rpc::{self, Rules},
    source::{self, Syntax},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn source(path: &str) -> &'static [u8] {
    match path {
        "program/main-v5.aml" => include_bytes!("../../../program/main-v5.aml"),
        "program/private-admin-factory.aml" => {
            include_bytes!("../../../program/private-admin-factory.aml")
        }
        _ => panic!("unrecognized native fixture source"),
    }
}
fn assert_bytes(actual: &[u8], native: &[u8], context: impl std::fmt::Display) {
    if actual != native {
        let at = actual
            .iter()
            .zip(native)
            .position(|(a, b)| a != b)
            .unwrap_or(actual.len().min(native.len()));
        let sample = |raw: &[u8]| hex::encode(&raw[at.min(raw.len())..(at + 32).min(raw.len())]);
        panic!("{context}: first mismatch at {at}, sizes Rust={} native={}, Rust sample={} native sample={}",
            actual.len(), native.len(), sample(actual), sample(native));
    }
}

#[test]
fn actual_vpn_and_factory_match_adopted_compiler_bytes_and_metadata() {
    let report: Value = serde_json::from_str(include_str!("fixtures/vpn-compiler.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], map["upstream_commit"]);
    assert_eq!(report["source_sha256"], map["files"]);
    assert_eq!(report["instrumentation"], serde_json::json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/vpn-compiler-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/vpn-compiler-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    for (path, expected) in report["vpn_source_sha256"].as_object().unwrap() {
        assert_eq!(
            *expected,
            hex::encode(Sha256::digest(source(path))),
            "{path}"
        );
    }
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let path = case["path"].as_str().unwrap();
        let raw = source(path);
        let syntax = match case["syntax"].as_str().unwrap() {
            "forms" => Syntax::Forms,
            "source" => Syntax::Source,
            _ => panic!("unrecognized native compiler syntax"),
        };
        let loops = case["loops"].as_bool().unwrap();
        let expected = &case["expected"];
        let result = source::compile(raw, syntax, loops);
        if let Some(reason) = expected["error"].as_str() {
            assert_eq!(result.unwrap_err().text(), reason.as_bytes(), "{case}");
            continue;
        }
        let compiled = result.unwrap_or_else(|error| panic!("{path} {syntax:?}/{loops}: {error}"));
        let output = compiler::source_result(
            &compiled,
            Version::Source,
            AbiMode::Source,
            syntax,
            SourceMode::Single,
            raw,
        );
        for (field, actual) in [
            ("bytecode", output.bytecode.as_slice()),
            ("abi", output.abi_json.as_slice()),
            ("verification", output.verification_json.as_slice()),
            ("certificate", output.certificate_json.as_slice()),
        ] {
            let native = STANDARD.decode(expected[field].as_str().unwrap()).unwrap();
            assert_bytes(
                actual,
                &native,
                format!("{path} {syntax:?}/{loops} {field}"),
            );
        }
        let native_facts = STANDARD
            .decode(expected["facts"].as_str().unwrap())
            .unwrap();
        assert_bytes(
            &output.program_facts.as_ref().unwrap().json(),
            &native_facts,
            format!("{path} {syntax:?}/{loops} storage/type-flow layout"),
        );
        let native_rpc = STANDARD.decode(expected["rpc"].as_str().unwrap()).unwrap();
        assert_bytes(
            &rpc::compiled(&output, None).unwrap(),
            &native_rpc,
            format!("{path} {syntax:?}/{loops} compiled response"),
        );
        let mode = if syntax == Syntax::Forms {
            compiler::package::CompilerMode::Protocol
        } else {
            compiler::package::CompilerMode::Source
        };
        assert_bytes(
            &rpc::single(
                raw,
                Rules {
                    compiler: mode,
                    point_ops: true,
                    loops,
                },
            )
            .unwrap(),
            &native_rpc,
            format!("{path} {syntax:?}/{loops} RPC entry"),
        );
    }
}
