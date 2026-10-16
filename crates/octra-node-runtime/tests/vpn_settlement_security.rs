use base64::{engine::general_purpose::STANDARD, Engine as _};
use num_bigint::BigInt;
use octra_node_protocol::{
    aml::source::{self, Syntax},
    circle_storage::StorageTable,
    octb::admission,
};
use octra_node_runtime::octb::{
    fix_jumps, Context, Host, Machine, Options, Unavailable, Value as Cell,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Transfers(Vec<Value>);
impl Host for Transfers {
    fn transfer(&mut self, from: &[u8], to: &[u8], amount: &BigInt) -> Result<bool, Unavailable> {
        self.0.push(json!([
            STANDARD.encode(from),
            STANDARD.encode(to),
            amount.to_string()
        ]));
        Ok(true)
    }
}

fn fragment(path: &str) -> &'static str {
    match path {
        "program/tests/v5/security.t.aml" => {
            include_str!("../../../program/tests/v5/security.t.aml")
        }
        "program/tests/v5/security-02.t.aml" => {
            include_str!("../../../program/tests/v5/security-02.t.aml")
        }
        "program/tests/v5/security-03.t.aml" => {
            include_str!("../../../program/tests/v5/security-03.t.aml")
        }
        "program/tests/v5/security-04.t.aml" => {
            include_str!("../../../program/tests/v5/security-04.t.aml")
        }
        "program/tests/v5/security-05.t.aml" => {
            include_str!("../../../program/tests/v5/security-05.t.aml")
        }
        "program/tests/v5/security-06.t.aml" => {
            include_str!("../../../program/tests/v5/security-06.t.aml")
        }
        _ => panic!("unknown security fragment"),
    }
}
fn test_source(path: &str) -> String {
    let production = include_str!("../../../program/main-v5.aml");
    format!(
        "{}\n{}\n}}\n",
        production.trim_end().strip_suffix('}').unwrap(),
        fragment(path)
    )
}

#[test]
fn rust_compiled_settlement_security_matches_pinned_native_vm() {
    let report: Value = serde_json::from_str(include_str!("fixtures/vpn-settlement.json")).unwrap();
    let inventory: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(report["source_sha256"], inventory["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (name, bytes) in [
        (
            "aml_sha256",
            include_bytes!("../../../program/main-v5.aml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/vpn-settlement-fixtures.py").as_slice(),
        ),
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/vpn-settlement-oracle.ml").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[name], hex::encode(Sha256::digest(bytes)), "{name}");
    }
    let fragments = report["fragments_sha256"].as_object().unwrap();
    assert_eq!(fragments.len(), 6);
    for (path, expected) in fragments {
        assert_eq!(
            *expected,
            hex::encode(Sha256::digest(fragment(path).as_bytes())),
            "{path}"
        );
    }
    let cases = report["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let method = case["input"]["method"].as_str().unwrap();
        let compiled = source::compile(
            test_source(case["input"]["fragment"].as_str().unwrap()).as_bytes(),
            Syntax::Source,
            true,
        )
        .unwrap();
        assert_eq!(
            compiled.octb,
            STANDARD.decode(case["bytecode"].as_str().unwrap()).unwrap(),
            "{method} compiled OCTB"
        );
        let admitted = admission::decode(&compiled.octb, true).unwrap();
        let code = fix_jumps(admitted.code());
        let caller = format!("oct{}", "1".repeat(44)).into_bytes();
        let mut machine = Machine::new(
            Context {
                caller: caller.clone(),
                origin: caller,
                address: b"program".to_vec(),
                epoch: 2_000_000,
                ..Context::default()
            },
            Options {
                limit: 5_000_000,
                proof_exec: true,
                fhe_work: true,
                math: true,
                async_exec: true,
                point_ops: true,
                integer_work: true,
                ..Options::default()
            },
            StorageTable::new(0),
        );
        machine.memory.insert(999, Cell::string(b"call".to_vec()));
        machine
            .memory
            .insert(1000, Cell::string(method.as_bytes().to_vec()));
        let mut host = Transfers::default();
        let ok = machine.run(&code, &mut host, None).unwrap();
        let mut rows = machine.storage.values().iter().collect::<Vec<_>>();
        rows.sort();
        let result = match &machine.regs[0] {
            Cell::Bool(value) => json!(value),
            value => json!(String::from_utf8(value.text().into_owned()).unwrap()),
        };
        let actual = json!({"ok":ok,"effort":machine.effort,"result":result,
            "storage":rows.into_iter().map(|(key,value)|json!([STANDARD.encode(key),STANDARD.encode(value)])).collect::<Vec<_>>(),
            "transfers":host.0,
            "events":machine.events.iter().map(|event|json!([STANDARD.encode(&event.name),event.values.iter().map(|value|STANDARD.encode(value.text())).collect::<Vec<_>>()])).collect::<Vec<_>>()});
        assert_eq!(actual, case["expected"], "{method}");
        if case["input"]["refusal"].is_null() {
            assert!(ok && actual["result"] == true, "{method}");
        } else {
            assert!(!ok, "{method}");
            let reason = STANDARD.encode(case["input"]["refusal"].as_str().unwrap());
            assert!(
                actual["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event[0] == STANDARD.encode(b"Require") && event[1][0] == reason),
                "{method} precise refusal"
            );
        }
    }
}
