use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_storage::StorageTable,
    octb::{work::Budget, Instruction},
};
use octra_node_runtime::{
    groth16,
    octb::{Context, Host, Machine, Options, Progress, Unavailable, Value as Cell},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[path = "common/circle_host.rs"]
#[allow(dead_code)]
mod common;

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn flag(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap_or(false)
}
struct ProofHost {
    unavailable: bool,
}
impl Host for ProofHost {
    fn groth16(&mut self, key: &[u8], proof: &[u8], inputs: &[u8]) -> Result<bool, Unavailable> {
        if self.unavailable {
            Err(Unavailable("worker unavailable".into()))
        } else {
            Ok(groth16::verify(key, proof, inputs))
        }
    }
}
fn run(v: &Value, stepped: bool) -> Value {
    let mut host = ProofHost {
        unavailable: flag(v, "unavailable"),
    };
    let mut machine = Machine::new(
        Context {
            caller: b"sender".to_vec(),
            origin: b"sender".to_vec(),
            address: b"program".to_vec(),
            ..Context::default()
        },
        Options {
            limit: v["limit"].as_i64().unwrap(),
            strict: flag(v, "strict"),
            is_view: flag(v, "view"),
            proof_exec: flag(v, "proof_exec"),
            fhe_work: flag(v, "fhe_work"),
            math: flag(v, "math"),
            async_exec: flag(v, "async"),
            ..Options::default()
        },
        StorageTable::new(0),
    );
    for (i, v) in v["args"].as_array().unwrap().iter().enumerate() {
        let (kind, value) = v.as_object().unwrap().iter().next().unwrap();
        machine.regs[i + 1] = match kind.as_str() {
            "str" => Cell::string(bytes(value)),
            "bytes" => Cell::Bytes(bytes(value).into()),
            "addr" => Cell::Address(bytes(value).into()),
            "int" => Cell::int(value.as_i64().unwrap()),
            _ => panic!("fixture value"),
        };
    }
    let mut budget = flag(v, "bytes").then(Budget::default);
    let code = [
        Instruction::Groth16VerifyBn254(0, 1, 2, 3),
        Instruction::Stop(),
    ];
    let result = if stepped {
        loop {
            match machine.step(&code, &mut host, budget.as_mut()) {
                Ok(Progress::Running) => (),
                Ok(Progress::Finished) => break Ok(true),
                Ok(Progress::Refused) => break Ok(false),
                Err(e) => break Err(e),
            }
        }
    } else {
        machine.run(&code, &mut host, budget.as_mut())
    };
    let result = result.map_or(json!("unavailable"), |v| json!(v));
    let output = match &machine.regs[0] {
        Cell::Bool(v) => json!({"bool":v}),
        Cell::Int(v) => json!({"int":v.to_string()}),
        _ => panic!(),
    };
    json!({"ok":result,"pc":machine.pc,"effort":machine.effort,"reverted":machine.reverted,
        "output_ready":machine.output_ready,"result":output,
        "events":machine.events.iter().map(|e|json!([STANDARD.encode(&e.name),e.values.iter().map(|v|STANDARD.encode(v.text())).collect::<Vec<_>>()])).collect::<Vec<_>>(),
        "budget":budget.as_ref().map(|b|[b.remaining(),b.available(),b.event_left()])})
}

#[test]
fn native_groth16_bytes_gates_effort_and_worker_outages() {
    let report: Value = serde_json::from_str(include_str!("fixtures/groth16.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], map["upstream_commit"]);
    assert_eq!(report["source_sha256"], map["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/groth16-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/groth16-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(report[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let cases = report["cases"].as_array().unwrap();
    assert!(cases.len() > 100);
    let mut failures = vec![];
    for v in cases {
        for stepped in [false, true] {
            let actual = run(v, stepped);
            if actual != v["expected"] {
                failures.push(format!(
                    "{} stepped={stepped}: actual {actual}, native {}",
                    v["name"], v["expected"]
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .take(15)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn existing_vpn_aml_private_administration_matches_native_state_and_effort() {
    use octra_node_protocol::octb::admission;
    use octra_node_runtime::octb::fix_jumps;
    let report: Value = serde_json::from_str(include_str!("fixtures/vpn-admin.json")).unwrap();
    let map: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(report["upstream_commit"], map["upstream_commit"]);
    assert_eq!(report["source_sha256"], map["files"]);
    assert_eq!(report["instrumentation"], json!({}));
    for (key, raw) in [
        (
            "oracle_sha256",
            include_bytes!("../../../scripts/node-port/vpn-admin-oracle.ml").as_slice(),
        ),
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/vpn-admin-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
        (
            "aml_sha256",
            include_bytes!("../../../program/main-v5.aml").as_slice(),
        ),
        (
            "public_fixture_sha256",
            include_bytes!("fixtures/vpn-admin-public.json").as_slice(),
        ),
    ] {
        assert_eq!(report[key], hex::encode(Sha256::digest(raw)), "{key}");
    }
    let code = admission::decode(&bytes(&report["cases"]["bytecode"]), true).unwrap();
    let code = fix_jumps(code.code());
    let mut committed = StorageTable::new(0);
    let mut host = ProofHost { unavailable: false };
    for case in report["cases"]["cases"].as_array().unwrap() {
        let call = &case["call"];
        let mut machine = Machine::new(
            Context {
                caller: b"relayer".to_vec(),
                origin: b"relayer".to_vec(),
                address: call["program"].as_str().unwrap().as_bytes().to_vec(),
                epoch: 2_000_000,
                ..Context::default()
            },
            Options {
                proof_exec: true,
                fhe_work: true,
                math: true,
                async_exec: true,
                point_ops: true,
                integer_work: true,
                ..Options::default()
            },
            committed.clone(),
        );
        machine.memory.insert(
            999,
            Cell::string(if call["method"] == "constructor" {
                b"constructor".to_vec()
            } else {
                b"call".to_vec()
            }),
        );
        machine.memory.insert(
            1000,
            Cell::string(call["method"].as_str().unwrap().as_bytes().to_vec()),
        );
        for (i, param) in call["params"].as_array().unwrap().iter().enumerate() {
            let value = if let Some(s) = param.as_str() {
                Cell::string(s.as_bytes().to_vec())
            } else {
                Cell::int(param.as_i64().unwrap())
            };
            machine.memory.insert(1001 + i as i64, value);
        }
        let ok = machine.run(&code, &mut host, None).unwrap();
        if ok {
            committed = machine.storage.clone();
        }
        let mut storage = committed
            .values()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        storage.sort();
        let result = match &machine.regs[0] {
            Cell::Bool(v) => json!(v),
            v => json!(String::from_utf8(v.text().into_owned()).unwrap()),
        };
        let actual = json!({"ok":ok,"effort":machine.effort,"result":result,
            "storage":storage.iter().map(|(k,v)|json!([STANDARD.encode(k),STANDARD.encode(v)])).collect::<Vec<_>>(),
            "events":machine.events.iter().map(|e|json!([STANDARD.encode(&e.name),e.values.iter().map(|v|STANDARD.encode(v.text())).collect::<Vec<_>>()])).collect::<Vec<_>>()});
        assert_eq!(actual, case["expected"], "{}", call["method"]);
    }
}

#[test]
fn circle_host_executes_private_admin_proof_and_rejects_replay() {
    use octra_node_protocol::{native_json::Document, transaction::RuleMode};
    use octra_node_runtime::{
        circle::{WasmProfile, WasmRules},
        circle_call,
        circle_query::Query,
        circle_store,
        circle_view::Profile,
        state_batch::StateBatch,
    };
    let report: Value = serde_json::from_str(include_str!("fixtures/vpn-admin.json")).unwrap();
    let public: Value =
        serde_json::from_str(include_str!("fixtures/vpn-admin-public.json")).unwrap();
    let circle = public["program"].as_str().unwrap().as_bytes();
    let code = bytes(&report["cases"]["bytecode"]);
    let hash = hex::encode(Sha256::digest(&code)).into_bytes();
    let mut state = StateBatch::default();
    state.begin().unwrap();
    common::install_octb_counter(&mut state, circle);
    state
        .set(
            &[b"circles", circle, b"program", b"code_b64"],
            STANDARD.encode(&code).into_bytes(),
        )
        .unwrap();
    state
        .set(&[b"circles", circle, b"code_hash"], hash.clone())
        .unwrap();
    state
        .set(&[b"circles", circle, b"call_code"], hash)
        .unwrap();
    // Import only the real native constructor's output. This tests the Circle
    // host boundary; deployment and funded account transitions have other gates.
    let mut initial = StorageTable::new(0);
    for row in report["cases"]["cases"][0]["expected"]["storage"]
        .as_array()
        .unwrap()
    {
        initial.replace(bytes(&row[0]), bytes(&row[1]));
    }
    circle_store::save_storage(&mut state, circle, &initial, 33_554_432, 65_536).unwrap();
    let runtime = common::runtime();
    for (index, case) in report["cases"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .skip(1)
    {
        if index == 2 {
            continue;
        } // Different program address was checked by the VM differential.
        let call = &case["call"];
        let before = state.root().unwrap();
        let context = circle_call::Context {
            caller: "relayer".into(),
            tx_hash: format!("{index:064x}"),
            epoch: 2_000_000,
            epoch_time_ms: 0,
            tree_hash: hex::encode(before).into_bytes(),
            node_id: b"node_001".to_vec(),
            depth: 0,
            limit: 1_000_000,
            profile: WasmRules {
                wasm_float: false,
                proof_exec: true,
                math: true,
            },
            manifest: WasmProfile::Standard,
            inspect: true,
            update_policy: true,
            hfhe_strict: true,
            storage_proof: true,
            fhe_work: true,
        };
        let attempted = circle_call::execute(
            &runtime,
            &state.snapshot(),
            circle,
            call["method"].as_str().unwrap().as_bytes(),
            &Document::parse(&serde_json::to_vec(&call["params"]).unwrap()).unwrap(),
            &context,
            None,
        )
        .unwrap();
        let success = case["expected"]["ok"].as_bool().unwrap();
        assert_eq!(attempted.receipt().success, success, "call {index}");
        assert_eq!(
            attempted.apply(&mut state).is_ok(),
            success,
            "apply {index}"
        );
        if !success {
            assert_eq!(state.root().unwrap(), before, "failed proof changed state");
        }
        let stored = circle_store::load_storage(&state.snapshot(), circle, None).unwrap();
        let expected = case["expected"]["storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (bytes(&row[0]), bytes(&row[1])))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(stored.values(), &expected);
    }
    let snapshot = state.snapshot();
    let profile = Profile {
        math: true,
        proof_exec: RuleMode::Active,
        fhe_work: RuleMode::Active,
        int_work: true,
        point_ops: true,
        ..Profile::prior(2_000_000)
    };
    let view = Query::new(&snapshot, &profile)
        .unwrap()
        .circle(
            circle,
            b"get_admin_nonce",
            &Document::parse(b"[]").unwrap(),
            b"reader",
            1_000_000,
        )
        .unwrap();
    assert!(view.success);
    assert_eq!(view.response.unwrap().text().as_ref(), b"1");
}
