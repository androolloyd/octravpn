use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    duty,
    program_wire::{Envelope, Package},
    transaction::{EnvelopeError, Nonce, OpType, RuleMode, Transaction},
    transaction_payload::Limits,
    transaction_policy::{self as policy, Profile},
};
use octra_node_runtime::{
    admission::{self, Postcheck, Precheck},
    crypto_payload,
};
use serde_json::{json, Value};
fn bytes(value: &Value, key: &str) -> Vec<u8> {
    STANDARD.decode(value[key].as_str().unwrap()).unwrap()
}
fn optional(value: &Value, key: &str) -> Option<Vec<u8>> {
    value[key].as_str().map(|v| STANDARD.decode(v).unwrap())
}
fn n(value: &Value, key: &str) -> Nonce {
    Nonce::new(value[key].as_str().unwrap().parse().unwrap()).unwrap()
}
fn float(value: &Value, key: &str) -> f64 {
    f64::from_bits(u64::from_str_radix(value[key].as_str().unwrap(), 16).unwrap())
}
fn bool(value: &Value, key: &str) -> bool {
    value[key].as_bool().unwrap()
}
fn unit<E: std::fmt::Display>(result: Result<(), E>) -> Value {
    match result {
        Ok(()) => Value::Null,
        Err(e) => json!(e.to_string()),
    }
}
fn result(result: Result<(), EnvelopeError>) -> Value {
    match result {
        Ok(()) => Value::Null,
        Err(e) => json!([e.tag, e.reason]),
    }
}
fn payload_result(result: Result<(), admission::Error>) -> Value {
    match result {
        Ok(()) => Value::Null,
        Err(admission::Error::Rejected(e)) => json!([e.tag, e.reason]),
        Err(e) => panic!("unexpected operational error {e}"),
    }
}
fn blob(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn evaluate(input: &Value, expected: &Value) -> Value {
    match input["kind"].as_str().unwrap() {
        "program" => match Package::decode_base64(&bytes(input, "raw")) {
            Ok(p) => {
                json!({"main":blob(&p.main),"profile":p.compiler_profile,"sources":p.sources.iter().map(|s|json!([blob(&s.path),blob(&s.body)])).collect::<Vec<_>>(),"envelope":blob(&p.envelope)})
            }
            Err(e) => json!({"error":e.to_string()}),
        },
        "envelope" => match Envelope::decode(&bytes(input, "raw")) {
            Ok(p) => json!({"code":blob(&p.code),"cert":blob(&p.cert)}),
            Err(e) => json!({"error":e.to_string()}),
        },
        "compute" => {
            let raw = bytes(input, "raw");
            json!({"fee":policy::compute_fee(&raw).to_string(),"request":match policy::compute_request(&raw){Ok((fuel,records))=>json!([fuel,records.iter().map(|v|blob(v)).collect::<Vec<_>>()]),Err(e)=>json!(e)}})
        }
        "transaction" => {
            let v = &input["tx"];
            let c = &input["context"];
            let tx = Transaction {
                from: bytes(v, "from"),
                to: bytes(v, "to"),
                amount: v["amount"].as_str().unwrap().parse().unwrap(),
                nonce: n(v, "nonce"),
                ou: v["ou"].as_str().unwrap().parse().unwrap(),
                timestamp: float(v, "timestamp_bits"),
                signature: if input["seed"].is_string() {
                    bytes(expected, "signature")
                } else {
                    bytes(v, "signature")
                },
                public_key: optional(v, "public_key"),
                message: optional(v, "message"),
                encrypted_data: optional(v, "encrypted_data"),
                op_type: OpType::parse(v["op_type"].as_str().unwrap().as_bytes()).unwrap(),
            };
            let profile = Profile::from_values(
                optional(c, "release").as_deref(),
                optional(c, "crypto").as_deref(),
                optional(c, "ops").as_deref(),
            );
            let limits = Limits {
                encrypted_data: c["encrypted_limit"].as_str().unwrap().parse().unwrap(),
                message: c["message_limit"].as_str().unwrap().parse().unwrap(),
                message_zkp: c["zkp_limit"].as_str().unwrap().parse().unwrap(),
                message_validator: c["validator_limit"].as_str().unwrap().parse().unwrap(),
                message_program: c["program_limit"].as_str().unwrap().parse().unwrap(),
            };
            let mode = if bool(c, "active") {
                RuleMode::Active
            } else {
                RuleMode::Prior
            };
            let head = c["head"].as_str().map(|v| v.parse().unwrap());
            let pre = Precheck {
                now: float(c, "now_bits"),
                max_timestamp_drift: float(c, "drift_bits"),
                observer: bool(c, "observer"),
                bft: bool(c, "bft"),
                profile: &profile,
                duty: head.map(|h| (h, mode)),
                limits,
            };
            let post = Postcheck {
                preverify_has_capacity: bool(c, "capacity"),
                preverify_pending: n(c, "pending"),
                preverify_pending_max: n(c, "pending_max"),
                bft: bool(c, "bft"),
                confirmed_nonce: n(c, "confirmed"),
                bft_window: n(c, "window"),
            };
            let min = policy::stealth_min_ou(optional(c, "stealth_min").as_deref());
            json!({"signature":blob(&tx.signature),"semantic":unit(policy::semantic_check(&tx)),"fee":policy::ou_cost(&tx,&min).to_string(),"staging":unit(policy::staging_admission(&tx,&min,&c["relay_fee"].as_str().unwrap().parse().unwrap())),"admits":profile.admits(tx.op_type),"consensus_admits":profile.consensus_admits(tx.op_type),"pre_route":result(admission::pre_route(&tx,&pre)),"pre_signature":result(admission::pre_signature(&tx,bool(c,"sender_exists"),&pre)),"payload_size":result(admission::payload_size(&tx,limits)),"payload":payload_result(admission::payload(&tx,limits)),"address":result(admission::address_route(&tx)),"self":result(admission::self_route(&tx)),"signature_admission":result(admission::signature(&tx,optional(c,"account_key").as_deref())),"sender":result(admission::sender(&tx,bool(c,"sender_exists"))),"post":result(admission::post_signature(&tx,post)),"duty_nonce":unit(admission::duty_nonce(&tx,head,n(c,"confirmed"))),"duty_retry":admission::duty_retry(&tx,&pre),"expired":duty::expired(&tx,head,mode),"call_params":admission::call_params_ok(&tx),"encrypted":crypto_payload::encrypted_payload_ok(&tx).unwrap()})
        }
        other => panic!("unexpected case {other}"),
    }
}
#[test]
fn native_transaction_admission_profiles_and_program_wire_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/transaction-admission.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/upstream.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["commit"]);
    for (path, hash) in fixture["sources"].as_object().unwrap() {
        assert_eq!(&sources["files"][path], hash, "source drift {path}");
    }
    assert_eq!(
        crypto_payload::expected_kat(),
        fixture["kat"].as_str().unwrap()
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() > 1000);
    for (index, case) in cases.iter().enumerate() {
        let actual = evaluate(&case["input"], &case["output"]);
        for (key, expected) in case["output"].as_object().unwrap() {
            // Lexer diagnostics carry OCaml-specific exception/line strings.
            // Their refusal and tag must match; semantic diagnostics stay exact.
            if expected[1]
                .as_str()
                .is_some_and(|v| v.contains("Yojson__Common.Json_error"))
                && actual[key][1]
                    .as_str()
                    .is_some_and(|v| v.starts_with("invalid native JSON at byte "))
            {
                assert_eq!(actual[key][0], expected[0]);
                continue;
            }
            assert_eq!(&actual[key], expected, "native case {index} field {key}");
        }
    }
}
