use super::*;
thread_local! { static CALLS: std::cell::RefCell<Vec<JsonValue>> = const { std::cell::RefCell::new(Vec::new()) }; }

fn frame(method: &str, tag: u8, parameter: &str) -> Vec<u8> {
    let mut bytes = b"OCWR1".to_vec();
    bytes.extend_from_slice(&(method.len() as u16).to_be_bytes());
    bytes.extend_from_slice(method.as_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(tag);
    bytes.extend_from_slice(&(parameter.len() as u32).to_be_bytes());
    bytes.extend_from_slice(parameter.as_bytes());
    bytes
}

fn execute(payload: &JsonValue) -> JsonValue {
    let bytes = serde_json::to_vec(payload).unwrap();
    let output: JsonValue = serde_json::from_str(&run_json(bytes.as_ptr(), bytes.len()).unwrap()).unwrap();
    let mut input = payload.clone();
    input["code_b64"] = json!("$registry_wasm");
    CALLS.with(|calls| calls.borrow_mut().push(json!({"input":input,"expected":output})));
    output
}

fn response(result: &JsonValue) -> JsonValue {
    let bytes = BASE64
        .decode(result["response_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(&bytes[..6], b"OCWS1\x04");
    let length = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
    assert_eq!(length, bytes.len() - 10);
    serde_json::from_slice(&bytes[10..]).unwrap()
}

#[test]
fn vpn_registry_circle_abi() {
    let wasm = std::fs::read(std::env::var("OCTRA_VPN_REGISTRY_WASM").unwrap()).unwrap();
    let address = |last: char| format!("oct{}{last}", "1".repeat(43));
    let operator = address('2');
    let request = json!({"expected_revision":0,"offer":{
        "settlement_circle":address('4'),"control_url":"https://vpn.example/control",
        "wireguard_endpoint":"203.0.113.7:51820","wireguard_key_hex":"11".repeat(32),
        "receipt_key_hex":"22".repeat(32),"region":"CA","exit":true,"relay":false,
        "price_ou_per_mib":100
    }});
    let mut payload = json!({"action":"execute","code_b64":BASE64.encode(&wasm),
        "export_name":"octra_update","request_b64":BASE64.encode(frame("publish",4,&request.to_string())),
        "caller":operator,"address":address('5'),"current_epoch":10,"is_view":false,
        "update_policy":true,"hfhe_strict":false,"fuel_limit":20_000_000,"storage_pairs":[]});
    let descriptor = execute(&json!({"action":"describe","code_b64":BASE64.encode(&wasm)}));
    assert_eq!(
        descriptor["manifest"]["methods"].as_array().unwrap().len(),
        3
    );
    let first = execute(&payload);
    assert_eq!(first["success"], true, "{first}");
    assert_eq!(response(&first)["operator"], operator);
    assert_eq!(response(&first)["revision"], 1);
    assert_eq!(first["events"].as_array().unwrap().len(), 1);
    payload["storage_pairs"] = first["storage_pairs"].clone();
    let replay = execute(&payload);
    assert_eq!(replay["success"], false);
    assert_eq!(response(&replay)["error"], "operator revision mismatch");
    assert_eq!(replay["storage_pairs"], first["storage_pairs"]);
    assert!(replay["events"].as_array().unwrap().is_empty());

    let mut query = payload.clone();
    query["export_name"] = json!("octra_query");
    query["is_view"] = json!(true);
    query["request_b64"] = json!(BASE64.encode(frame("operator", 4, &operator)));
    let read = execute(&query);
    assert_eq!(read["success"], true);
    assert_eq!(response(&read), response(&first));
    assert!(read["storage_pairs"].is_null());

    payload["request_b64"] = json!(BASE64.encode(frame("retire", 3, "1")));
    payload["caller"] = json!(address('3'));
    let outsider = execute(&payload);
    assert_eq!(outsider["success"], false);
    assert_eq!(outsider["storage_pairs"], first["storage_pairs"]);
    payload["caller"] = json!(operator);
    let retired = execute(&payload);
    assert_eq!(retired["success"], true);
    assert_eq!(response(&retired)["retired"], true);
    assert_eq!(response(&retired)["revision"], 2);

    payload["storage_pairs"] = retired["storage_pairs"].clone();
    let mut update = request.clone();
    update["expected_revision"] = json!(2);
    payload["request_b64"] = json!(BASE64.encode(frame("publish", 4, &update.to_string())));
    let resumed = execute(&payload);
    assert_eq!(resumed["success"], true);
    assert_eq!(response(&resumed)["revision"], 3);
    query["request_b64"] = payload["request_b64"].clone();
    assert_eq!(execute(&query)["success"], false);
    let mut invalid = frame("retire", 3, "3");
    invalid.push(0);
    payload["request_b64"] = json!(BASE64.encode(invalid));
    assert_eq!(execute(&payload)["success"], false);
    std::fs::write(std::env::var("OCTRA_VPN_CIRCLE_EVIDENCE").unwrap(),
        serde_json::to_vec_pretty(&json!({"passed":true,"scope":"upstream Rust WASM Circle host ABI; not OCaml Circle commit or chain finality",
            "cases":["manifest","publish","query","replay rejection","caller ownership","retire","republication","view mutation refusal","malformed frame"]})).unwrap()).unwrap();
    if let Ok(path) = std::env::var("OCTRA_VPN_RUNTIME_FIXTURE") {
        let calls = CALLS.with(|calls| calls.borrow().clone());
        std::fs::write(path, serde_json::to_vec_pretty(&calls).unwrap()).unwrap();
    }
}
