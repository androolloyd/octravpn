//! Native Grpc_config/deadline/frame/proto/status boundary regressions. Wire
//! expectations are independent protobuf bytes from the adopted schema.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    epoch_page,
    grpc::{self, proto, Config, Status},
    rpc::Fault,
};
use std::time::Duration;

fn config(extra: &[(&str, &[u8])]) -> Result<Option<Config>, String> {
    Config::capture(|name| {
        extra
            .iter()
            .find_map(|(key, value)| (*key == name).then(|| value.to_vec()))
            .or_else(|| (name == "OCTRA_GRPC_ENABLE").then(|| b"1".to_vec()))
    })
}
fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 127 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn integer(out: &mut Vec<u8>, field: u8, value: u64) {
    out.push(field << 3);
    varint(out, value);
}
fn bytes(out: &mut Vec<u8>, field: u8, value: &[u8]) {
    out.push((field << 3) | 2);
    varint(out, value.len() as u64);
    out.extend_from_slice(value);
}
fn field(value: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    bytes(&mut out, 1, value);
    out
}
fn call(path: &str, wire: &[u8]) -> (&'static [u8], Vec<u8>, bool) {
    match proto::decode(path, wire).unwrap() {
        proto::Request::Call {
            method,
            params,
            page,
        } => (method, params, page),
        proto::Request::Health(_) => panic!("unexpected health request"),
    }
}

#[test]
fn optional_listener_policy_and_native_error_precedence() {
    assert!(Config::capture(|_| None).unwrap().is_none());
    assert!(config(&[
        ("OCTRA_GRPC_ENABLE", b"false"),
        ("OCTRA_GRPC_PORT", b"invalid")
    ])
    .unwrap()
    .is_none());
    let default = config(&[]).unwrap().unwrap();
    assert_eq!(default.listen, "127.0.0.1:8081".parse().unwrap());
    assert_eq!(
        (
            default.request_bytes,
            default.response_bytes,
            default.submit_bytes,
            default.streams
        ),
        (65_536, 4_194_304, Some(5_000_005), 32)
    );
    assert_eq!(
        config(&[("OCTRA_GRPC_HOST", b"0.0.0.0")]).unwrap_err(),
        "OCTRA_GRPC_HOST must be a loopback address"
    );
    assert_eq!(
        config(&[("OCTRA_GRPC_HOST", b"localhost")]).unwrap_err(),
        "OCTRA_GRPC_HOST must be a numeric address"
    );
    assert!(config(&[("OCTRA_GRPC_HOST", b"::1")])
        .unwrap()
        .unwrap()
        .listen
        .ip()
        .is_loopback());
    assert_eq!(
        config(&[
            ("OCTRA_GRPC_DEADLINE_MS", b"bad"),
            ("OCTRA_GRPC_MAX_DEADLINE_MS", b"bad")
        ])
        .unwrap_err(),
        "OCTRA_GRPC_DEADLINE_MS is invalid"
    );
    assert_eq!(
        config(&[
            ("OCTRA_GRPC_DEADLINE_MS", b"0"),
            ("OCTRA_GRPC_MAX_DEADLINE_MS", b"bad")
        ])
        .unwrap_err(),
        "OCTRA_GRPC_MAX_DEADLINE_MS is invalid"
    );
    assert!(config(&[
        ("OCTRA_GRPC_SUBMIT_ENABLE", b"NO"),
        ("OCTRA_GRPC_MAX_SUBMIT_BYTES", b"invalid")
    ])
    .unwrap()
    .unwrap()
    .submit_bytes
    .is_none());
    for (key, values) in [
        ("OCTRA_GRPC_PORT", [b"0".as_slice(), b"65536"]),
        (
            "OCTRA_GRPC_MAX_REQUEST_BYTES",
            [b"0".as_slice(), b"1048577"],
        ),
        (
            "OCTRA_GRPC_MAX_RESPONSE_BYTES",
            [b"0".as_slice(), b"16777217"],
        ),
        ("OCTRA_GRPC_MAX_SUBMIT_BYTES", [b"0".as_slice(), b"5000006"]),
        ("OCTRA_GRPC_MAX_STREAMS", [b"0".as_slice(), b"129"]),
        ("OCTRA_GRPC_MAX_DEADLINE_MS", [b"0".as_slice(), b"60001"]),
    ] {
        for value in values {
            assert!(config(&[(key, value)]).is_err(), "{key}");
        }
    }
}
#[test]
fn deadline_units_bounds_and_diagnostics() {
    let config = config(&[]).unwrap().unwrap();
    for (raw, expected) in [
        (b"25m".as_slice(), Duration::from_millis(25)),
        (b"1u", Duration::from_micros(1)),
        (b"1n", Duration::from_nanos(1)),
        (b"99S", Duration::from_secs(10)),
        (b" 1H\t", Duration::from_secs(10)),
    ] {
        assert_eq!(config.deadline(Some(raw)).unwrap(), expected);
    }
    assert_eq!(config.deadline(None).unwrap(), Duration::from_secs(5));
    for raw in [b"".as_slice(), b"1", b"0m", b"-1m", b"123456789S"] {
        assert_eq!(
            config.deadline(Some(raw)).unwrap_err().message,
            b"grpc-timeout is invalid"
        );
    }
    assert_eq!(
        config.deadline(Some(b"1s")).unwrap_err().message,
        b"grpc-timeout unit is invalid"
    );
}
#[test]
fn unary_framing_refuses_compression_oversize_truncation_and_second_message() {
    let wire = grpc::frame(b"abc");
    assert_eq!(wire, b"\0\0\0\0\x03abc");
    assert_eq!(grpc::unframe(&wire, 3).unwrap(), b"abc");
    assert_eq!(grpc::unframe(&wire, 2).unwrap_err().code, 8);
    for cut in 0..wire.len() {
        assert_eq!(
            grpc::unframe(&wire[..cut], 3).unwrap_err().message,
            b"request frame is incomplete"
        );
    }
    let mut second = wire.clone();
    second.extend(grpc::frame(b""));
    assert_eq!(
        grpc::unframe(&second, 3).unwrap_err().message,
        b"unary request has extra data"
    );
    let mut compressed = wire;
    compressed[0] = 1;
    assert_eq!(grpc::unframe(&compressed, 0).unwrap_err().code, 12);
}
#[test]
fn schema_last_wins_unknown_fields_and_submit_type_rules() {
    assert_eq!(
        call(proto::STATUS, b""),
        (b"node_status".as_slice(), b"[]".to_vec(), false)
    );
    let mut wire = field(b"first");
    bytes(&mut wire, 7, b"ignored");
    wire.extend(field(b"oct-address"));
    assert_eq!(call(proto::ACCOUNT, &wire).1, br#"["oct-address"]"#);
    assert!(proto::decode(proto::ACCOUNT, &field(b"")).is_err());
    let mut epoch = vec![];
    integer(&mut epoch, 1, u64::MAX);
    integer(&mut epoch, 1, 42);
    assert_eq!(call(proto::EPOCH, &epoch).1, b"[42]");
    let mut invalid = vec![];
    integer(&mut invalid, 1, 1 << 62);
    assert!(proto::decode(proto::EPOCH, &invalid).is_err());
    let mut submit = field(b"{}");
    submit.extend(field(br#"{"nonce":7,"signature":"signed"}"#));
    assert_eq!(
        call(proto::SUBMIT, &submit).1,
        br#"[{"nonce":7,"signature":"signed"}]"#
    );
    integer(&mut submit, 1, 7);
    assert_eq!(
        proto::decode(proto::SUBMIT, &submit).err(),
        Some("protobuf message is invalid")
    );
    for raw in [b"".as_slice(), b"[]", b"null", b"{", b"{} {}"] {
        assert!(proto::decode(proto::SUBMIT, &field(raw)).is_err());
    }
    assert!(proto::decode(
        proto::TRANSACTION,
        b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"
    )
    .is_err());
}
#[test]
fn epoch_page_nested_anchor_merge_and_exact_reply_wire() {
    let root = vec![b'a'; 64];
    let mut anchor1 = vec![];
    bytes(&mut anchor1, 1, b"test");
    let mut anchor2 = vec![];
    integer(&mut anchor2, 2, 0);
    bytes(&mut anchor2, 3, &root);
    let mut request = vec![];
    bytes(&mut request, 3, &anchor1);
    bytes(&mut request, 3, &anchor2);
    let (_, params, page) = call(proto::EPOCHS, &request);
    assert!(page);
    let doc = octra_node_protocol::native_json::Document::parse(&params).unwrap();
    let parsed = epoch_page::Request::parse(&doc, doc.root()).unwrap();
    assert_eq!(parsed.anchor.unwrap().root, root);
    request.extend_from_slice(&[16, 0]);
    assert_eq!(
        proto::decode(proto::EPOCHS, &request).err(),
        Some("invalid params")
    );
    let page = epoch_page::Page {
        anchor: epoch_page::Anchor {
            chain: b"test".to_vec(),
            epoch: 0,
            root: root.clone(),
        },
        rows: vec![epoch_page::Row {
            epoch: 0,
            root: root.clone(),
            previous: vec![],
            tx_start: 0,
            tx_count: 0,
            time: 1.25,
        }],
        next: 1,
        stop: epoch_page::Stop::Complete,
    };
    let mut anchor = vec![];
    bytes(&mut anchor, 1, b"test");
    integer(&mut anchor, 2, 0);
    bytes(&mut anchor, 3, &root);
    let mut row = vec![];
    integer(&mut row, 1, 0);
    bytes(&mut row, 2, &root);
    bytes(&mut row, 3, b"");
    integer(&mut row, 4, 0);
    integer(&mut row, 5, 0);
    row.push(49);
    row.extend(1.25f64.to_le_bytes());
    let mut expected = vec![];
    bytes(&mut expected, 1, &anchor);
    bytes(&mut expected, 2, &row);
    integer(&mut expected, 3, 1);
    integer(&mut expected, 4, 1);
    assert_eq!(
        proto::encode_page(&page.encode().unwrap()).unwrap(),
        expected
    );
}
#[test]
fn native_error_mapping_and_binary_safe_trailers() {
    for (rpc, grpc) in [
        (-32700, 3),
        (-32600, 3),
        (-32602, 3),
        (-32601, 12),
        (101, 16),
        (104, 9),
        (107, 8),
        (110, 14),
        (-32005, 14),
        (-32012, 14),
        (100, 5),
        (112, 5),
        (105, 3),
        (109, 3),
        (114, 3),
        (106, 9),
    ] {
        assert_eq!(Status::from_rpc(Fault::new(rpc, b"reason")).code, grpc);
    }
    let fault = Fault::new(112, b"missing %\n\xff").string_data(b"\0data");
    let status = Status::from_rpc(fault.clone());
    let trailers = status.trailers();
    assert_eq!(trailers[0], ("grpc-status", "5".into()));
    assert_eq!(trailers[1], ("grpc-message", "missing %25%0A%FF".into()));
    assert_eq!(trailers[2], ("octra-rpc-code", "112".into()));
    assert_eq!(STANDARD.decode(&trailers[3].1).unwrap(), fault.encode());
    assert_eq!(
        Status::new(0, b"").trailers(),
        vec![("grpc-status", "0".into())]
    );
}
