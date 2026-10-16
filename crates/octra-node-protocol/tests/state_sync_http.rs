//! Native HTTP byte projections and adversarial multipart reconstruction.
//! These vectors do not replace native-process or finality qualification.
use octra_node_protocol::{
    consensus::CatchupEpochRecord,
    native_json::Document,
    state_sync::{
        http,
        range_part::{self, Encoded, View},
    },
};

#[test]
fn live_head_preserves_native_field_order_and_lag_boundary() {
    let root = vec![b'a'; 64];
    let head = http::Head {
        epoch: 3001,
        state_root: root,
        txid_hi: -1,
        irmin_commit: None,
    };
    let raw = http::head_response(3002, Some(&head), Some(1));
    let expected=format!("{{\"version\":\"octra-state-sync\",\"mode\":\"live_head\",\"current_epoch\":3002,\"snapshot_epoch\":1,\"head_epoch\":3001,\"state_root\":\"{}\",\"txid_hi\":\"-1\",\"snapshot_status\":\"ready\",\"snapshot_lag\":3000,\"snapshot_lag_limit\":3000}}","a".repeat(64));
    assert_eq!(raw, expected.as_bytes());
    assert_eq!(http::Head::parse_response(&raw).unwrap(), Some(head));
    let old = http::head_response(3003, None, Some(1));
    let doc = Document::parse(&old).unwrap();
    assert!(
        matches!(doc.field(doc.root(),b"snapshot_status"),Some(octra_node_protocol::native_json::Value::String(v)) if v==b"old_epoch")
    );
    assert_eq!(http::head_response(0,None,None),b"{\"version\":\"octra-state-sync\",\"mode\":\"live_head\",\"current_epoch\":0,\"snapshot_epoch\":null,\"head_epoch\":null,\"state_root\":null,\"txid_hi\":null,\"snapshot_status\":\"missing\",\"snapshot_lag\":null,\"snapshot_lag_limit\":3000}");
    let invalid = expected.replace("\"head_epoch\":3001", "\"head_epoch\":4611686018427387904");
    assert!(http::Head::parse_response(invalid.as_bytes()).is_err());
}

#[test]
fn range_query_uses_native_integer_fallbacks_and_rejects_unbound_digest() {
    let q = http::RangeQuery::parse(Some(b"0x10"), Some(b"bogus"), None, None).unwrap();
    assert_eq!((q.from_epoch, q.max_epochs), (16, 16));
    assert!(http::RangeQuery::parse(None, None, None, None).is_err());
    assert!(http::RangeQuery::parse(Some(b"1"), Some(b"0"), None, None).is_err());
    assert!(http::RangeQuery::parse(Some(b"1"), None, Some(b"bad"), None).is_err());
    assert!(http::RangeQuery::parse(Some(b"1"), None, None, Some(&[b'a'; 64])).is_err());
    assert!(http::RangeQuery::parse(Some(b"1"), None, Some(b"0"), Some(&[b'A'; 64])).is_err());
    assert!(http::RangeQuery::parse(Some(b"4611686018427387888"), None, None, None).is_err());
    assert!(http::RangeQuery::parse(
        Some(b"4611686018427387887"),
        Some(b"4611686018427387903"),
        Some(b"0"),
        Some(&[b'a'; 64])
    )
    .is_ok());
}

#[test]
fn range_errors_and_records_preserve_json_string_payload_bytes() {
    let q = http::RangeQuery::parse(Some(b"4"), Some(b"100"), None, None).unwrap();
    let missing = http::range_response(None, &q, &http::RangeResult::Missing).unwrap();
    assert_eq!(missing,b"{\"version\":\"octra-state-sync\",\"mode\":\"catchup_range\",\"status\":\"not_found\",\"from_epoch\":\"4\",\"max_epochs\":100,\"next_epoch\":null,\"records\":[],\"head_epoch\":null,\"head_state_root\":null}");
    assert_eq!(
        http::parse_range(&Document::parse(&missing).unwrap()).unwrap(),
        http::RangeResult::Missing
    );
    let failure = http::RangeResult::Retry(b"disk\0\xff".to_vec());
    let raw = http::range_response(None, &q, &failure).unwrap();
    assert_eq!(
        http::parse_range(&Document::parse(&raw).unwrap()).unwrap(),
        failure
    );
    let record = CatchupEpochRecord {
        epoch_id: 4,
        prev_state_root: vec![1; 32],
        state_root: vec![2; 32],
        tx_list_hash: vec![3; 32],
        tx_hashes: vec![vec![b'f'; 64]],
        txs_json: vec![b"{\"payload\":\"\xff\"}".to_vec()],
        receipt_root: vec![4; 32],
        receipts_json: vec![b"[\"receipt\",\"\xff\"]".to_vec()],
        epoch_ts: 123.125,
        creator_addr: b"creator\xff".to_vec(),
        commit_round: 3,
        reward_source: None,
        finality: None,
    };
    let result = http::RangeResult::Records {
        records: vec![record],
        next_epoch: Some(5),
    };
    let raw = http::range_response(None, &q, &result).unwrap();
    assert_eq!(
        http::parse_range(&Document::parse(&raw).unwrap()).unwrap(),
        result
    );
}

fn quoted(size: usize) -> Vec<u8> {
    let mut raw = vec![b'a'; size];
    raw[0] = b'"';
    raw[size - 1] = b'"';
    raw
}
#[test]
fn multipart_pins_exact_bytes_and_rejects_reordering_tampering_and_inline_parts() {
    let inline = quoted(range_part::BODY_MAX);
    let encoded = Encoded::encode(inline.clone()).unwrap();
    assert!(encoded.digest().is_none());
    assert_eq!(encoded.render(None).unwrap(), inline);
    assert_eq!(
        encoded.render(Some(0)).unwrap_err().to_string(),
        "range response has no parts"
    );
    let full = quoted(range_part::BODY_MAX + 1);
    let encoded = Encoded::encode(full.clone()).unwrap();
    let parts = (0..2)
        .map(
            |i| match range_part::view(&encoded.render(Some(i)).unwrap()).unwrap() {
                View::Part(part) => part,
                View::Full(_) => panic!("expected multipart"),
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(parts[0].data.len(), range_part::RAW_MAX);
    assert_eq!(range_part::join(&parts).unwrap(), full);
    assert_eq!(
        encoded.render(Some(2)).unwrap_err().to_string(),
        "range part index is invalid"
    );
    let mut changed = parts.clone();
    changed.swap(0, 1);
    assert_eq!(
        range_part::join(&changed).unwrap_err().to_string(),
        "range part sequence does not match"
    );
    let mut changed = parts.clone();
    changed[1].data[0] ^= 1;
    assert_eq!(
        range_part::join(&changed).unwrap_err().to_string(),
        "range part hash does not match"
    );
    let mut changed = parts;
    changed[0].data.pop();
    assert_eq!(
        range_part::join(&changed).unwrap_err().to_string(),
        "range part size is invalid"
    );
    assert!(Encoded::encode(vec![0; range_part::FULL_MAX + 1]).is_err());
}

#[test]
fn multipart_requires_exact_fields_and_native_canonical_base64() {
    let base=format!("{{\"version\":\"octra-range-part-v1\",\"status\":\"part\",\"sha256\":\"{}\",\"index\":1,\"count\":2,\"data\":\"Zh==\"}}","a".repeat(64));
    let reason = match range_part::view(base.as_bytes()) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("noncanonical padding accepted"),
    };
    assert_eq!(reason, "range part data is not exact");
    let duplicate = base.replace("\"count\":2", "\"count\":2,\"count\":2");
    assert_eq!(
        match range_part::view(duplicate.as_bytes()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("duplicate field accepted"),
        },
        "range part fields are invalid"
    );
    let wrong_type = base.replace("\"index\":1", "\"index\":\"1\"");
    assert_eq!(
        match range_part::view(wrong_type.as_bytes()) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("string index accepted"),
        },
        "range part values are invalid"
    );
}

#[test]
fn progress_uses_first_fields_and_native_defaults_without_granting_authority() {
    let doc=Document::parse(b"{\"peer\":7,\"phase\":\"first\",\"phase\":\"last\",\"file_done\":\"9\",\"file_size\":12,\"total_done\":true,\"rate_bps\":2.5,\"eta_seconds\":7}").unwrap();
    let p = http::Progress::parse(&doc).unwrap();
    assert_eq!(
        (p.peer, p.phase, p.path),
        (b"unknown".to_vec(), b"first".to_vec(), b"-".to_vec())
    );
    assert_eq!(
        (p.file_done, p.file_size, p.total_done, p.total_size),
        (0, 12, 0, 0)
    );
    assert_eq!((p.rate_bps, p.eta_seconds), (2.5, Some(7.)));
    assert_eq!(
        http::Progress::parse(&Document::parse(b"[]").unwrap())
            .unwrap_err()
            .to_string(),
        "progress report must be a JSON object"
    );
}

#[test]
fn adopted_native_http_oracle_vectors_match() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    let report: Value =
        serde_json::from_str(include_str!("fixtures/state-sync-http.json")).unwrap();
    assert_eq!(
        report["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let mut count = 0;
    for case in report["cases"].as_array().unwrap() {
        let op = case["op"].as_str().unwrap();
        if op == "error" || op == "query" {
            continue;
        } // Actual HTTP error construction is replayed in the node crate.
        let run = || -> Result<Value, String> {
            let raw = || STANDARD.decode(case["raw"].as_str().unwrap()).unwrap();
            let bytes = |value: Vec<u8>| json!(STANDARD.encode(value));
            match op {
                "head" => {
                    let head = if case["head"].is_null() {
                        None
                    } else {
                        Some(http::Head {
                            epoch: case["head"]["epoch"].as_i64().unwrap(),
                            state_root: case["head"]["root"].as_str().unwrap().as_bytes().to_vec(),
                            txid_hi: case["head"]["txid_hi"].as_str().unwrap().parse().unwrap(),
                            irmin_commit: None,
                        })
                    };
                    Ok(
                        json!({"status":200,"raw":STANDARD.encode(http::head_response(case["current_epoch"].as_i64().unwrap(),head.as_ref(),None))}),
                    )
                }
                "progress" => {
                    let progress = http::Progress::parse(&Document::parse(&raw()).unwrap())
                        .map_err(|e| e.to_string())?;
                    let actual = json!({"peer":String::from_utf8(progress.peer).unwrap(),"phase":String::from_utf8(progress.phase).unwrap(),"path":String::from_utf8(progress.path).unwrap(),
                        "file_done":progress.file_done,"file_size":progress.file_size,"total_done":progress.total_done,"total_size":progress.total_size,"rate_bps":progress.rate_bps,"eta_seconds":progress.eta_seconds});
                    let expected: Value = serde_json::from_slice(
                        &STANDARD
                            .decode(case["expected"]["ok"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(actual, expected, "{case}");
                    Ok(case["expected"]["ok"].clone())
                }
                "range_missing" | "range_error" => {
                    let query = http::RangeQuery {
                        from_epoch: case["from_epoch"].as_str().unwrap().parse().unwrap(),
                        max_epochs: case["max_epochs"].as_i64().unwrap(),
                        part: None,
                        hash: None,
                    };
                    let result = if op == "range_missing" {
                        http::RangeResult::Missing
                    } else {
                        http::RangeResult::Retry(
                            case["reason"].as_str().unwrap().as_bytes().to_vec(),
                        )
                    };
                    http::range_response(None, &query, &result)
                        .map(bytes)
                        .map_err(|e| e.to_string())
                }
                "part_view" => match range_part::view(&raw()).map_err(|e| e.to_string())? {
                    View::Full(_) => Ok(json!("full")),
                    View::Part(part) => Ok(
                        json!({"sha256":String::from_utf8(part.sha256).unwrap(),"index":part.index,"count":part.count,"data":STANDARD.encode(part.data)}),
                    ),
                },
                "multipart" => {
                    let encoded = Encoded::encode(quoted(case["size"].as_u64().unwrap() as usize))
                        .map_err(|e| e.to_string())?;
                    let rendered = encoded
                        .render(case["index"].as_i64())
                        .map_err(|e| e.to_string())?;
                    match range_part::view(&rendered).map_err(|e| e.to_string())? {
                        View::Full(_) => Ok(
                            json!({"kind":"full","size":rendered.len(),"sha256":hex::encode(Sha256::digest(&rendered))}),
                        ),
                        View::Part(part) => {
                            let parts = (0..part.count)
                                .map(|i| {
                                    match range_part::view(&encoded.render(Some(i)).unwrap())
                                        .unwrap()
                                    {
                                        View::Part(part) => part,
                                        View::Full(_) => panic!("multipart"),
                                    }
                                })
                                .collect::<Vec<_>>();
                            let joined = range_part::join(&parts).map_err(|e| e.to_string())?;
                            Ok(
                                json!({"kind":"part","size":joined.len(),"sha256":hex::encode(Sha256::digest(&joined)),"index":part.index,"count":part.count,"data_size":part.data.len()}),
                            )
                        }
                    }
                }
                _ => panic!("unknown native vector"),
            }
        };
        let actual = match run() {
            Ok(value) => json!({"ok":value}),
            Err(error) => json!({"error":error}),
        };
        assert_eq!(actual, case["expected"], "{case}");
        count += 1;
    }
    assert_eq!(count, 20);
}
