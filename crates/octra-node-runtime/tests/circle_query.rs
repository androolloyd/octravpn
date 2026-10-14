use base64::{engine::general_purpose::STANDARD, Engine};
use octra_browser::{
    application::{ApplicationHost, Context, ReadMethod, ReadRequest},
    Error,
};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{epoch_index, native_json::Document, transaction::RuleMode};
use octra_node_runtime::{
    canonical::CanonicalStore, circle_application::CanonicalApplications,
    circle_assets::CanonicalAssets, circle_query::Query, circle_view::Profile,
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[path = "common/circle_host.rs"]
#[allow(dead_code)]
mod common;

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/circle-octb-view.json")).unwrap()
}
fn setup(input: &Value) -> (StateBatch, Profile) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for entry in input["entries"].as_array().unwrap() {
        let path = entry["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                bytes(&entry["value"]),
            )
            .unwrap();
    }
    let mode = |key| {
        if input[key] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    let profile = Profile {
        point_ops: input["point"].as_bool().unwrap(),
        int_work: input["integer_work"].as_bool().unwrap(),
        proof_exec: mode("proof"),
        fhe_work: mode("fhe_work"),
        ..Profile::prior(input["epoch"].as_i64().unwrap())
    };
    (state, profile)
}

#[test]
fn native_rpc_context_matches_octb_view_receipts_and_immutable_roots() {
    let fixture = fixture();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inventory: Value = serde_json::from_slice(
        &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(fixture["upstream_commit"], inventory["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], inventory["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    for (key, file) in [
        ("oracle_sha256", "circle-octb-view-oracle.ml"),
        ("runner_sha256", "native-oracle.py"),
        ("generator_sha256", "circle-octb-view-fixtures.py"),
    ] {
        assert_eq!(
            fixture[key],
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(file)).unwrap()
            ))
        );
    }
    for (file, hash) in fixture["generator_dependencies"].as_object().unwrap() {
        assert_eq!(
            *hash,
            hex::encode(Sha256::digest(
                std::fs::read(root.join("scripts/node-port").join(file)).unwrap()
            ))
        );
    }
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let expected = &case["expected"];
        let (state, profile) = setup(input);
        assert_eq!(
            hex::encode(state.root().unwrap()),
            expected["root"],
            "case {index}"
        );
        let snapshot = state.snapshot();
        let receipt = Query::new(&snapshot, &profile)
            .unwrap()
            .circle(
                &bytes(&input["circle"]),
                &bytes(&input["method"]),
                &Document::parse(&bytes(&input["params"])).unwrap(),
                &bytes(&input["caller"]),
                input["limit"].as_i64().unwrap(),
            )
            .unwrap_or_else(|e| panic!("case {index}: {e}"));
        let result = receipt.response.as_ref().map_or_else(
            || b"null".to_vec(),
            octra_node_runtime::octb::Value::result_json,
        );
        let events = receipt.events.iter().map(|e| json!({
            "contract":STANDARD.encode(&e.contract),"depth":e.depth,
            "name":STANDARD.encode(&e.topic),"values":e.values.iter().map(|v|STANDARD.encode(v)).collect::<Vec<_>>()
        })).collect::<Vec<_>>();
        assert_eq!(
            json!({"success":receipt.success,"effort":receipt.effort,
            "result_json":STANDARD.encode(result),"error":receipt.error.map(|e|STANDARD.encode(e)),"events":events}),
            expected["receipt"],
            "case {index}: {input}"
        );
        assert_eq!(hex::encode(snapshot.root().unwrap()), expected["after"]);
    }
}

async fn capture(
    path: &std::path::Path,
    state: &StateBatch,
    profile: Profile,
) -> (CanonicalStore, CanonicalApplications) {
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let store = CanonicalStore::create(
        path,
        ChainIdentity {
            chain_id: "octb-views".into(),
            genesis_root: StateRoot(root),
        },
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    let assets = CanonicalAssets::capture(&store).await.unwrap();
    let host = CanonicalApplications::new(assets, common::runtime(), profile);
    (store, host)
}
fn request(host: &CanonicalApplications, input: &Value, method: ReadMethod) -> ReadRequest {
    ReadRequest {
        context: Context {
            circle_id: String::from_utf8(bytes(&input["circle"])).unwrap(),
            provenance: host.provenance(),
        },
        method,
        params: json!({"method":String::from_utf8(bytes(&input["method"])).unwrap(),
            "params":serde_json::from_slice::<Value>(&bytes(&input["params"])).unwrap()}),
    }
}
#[tokio::test]
async fn browser_octb_metadata_and_views_match_native_receipts() {
    let fixture = fixture();
    let dir = tempfile::tempdir().unwrap();
    for (i, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        // Browser exposes a fixed fuel limit, so native custom-limit cases belong above.
        if input["limit"] != 20_000_000 {
            continue;
        }
        let (state, profile) = setup(input);
        let (store, host) = capture(&dir.path().join(format!("{i}.db")), &state, profile).await;
        let expected = &case["expected"];
        let actual = host
            .read(request(&host, input, ReadMethod::ProgramInfo))
            .await;
        if expected["descriptor"]["ok"].is_string() {
            let descriptor: Value =
                serde_json::from_slice(&bytes(&expected["descriptor"]["ok"])).unwrap();
            assert_eq!(actual.unwrap(), descriptor, "descriptor {i}");
        } else {
            let expected_error =
                String::from_utf8(bytes(&expected["descriptor"]["error"])).unwrap();
            assert!(
                matches!(actual, Err(Error::Invalid(ref e)) if e == &expected_error),
                "descriptor {i}: {actual:?}, expected {expected_error}"
            );
        }
        let request = request(&host, input, ReadMethod::ProgramView);
        // JavaScript clients send arbitrary-precision integers as decimal
        // strings. Native integer literals remain covered by Query above.
        let native_params = Document::parse(&bytes(&input["params"])).unwrap();
        let browser_params =
            Document::parse(&serde_json::to_vec(&request.params["params"]).unwrap()).unwrap();
        if native_params != browser_params {
            assert!(input["name"]
                .as_str()
                .unwrap()
                .starts_with("parameter [142724"));
            store.close().await;
            continue;
        }
        let actual = host.read(request).await;
        let receipt = &expected["receipt"];
        if receipt["success"] == true {
            match serde_json::from_slice::<Value>(&bytes(&receipt["result_json"])) {
                Ok(result) => assert_eq!(actual.unwrap(), json!({"result":result}), "view {i}"),
                Err(_) => assert!(
                    matches!(actual, Err(Error::Unavailable(_))),
                    "binary view {i}: {actual:?}"
                ),
            }
        } else {
            let error = String::from_utf8(bytes(&receipt["error"])).unwrap();
            assert!(
                matches!(actual, Err(Error::Invalid(ref e)) if e == &error),
                "view {i}: {actual:?} expected {error}"
            );
        }
        assert_eq!(
            hex::encode(store.snapshot().await.unwrap().1.root().unwrap()),
            expected["root"]
        );
        store.close().await;
    }
}

#[tokio::test]
async fn octb_browser_refuses_stale_profiles_private_state_and_oversized_programs() {
    let fixture = fixture();
    let input = &fixture["cases"][0]["input"];
    let circle = bytes(&input["circle"]);
    let dir = tempfile::tempdir().unwrap();
    for (index, kind) in ["profile", "privacy", "size", "provenance"]
        .iter()
        .enumerate()
    {
        let (mut state, mut profile) = setup(input);
        match *kind {
            "profile" => profile.epoch += 1,
            "privacy" => state
                .set(
                    &[b"circles", &circle, b"privacy", b"class"],
                    b"sealed".to_vec(),
                )
                .unwrap(),
            "size" => state
                .set(
                    &[b"circles", &circle, b"program", b"code_b64"],
                    vec![b'A'; octra_node_runtime::circle::MAX_INPUT_BYTES + 1],
                )
                .unwrap(),
            _ => (),
        }
        let (store, host) = capture(
            &dir.path().join(format!("guard-{index}.db")),
            &state,
            profile,
        )
        .await;
        for method in [ReadMethod::ProgramInfo, ReadMethod::ProgramView] {
            let mut request = request(&host, input, method);
            if *kind == "provenance" {
                request.context.provenance = octra_browser::Provenance::UnpinnedRpc;
            }
            let result = host.read(request).await;
            match *kind {
                "profile" => assert!(matches!(result, Err(Error::Unavailable(_)))),
                "privacy" => assert!(matches!(result, Err(Error::Sealed))),
                "size" => assert!(matches!(result, Err(Error::TooLarge))),
                "provenance" => assert!(matches!(result, Err(Error::SnapshotChanged))),
                _ => unreachable!(),
            }
        }
        assert_eq!(
            store.snapshot().await.unwrap().1.root().unwrap(),
            state.root().unwrap()
        );
        store.close().await;
    }
}
