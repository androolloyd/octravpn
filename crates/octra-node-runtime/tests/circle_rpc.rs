//! Differential coverage of the actual native RPC clock and view host.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_browser::{
    application::{ApplicationHost, Context, ReadMethod, ReadRequest},
    AssetResolver, Error, OctUrl,
};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{
    epoch_index,
    rules::{self, Graph, RootRead},
    transaction::RuleMode,
};
use octra_node_runtime::{
    canonical::CanonicalStore,
    circle::{CircleRuntime, HfheBackend},
    circle_application::CanonicalApplications,
    circle_assets::CanonicalAssets,
    circle_view::{self, Profile, ReadKind},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};

fn fixture() -> &'static Value {
    static VALUE: OnceLock<Value> = OnceLock::new();
    VALUE.get_or_init(|| {
        let data: Value = serde_json::from_str(include_str!("fixtures/circle-rpc.json")).unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let inventory: Value = serde_json::from_slice(
            &std::fs::read(root.join("docs/rust-node/source-map.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(data["upstream_commit"], inventory["upstream_commit"]);
        assert_eq!(data["source_sha256"], inventory["files"]);
        assert_eq!(data["instrumentation"], json!({}));
        for (field, path) in [
            ("oracle_sha256", "scripts/node-port/circle-rpc-oracle.ml"),
            ("runner_sha256", "scripts/node-port/native-oracle.py"),
            (
                "generator_sha256",
                "scripts/node-port/circle-rpc-fixtures.py",
            ),
            (
                "epoch_guest_source_sha256",
                "scripts/node-port/epoch-guest.rs",
            ),
        ] {
            assert_eq!(
                data[field],
                hex::encode(Sha256::digest(std::fs::read(root.join(path)).unwrap()))
            );
        }
        let counter: Value =
            serde_json::from_str(include_str!("fixtures/circle-view.json")).unwrap();
        assert_eq!(data["guest_source_sha256"], counter["guest_source_sha256"]);
        assert_eq!(data["wasm_sha256"], counter["wasm_sha256"]);
        data
    })
}

#[test]
fn native_rpc_clock_and_view_profile_fault_order() {
    for case in fixture()["cases"].as_array().unwrap() {
        let input = &case["input"];
        let expected = &case["expected"];
        match input["kind"].as_str().unwrap() {
            "clock" => {
                let raw = input["epoch"].as_str().map(str::as_bytes);
                for (kind, name) in [
                    (ReadKind::View, "view"),
                    (ReadKind::Program, "program"),
                    (ReadKind::Policy, "asset"),
                ] {
                    match circle_view::epoch(raw, kind) {
                        Ok(epoch) => assert_eq!(json!(epoch.to_string()), expected["view_epoch"]),
                        Err(error) => assert_eq!(json!(error.to_string()), expected[name]["error"]),
                    }
                }
            }
            "profile" => {
                let graph = Graph::new(
                    STANDARD.decode(input["chain"].as_str().unwrap()).unwrap(),
                    None,
                );
                let root = |epoch: i64| {
                    let name = epoch.to_string();
                    let kind = input["roots"][&name]
                        .as_str()
                        .unwrap_or(input["default"].as_str().unwrap());
                    match kind {
                        "missing" => RootRead::Missing,
                        "bad" => RootRead::Root(b"wrong-root".to_vec()),
                        "unreadable" => RootRead::Unreadable(b"disk unavailable".to_vec()),
                        "good" => rules::ALL
                            .iter()
                            .filter_map(|r| graph.activation(*r))
                            .find(|p| p.anchor_epoch == epoch)
                            .map_or(RootRead::Missing, |p| RootRead::Root(p.anchor_state_root)),
                        _ => panic!("unknown root fixture"),
                    }
                };
                let found = match Profile::resolve(&graph, input["epoch"].as_i64().unwrap(), &root)
                {
                    Err(error) => json!({"error":STANDARD.encode(error.message())}),
                    Ok(p) => {
                        json!({"epoch":p.epoch.to_string(),"point_ops":p.point_ops,"math":p.math,"object_cost":p.object_cost,"int_work":p.int_work,"fhe_work":p.fhe_work == RuleMode::Active,"proof_exec":p.proof_exec == RuleMode::Active,"wasm_float":p.wasm_float == RuleMode::Active})
                    }
                };
                assert_eq!(&found, expected, "{input}");
            }
            "view" => (),
            _ => panic!("unknown fixture"),
        }
    }
}

struct NoHfhe;
impl HfheBackend for NoHfhe {
    fn call(&self, _: &Value) -> Result<Value, octra_node_runtime::circle::Error> {
        panic!("public read unexpectedly invoked HFHE")
    }
}

#[tokio::test]
async fn native_rpc_public_reads_and_browser_assets_share_next_epoch_visibility() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::resolve(&Graph::new(b"local".to_vec(), None), 1, &|_| {
        RootRead::Missing
    })
    .unwrap();
    for (index, case) in fixture()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, c)| c["input"]["kind"] == "view")
    {
        let input = &case["input"];
        let mut state = StateBatch::default();
        state.begin().unwrap();
        for entry in input["entries"].as_array().unwrap() {
            let path = entry["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| STANDARD.decode(p.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>();
            state
                .set(
                    &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    STANDARD.decode(entry["value"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(hex::encode(state.root().unwrap()), case["expected"]["root"]);
        let program = state
            .get(&[
                b"circles",
                input["circle"].as_str().unwrap().as_bytes(),
                b"program",
                b"code_b64",
            ])
            .unwrap();
        let expected_hash = if input["method"] == "epoch" {
            "epoch_guest_wasm_sha256"
        } else {
            "wasm_sha256"
        };
        assert_eq!(
            hex::encode(Sha256::digest(STANDARD.decode(program).unwrap())),
            fixture()[expected_hash]
        );
        let index_root =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap()
                .1;
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index_root).as_bytes(),
        )
        .unwrap();
        let store = CanonicalStore::create(
            &temp.path().join(format!("{index}.db")),
            ChainIdentity::genesis("local", StateRoot(root)),
            state.snapshot(),
            0,
        )
        .await
        .unwrap();
        let assets = CanonicalAssets::capture(&store).await.unwrap();
        let host = CanonicalApplications::new(
            assets.clone(),
            CircleRuntime::new(Arc::new(NoHfhe)),
            profile.clone(),
        );
        let circle = input["circle"].as_str().unwrap();
        let result = host
            .read(ReadRequest {
                context: Context {
                    circle_id: circle.into(),
                    provenance: host.provenance(),
                },
                method: ReadMethod::ProgramView,
                params: json!({"method":input["method"],"params":input["params"]}),
            })
            .await;
        let found = match result {
            Ok(value) => value,
            Err(Error::Invalid(e) | Error::Unavailable(e)) => json!({"error":e}),
            Err(error) => panic!("unexpected: {error}"),
        };
        assert_eq!(found, case["expected"]["found"], "native RPC case {index}");
        if input["method"] == "epoch" {
            assert_eq!(found, json!({"result":"1"}));
        } else {
            let asset = assets
                .resolve(&OctUrl::parse(&format!("oct://{circle}/public.bin")).unwrap())
                .await;
            if found.get("error").is_some() {
                assert!(
                    matches!(asset, Err(Error::NotFound)),
                    "browser exposed inactive/expired resource"
                );
            } else {
                assert_eq!(&*asset.unwrap().bytes, b"abcdefgh");
            }
        }
        assert_eq!(
            assets.identity().epoch,
            0,
            "provenance remains the captured epoch"
        );
        assert_eq!(
            hex::encode(store.snapshot().await.unwrap().1.root().unwrap()),
            case["expected"]["root"]
        );
        store.close().await;
    }
}
