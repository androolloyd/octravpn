#[path = "common/finality_host.rs"]
mod finality_host;
#[path = "common/circle_host.rs"]
#[allow(dead_code)] // This suite uses the shared runtime/fixture without install_counter.
mod host;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    circle_program::Deploy,
    native_json::Document,
    state::{Account, Ledger},
    transaction::{Nonce, OpType, RuleMode, Transaction},
};
use octra_node_runtime::{
    account_store,
    circle::WasmRules,
    circle_transaction::{self, Rules},
    state_batch::StateBatch,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn encoded(bytes: &[u8]) -> Value {
    json!(STANDARD.encode(bytes))
}
fn optional(value: &Value) -> Option<Vec<u8>> {
    (!value.is_null()).then(|| bytes(value))
}
fn expand(mut raw: &[u8], fixture: &Value) -> Vec<u8> {
    let token = b"$COUNTER";
    let mut out = Vec::new();
    while let Some(index) = raw.windows(token.len()).position(|w| w == token) {
        out.extend_from_slice(&raw[..index]);
        out.extend_from_slice(fixture["wasm_b64"].as_str().unwrap().as_bytes());
        raw = &raw[index + token.len()..];
    }
    out.extend_from_slice(raw);
    out
}
fn tx(index: usize, value: &Value, fixture: &Value, previous: &[u8]) -> Transaction {
    let mut tx = Transaction {
        from: bytes(&value["from"]),
        to: bytes(&value["to"]),
        amount: value["amount"].as_str().unwrap().parse().unwrap(),
        nonce: Nonce::new(value["nonce"].as_i64().unwrap()).unwrap(),
        ou: value["ou"].as_str().unwrap().parse().unwrap(),
        timestamp: 1.,
        signature: index.to_string().into_bytes(),
        public_key: None,
        message: optional(&value["params"]).map(|raw| expand(&raw, fixture)),
        encrypted_data: optional(&value["method"]),
        op_type: match value["op"].as_str().unwrap() {
            "deploy" => OpType::CircleDeploy,
            "update" => OpType::CircleProgramUpdate,
            "call" => OpType::CircleCall,
            _ => panic!("unknown operation"),
        },
    };
    if tx.to == b"$derive" {
        tx.to = derived(&tx).unwrap_or_else(|| b"invalid".to_vec());
    }
    if tx.to == b"$previous" {
        tx.to = previous.to_vec();
    }
    tx
}
fn derived(tx: &Transaction) -> Option<Vec<u8>> {
    let doc = Document::parse(tx.message.as_deref()?).ok()?;
    Some(Deploy::from_document(&doc).ok()?.id(&tx.from, tx.nonce))
}
fn setup(input: &Value, fixture: &Value) -> (StateBatch, Ledger, Vec<Transaction>) {
    let rows = input["transactions"].as_array().unwrap();
    let circle = rows.iter().find(|v| v["op"] == "deploy").map_or_else(
        || format!("oct{}", "3".repeat(44)).into_bytes(),
        |v| {
            let t = tx(0, v, fixture, b"");
            derived(&t).unwrap_or_else(|| b"invalid".to_vec())
        },
    );
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for e in input["entries"].as_array().unwrap() {
        let path = e["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let raw = bytes(v);
                if raw == b"$circle" {
                    circle.clone()
                } else {
                    raw
                }
            })
            .collect::<Vec<_>>();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                expand(&bytes(&e["value"]), fixture),
            )
            .unwrap();
    }
    let accounts: BTreeMap<_, _> = input["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                bytes(&v["address"]),
                Account {
                    balance: v["balance"].as_str().unwrap().parse().unwrap(),
                    nonce: Nonce::new(v["nonce"].as_i64().unwrap()).unwrap(),
                    ..Account::default()
                },
            )
        })
        .collect();
    for (address, account) in &accounts {
        account_store::set(&mut state, address, account, RuleMode::Prior).unwrap();
    }
    let ledger = Ledger::from_accounts(accounts).unwrap();
    let transactions = input["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, v)| tx(i, v, fixture, &circle))
        .collect();
    (state, ledger, transactions)
}
fn rules(input: &Value) -> Rules {
    Rules {
        manifest: if input["wasm_compute"] == false {
            octra_node_runtime::circle::WasmProfile::Compute
        } else {
            octra_node_runtime::circle::WasmProfile::Manifest
        },
        update_policy: input["circle_policy"] == true,
        wasm: WasmRules {
            proof_exec: input["proof"].as_bool().unwrap(),
            wasm_float: input["float"].as_bool().unwrap(),
            math: input["math"].as_bool().unwrap(),
        },
        inspect: input["inspect"].as_bool().unwrap(),
        storage_proof: input["storage_proof"].as_bool().unwrap(),
        fhe_work: input["fhe_work"] == true,
    }
}
#[test]
fn native_circle_code_epochs_match_state_fees_and_refusals() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-code.json")).unwrap();
    assert_eq!(
        fixture["guest_source_sha256"],
        host::fixture()["guest_source_sha256"]
    );
    assert_bft_epochs(&fixture);
}

#[test]
fn native_octb_admission_epochs_match_installation_fees_and_refusal_priority() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-octb.json")).unwrap();
    for (key, source) in [
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/circle-octb-fixtures.py").as_slice(),
        ),
        (
            "generator_dependency_sha256",
            include_bytes!("../../../scripts/node-port/circle-code-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[key], hex::encode(Sha256::digest(source)));
    }
    assert_bft_epochs(&fixture);
}

#[test]
fn native_nested_circle_journals_match_value_reentry_events_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-journal.json")).unwrap();
    assert_eq!(
        fixture["guest_source_sha256"]["scripts/node-port/circle-journal-guest.rs"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-journal-guest.rs"
        )))
    );
    assert_eq!(
        fixture["guest_source_sha256"]["contracts/examples/rust_circle_sdk/src/lib.rs"],
        host::fixture()["guest_source_sha256"]["contracts/examples/rust_circle_sdk/src/lib.rs"]
    );
    assert_bft_epochs(&fixture);
}

#[test]
fn unavailable_code_admission_restores_earlier_deployment_and_fee() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/circle-code.json")).unwrap();
    let input = &fixture["cases"][0]["input"];
    for unavailable in [b"{".as_slice(), b"octb"] {
        let (mut state, mut ledger, mut transactions) = setup(input, &fixture);
        let before = state.root().unwrap();
        let accounts = ledger.accounts().clone();
        let supply = ledger.total_supply().clone();
        let mut second = transactions[0].clone();
        second.nonce = second.nonce.successor();
        if unavailable == b"octb" {
            let mut payload: Value =
                serde_json::from_slice(second.message.as_ref().unwrap()).unwrap();
            payload["runtime"] = json!("octb");
            payload["code_b64"] = json!(STANDARD.encode(
                octra_node_protocol::program_wire::Envelope {
                    code: b"OCTB\x01\x00\x00\x00\x01\x00\x00\x00\x17".to_vec(),
                    cert: b"{}".to_vec(),
                }
                .encode()
                .unwrap()
            ));
            second.message = Some(serde_json::to_vec(&payload).unwrap());
            second.to = derived(&second).unwrap();
        } else {
            second.message = Some(unavailable.to_vec());
        }
        transactions.push(second);
        let error = circle_transaction::execute(
            &host::runtime(),
            rules(input),
            3,
            123.5,
            &transactions,
            &mut ledger,
            &mut state,
        )
        .err()
        .expect("missing admission capability must abort the attempt");
        if unavailable == b"octb" {
            assert_eq!(
                error.0,
                "OCTB Program certificate admission host is not available"
            );
        }
        assert_eq!(state.root().unwrap(), before);
        assert_eq!(*ledger.accounts(), accounts);
        assert_eq!(*ledger.total_supply(), supply);
        assert!(ledger.spent_nonces().is_empty());
        assert!(!ledger.journal_active());
    }
}

#[test]
fn native_spawn_and_asset_epochs_match_ownership_usage_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-effects.json")).unwrap();
    assert_eq!(
        fixture["guest_source_sha256"]["scripts/node-port/circle-effects-guest.rs"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-effects-guest.rs"
        )))
    );
    assert_eq!(
        fixture["guest_source_sha256"]["contracts/examples/rust_circle_sdk/src/lib.rs"],
        host::fixture()["guest_source_sha256"]["contracts/examples/rust_circle_sdk/src/lib.rs"]
    );
    assert_bft_epochs(&fixture);
}

#[tokio::test]
async fn signed_spawn_publishes_oct_page_and_exex_record_through_restart() {
    use ed25519_dalek::{Signer, SigningKey};
    use octra_browser::{AssetResolver, OctUrl};
    use octra_exex::{
        native_history::{ArchiveProof, NativeTransaction},
        ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
    };
    use octra_node_protocol::{
        consensus::codec::Wire, emission::Schedule, epoch_index, transaction,
        transaction_payload::Limits, transaction_policy::Profile,
    };
    use octra_node_runtime::{
        admission::{self, Postcheck, Precheck},
        canonical::CanonicalStore,
        circle_assets::CanonicalAssets,
        epoch_footer,
        finality::{ExecutedEpoch, Publisher},
    };
    use std::sync::Arc;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-effects.json")).unwrap();
    let mut input = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["name"] == "spawn with assets"
                && c["input"]["proof"] == true
                && c["input"]["inspect"] == true
                && serde_json::from_slice::<Value>(&bytes(&c["input"]["transactions"][0]["params"]))
                    .unwrap()[1]
                    == "parent"
        })
        .unwrap()["input"]
        .clone();
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    let sender = transaction::address_from_public_key(&public);
    let old_sender = input["accounts"][0]["address"].clone();
    input["accounts"][0]["address"] = encoded(&sender);
    input["transactions"][0]["from"] = encoded(&sender);
    for entry in input["entries"].as_array_mut().unwrap() {
        if entry["value"] == old_sender {
            entry["value"] = encoded(&sender);
        }
    }
    let (mut state, mut ledger, mut transactions) = setup(&input, &fixture);
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state
        .set(
            &[b"meta", b"total_supply"],
            ledger.total_supply().to_string().into_bytes(),
        )
        .unwrap();
    state
        .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
        .unwrap();
    let index = epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
        .unwrap()
        .1;
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spawn.db");
    let store = Arc::new(
        CanonicalStore::create(
            &path,
            ChainIdentity {
                chain_id: "circle-effects-development".into(),
                genesis_root: StateRoot(root),
            },
            state.snapshot(),
            0,
        )
        .await
        .unwrap(),
    );
    let authority = finality_host::Authority {
        seed: 1,
        chain: store.chain().clone(),
    };
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let before = CanonicalAssets::capture(&store).await.unwrap();
    let base = store.head().await.unwrap();
    let tx = &mut transactions[0];
    tx.public_key = Some(public);
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    let release = Profile::from_values(Some(b"devnet_full_v1"), None, None);
    let admitted = admission::submit(
        tx.clone(),
        &ledger,
        &Precheck {
            now: 1.,
            max_timestamp_drift: 60.,
            observer: false,
            bft: true,
            profile: &release,
            duty: None,
            limits: Limits::default(),
        },
        Postcheck {
            preverify_has_capacity: true,
            preverify_pending: Nonce::default(),
            preverify_pending_max: Nonce::new(100).unwrap(),
            bft: true,
            confirmed_nonce: Nonce::default(),
            bft_window: Nonce::new(100).unwrap(),
        },
    )
    .unwrap()
    .into_transaction();
    let tx_hash = hex::encode(admitted.hash().unwrap());
    let parent = admitted.to.clone();
    let mut next = store.snapshot().await.unwrap().1;
    next.begin().unwrap();
    let batch = circle_transaction::execute(
        &host::runtime(),
        rules(&input),
        1,
        123.5,
        std::slice::from_ref(&admitted),
        &mut ledger,
        &mut next,
    )
    .unwrap();
    let receipt = batch.receipts[&tx_hash].clone();
    let receipt_json: Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(receipt_json["success"], true);
    let child = receipt_json["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"] == "Child")
        .unwrap()["values"][0]
        .as_str()
        .unwrap();
    assert_eq!(
        next.get(&[b"circles", child.as_bytes(), b"owner"]),
        Some(parent.as_slice())
    );
    let url = OctUrl::parse(&format!("oct://{child}/index.html")).unwrap();
    assert!(before.resolve(&url).await.is_err());
    epoch_footer::apply(
        &epoch_footer::Policy {
            emission_guard: true,
            schedule: Schedule::Inactive,
            legacy_total: None,
        },
        &epoch_footer::Request {
            epoch: 1,
            reward: &finality_host::reward(authority.seed),
            validator_keys: &[],
            confirmed_fees: batch.fees,
        },
        &mut ledger,
        &mut next,
    )
    .unwrap();
    account_store::flush_dirty(&mut ledger, &mut next, RuleMode::Active).unwrap();
    next.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
    let identity = admitted.identity_bytes().unwrap();
    let item = NativeTransaction {
        txid: 0,
        proof: ArchiveProof::Exact,
        identity: identity.clone(),
        transaction: identity,
        receipt: Some(receipt.clone()),
        hash: tx_hash,
    };
    item.validate().unwrap();
    let executed = ExecutedEpoch {
        state: next.snapshot(),
        transactions: vec![item.clone()],
        consensus_receipts: vec![],
        reward_source: finality_host::reward_source(authority.seed),
        date: 1,
        message: b"publish spawned Circle page".to_vec(),
    };
    let certificate = finality_host::certificate(&base, &executed, &authority)
        .encode()
        .unwrap();
    let prepared = publisher
        .prepare(&base, &certificate, executed)
        .await
        .unwrap();
    assert!(CanonicalAssets::capture(&store)
        .await
        .unwrap()
        .resolve(&url)
        .await
        .is_err());
    assert!(store.source().load(Sequence(1)).await.unwrap().is_none());
    prepared.commit().await.unwrap();
    let published = CanonicalAssets::capture(&store).await.unwrap();
    let asset = published.resolve(&url).await.unwrap();
    assert_eq!(asset.bytes.as_ref(), b"<h1>Native Circle</h1>");
    assert!(before.resolve(&url).await.is_err());
    assert_eq!(
        store
            .source()
            .load(Sequence(1))
            .await
            .unwrap()
            .unwrap()
            .events,
        vec![item.clone()]
    );
    publisher.audit().await.unwrap();
    let chain = store.chain().clone();
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
    let store = Arc::new(CanonicalStore::open(&path, &chain).await.unwrap());
    let publisher = Publisher::open(store.clone(), authority).await.unwrap();
    let recovered = CanonicalAssets::capture(&store).await.unwrap();
    assert_eq!(published.provenance(), recovered.provenance());
    assert_eq!(recovered.resolve(&url).await.unwrap().bytes, asset.bytes);
    assert_eq!(
        store
            .source()
            .load(Sequence(1))
            .await
            .unwrap()
            .unwrap()
            .events,
        vec![item]
    );
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
}

#[test]
fn unavailable_nested_execution_restores_earlier_child_effects_and_fees() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-journal.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["name"] == "nested money"
                && c["input"]["inspect"] == true
                && c["expected"]["result"]["confirmed"] == json!([[0, 0]])
                && serde_json::from_slice::<Value>(&bytes(&c["input"]["transactions"][0]["params"]))
                    .unwrap()[0]
                    == format!("oct{}", "5".repeat(44))
        })
        .expect("successful native nested transfer")["input"];
    let (mut state, mut ledger, mut transactions) = setup(input, &fixture);
    let unavailable = format!("oct{}", "8".repeat(44));
    state
        .set(
            &[b"contracts", unavailable.as_bytes(), b"bytecode"],
            b"unsupported OCTB fixture".to_vec(),
        )
        .unwrap();
    let before = state.root().unwrap();
    let accounts = ledger.accounts().clone();
    let supply = ledger.total_supply().clone();
    let mut second = transactions[0].clone();
    second.nonce = second.nonce.successor();
    second.message = Some(serde_json::to_vec(&json!([unavailable, "return", true])).unwrap());
    transactions.push(second);
    let error = circle_transaction::execute(
        &host::runtime(),
        rules(input),
        3,
        123.5,
        &transactions,
        &mut ledger,
        &mut state,
    )
    .err()
    .expect("unsupported nested execution must abort the attempt");
    assert_eq!(
        error.0,
        format!(
            "Circle execution unavailable: {:?}",
            octra_node_protocol::circle_wasm::Error::Unavailable(
                b"OCTB execution host is not available".to_vec()
            )
        )
    );
    assert_eq!(state.root().unwrap(), before);
    assert_eq!(*ledger.accounts(), accounts);
    assert_eq!(*ledger.total_supply(), supply);
    assert!(ledger.spent_nonces().is_empty());
    assert!(!ledger.journal_active());
}

#[test]
fn native_octb_circle_execution_matches_complete_epoch_effects() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-octb-execution.json")).unwrap();
    assert_eq!(
        fixture["generator_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-octb-execution-fixtures.py"
        )))
    );
    for (name, source) in [
        (
            "circle-code-fixtures.py",
            include_bytes!("../../../scripts/node-port/circle-code-fixtures.py").as_slice(),
        ),
        (
            "octb-execution-fixtures.py",
            include_bytes!("../../../scripts/node-port/octb-execution-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(
            fixture["generator_dependencies"][name],
            hex::encode(Sha256::digest(source))
        );
    }
    assert_bft_epochs(&fixture);
}

#[test]
fn native_circle_binary_refusals_match_receipts_fees_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-byte-errors.json")).unwrap();
    assert_octb_generator(
        &fixture,
        include_bytes!("../../../scripts/node-port/circle-byte-errors-fixtures.py"),
    );
    let oracle = [
        b"let () = Octra_log._set_level Octra_log.FATAL\n".as_slice(),
        include_bytes!("../../../scripts/node-port/circle-code-oracle.ml"),
    ]
    .concat();
    assert_bft_epochs_with_oracle(&fixture, &oracle);
}

#[test]
fn native_octb_circle_spawns_match_ownership_admission_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-octb-spawn.json")).unwrap();
    assert_octb_generator(
        &fixture,
        include_bytes!("../../../scripts/node-port/circle-octb-spawn-fixtures.py"),
    );
    assert_bft_epochs(&fixture);
}

fn assert_octb_generator(fixture: &Value, generator: &[u8]) {
    assert_eq!(
        fixture["generator_sha256"],
        hex::encode(Sha256::digest(generator))
    );
    for (name, source) in [
        (
            "circle-code-fixtures.py",
            include_bytes!("../../../scripts/node-port/circle-code-fixtures.py").as_slice(),
        ),
        (
            "octb-execution-fixtures.py",
            include_bytes!("../../../scripts/node-port/octb-execution-fixtures.py").as_slice(),
        ),
        (
            "circle-octb-execution-fixtures.py",
            include_bytes!("../../../scripts/node-port/circle-octb-execution-fixtures.py")
                .as_slice(),
        ),
    ] {
        assert_eq!(
            fixture["generator_dependencies"][name],
            hex::encode(Sha256::digest(source))
        );
    }
}

#[test]
fn unavailable_octb_child_restores_the_entire_speculative_attempt() {
    use octra_node_protocol::octb::{self, Instruction as I, Metadata, Value as Constant};
    use std::sync::Arc;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-octb-journal.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["name"] == "OCTB chain money"
                && c["input"]["inspect"] == true
                && c["expected"]["result"]["confirmed"] == json!([[0, 0]])
        })
        .unwrap()["input"];
    let (mut state, mut ledger, mut transactions) = setup(input, &fixture);
    let child = format!("oct{}", "8".repeat(44));
    let template = format!("oct{}", "5".repeat(44));
    for entry in input["entries"].as_array().unwrap() {
        let mut path = entry["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect::<Vec<_>>();
        if path[1] != template.as_bytes() {
            continue;
        }
        path[1] = child.as_bytes().to_vec();
        state
            .set(
                &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                bytes(&entry["value"]),
            )
            .unwrap();
    }
    let code = octb::encode(
        &[
            I::Jdest(100),
            I::Mload(1, 1000),
            I::Ldi(2, Arc::new(Constant::Str(Arc::from(b"private".as_slice())))),
            I::Eq(3, 1, 2),
            I::Jif(3, 200),
            I::Revert(),
            I::Jdest(200),
            I::FheMul(0, 1, 2, 3),
            I::Stop(),
        ],
        &Metadata::default(),
        false,
    )
    .unwrap();
    for (suffix, value) in [
        (
            vec![b"program".as_slice(), b"code_b64"],
            STANDARD.encode(&code).into_bytes(),
        ),
        (
            vec![b"code_hash".as_slice()],
            hex::encode(Sha256::digest(&code)).into_bytes(),
        ),
        (
            vec![b"call_code".as_slice()],
            hex::encode(Sha256::digest(&code)).into_bytes(),
        ),
    ] {
        let mut path = vec![b"circles".as_slice(), child.as_bytes()];
        path.extend(suffix);
        state.set(&path, value).unwrap();
    }
    let before = state.root().unwrap();
    let accounts = ledger.accounts().clone();
    let supply = ledger.total_supply().clone();
    let mut second = transactions[0].clone();
    second.nonce = second.nonce.successor();
    second.message = Some(serde_json::to_vec(&json!([child, "private"])).unwrap());
    transactions.push(second);
    let error = circle_transaction::execute(
        &host::runtime(),
        rules(input),
        3,
        123.5,
        &transactions,
        &mut ledger,
        &mut state,
    )
    .err()
    .expect("missing private execution must abort the complete attempt");
    assert!(error.0.contains("Unavailable"), "{error:?}");
    assert_eq!(state.root().unwrap(), before);
    assert_eq!(*ledger.accounts(), accounts);
    assert_eq!(*ledger.total_supply(), supply);
    assert!(ledger.spent_nonces().is_empty());
    assert!(!ledger.journal_active());
}

#[test]
fn native_mixed_octb_wasm_journals_match_reentry_budget_and_rollback() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/circle-octb-journal.json")).unwrap();
    assert_eq!(
        fixture["generator_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/circle-octb-journal-fixtures.py"
        )))
    );
    assert_eq!(
        fixture["guest_fixture_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/circle-journal.json"
        )))
    );
    for (name, source) in [
        (
            "circle-octb-execution-fixtures.py",
            include_bytes!("../../../scripts/node-port/circle-octb-execution-fixtures.py")
                .as_slice(),
        ),
        (
            "circle-code-fixtures.py",
            include_bytes!("../../../scripts/node-port/circle-code-fixtures.py").as_slice(),
        ),
        (
            "octb-execution-fixtures.py",
            include_bytes!("../../../scripts/node-port/octb-execution-fixtures.py").as_slice(),
        ),
    ] {
        assert_eq!(
            fixture["generator_dependencies"][name],
            hex::encode(Sha256::digest(source))
        );
    }
    assert_bft_epochs_with_oracle(
        &fixture,
        include_bytes!("../../../scripts/node-port/circle-octb-journal-oracle.ml"),
    );
}

fn assert_bft_epochs(fixture: &Value) {
    assert_bft_epochs_with_oracle(
        fixture,
        include_bytes!("../../../scripts/node-port/circle-code-oracle.ml"),
    );
}
fn assert_bft_epochs_with_oracle(fixture: &Value, oracle: &[u8]) {
    use octra_node_protocol::{
        emission::Schedule,
        epoch_rewards::{Attribution, Validator},
        transaction_outcome,
        validator::policy::Policy,
    };
    use octra_node_runtime::{
        epoch_execution::{self, Request},
        epoch_footer, validator_epoch,
    };
    let source: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], source["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], source["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        hex::encode(Sha256::digest(oracle))
    );
    assert_eq!(
        fixture["runner_sha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/native-oracle.py"
        )))
    );
    assert_eq!(
        fixture["wasm_sha256"],
        hex::encode(Sha256::digest(bytes(&fixture["wasm_b64"])))
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (mut state, mut ledger, transactions) = setup(input, fixture);
        state
            .set(
                &[b"meta", b"total_supply"],
                ledger.total_supply().to_string().into_bytes(),
            )
            .unwrap();
        state
            .set(&[b"meta", b"emission_remaining"], b"0".to_vec())
            .unwrap();
        let deployments: Vec<_> = transactions
            .iter()
            .filter(|tx| tx.op_type == OpType::CircleDeploy)
            .filter_map(|tx| {
                let doc = Document::parse(tx.message.as_deref()?).ok()?;
                let p = Deploy::from_document(&doc).ok()?;
                let canonical = String::from_utf8(p.canonical())
                    .unwrap()
                    .replace(fixture["wasm_b64"].as_str().unwrap(), "$COUNTER");
                Some(json!([
                    String::from_utf8(p.id(&tx.from, tx.nonce)).unwrap(),
                    encoded(canonical.as_bytes())
                ]))
            })
            .collect();
        let before = hex::encode(state.root().unwrap());
        state.acknowledge_commit().unwrap();
        state.begin().unwrap();
        let committed = state.snapshot();
        let runtime = host::runtime();
        let epoch = input["epoch"].as_i64().unwrap();
        let mut calls = circle_transaction::Calls::new(
            &runtime,
            rules(input),
            epoch,
            input["now"].as_f64().unwrap(),
            before.as_bytes(),
            circle_transaction::Verification::Direct,
        );
        let emission = epoch_footer::Policy {
            emission_guard: true,
            schedule: Schedule::Inactive,
            legacy_total: None,
        };
        let addr = format!("oct{}", "4".repeat(44)).into_bytes();
        let reward = Attribution {
            proposer: addr.clone(),
            proposer_public_key: None,
            validators: vec![Validator {
                address: addr.clone(),
                public_key: None,
                weight: 1.into(),
            }],
        };
        let fold = |_: i64, _: &StateBatch| {
            Ok(validator_epoch::Fold {
                vm_bytes: if input["inspect"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                proof_exec: if input["proof"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                fhe_work: if input["fhe_work"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                ..validator_epoch::Fold::prior()
            })
        };
        let result = epoch_execution::execute(
            &Request {
                validators: validator_epoch::Request {
                    chain: b"epoch-circle-fixture",
                    epoch,
                    policy: &Policy::Inactive,
                    legacy_members: &[addr],
                    previous_root: before.as_bytes(),
                    committed_head: Some(&committed),
                },
                envelope: transaction_outcome::Rules {
                    envelope: RuleMode::Prior,
                    compute: RuleMode::Prior,
                    settle: RuleMode::Prior,
                },
                sender_key_activation: Some(0),
                preverification: None,
                emission: &emission,
                reward: &reward,
                validator_keys: &[],
            },
            &fold,
            &transactions,
            &mut ledger,
            &mut state,
            |tx, ledger, state| calls.process(tx, ledger, state),
        );
        let result = match result {
            Ok(result) => {
                json!({"fees":result.artifacts.confirmed_fees.to_string(),"confirmed":result.artifacts.confirmed,"rejected":result.artifacts.rejected.iter().map(|r|json!({"index":r.input_index,"type":encoded(&r.refusal.error_type),"reason":encoded(&r.refusal.reason),"charged":r.charged})).collect::<Vec<_>>() })
            }
            Err(e) => json!({"error":format!("Failure({:?})",e.0)}),
        };
        let actual = json!({"deployments":deployments,"before":before,"result":result,"root":hex::encode(state.root().unwrap()),"receipts":calls.receipts().iter().map(|(k,v)|json!([k,encoded(v)])).collect::<Vec<_>>(),"accounts":ledger.accounts().iter().map(|(a,v)|json!([encoded(a),encoded(&v.to_json_bytes())])).collect::<Vec<_>>(),"supply":ledger.total_supply().to_string(),"spent":ledger.spent_nonces().len(),"journal":ledger.journal_active()});
        assert_eq!(
            actual, case["expected"],
            "native Circle code epoch {index}: {}",
            input["name"]
        );
    }
}
