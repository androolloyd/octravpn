use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octra_node_protocol::{
    consensus::{codec::Wire, ParentCommit},
    native_json::Document,
    state::{Account, Ledger},
    transaction::{address_from_public_key, Nonce, RuleMode, Transaction},
    validator::{
        policy::{self, Active, Policy},
        registry,
    },
};
use octra_node_runtime::{
    account_store,
    execution::{self, Completion, Error, Executed, OperationHost, Outcome, Route},
    state_batch::StateBatch,
    validator_transaction::{Fold, Host, ReadyEnvironment},
};
use serde_json::{json, Value};
fn address(id: i64) -> Vec<u8> {
    address_from_public_key(
        STANDARD
            .encode(
                SigningKey::from_bytes(&[id as u8; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .as_bytes(),
    )
}
fn b64(raw: &[u8]) -> Value {
    json!(STANDARD.encode(raw))
}
fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn event(e: Executed) -> Value {
    let outcome = match e.outcome {
        Outcome::NonceMismatch { expected, got } => json!({"mismatch":[expected.get(),got.get()]}),
        Outcome::Completed(Completion::Confirmed { created_account }) => {
            assert!(created_account.is_none());
            json!("confirmed")
        }
        Outcome::Completed(Completion::Rejected(r)) => {
            assert!(!r.consume_nonce && !r.persist_state && r.notify_reason.is_none());
            json!({"rejected":[r.tag,String::from_utf8(r.reason).unwrap()]})
        }
        Outcome::Completed(Completion::Deferred { .. }) => panic!("unexpected completion"),
    };
    json!({"index":e.input_index,"outcome":outcome})
}
fn initial(input: &Value) -> (Ledger, StateBatch) {
    let mut store = StateBatch::default();
    store.begin().unwrap();
    for a in input["accounts"].as_array().unwrap() {
        let account = Account {
            balance: a["balance"].as_str().unwrap().parse().unwrap(),
            nonce: Nonce::new(a["nonce"].as_i64().unwrap()).unwrap(),
            ..Account::default()
        };
        account_store::set(
            &mut store,
            &address(a["id"].as_i64().unwrap()),
            &account,
            RuleMode::Prior,
        )
        .unwrap();
    }
    (account_store::ledger(&store).unwrap(), store)
}
/// Observe successful host completions before the sender loop's outer savepoint
/// discards them on a later operational error. This is test evidence, not state.
struct Witness<H> {
    host: H,
    confirmed: Vec<usize>,
}
impl<H: OperationHost> OperationHost for Witness<H> {
    fn execute(
        &mut self,
        route: Route,
        tx: &Transaction,
        ledger: &mut Ledger,
        store: &mut StateBatch,
    ) -> Result<Completion, Error> {
        let result = self.host.execute(route, tx, ledger, store);
        if matches!(result, Ok(Completion::Confirmed { .. })) {
            self.confirmed
                .push(std::str::from_utf8(&tx.signature).unwrap().parse().unwrap());
        }
        result
    }
}
fn execute(
    input: &Value,
    round: &Value,
    material: &Value,
    ledger: &mut Ledger,
    store: &mut StateBatch,
) -> Value {
    for meta in round["meta"].as_array().unwrap() {
        store
            .set(
                &[b"meta", meta["key"].as_str().unwrap().as_bytes()],
                raw(&meta["value"]),
            )
            .unwrap();
    }
    if round["drain_escrow"] == true {
        let escrow = registry::escrow_address();
        let amount = ledger.account(&escrow).unwrap().balance.clone();
        ledger.debit_amount_only(&escrow, &amount).unwrap();
    }
    let policy = if input["inactive"] == true {
        Policy::Inactive
    } else {
        Policy::Bonded(Active {
            activation_epoch: 64,
            parameters: octra_node_protocol::validator::admission::Parameters {
                unbonding_epochs: 128,
                ..policy::parameters()
            },
            snapshot_interval: 64,
            evidence_epochs: 100,
        })
    };
    let chain = raw(&input["chain"]);
    let is_ready = input["readiness"] == true;
    let prior_root = round["prev_root"].as_str().map_or_else(
        || if is_ready { vec![b'a'; 64] } else { vec![] },
        |_| raw(&round["prev_root"]),
    );
    let lookup = |epoch: i64| {
        round["roots"][epoch.to_string()]
            .as_str()
            .map(|v| STANDARD.decode(v).unwrap())
    };
    let mode = |key: &str| {
        if round[key] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    let host = Host {
        chain: &chain,
        epoch: round["epoch"].as_i64().unwrap(),
        policy: &policy,
        ready: ReadyEnvironment {
            prev_state_root: &prior_root,
            max_lag: round["max_lag"].as_i64().unwrap_or(2),
            root_at: (!round["roots"].is_null()).then_some(&lookup),
        },
        fold: |_: i64, _: &StateBatch| {
            if round["fold_fail"] == true {
                return Err(Error("fixture anchor unavailable".into()));
            }
            let members = if round["standard_active"] == true {
                "active"
            } else {
                "legacy_active"
            };
            Ok(Fold {
                mode: mode("duty_active"),
                ready_mode: mode("ready_active"),
                ready_ref_mode: mode("ref_active"),
                ready_exec_mode: mode("exec_active"),
                live_mode: mode("live_active"),
                standard_mode: mode("standard_active"),
                ready_config_hash: round["config"].as_str().map(|_| raw(&round["config"])),
                parent: round["parent_wire"]
                    .as_str()
                    .map(|_| ParentCommit::decode(&raw(&round["parent_wire"])).unwrap()),
                members: round["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| address(v.as_i64().unwrap()))
                    .collect(),
                exit_mode: if round["exit_active"] == true {
                    RuleMode::Active
                } else {
                    RuleMode::Prior
                },
                active_addresses: round[members]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| address(v.as_i64().unwrap()))
                    .collect(),
                ..Fold::prior()
            })
        },
    };
    // Native oracle emits deterministic proof-bearing transactions as input
    // material. Only execution outputs below are compared with its expectation.
    let transactions = material
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Transaction::from_document(&Document::parse(&raw(v)).unwrap()).unwrap())
        .collect::<Vec<_>>();
    let mut witness = Witness {
        host,
        confirmed: Vec::new(),
    };
    let outcome = match execution::execute_checked(&transactions, ledger, store, &mut witness) {
        Ok(events) => {
            json!({"fees":execution::confirmed_fees(&transactions,&events).to_string(),"events":events.into_iter().map(event).collect::<Vec<_>>()})
        }
        Err(e) => json!({"error":e.to_string(),"confirmed_before_error":witness.confirmed}),
    };
    account_store::flush_dirty(ledger, store, RuleMode::Prior).unwrap();
    let mut out = json!({"transactions":material,"outcome":outcome,"root":hex::encode(store.root().unwrap()),"accounts":ledger.accounts().iter().map(|(a,v)|json!([b64(a),b64(&v.to_json_bytes())])).collect::<Vec<_>>(),"supply":ledger.total_supply().to_string(),"registry":store.get(&[b"meta",registry::META_KEY]).map(b64),"retired":store.get(&[b"meta",b"supply_retired"]).map(b64),"spent":ledger.spent_nonces().iter().map(|(a,n)|json!([b64(a),n.get()])).collect::<Vec<_>>(),"journal":ledger.journal_active()});
    if is_ready {
        out["duty"] = store
            .get(&[b"meta", octra_node_protocol::validator::set_fold::META_KEY])
            .map_or(Value::Null, b64);
        out["setup"] = round["setup"].clone();
        out["parent"] = round["parent_wire"].clone();
    }
    out
}
fn ready_round(round: &Value, expected: &Value) -> Value {
    let mut round = round.clone();
    round["setup"] = expected["setup"].clone();
    round["parent_wire"] = expected["parent"].clone();
    for meta in expected["setup"].as_array().unwrap() {
        // Setup is fixture input. Independently reconstruct pending metadata
        // to verify the native weighted-set constructor and byte encoding.
        if meta["key"] == "bft.validator_set.pending" {
            use octra_node_protocol::{
                control_payload::ValidatorUpdate, validator::admission::Member,
            };
            let members = (1..=4)
                .map(|id| Member {
                    address: address(id),
                    pubkey: SigningKey::from_bytes(&[id as u8; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                    weight: 1_000_000.into(),
                })
                .collect::<Vec<_>>();
            assert_eq!(
                ValidatorUpdate::make_weighted(0, 64, &members)
                    .unwrap()
                    .to_bytes(),
                raw(&meta["value"])
            );
        }
        round["meta"].as_array_mut().unwrap().push(meta.clone());
    }
    round
}
#[test]
fn native_validator_readiness_savepoints() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-ready.json")).unwrap();
    let sources: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    for (index, case) in fixtures["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (mut ledger, mut store) = initial(input);
        for (step, (round, expected)) in input["rounds"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"].as_array().unwrap())
            .enumerate()
        {
            let round = ready_round(round, expected);
            let actual = execute(
                input,
                &round,
                &expected["transactions"],
                &mut ledger,
                &mut store,
            );
            assert_eq!(actual, *expected, "case {index} round {step}: {round}");
        }
    }
}
#[test]
fn native_validator_escrow_supply_and_savepoints() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-transactions.json")).unwrap();
    let sources: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    for (index, case) in fixtures["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (mut ledger, mut store) = initial(input);
        for (step, (round, expected)) in input["rounds"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"].as_array().unwrap())
            .enumerate()
        {
            let actual = execute(
                input,
                round,
                &expected["transactions"],
                &mut ledger,
                &mut store,
            );
            assert_eq!(actual, *expected, "case {index} round {step}: {round}");
        }
    }
}

async fn validator_restart(case: &Value) {
    use octra_exex::{
        native_history::{ArchiveProof, NativeTransaction},
        ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
    };
    use octra_node_protocol::epoch_index;
    use octra_node_runtime::canonical::{AppliedEpoch, CanonicalStore};
    let input = &case["input"];
    let readiness = input["readiness"] == true;
    let (mut ledger, mut state) = initial(input);
    let (_, index_root) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index_root).as_bytes(),
    )
    .unwrap();
    let chain = ChainIdentity {
        chain_id: "validator-storage-fixture".into(),
        genesis_root: StateRoot(root),
    };
    state.acknowledge_commit().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let mut store = CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap();
    for step in 0..2 {
        let (head, mut next) = store.snapshot().await.unwrap();
        next.begin().unwrap();
        let round = &input["rounds"][step];
        let expected = &case["expected"][step];
        let round = if readiness {
            ready_round(round, expected)
        } else {
            round.clone()
        };
        let actual = execute(
            input,
            &round,
            &expected["transactions"],
            &mut ledger,
            &mut next,
        );
        for field in [
            "outcome", "root", "accounts", "supply", "registry", "retired", "journal", "duty",
        ] {
            assert_eq!(
                actual[field], expected[field],
                "recovered step {step}: {field}"
            );
        }
        assert_eq!(actual["spent"], json!([[b64(&address(1)), step + 1]]));
        let transaction = Transaction::from_document(
            &Document::parse(&raw(&expected["transactions"][0])).unwrap(),
        )
        .unwrap();
        let identity = transaction.identity_bytes().unwrap();
        let archived = NativeTransaction {
            txid: head.txid_hi + 1,
            hash: hex::encode(transaction.hash().unwrap()),
            proof: ArchiveProof::Exact,
            identity: identity.clone(),
            transaction: identity,
            receipt: None,
        };
        let (_, index) = epoch_index::next_root(
            head.index_root.as_bytes(),
            (step + 1) as i64,
            &[epoch_index::Item {
                txid: archived.txid,
                hash: archived.hash.as_bytes().to_vec(),
            }],
        )
        .unwrap();
        let expected_root = StateRoot(
            epoch_index::folded_state_root(
                hex::encode(next.root().unwrap()).as_bytes(),
                hex::encode(index).as_bytes(),
            )
            .unwrap(),
        );
        // This test uses the trusted storage API. Finality authentication belongs
        // to the live consensus tests; these fixture outer signatures are labels.
        let applied = AppliedEpoch {
            epoch: (step + 1) as u64,
            state: next.snapshot(),
            expected_root,
            transactions: vec![archived.clone()],
            certificate: b"trusted validator storage fixture".to_vec(),
            date: (step + 1) as i64,
            message: b"validator lifecycle".to_vec(),
        };
        let pending = store.prepare(&head, applied.clone()).await.unwrap();
        assert_eq!(store.source().head().await.unwrap(), head.cursor);
        assert!(store
            .source()
            .load(Sequence((step + 1) as u64))
            .await
            .unwrap()
            .is_none());
        drop(pending);
        assert_eq!(store.head().await.unwrap(), head);
        let committed = store
            .prepare(&head, applied)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        store.close().await;
        store = CanonicalStore::open(&path, &chain).await.unwrap();
        let (recovered, tree) = store.snapshot().await.unwrap();
        assert_eq!(committed, recovered);
        let restored = account_store::ledger(&tree).unwrap();
        assert_eq!(restored.accounts(), ledger.accounts());
        assert_eq!(
            tree.get(&[b"meta", registry::META_KEY]),
            next.get(&[b"meta", registry::META_KEY])
        );
        let event = store
            .source()
            .load(recovered.cursor.sequence)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.events, vec![archived]);
        assert_eq!(store.source().head().await.unwrap(), recovered.cursor);
        // Epoch-local spent nonce cache is reconstructed; account nonces are durable.
        ledger = restored;
    }
    if readiness {
        let (head, mut tree) = store.snapshot().await.unwrap();
        tree.begin().unwrap();
        let before = tree.root().unwrap();
        let expected = &case["expected"][1];
        let mut round = input["rounds"][1].clone();
        round["parent_wire"] = expected["parent"].clone();
        let replay = execute(
            input,
            &round,
            &expected["transactions"],
            &mut ledger,
            &mut tree,
        );
        assert_eq!(
            replay["outcome"]["events"][0]["outcome"],
            json!({"mismatch":[3,2]})
        );
        assert_eq!(tree.root().unwrap(), before);
        assert_eq!(
            tree.get(&[b"meta", octra_node_protocol::validator::set_fold::META_KEY]),
            Some(raw(&expected["duty"]).as_slice())
        );
        assert_eq!(store.head().await.unwrap(), head);
        assert!(store.source().load(Sequence(3)).await.unwrap().is_none());
        store.close().await;
        return;
    }
    let (head, mut tree) = store.snapshot().await.unwrap();
    tree.begin().unwrap();
    let active = &input["rounds"][4];
    assert_eq!(active["epoch"], 130);
    // Run the original bond again after restart: persisted nonce prevents debit.
    let replay = execute(
        input,
        &input["rounds"][0],
        &case["expected"][0]["transactions"],
        &mut ledger,
        &mut tree,
    );
    assert_eq!(
        replay["outcome"]["events"][0]["outcome"],
        json!({"mismatch":[3,1]})
    );
    // The remaining lifecycle checks use the recovered execution tree. Only the
    // bond/exit commits above are published; no epochs are skipped in history.
    let withdraw = execute(
        input,
        active,
        &case["expected"][4]["transactions"],
        &mut ledger,
        &mut tree,
    );
    assert_eq!(withdraw["outcome"]["events"][0]["outcome"], "confirmed");
    assert!(
        registry::Registry::from_bytes(tree.get(&[b"meta", registry::META_KEY]).unwrap())
            .unwrap()
            .candidates()
            .is_empty()
    );
    assert_eq!(
        ledger.account(&address(1)).unwrap().balance.to_string(),
        "9999979"
    );
    assert_eq!(store.head().await.unwrap(), head);
    assert!(store.source().load(Sequence(3)).await.unwrap().is_none());
    // Do not publish the speculative withdrawal. Reopening restores bonded escrow.
    tree.abort();
    store.close().await;
    let store = CanonicalStore::open(&path, &chain).await.unwrap();
    let (_, tree) = store.snapshot().await.unwrap();
    assert_eq!(
        account_store::ledger(&tree)
            .unwrap()
            .account(&registry::escrow_address())
            .unwrap()
            .balance
            .to_string(),
        "1000000"
    );
    store.close().await;
}

#[tokio::test]
async fn bonded_stake_and_exex_survive_canonical_restart() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-transactions.json")).unwrap();
    validator_restart(&fixtures["cases"][0]).await;
}
#[tokio::test]
async fn duty_readiness_and_exex_survive_canonical_restart() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-ready.json")).unwrap();
    let case = fixtures["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["input"]["rounds"][1]["record_final"] == true
                && c["input"]["rounds"][1]["transactions"][0]["proof_owner"] == 1
        })
        .unwrap();
    assert_eq!(
        case["expected"][1]["outcome"]["events"][0]["outcome"],
        "confirmed"
    );
    validator_restart(case).await;
}
