use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::{codec::Wire, ParentCommit},
    transaction::RuleMode,
    validator::{policy::Policy, registry, set_fold::CapMode, update},
};
use octra_node_runtime::{
    execution::Error,
    state_batch::{Snapshot, StateBatch},
    validator_epoch::{self, Fold, Request},
};
use serde_json::{json, Value};

fn raw(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}
fn b64(v: &[u8]) -> Value {
    json!(STANDARD.encode(v))
}
fn addresses(v: &Value) -> Vec<Vec<u8>> {
    use ed25519_dalek::SigningKey;
    use octra_node_protocol::transaction::address_from_public_key;
    v.as_array()
        .unwrap()
        .iter()
        .map(|id| {
            address_from_public_key(
                STANDARD
                    .encode(
                        SigningKey::from_bytes(&[id.as_u64().unwrap() as u8; 32])
                            .verifying_key()
                            .to_bytes(),
                    )
                    .as_bytes(),
            )
        })
        .collect()
}
fn writes(state: &mut StateBatch, values: &Value) {
    for v in values.as_array().unwrap() {
        let path = v["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().as_bytes())
            .collect::<Vec<_>>();
        state.set(&path, raw(&v["value"])).unwrap();
    }
}
fn fold(round: &Value, parent: Option<ParentCommit>) -> Fold {
    let m = |name: &str| {
        if round[name] == true {
            RuleMode::Active
        } else {
            RuleMode::Prior
        }
    };
    Fold {
        mode: m("duty"),
        live_mode: m("live"),
        seat_mode: m("seat"),
        open_mode: m("open"),
        standard_mode: m("standard"),
        plan_mode: m("plan"),
        vm_bytes: m("vm"),
        parent,
        cap_mode: if round["prune"] == true {
            CapMode::Prune
        } else {
            CapMode::Reject
        },
        members: addresses(&round["members"]),
        start: round["start"].as_str().unwrap().parse().unwrap(),
        profile_start: round["start"].as_str().unwrap().parse().unwrap(),
        ..Fold::prior()
    }
}
fn round(
    input: &Value,
    step: &Value,
    expected: &Value,
    state: &mut StateBatch,
    head: &mut Option<Snapshot>,
) {
    writes(state, &step["writes"]);
    if !expected["setup_pending"].is_null() {
        state
            .set(
                &[b"meta", update::PENDING_KEY],
                raw(&expected["setup_pending"]),
            )
            .unwrap();
    }
    if !step["head"].is_null() {
        let mut committed = StateBatch::default();
        committed.begin().unwrap();
        writes(&mut committed, &step["head"]["entries"]);
        if let Some(e) = step["head"]["epoch"].as_str() {
            committed
                .set(&[b"meta", b"last_epoch"], e.as_bytes().to_vec())
                .unwrap();
        }
        *head = Some(committed.snapshot());
    }
    let before = hex::encode(state.root().unwrap());
    assert_eq!(before, expected["before"]);
    let parent = (!expected["parent"].is_null())
        .then(|| ParentCommit::decode(&raw(&expected["parent"])).unwrap());
    let ctx = fold(step, parent);
    let resolver = |_: i64, _: &StateBatch| -> Result<Fold, Error> {
        if step["fold_fail"] == true {
            Err(Error("fixture anchor unavailable".into()))
        } else {
            Ok(ctx.clone())
        }
    };
    let chain = raw(&input["chain"]);
    let previous = raw(&step["previous"]);
    let legacy = addresses(&step["legacy"]);
    let policy = if input["inactive"] == true {
        Policy::Inactive
    } else {
        Policy::from_value(Some(b"64")).unwrap()
    };
    let request = Request {
        chain: &chain,
        epoch: step["epoch"].as_i64().unwrap(),
        policy: &policy,
        legacy_members: &legacy,
        previous_root: &previous,
        committed_head: head.as_ref(),
    };
    let advanced = validator_epoch::advance(&request, &resolver, state);
    let error = advanced.as_ref().err().map(ToString::to_string);
    if let Some((prefix, _)) = expected["error"]
        .as_str()
        .and_then(|e| e.split_once("Yojson__Common.Json_error("))
    {
        // Parser implementation diagnostics are not consensus bytes. Preserve
        // the native operation tag and require the Rust syntax error explicitly.
        let actual = error.as_deref().unwrap();
        let offset = actual
            .strip_prefix(&format!("{prefix}invalid native JSON at byte "))
            .unwrap();
        assert!(offset.parse::<usize>().is_ok());
    } else {
        assert_eq!(json!(error), expected["error"]);
    }
    let after = hex::encode(state.root().unwrap());
    assert_eq!(after, expected["root"]);
    if error.is_some() {
        assert_eq!(
            after, before,
            "failed advancement must restore all prior writes"
        );
    }
    for (name, key) in [
        ("duty", octra_node_protocol::validator::set_fold::META_KEY),
        ("pending", update::PENDING_KEY),
        ("active", update::ACTIVE_KEY),
    ] {
        assert_eq!(
            json!(state.get(&[b"meta", key]).map(b64)),
            expected[name],
            "{name}"
        );
    }
    let snapshot = state.snapshot();
    let roots = step["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| {
            let epoch: i64 = q.as_str().unwrap().parse().unwrap();
            let slot = (epoch % 65).to_string();
            let meta = state.get(&[b"compute", b"roots", slot.as_bytes(), b"meta"]);
            let hash = snapshot
                .hash_at(&[b"compute", b"roots", slot.as_bytes(), b"data"])
                .unwrap()
                .map(hex::encode);
            if meta.is_some() {
                let root = octra_node_runtime::compute_roots::load(state, epoch)
                    .unwrap()
                    .unwrap();
                assert!(
                    octra_node_runtime::compute_roots::recent(state, root.epoch, &root.state)
                        .is_ok()
                );
                assert!(
                    octra_node_runtime::compute_roots::recent(state, root.epoch, b"wrong").is_err()
                );
                assert!(!root.tree.contains_tree(&[b"accounts"]));
                assert!(!root.tree.contains_tree(&[b"circles", b"speculative"]));
                if root.epoch != epoch {
                    assert!(
                        octra_node_runtime::compute_roots::recent(state, epoch, &root.state)
                            .is_err()
                    );
                }
            }
            json!([meta.map(b64), hash])
        })
        .collect::<Vec<_>>();
    assert_eq!(json!(roots), expected["roots"]);
    if let Ok(advanced) = advanced {
        if let Some(update) = advanced.scheduled {
            assert_eq!(
                state.get(&[b"meta", update::PENDING_KEY]),
                Some(update.to_bytes().as_slice())
            );
        }
    }
}
#[test]
fn native_validator_epoch_advancement_and_committed_roots() {
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-epoch.json")).unwrap();
    let sources: Value =
        serde_json::from_slice(include_bytes!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixtures["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixtures["source_sha256"], sources["files"]);
    for (i, case) in fixtures["cases"].as_array().unwrap().iter().enumerate() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        // Native-encoded registry and parent QC are explicit initial inputs.
        // Their codecs and cryptographic validation have separate parity tests.
        state
            .set(
                &[b"meta", registry::META_KEY],
                raw(&case["expected"]["setup_registry"]),
            )
            .unwrap();
        let mut head = None;
        for (j, (step, expected)) in case["input"]["rounds"]
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"]["rounds"].as_array().unwrap())
            .enumerate()
        {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                round(&case["input"], step, expected, &mut state, &mut head);
            }));
            assert!(result.is_ok(), "case {i} step {j}: {step}");
        }
    }
}

#[tokio::test]
async fn scheduled_membership_and_circle_roots_survive_canonical_restart() {
    use ed25519_dalek::{Signer, SigningKey};
    use octra_exex::{ChainIdentity, CommittedEpochSource, Sequence, StateRoot};
    use octra_node_protocol::{consensus::hash, control_payload::ValidatorUpdate, epoch_index};
    use octra_node_runtime::canonical::{AppliedEpoch, CanonicalStore};
    use octra_node_runtime::validator_history::{CanonicalValidators, Environment};
    let fixtures: Value =
        serde_json::from_slice(include_bytes!("fixtures/validator-epoch.json")).unwrap();
    let case = fixtures["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["input"]["count"] == 4 && c["input"]["inactive"] == false)
        .unwrap();
    let chain_id = raw(&case["input"]["chain"]);
    let scheduled = raw(&case["expected"]["rounds"][0]["pending"]);
    let pending = ValidatorUpdate::parse(Some(&scheduled)).unwrap();
    assert_eq!(pending.activate_epoch, 64);
    let mut template =
        ParentCommit::decode(&raw(&case["expected"]["rounds"][1]["parent"])).unwrap();
    let boot = Environment {
        current: Some(
            template
                .validator_set
                .validators
                .iter()
                .map(|v| {
                    [
                        v.address.as_slice(),
                        b":",
                        STANDARD.encode(&v.pubkey).as_bytes(),
                    ]
                    .concat()
                })
                .collect::<Vec<_>>()
                .join(&b','),
        ),
        ..Environment::default()
    };
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state
        .set(
            &[b"meta", registry::META_KEY],
            raw(&case["expected"]["setup_registry"]),
        )
        .unwrap();
    state
        .set(&[b"meta", update::PENDING_KEY], scheduled.clone())
        .unwrap();
    state.set(&[b"meta", b"last_epoch"], b"0".to_vec()).unwrap();
    state
        .set(&[b"circles", b"app", b"value"], b"0".to_vec())
        .unwrap();
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let chain = ChainIdentity {
        chain_id: String::from_utf8(chain_id.clone()).unwrap(),
        genesis_root: StateRoot(root),
    };
    state.acknowledge_commit().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("validator-activation.sqlite");
    let mut store = CanonicalStore::create(&path, chain.clone(), state.snapshot(), 0)
        .await
        .unwrap();
    let policy = Policy::from_value(Some(b"64")).unwrap();
    let legacy = addresses(&json!([1, 2, 3, 4]));
    let genesis = store.head().await.unwrap();
    for epoch in 1..=66 {
        let (head, mut next) = store.snapshot().await.unwrap();
        let committed = next.snapshot();
        next.begin().unwrap();
        template.certificate.epoch_id = epoch - 1;
        template.certificate.header.epoch_id = epoch - 1;
        template.certificate.header.proposed_state_root = head.cursor.state_root.0.to_vec();
        template.certificate.proposal_id = hash::proposal_id(&template.certificate.header)
            .unwrap()
            .to_vec();
        if epoch > 64 {
            template.validator_set = pending
                .validator_set()
                .unwrap()
                .for_epoch(&chain_id, epoch - 1)
                .unwrap();
        }
        for (i, vote) in template.certificate.precommits.iter_mut().enumerate() {
            vote.epoch_id = epoch - 1;
            vote.proposal_id = template.certificate.proposal_id.clone();
            vote.signature = SigningKey::from_bytes(&[(i + 1) as u8; 32])
                .sign(&hash::vote_sign_bytes(vote).unwrap())
                .to_bytes()
                .to_vec();
        }
        let context = Fold {
            vm_bytes: RuleMode::Active,
            parent: Some(template.clone()),
            ..Fold::prior()
        };
        let resolver = |_: i64, _: &StateBatch| Ok(context.clone());
        let request = Request {
            chain: &chain_id,
            epoch,
            policy: &policy,
            legacy_members: &legacy,
            previous_root: &head.cursor.state_root.0,
            committed_head: Some(&committed),
        };
        next.set(
            &[b"circles", b"app", b"value"],
            epoch.to_string().into_bytes(),
        )
        .unwrap();
        if epoch == 64 {
            let saved = next.save().unwrap();
            next.set(&[b"meta", update::PENDING_KEY], b"{".to_vec())
                .unwrap();
            let before = next.root().unwrap();
            assert!(validator_epoch::advance(&request, &resolver, &mut next).is_err());
            assert_eq!(next.root().unwrap(), before);
            assert_eq!(store.head().await.unwrap(), head);
            assert!(store
                .source()
                .load(Sequence(epoch as u64))
                .await
                .unwrap()
                .is_none());
            // A corrupt speculative pending update cannot influence authority.
            let membership = CanonicalValidators::new(store.reader(), boot.clone());
            let selected = membership
                .expected_set(&head, epoch, None, &|_| Ok(None))
                .await
                .unwrap();
            assert_eq!(
                selected,
                pending
                    .validator_set()
                    .unwrap()
                    .for_epoch(&chain_id, epoch)
                    .unwrap()
            );
            next.restore(saved).unwrap();
        }
        let advanced = validator_epoch::advance(&request, &resolver, &mut next).unwrap();
        assert_eq!(advanced.promoted.is_some(), epoch == 64);
        let retained =
            octra_node_runtime::compute_roots::recent(&next, epoch - 1, &head.cursor.state_root.0)
                .unwrap();
        assert_eq!(
            retained.tree.get(&[b"circles", b"app", b"value"]),
            Some((epoch - 1).to_string().as_bytes())
        );
        next.set(&[b"meta", b"last_epoch"], epoch.to_string().into_bytes())
            .unwrap();
        let (_, index) = epoch_index::next_root(head.index_root.as_bytes(), epoch, &[]).unwrap();
        let expected_root = StateRoot(
            epoch_index::folded_state_root(
                hex::encode(next.root().unwrap()).as_bytes(),
                hex::encode(index).as_bytes(),
            )
            .unwrap(),
        );
        // Raw publication isolates storage/ExEx recovery here; live driver tests
        // authenticate consensus finality. No fixture certificate is authority.
        let applied = AppliedEpoch {
            epoch: epoch as u64,
            state: next.snapshot(),
            expected_root,
            transactions: vec![],
            certificate: b"trusted epoch storage fixture".to_vec(),
            date: epoch,
            message: b"validator advancement".to_vec(),
        };
        if epoch == 64 || epoch == 65 {
            drop(store.prepare(&head, applied.clone()).await.unwrap());
            assert_eq!(store.source().head().await.unwrap(), head.cursor);
            assert!(store
                .source()
                .load(Sequence(epoch as u64))
                .await
                .unwrap()
                .is_none());
        }
        let published = store
            .prepare(&head, applied)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        assert_eq!(store.source().head().await.unwrap(), published.cursor);
        assert!(store
            .source()
            .load(published.cursor.sequence)
            .await
            .unwrap()
            .unwrap()
            .events
            .is_empty());
        if epoch == 1 || epoch == 63 || epoch == 64 || epoch == 66 {
            store.close().await;
            store = CanonicalStore::open(&path, &chain).await.unwrap();
            let (recovered, tree) = store.snapshot().await.unwrap();
            assert_eq!(recovered, published);
            assert_eq!(tree.root().unwrap(), next.root().unwrap());
            assert_eq!(
                tree.get(&[b"meta", update::ACTIVE_KEY]).is_some(),
                epoch >= 64
            );
            assert!(octra_node_runtime::compute_roots::recent(
                &tree,
                epoch - 1,
                &head.cursor.state_root.0
            )
            .is_ok());
            let reader = store.reader();
            let membership = CanonicalValidators::new(reader.clone(), boot.clone());
            let selected = membership
                .expected_set(&recovered, epoch + 1, None, &|_| Ok(None))
                .await
                .unwrap();
            assert_eq!(selected.weighted, epoch >= 63);
            assert_eq!(
                membership
                    .stake_set(&recovered, epoch + 1)
                    .await
                    .unwrap()
                    .weighted,
                epoch >= 63
            );
            let original = membership
                .expected_set(&genesis, 1, None, &|_| Ok(None))
                .await
                .unwrap();
            assert!(
                !original.weighted,
                "later activation must not rewrite historical membership"
            );
            assert_eq!(reader.head_at(Sequence(0)).await.unwrap(), genesis);
            let mut forged = recovered.clone();
            forged.cursor.state_root.0[0] ^= 1;
            assert!(membership
                .config(&forged)
                .await
                .unwrap_err()
                .to_string()
                .contains("historical head differs"));
            if epoch == 66 {
                assert!(
                    octra_node_runtime::compute_roots::recent(&tree, 0, &chain.genesis_root.0)
                        .is_err()
                );
            }
        }
    }
    store.close().await;
}
