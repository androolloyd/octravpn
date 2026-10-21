//! A genuine signed native checkpoint, with pre-floor history absent. Public
//! leaves are merely hints; the imported snapshot authenticates their roots.
use super::*;
use crate::vpn::payments::shielded::index::{Index, Limits as IndexLimits, Seed};
use crate::vpn::payments::shielded::payer::{
    movement::Window,
    native::{FeePolicy, Operation},
    Incoming, Payer, Progress,
};
use crate::{bootstrap, bootstrap::export::package};
use octra_node_protocol::state_sync::{anchor, manifest};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;
#[path = "bootstrap_tests/setup.rs"]
mod setup;

async fn imported(fixture: &Fixture) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let chain = fixture.node.store.chain().clone();
    let signer = payment_host::key(7);
    let members = validators()
        .validators
        .iter()
        .map(|v| {
            format!(
                "{}:{}",
                String::from_utf8(v.address.clone()).unwrap(),
                STANDARD.encode(&v.pubkey)
            )
        })
        .collect();
    let authority = bootstrap::Authority::new(bootstrap::Network {
        identity: chain.clone(),
        config_hash: "ab".repeat(32),
        minimum_epoch: 0,
        migration_root: None,
        validators: members,
        exporters: vec![format!(
            "{}:{}",
            payment_host::address(7),
            STANDARD.encode(signer.verifying_key().as_bytes())
        )],
    })
    .unwrap();
    let head = fixture.node.snapshot().unwrap().head().clone();
    let expected_clock = fixture
        .node
        .store
        .reader()
        .epoch_time_ms(&head)
        .await
        .unwrap();
    let record = fixture
        .node
        .publisher
        .record(head.cursor.sequence)
        .await
        .unwrap();
    let finality = anchor::Anchor {
        steps: vec![],
        finalize: record.finality.unwrap().finalize,
        validator_set: validators(),
    };
    let capture = package::capture(
        &authority,
        &fixture.node.store,
        fixture.directory.path(),
        head.clone(),
        finality,
    )
    .await
    .unwrap();
    let image = directory.path().join("snapshot");
    std::fs::create_dir(&image).unwrap();
    package::prepare_capture(
        fixture.directory.path(),
        &image,
        capture,
        1024 * 1024,
        octra_node_runtime::ledger_image::Limits {
            bytes: 64 * 1024 * 1024,
            records: 1_000_000,
            string_bytes: 32 * 1024 * 1024,
        },
    )
    .unwrap();
    // Use the fixture's explicitly fixed epoch clock, with the real manifest
    // signature and original finalized QC. Production wall-clock policy stays.
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(image.join("snapshot.draft.json")).unwrap()).unwrap();
    let encoded = serde_json::to_vec(&value).unwrap();
    let document = octra_node_protocol::native_json::Document::parse(&encoded).unwrap();
    let draft = manifest::Draft::parse(&document, document.root()).unwrap();
    let signature = STANDARD.encode(signer.sign(&draft.manifest.hash().unwrap()).to_bytes());
    value["finality"] = json!(std::fs::read_to_string(image.join("snapshot.finality")).unwrap());
    value["exporter_signatures"] =
        json!([{"signer":payment_host::address(7),"signature":signature}]);
    let certificate = serde_json::to_vec(&value).unwrap();
    authority
        .trust()
        .verify(&certificate, draft.checkpoint.created_at)
        .unwrap();
    let window = std::fs::read(image.join("ready_roots")).unwrap();
    let store = CanonicalStore::create_from_checkpoint(
        &directory.path().join("node.db"),
        chain.clone(),
        fixture
            .node
            .store
            .reader()
            .snapshot_at(&head)
            .await
            .unwrap(),
        &certificate,
        &window,
        &authority.trust(),
        draft.checkpoint.created_at,
    )
    .await
    .unwrap();
    let floor = store.head().await.unwrap();
    assert_eq!(floor.cursor.sequence.0, 0);
    assert_eq!(floor.cursor.epoch, head.cursor.epoch);
    assert_eq!(floor.cursor.state_root, head.cursor.state_root);
    assert_ne!(floor.irmin_commit, head.irmin_commit);
    assert_eq!(
        store.reader().epoch_time_ms(&floor).await.unwrap(),
        expected_clock
    );
    let mut foreign_clock = floor.clone();
    foreign_clock.date += 1;
    assert!(store.reader().epoch_time_ms(&foreign_clock).await.is_err());
    assert!(store
        .reader()
        .head_for_epoch(head.cursor.epoch.0 - 1)
        .await
        .is_err());
    store.close().await;
    let store = CanonicalStore::open_from_checkpoint(
        &directory.path().join("node.db"),
        &chain,
        &authority.trust(),
    )
    .await
    .unwrap();
    assert_eq!(
        store.reader().epoch_time_ms(&floor).await.unwrap(),
        expected_clock
    );

    let genesis = fixture.node.store.reader().head_for_epoch(0).await.unwrap();
    let genesis_state = fixture
        .node
        .store
        .reader()
        .snapshot_at(&genesis)
        .await
        .unwrap();
    let profile = fixture.graph.application_fixture().unwrap();
    let proof = STANDARD.encode(
        genesis_state
            .read_proof(&[b"meta", profile.metadata_key()], false)
            .unwrap(),
    );
    let graph = fixture
        .graph
        .clone()
        .with_application_opt_in_proof(
            genesis.ledger_root.as_bytes(),
            genesis.index_root.as_bytes(),
            proof.as_bytes(),
        )
        .unwrap();
    assert!(fixture
        .graph
        .clone()
        .with_application_opt_in_proof(b"bad", genesis.index_root.as_bytes(), proof.as_bytes())
        .is_err());
    assert!(fixture
        .graph
        .clone()
        .with_application_opt_in_proof(
            genesis.ledger_root.as_bytes(),
            genesis.index_root.as_bytes(),
            b"broken"
        )
        .is_err());
    let node = Arc::new(
        Node::open(
            store,
            Authority { chain },
            circle_host::runtime(),
            Arc::new(UnavailableHost),
            Arc::new(
                SqliteCheckpoints::open(&directory.path().join("exex.db"))
                    .await
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .with_view_graph(graph.clone())
        .unwrap(),
    );
    let native = Fixture::executor(&node, graph.clone(), fixture.protocol, directory.path());
    Fixture {
        node,
        native,
        graph,
        protocol: fixture.protocol,
        domain: fixture.domain.clone(),
        tariff: fixture.tariff.clone(),
        now: fixture.now,
        factory: fixture.factory.clone(),
        program: fixture.program.clone(),
        application: fixture.application,
        payment_code: fixture.payment_code.clone(),
        factory_code: fixture.factory_code.clone(),
        directory,
    }
}

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    config: shielded::Config,
    pk: Arc<ProvingKey<Bn254>>,
    recovery: super::index_flow::Recovery,
) {
    let source_path = fixture.directory.path().join("bootstrap-seed-source");
    let temporary = Index::create(
        &fixture.directory.path().join("seed-export-index"),
        Key::from_bytes([182; 32]),
        source.clone(),
        IndexLimits::default(),
    )
    .await
    .unwrap();
    for _ in 0..16 {
        if temporary.sync(128).await.unwrap().complete {
            break;
        }
    }
    let view = temporary.view().await.unwrap();
    assert_eq!(view.index().roots(), recovery.index.roots());
    let original_seed = view.seed().unwrap();
    temporary.close().await;
    let before = Index::bootstrap(
        &source_path,
        Key::from_bytes([181; 32]),
        source.clone(),
        &original_seed,
        IndexLimits::default(),
    )
    .await
    .unwrap();
    let seed = before.view().await.unwrap().seed().unwrap();
    let wire = seed.encode().unwrap();
    assert!(Seed::decode(&wire[..wire.len() - 1], IndexLimits::default()).is_err());
    assert!(Seed::decode(
        &wire,
        IndexLimits {
            max_notes: 1,
            max_updates: 1
        }
    )
    .is_err());
    before.close().await;
    let legacy_path = fixture.directory.path().join("canonical-private-index");
    let rebased = Index::reanchor(
        &legacy_path,
        Key::from_bytes([171; 32]),
        source.clone(),
        &seed,
    )
    .await
    .unwrap();
    assert_eq!(rebased.sync(1).await.unwrap().updates, recovery.updates);
    rebased.close().await;

    // Give the checkpoint an old owned note which can be spent using only the
    // authenticated imported tree, without reading its missing creation epoch.
    let payer_path = fixture.directory.path().join("checkpoint-payer");
    let payer = Payer::create(&payer_path, Key::from_bytes([191; 32]), source.clone())
        .await
        .unwrap();
    let recipient = payer.address().await.unwrap();
    let draft = envelope::Draft::new(
        pool::decode_field(&recipient.owner).unwrap(),
        4,
        &recipient.view_public,
    )
    .unwrap();
    let call = Call {
        quote: [0; 32],
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        payout: address(&payment_host::address(12)),
        deposit_ou: 4,
        withdraw_ou: 0,
        boxes: [draft.ciphertext.clone(), String::new()],
    };
    let context = call
        .context(
            &source.origin(),
            &address(source.circle()),
            &address(&payment_host::address(12)),
        )
        .unwrap();
    let note = draft.bind(&context);
    let old_index = Index::resume(&source_path, Key::from_bytes([181; 32]), source.clone())
        .await
        .unwrap();
    let current = old_index.view().await.unwrap();
    let position: u32 = current.index().roots().2.try_into().unwrap();
    let (deposit, _) = current
        .index()
        .prepare(
            source.domain(),
            &[],
            std::slice::from_ref(&note),
            4,
            0,
            context,
        )
        .unwrap();
    call_pool(
        fixture,
        source.circle(),
        12,
        "exchange",
        args(&deposit, &call, &proof(&deposit, &pk)),
        4,
    )
    .await;
    let creation_epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0;
    fixture.publish(vec![]).await;
    old_index.sync(128).await.unwrap();
    let view = old_index.view().await.unwrap();
    let membership = view.index().membership(position).unwrap();
    assert!(payer
        .receive(Incoming {
            slot: recipient.slot,
            epoch: creation_epoch,
            commitment: pool::encode_field(note.commitment(source.domain())),
            membership: &membership,
            output: 0,
            call: &call,
            relayer: address(&payment_host::address(12)),
        })
        .await
        .unwrap());
    assert_eq!(payer.available_ou(view.index()).await.unwrap(), 4);
    let pending = Box::pin(super::recovery_flow::prepare(
        fixture,
        source.clone(),
        config.clone(),
        pk.clone(),
        &payer,
        &old_index,
    ))
    .await;
    let view = old_index.view().await.unwrap();
    let seed = view.seed().unwrap();
    let expected = view.index().roots();
    drop(payer);
    old_index.close().await;
    let mut restored = Box::pin(imported(fixture)).await;
    assert!(restored
        .node
        .store
        .reader()
        .head_for_epoch(creation_epoch)
        .await
        .is_err());
    let target = Arc::new(Pool::new(Arc::new(restored.payments()), config.clone()).unwrap());
    let (offline_path, offline_key) = Box::pin(setup::run(
        &restored,
        source.clone(),
        target.clone(),
        config.clone(),
        &seed,
    ))
    .await;
    assert!(restored.node.resume().await.unwrap());
    let offline = Index::resume(&offline_path, offline_key, target.clone())
        .await
        .unwrap();
    assert_eq!(offline.view().await.unwrap().index().roots(), expected);
    offline.close().await;
    let target_path = restored.directory.path().join("public-tree");
    assert!(Index::create(
        &restored.directory.path().join("no-baseline"),
        Key::from_bytes([184; 32]),
        target.clone(),
        IndexLimits::default()
    )
    .await
    .is_err());
    for at in [8, 48, 96] {
        let mut bad = seed.encode().unwrap();
        bad[at] ^= 1;
        let bad = Seed::decode(&bad, IndexLimits::default()).unwrap();
        let path = restored.directory.path().join(format!("bad-{at}"));
        assert!(Index::bootstrap(
            &path,
            Key::from_bytes([184; 32]),
            target.clone(),
            &bad,
            IndexLimits::default()
        )
        .await
        .is_err());
        assert!(!path.exists());
    }
    let public = Index::bootstrap(
        &target_path,
        Key::from_bytes([185; 32]),
        target.clone(),
        &seed,
        IndexLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(public.view().await.unwrap().index().roots(), expected);
    public.close().await;
    let public = Index::resume(&target_path, Key::from_bytes([185; 32]), target.clone())
        .await
        .unwrap();
    let payer = Payer::resume(&payer_path, Key::from_bytes([191; 32]), target.clone())
        .await
        .unwrap();
    let index = public.view().await.unwrap();
    assert!(payer.available_ou(&PoolIndex::default()).await.is_err());
    restored.node.suspend("payer checkpoint source lost sync");
    assert!(payer.available_ou(index.index()).await.is_err());
    assert!(restored.node.resume().await.unwrap());
    assert_eq!(payer.available_ou(index.index()).await.unwrap(), 0);
    Box::pin(super::recovery_flow::resume(
        &restored,
        fixture.directory.path(),
        config.clone(),
        &payer,
        index.index(),
        &pending,
    ))
    .await;
    assert_eq!(payer.available_ou(index.index()).await.unwrap(), 3);
    // The recovered financial journal reserves the existing note, proves and
    // signs locally. It cannot treat current membership as a new receipt.
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let window = Window {
        valid_from_ms: millis(&restored),
        expires_ms: millis(&restored) + 120_000,
        relayer: address(&payment_host::address(11)),
    };
    let id = [192; 32];
    let prepared = payer
        .prepare_withdrawal(
            id,
            3,
            address(&payment_host::address(13)),
            window,
            index.index(),
            &prover,
        )
        .await
        .unwrap();
    let next = index
        .index()
        .observe(&prepared.statement().unwrap())
        .unwrap();
    let operation = Operation::Movement(id);
    let policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 2 * payment_host::FEE,
        max_attempts: 2,
    };
    let signed = payer
        .sign_native(operation, index.index(), &payment_host::key(11), policy)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(index.index()).await.unwrap(), 0);
    drop(payer);
    let payer = Payer::resume(&payer_path, Key::from_bytes([191; 32]), target.clone())
        .await
        .unwrap();
    assert_eq!(payer.available_ou(index.index()).await.unwrap(), 0);
    assert_eq!(
        payer
            .sign_native(operation, index.index(), &payment_host::key(11), policy)
            .await
            .unwrap()
            .transaction(),
        signed.transaction()
    );
    let rpc = super::super::rpc_admission::Rpc::open(&restored, restored.native.clone()).await;
    payer
        .broadcast(&rpc.submission, &signed, index.index())
        .await
        .unwrap();
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    restored.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    public.sync(128).await.unwrap();
    assert_eq!(public.view().await.unwrap().index().roots(), next.roots());
    assert!(payer
        .reconcile_native(&signed, &next)
        .await
        .unwrap()
        .is_some());
    assert!(matches!(
        payer.movement_progress(id).await.unwrap(),
        Progress::Paid
    ));
    assert_eq!(payer.available_ou(&next).await.unwrap(), 0);
    drop(payer);
    let payer = Payer::resume(&payer_path, Key::from_bytes([191; 32]), target.clone())
        .await
        .unwrap();
    assert!(matches!(
        payer.movement_progress(id).await.unwrap(),
        Progress::Paid
    ));
    assert_eq!(payer.available_ou(&next).await.unwrap(), 0);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
    Box::pin(super::recovery_flow::extend(
        &restored,
        fixture.directory.path(),
        config.clone(),
        &payer,
        &pending,
    ))
    .await;
    drop(payer);
    public.close().await;
    let reopened = Index::resume(&target_path, Key::from_bytes([185; 32]), target.clone())
        .await
        .unwrap();
    assert_eq!(reopened.view().await.unwrap().index().roots(), next.roots());
    let latest_seed = reopened.view().await.unwrap().seed().unwrap();
    assert_eq!(reopened.sync(1).await.unwrap().updates, 1);
    reopened.close().await;
    // Seed rows are part of the encrypted recovery journal, rather than a
    // best-effort cache. Only an explicit authenticated reanchor repairs loss.
    let edit = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(target_path.join("wallet.sqlite"))
                .create_if_missing(false),
        )
        .await
        .unwrap();
    assert_eq!(sqlx::query("DELETE FROM wallet_records WHERE kind=2 AND tag=(SELECT tag FROM wallet_records WHERE kind=2 LIMIT 1)")
        .execute(&edit).await.unwrap().rows_affected(), 1);
    edit.close().await;
    assert!(
        Index::resume(&target_path, Key::from_bytes([185; 32]), target.clone())
            .await
            .is_err()
    );
    assert!(Index::reanchor(
        &target_path,
        Key::from_bytes([185; 32]),
        target.clone(),
        &seed
    )
    .await
    .is_err());
    let repaired = Index::reanchor(
        &target_path,
        Key::from_bytes([185; 32]),
        target.clone(),
        &latest_seed,
    )
    .await
    .unwrap();
    assert_eq!(repaired.sync(1).await.unwrap().updates, 1);
    assert_eq!(repaired.view().await.unwrap().index().roots(), next.roots());
    repaired.close().await;
    Box::pin(super::income_floor_flow::run(
        &mut restored,
        fixture.directory.path(),
        target,
        config,
        pk,
        next,
    ))
    .await;
    restored.node.shutdown().await.unwrap();
}
