use super::*;
use octra_node::executor::Pending;
use octra_node_protocol::{consensus::policy::Protocol, rules::Graph, transaction_policy::Profile};
use octra_node_runtime::{
    staging::{intake, DropRecord, Pool},
    state_batch::Snapshot,
};

/// Actual signature/payload/nonce/fee intake. These fixtures contain only public
/// operations, which require no cryptographic preverification worker.
pub(super) fn admitted(state: &Snapshot, txs: &[Transaction]) -> Arc<Pending> {
    struct Public;
    impl intake::Host for Public {
        fn preverify(&mut self, tx: &Transaction, _: &Pool) -> std::result::Result<(), String> {
            assert!(matches!(
                tx.op_type,
                OpType::Standard | OpType::CircleCall | OpType::ValidatorExit
            ));
            Ok(())
        }
        fn save_drops(&mut self, drops: &[DropRecord]) {
            assert!(drops.is_empty());
        }
        fn invalidate(&mut self, _: &[u8]) {
            panic!("unexpected invalidation");
        }
        fn changed(&mut self, _: &Pool) {}
        fn accepted(&mut self, _: &Transaction, _: &Pool) {}
    }
    let ledger = account_store::ledger(&StateBatch::from_snapshot(state.clone())).unwrap();
    let mut pool = Pool::default();
    let rules = intake::Rules {
        bft: true,
        profile: Profile {
            admit_ops: b"circle_call".to_vec(),
            ..Default::default()
        },
        compute: RuleMode::Active,
        settle: RuleMode::Active,
        proof: RuleMode::Active,
        duty: Some((0, RuleMode::Active)),
        queue_head: Some(0),
        stealth_minimum: 5000.into(),
    };
    let rpc = intake::Rpc {
        now: 10.,
        max_drift: 100.,
        observer: false,
        preverify_capacity: true,
        preverify_pending: Nonce::default(),
        preverify_maximum: Nonce::new(1000).unwrap(),
        nonce_window: Nonce::new(1000).unwrap(),
    };
    for tx in txs {
        intake::submit(&mut pool, tx, &ledger, &rules, &rpc, &mut Public, &|| 10.).unwrap();
    }
    Arc::new(Pending::new(pool))
}
fn signed(mut tx: Transaction, id: u8) -> Transaction {
    let key = SigningKey::from_bytes(&[id; 32]);
    let public = STANDARD.encode(key.verifying_key().to_bytes()).into_bytes();
    tx.from = transaction::address_from_public_key(&public);
    tx.public_key = Some(public);
    tx.signature = STANDARD
        .encode(key.sign(&tx.signing_bytes().unwrap()).to_bytes())
        .into_bytes();
    tx
}

#[tokio::test]
async fn pending_fee_order_recovery_and_stale_queue_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let circle = format!("oct{}", "1".repeat(44));
    let mut state = genesis(circle.as_bytes());
    let public = STANDARD
        .encode(SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes())
        .into_bytes();
    account_store::set(
        &mut state,
        &transaction::address_from_public_key(&public),
        &Account {
            balance: 10000.into(),
            public_key: Some(public),
            ..Default::default()
        },
        RuleMode::Active,
    )
    .unwrap();
    state
        .set(&[b"meta", b"total_supply"], b"20000".to_vec())
        .unwrap();
    let chain = ChainIdentity {
        chain_id: "pending-build-fixture".into(),
        genesis_root: StateRoot(finality_host::root(None, &state, &[])),
    };
    let authority = finality_host::Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let db = dir.path().join("node.db");
    drop(
        CanonicalStore::create(&db, chain.clone(), state.snapshot(), 0)
            .await
            .unwrap(),
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("exex.db"))
            .await
            .unwrap(),
    );
    let node = open(&db, checkpoints, chain.clone(), Arc::default()).await;
    node.resume().await.unwrap();
    let protocol = Protocol::new(2).unwrap();
    let graph = Graph::new(chain.chain_id.as_bytes().to_vec(), None);
    let policy = octra_node_runtime::finality::proposal::Policy {
        protocol,
        genesis_time: Some(0.),
    };
    let draft = Arc::new(
        node.proposal_draft(&graph, policy, b"validator-0", 10.)
            .await
            .unwrap(),
    );
    let executor = ImportExecutor::with_protocol(&authority, &node, protocol).native;
    let mut transfer = circle_call(1, circle.as_bytes());
    transfer.op_type = OpType::Standard;
    transfer.message = None;
    transfer.encrypted_data = None;
    let mut txs = [signed(transfer.clone(), 42), signed(transfer, 43)];
    txs.sort_by(|a, b| a.from.cmp(&b.from));
    txs[1].ou = 5000.into();
    let signer = if txs[1].from == circle_call(1, circle.as_bytes()).from {
        42
    } else {
        43
    };
    txs[1] = signed(txs[1].clone(), signer);
    let pending = admitted(draft.state(), &txs);
    let capped = executor
        .build_pending(draft.clone(), pending.clone(), 1000.into(), 4)
        .await
        .unwrap();
    assert_eq!(
        capped.bundle().tx_hashes,
        vec![hex::encode(txs[1].hash().unwrap()).into_bytes()]
    );
    let all = executor
        .build_pending(draft.clone(), pending.clone(), 2000.into(), 4)
        .await
        .unwrap();
    let canonical = executor
        .build_proposal(draft.clone(), txs.to_vec())
        .await
        .unwrap();
    assert_eq!(all.plan().header, canonical.plan().header);
    assert_eq!(all.bundle(), canonical.bundle());
    assert_eq!(
        all.execution().state.root().unwrap(),
        canonical.execution().state.root().unwrap()
    );
    assert_eq!(pending.transactions().unwrap(), txs);

    let mut failed = circle_call(1, circle.as_bytes());
    failed.encrypted_data = Some(b"missing_method".to_vec());
    failed = signed(failed, 42);
    let mut successor = circle_call(2, circle.as_bytes());
    successor = signed(successor, 42);
    let other = txs
        .iter()
        .find(|tx| tx.from != failed.from)
        .unwrap()
        .clone();
    let queue = admitted(
        draft.state(),
        &[failed.clone(), successor.clone(), other.clone()],
    );
    let recovered = executor
        .build_pending(draft.clone(), queue.clone(), 100_000.into(), 4)
        .await
        .unwrap();
    assert_eq!(recovered.refused(), &[failed]);
    assert!(recovered.held().is_empty());
    assert_eq!(
        recovered.bundle().tx_hashes,
        vec![hex::encode(other.hash().unwrap()).into_bytes()]
    );
    let retained = queue.transactions().unwrap();
    assert_eq!(retained.len(), 2);
    assert!(retained.contains(&successor) && retained.contains(&other));
    // Canonical suspension and resume never revive a draft or permit its queue
    // effects to remove work from the new view.
    node.suspend("pending freshness regression");
    node.resume().await.unwrap();
    assert!(executor
        .build_pending(draft, queue.clone(), 100_000.into(), 4)
        .await
        .is_err());
    assert_eq!(queue.transactions().unwrap(), retained);
    node.shutdown().await.unwrap();
}
