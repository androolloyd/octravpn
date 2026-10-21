//! Native intake, durable fee/nonce recovery, real private consolidation and
//! partial/full withdrawal with native custody and signed canonical epochs.
use super::*;
use crate::vpn::payments::shielded::payer::{
    movement::{Prepared, Window},
    native::{FeePolicy, Operation},
    Payer, Progress,
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;

fn account(fixture: &Fixture, who: u8) -> Account {
    account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        payment_host::address(who).as_bytes(),
    )
    .unwrap()
    .unwrap()
}
fn window(fixture: &Fixture) -> Window {
    Window {
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        relayer: address(&payment_host::address(11)),
    }
}
async fn execute(
    fixture: &mut Fixture,
    source: &Arc<Pool>,
    pk: &Arc<ProvingKey<Bn254>>,
    payer: Payer,
    index: PoolIndex,
    prepared: &Prepared,
    policy: FeePolicy,
    restart: bool,
) -> (Payer, PoolIndex) {
    let operation = Operation::Movement(prepared.id);
    let signed = payer
        .sign_native(operation, &index, &payment_host::key(11), policy)
        .await
        .unwrap();
    let reserved = payer
        .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
        .await
        .unwrap();
    let again = payer
        .sign_native(operation, &index, &payment_host::key(11), policy)
        .await
        .unwrap();
    assert_eq!(signed.transaction(), again.transaction());
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        reserved
    );
    let payer = if restart {
        drop(payer);
        let reopened = Payer::resume(
            &fixture.directory.path().join("private-payer"),
            Key::from_bytes([86; 32]),
            source.clone(),
        )
        .await
        .unwrap();
        let recovered = reopened
            .sign_native(operation, &index, &payment_host::key(11), policy)
            .await
            .unwrap();
        assert_eq!(recovered.transaction(), signed.transaction());
        reopened
    } else {
        payer
    };
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    let mut next = index.observe(&prepared.statement().unwrap()).unwrap();
    let output = prepared.output_slot().map(|_| {
        next.membership(prepared.first_output_index().unwrap())
            .unwrap()
    });
    assert!(payer
        .complete_movement(prepared.id, &index, epoch, output.as_ref())
        .await
        .is_err());
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    let before = fixture.node.snapshot().unwrap().head().clone();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    payer
        .broadcast(&rpc.submission, &signed, &index)
        .await
        .unwrap();
    let _ = payer.broadcast(&rpc.submission, &signed, &index).await;
    assert_eq!(
        rpc.pending.transactions().unwrap(),
        vec![signed.transaction().clone()]
    );
    assert_eq!(fixture.node.snapshot().unwrap().head(), &before);
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    assert_eq!(payer.confirmed_native(&signed).await.unwrap(), Some(epoch));
    if restart {
        let stranger = Payer::create(
            &fixture
                .directory
                .path()
                .join(format!("late-append-{}", prepared.id[0])),
            Key::from_bytes([89; 32]),
            source.clone(),
        )
        .await
        .unwrap();
        (next, _) = super::payer_flow::deposit(fixture, source, pk, next, &stranger, 1).await;
    }
    assert!(payer
        .complete_movement(prepared.id, &next, epoch - 1, output.as_ref())
        .await
        .is_err());
    assert!(payer
        .sign_native(operation, &next, &payment_host::key(11), policy)
        .await
        .is_err());
    assert_eq!(
        payer.reconcile_native(&signed, &next).await.unwrap(),
        Some(epoch)
    );
    assert_eq!(
        payer.reconcile_native(&signed, &next).await.unwrap(),
        Some(epoch)
    );
    assert!(matches!(
        payer.movement_progress(prepared.id).await.unwrap(),
        Progress::Paid
    ));
    assert!(payer
        .cancel_movement(prepared.id, &next, false)
        .await
        .is_err());
    (payer, next)
}

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    pk: Arc<ProvingKey<Bn254>>,
    mut index: PoolIndex,
) -> PoolIndex {
    let key = Key::from_bytes([86; 32]);
    let mut payer = Payer::resume(
        &fixture.directory.path().join("private-payer"),
        key.clone(),
        source.clone(),
    )
    .await
    .unwrap();
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 4 * payment_host::FEE,
        max_attempts: 4,
    };
    let notes = payer.available_notes(&index).await.unwrap();
    assert_eq!(notes.len(), 2);
    assert!(notes.iter().all(|n| n.value_ou == 1));
    assert!(payer.available_notes(&PoolIndex::default()).await.is_err());
    let ids = [notes[0].commitment, notes[1].commitment];
    assert!(payer
        .consolidate([50; 32], [ids[0], ids[0]], window(fixture), &index, &prover)
        .await
        .is_err());
    let consolidated = payer
        .consolidate([50; 32], ids, window(fixture), &index, &prover)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 0);
    assert!(payer
        .prepare_withdrawal(
            [50; 32],
            1,
            address(&payment_host::address(13)),
            window(fixture),
            &index,
            &prover
        )
        .await
        .is_err());
    assert!(payer
        .cancel_movement([50; 32], &index, false)
        .await
        .is_err());
    assert!(payer
        .sign_native(
            Operation::Movement([50; 32]),
            &index,
            &payment_host::key(12),
            policy
        )
        .await
        .is_err());
    (payer, index) = Box::pin(execute(
        fixture,
        &source,
        &pk,
        payer,
        index,
        &consolidated,
        policy,
        true,
    ))
    .await;
    assert_eq!(payer.available_ou(&index).await.unwrap(), 2);
    assert_eq!(payer.available_notes(&index).await.unwrap().len(), 1);
    let before = account(fixture, 13).balance;
    let partial = payer
        .prepare_withdrawal(
            [51; 32],
            1,
            address(&payment_host::address(13)),
            window(fixture),
            &index,
            &prover,
        )
        .await
        .unwrap();
    assert!(partial.output_slot().is_some());
    (payer, index) = Box::pin(execute(
        fixture, &source, &pk, payer, index, &partial, policy, false,
    ))
    .await;
    assert_eq!(account(fixture, 13).balance, before + 1);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 1);
    let before = account(fixture, 13).balance;
    let count = index.roots().2;
    let full = payer
        .prepare_withdrawal(
            [52; 32],
            1,
            address(&payment_host::address(13)),
            window(fixture),
            &index,
            &prover,
        )
        .await
        .unwrap();
    assert!(full.output_slot().is_none());
    assert_eq!(full.outputs(), [[0; 32]; 2]);
    (payer, index) = Box::pin(execute(
        fixture, &source, &pk, payer, index, &full, policy, true,
    ))
    .await;
    assert_eq!(
        index.roots().2,
        count + 1,
        "only the later append may advance the count; full withdrawal creates no dust note"
    );
    assert_eq!(account(fixture, 13).balance, before + 1);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 0);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        4 * payment_host::FEE
    );
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &payer, 1).await;
    index = next;
    let final_window = window(fixture);
    let limited = payer
        .prepare_withdrawal(
            [53; 32],
            1,
            address(&payment_host::address(13)),
            final_window,
            &index,
            &prover,
        )
        .await
        .unwrap();
    assert!(payer
        .sign_native(
            Operation::Movement(limited.id),
            &index,
            &payment_host::key(11),
            policy
        )
        .await
        .is_err());
    let altered = FeePolicy {
        lifetime_budget_ou: 5 * payment_host::FEE,
        ..policy
    };
    assert!(payer
        .sign_native(
            Operation::Movement(limited.id),
            &index,
            &payment_host::key(11),
            altered
        )
        .await
        .is_err());
    assert!(payer
        .cancel_movement(limited.id, &index, false)
        .await
        .is_err());
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &payer, 1).await;
    index = next;
    payer
        .cancel_movement(limited.id, &index, false)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 2);
    drop(payer);
    let payer = Payer::resume(&fixture.directory.path().join("private-payer"), key, source)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 2);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        4 * payment_host::FEE
    );
    index
}
