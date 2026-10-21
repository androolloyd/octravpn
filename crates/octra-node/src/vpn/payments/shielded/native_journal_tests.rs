//! Real post-16 native execution, original inline-journal migration, nonce
//! contention and stale-proof refusal. No local counter stands in for finality.
use super::*;
use crate::vpn::payments::shielded::payer::{
    movement::{Prepared, Window},
    native::{self, FeePolicy, Operation, SignedAttempt},
    Payer,
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;

fn window(fixture: &Fixture) -> Window {
    Window {
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        relayer: address(&payment_host::address(14)),
    }
}
async fn commit(
    fixture: &mut Fixture,
    payer: &Payer,
    index: PoolIndex,
    prepared: &Prepared,
    policy: FeePolicy,
) -> (PoolIndex, SignedAttempt) {
    let signed = payer
        .sign_native(
            Operation::Movement(prepared.id),
            &index,
            &payment_host::key(14),
            policy,
        )
        .await
        .unwrap();
    let before = fixture.node.snapshot().unwrap().head().clone();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    payer
        .broadcast(&rpc.submission, &signed, &index)
        .await
        .unwrap();
    assert_eq!(fixture.node.snapshot().unwrap().head(), &before);
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    let next = index.observe(&prepared.statement().unwrap()).unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    assert!(payer
        .reconcile_native(&signed, &next)
        .await
        .unwrap()
        .is_some());
    (next, signed)
}
pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    pk: Arc<ProvingKey<Bn254>>,
    mut index: PoolIndex,
) -> PoolIndex {
    let path = fixture.directory.path().join("private-payer");
    let key = Key::from_bytes([86; 32]);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let public11 = payment_host::key(11).verifying_key().to_bytes();
    let original = payer.native_attempt(&public11, 1).await.unwrap();
    native::journal_tests::legacy(&payer, &public11).await;
    drop(payer);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    // Authentic v1 migration preserves every signature and already-reserved
    // fee; it must not enlarge the caller's original four-attempt policy.
    assert_eq!(
        payer.reserved_fees(&public11).await.unwrap(),
        4 * payment_host::FEE
    );
    let migrated = payer.native_attempt(&public11, 1).await.unwrap();
    assert_eq!(migrated.transaction(), original.transaction());
    assert_eq!(
        payer.confirmed_native(&migrated).await.unwrap(),
        payer.confirmed_native(&original).await.unwrap()
    );
    native::journal_tests::record_failure_is_closed(&payer, &public11).await;
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &payer, 18).await;
    index = next;
    let public14 = payment_host::key(14).verifying_key().to_bytes();
    let policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 18 * payment_host::FEE,
        max_attempts: 32,
    };
    let payout = address(&payment_host::address(13));
    let balance_before = account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        &payout,
    )
    .unwrap()
    .unwrap()
    .balance;
    let mut first = None;
    for number in 0_u8..17 {
        let prepared = payer
            .prepare_withdrawal(
                [100 + number; 32],
                1,
                payout,
                window(fixture),
                &index,
                &prover,
            )
            .await
            .unwrap();
        let (next, signed) = Box::pin(commit(fixture, &payer, index, &prepared, policy)).await;
        index = next;
        assert_eq!(signed.sequence(), u32::from(number) + 1);
        if number == 0 {
            first = Some(signed);
        }
    }
    assert_eq!(payer.available_ou(&index).await.unwrap(), 3);
    assert_eq!(
        payer.reserved_fees(&public14).await.unwrap(),
        17 * payment_host::FEE
    );
    let first = first.unwrap();
    drop(payer);
    let payer = Payer::resume(&path, key, source.clone()).await.unwrap();
    assert_eq!(
        payer
            .native_attempt(&public14, 1)
            .await
            .unwrap()
            .transaction(),
        first.transaction()
    );
    let seventeenth = payer.native_attempt(&public14, 17).await.unwrap();
    assert_eq!(
        seventeenth.transaction().nonce.get(),
        first.transaction().nonce.get() + 16
    );
    assert!(payer
        .confirmed_native(&seventeenth)
        .await
        .unwrap()
        .is_some());
    native::journal_tests::record_failure_is_closed(&payer, &public14).await;
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &payer, 1).await;
    index = next;
    let w = window(fixture);
    let a = payer
        .prepare_withdrawal([120; 32], 1, payout, w, &index, &prover)
        .await
        .unwrap();
    let b = payer
        .prepare_withdrawal([121; 32], 1, payout, w, &index, &prover)
        .await
        .unwrap();
    let active = payer
        .sign_native(
            Operation::Movement(a.id),
            &index,
            &payment_host::key(14),
            policy,
        )
        .await
        .unwrap();
    let busy = payer
        .sign_native(
            Operation::Movement(b.id),
            &index,
            &payment_host::key(14),
            policy,
        )
        .await
        .err()
        .unwrap();
    assert!(busy.to_string().contains("unresolved"), "{busy}");
    assert_eq!(
        payer.reserved_fees(&public14).await.unwrap(),
        18 * payment_host::FEE
    );
    let (next, signed) = Box::pin(commit(fixture, &payer, index, &a, policy)).await;
    index = next;
    assert_eq!(signed.transaction(), active.transaction());
    let stale = payer
        .sign_native(
            Operation::Movement(b.id),
            &index,
            &payment_host::key(14),
            policy,
        )
        .await
        .err()
        .unwrap();
    assert!(stale.to_string().contains("rebase"), "{stale}");
    payer.cancel_movement(b.id, &index, false).await.unwrap();
    let limited = payer
        .prepare_withdrawal([122; 32], 1, payout, window(fixture), &index, &prover)
        .await
        .unwrap();
    assert!(payer
        .sign_native(
            Operation::Movement(limited.id),
            &index,
            &payment_host::key(14),
            policy
        )
        .await
        .is_err());
    let stranger = Payer::create(
        &fixture.directory.path().join("native-journal-invalidation"),
        Key::from_bytes([88; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &stranger, 1).await;
    index = next;
    payer
        .cancel_movement(limited.id, &index, false)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 3);
    let balance_after = account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        &payout,
    )
    .unwrap()
    .unwrap()
    .balance;
    assert_eq!(balance_after, balance_before + 18);
    assert_eq!(
        payer.reserved_fees(&public14).await.unwrap(),
        18 * payment_host::FEE
    );
    assert_eq!(
        payer.reserved_fees(&public11).await.unwrap(),
        4 * payment_host::FEE
    );
    // A signed attempt from an earlier process has aged out of native intake.
    // The test rewrites only its timestamp/signature using the same fixed local
    // key; no production clock override or fabricated canonical record exists.
    let public13 = payment_host::key(13).verifying_key().to_bytes();
    let retry_policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 3 * payment_host::FEE,
        max_attempts: 32,
    };
    let retry_window = Window {
        relayer: address(&payment_host::address(13)),
        ..window(fixture)
    };
    let retry = payer
        .prepare_withdrawal([123; 32], 1, payout, retry_window, &index, &prover)
        .await
        .unwrap();
    let op = Operation::Movement(retry.id);
    let _ = payer
        .sign_native(op, &index, &payment_host::key(13), retry_policy)
        .await
        .unwrap();
    let expired = native::journal_tests::expire_last(&payer, &payment_host::key(13)).await;
    let same_head = payer
        .sign_native(op, &index, &payment_host::key(13), retry_policy)
        .await
        .err()
        .unwrap();
    assert!(
        same_head.to_string().contains("canonical head"),
        "{same_head}"
    );
    assert_eq!(
        payer.reserved_fees(&public13).await.unwrap(),
        payment_host::FEE
    );
    fixture.publish(vec![]).await;
    let replacement = payer
        .sign_native(op, &index, &payment_host::key(13), retry_policy)
        .await
        .unwrap();
    assert_eq!(replacement.sequence(), 2);
    assert_eq!(replacement.transaction().nonce, expired.transaction().nonce);
    assert_ne!(replacement.transaction(), expired.transaction());
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    assert!(rpc
        .submission
        .submit_native(expired.transaction().clone())
        .await
        .is_err());
    assert!(rpc.pending.transactions().unwrap().is_empty());
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &stranger, 1).await;
    index = next;
    let stale_broadcast = payer
        .broadcast(&rpc.submission, &replacement, &index)
        .await
        .err()
        .unwrap();
    assert!(
        stale_broadcast.to_string().contains("rebase"),
        "{stale_broadcast}"
    );
    assert!(rpc.pending.transactions().unwrap().is_empty());
    let rebased = payer
        .prepare_withdrawal([123; 32], 1, payout, retry_window, &index, &prover)
        .await
        .unwrap();
    assert_eq!(rebased.output_slot(), retry.output_slot());
    let still_live = payer
        .sign_native(op, &index, &payment_host::key(13), retry_policy)
        .await
        .err()
        .unwrap();
    assert!(
        still_live.to_string().contains("unresolved"),
        "{still_live}"
    );
    let expired_second = native::journal_tests::expire_last(&payer, &payment_host::key(13)).await;
    let replacement = payer
        .sign_native(op, &index, &payment_host::key(13), retry_policy)
        .await
        .unwrap();
    assert_eq!(replacement.sequence(), 3);
    assert_eq!(
        replacement.transaction().nonce,
        expired_second.transaction().nonce
    );
    assert!(rpc
        .submission
        .submit_native(expired_second.transaction().clone())
        .await
        .is_err());
    payer
        .broadcast(&rpc.submission, &replacement, &index)
        .await
        .unwrap();
    let next = index.observe(&rebased.statement().unwrap()).unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    assert!(payer
        .reconcile_native(&replacement, &next)
        .await
        .unwrap()
        .is_some());
    assert!(payer.confirmed_native(&expired).await.unwrap().is_none());
    assert!(payer
        .confirmed_native(&expired_second)
        .await
        .unwrap()
        .is_none());
    assert_eq!(payer.available_ou(&next).await.unwrap(), 2);
    assert_eq!(
        payer.reserved_fees(&public13).await.unwrap(),
        3 * payment_host::FEE
    );
    next
}
