//! Real native deposits, encrypted signer recovery and an adversarial consumed
//! nonce. A funding operation never silently replaces its original signature.
use super::*;
use crate::vpn::payments::shielded::payer::{
    funding::{Funding, Services as FundingServices, State as FundingState, Terms as FundingTerms},
    movement::Window,
    Progress,
};
use std::path::Path;

fn balance(fixture: &Fixture) -> num_bigint::BigInt {
    account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        payment_host::address(13).as_bytes(),
    )
    .unwrap()
    .unwrap()
    .balance
}
pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    payer: Payer,
    index: PoolIndex,
    path: &Path,
    key: &Key,
    amount: u64,
    prover: &Prover,
    policy: FeePolicy,
) -> (Payer, PoolIndex) {
    let relayer = payment_host::key(13);
    let public = relayer.verifying_key().to_bytes();
    let window = Window {
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        relayer: address(&payment_host::address(13)),
    };
    assert!(payer
        .prepare_deposit([196; 32], 0, window, &index, prover)
        .await
        .is_err());
    assert!(payer
        .prepare_deposit([196; 32], i64::MAX as u64 + 1, window, &index, prover)
        .await
        .is_err());
    let old = payer
        .prepare_deposit([196; 32], amount, window, &index, prover)
        .await
        .unwrap();
    let first = payer
        .sign_native(Operation::Movement(old.id), &index, &relayer, policy)
        .await
        .unwrap();
    assert_eq!(first.transaction().amount, amount.into());
    assert_eq!(payer.available_ou(&index).await.unwrap(), 0);
    assert!(payer.cancel_movement(old.id, &index, false).await.is_err());
    // Another legitimate application consumes the relayer nonce without
    // touching the pool. A generic nonce retry would now sign another deposit.
    let consume = fixture.transaction(
        13,
        &fixture.program,
        OpType::CircleCall,
        json!([payment_host::address(11)]),
        0,
        b"get_operator_generation".to_vec(),
    );
    assert_eq!(consume.nonce, first.transaction().nonce);
    fixture.publish(vec![consume]).await;
    let consumed = account_store::load(
        &StateBatch::from_snapshot(fixture.node.snapshot().unwrap().state().clone()),
        payment_host::address(13).as_bytes(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(consumed.nonce, first.transaction().nonce);
    assert!(payer.confirmed_native(&first).await.unwrap().is_none());
    let same = payer
        .sign_native(Operation::Movement(old.id), &index, &relayer, policy)
        .await
        .unwrap();
    assert_eq!(same.transaction(), first.transaction());
    assert_eq!(payer.reserved_fees(&public).await.unwrap(), policy.fee_ou);
    // Renewed funding requires a genuinely distinct caller consent ID.
    let consent = FundingTerms {
        amount_ou: amount,
        valid_from_ms: window.valid_from_ms,
        expires_ms: window.expires_ms,
        relayer_public: public,
        fees: policy,
    };
    let mut mismatched = consent.clone();
    mismatched.amount_ou += 1;
    assert!(Funding::create(payer.clone(), old.id, mismatched)
        .await
        .is_err());
    let mut mismatched = consent.clone();
    mismatched.expires_ms += 1;
    assert!(Funding::create(payer.clone(), old.id, mismatched)
        .await
        .is_err());
    crate::vpn::payments::shielded::payer::funding::Funding::create(
        payer.clone(),
        [197; 32],
        consent.clone(),
    )
    .await
    .unwrap();
    let mut changed = consent;
    changed.amount_ou += 1;
    assert!(
        crate::vpn::payments::shielded::payer::funding::Funding::create(
            payer.clone(),
            [197; 32],
            changed
        )
        .await
        .is_err()
    );
    let prepared = payer
        .prepare_deposit([197; 32], amount, window, &index, prover)
        .await
        .unwrap();
    assert_ne!(prepared.output_slot(), old.output_slot());
    assert!(payer
        .prepare_deposit(prepared.id, amount + 1, window, &index, prover)
        .await
        .is_err());
    let live_index = Index::create(
        &fixture.directory.path().join("private-funding-index"),
        Key::from_bytes([191; 32]),
        source.clone(),
        IndexLimits::default(),
    )
    .await
    .unwrap();
    let intake =
        super::super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    let before = balance(fixture);
    let funding = Funding::discover(payer.clone())
        .await
        .unwrap()
        .pop()
        .unwrap();
    let FundingState::Submitted { hash } = funding
        .step(FundingServices {
            index: &live_index,
            submission: &intake.submission,
            relayer: &relayer,
            prover,
        })
        .await
        .unwrap()
    else {
        panic!("funding was not staged");
    };
    let sequences = payer
        .native_sequences(&public, Operation::Movement(prepared.id))
        .await
        .unwrap();
    assert_eq!(sequences.len(), 1);
    let signed = payer.native_attempt(&public, sequences[0]).await.unwrap();
    assert_eq!(signed.hash().unwrap(), hash);
    drop(funding);
    assert_eq!(signed.transaction().amount, amount.into());
    assert_eq!(
        payer.reserved_fees(&public).await.unwrap(),
        2 * policy.fee_ou
    );
    drop(payer);
    let payer = Payer::resume(path, key.clone(), source.clone())
        .await
        .unwrap();
    let same = payer
        .sign_native(Operation::Movement(prepared.id), &index, &relayer, policy)
        .await
        .unwrap();
    assert_eq!(same.transaction(), signed.transaction());
    let next = index.observe(&prepared.statement().unwrap()).unwrap();
    let member = next
        .membership(prepared.first_output_index().unwrap())
        .unwrap();
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    assert!(payer
        .complete_movement(prepared.id, &index, epoch, Some(&member))
        .await
        .is_err());
    let funding = Funding::discover(payer.clone())
        .await
        .unwrap()
        .pop()
        .unwrap();
    let FundingState::Submitted { hash: retried } = funding
        .step(FundingServices {
            index: &live_index,
            submission: &intake.submission,
            relayer: &relayer,
            prover,
        })
        .await
        .unwrap()
    else {
        panic!("funding retry was not staged");
    };
    assert_eq!(hash, retried);
    payer
        .broadcast(&intake.submission, &signed, &index)
        .await
        .unwrap();
    payer
        .broadcast(&intake.submission, &signed, &index)
        .await
        .unwrap();
    assert_eq!(
        intake.pending.transactions().unwrap(),
        vec![signed.transaction().clone()]
    );
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    assert_eq!(payer.available_ou(&index).await.unwrap(), 0);
    fixture
        .publish(intake.pending.transactions().unwrap())
        .await;
    let FundingState::Funded { epoch: paid } = funding
        .step(FundingServices {
            index: &live_index,
            submission: &intake.submission,
            relayer: &relayer,
            prover,
        })
        .await
        .unwrap()
    else {
        panic!("funding was not confirmed");
    };
    assert_eq!(paid, epoch);
    drop(funding);
    live_index.close().await;
    intake.close().await;
    assert_eq!(
        balance(fixture),
        before - num_bigint::BigInt::from(policy.fee_ou) - amount
    );
    assert!(payer
        .prepare_deposit(prepared.id, amount, window, &next, prover)
        .await
        .is_err());
    assert!(payer
        .sign_native(Operation::Movement(prepared.id), &next, &relayer, policy)
        .await
        .is_err());
    assert!(payer
        .cancel_movement(prepared.id, &next, false)
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
    assert_eq!(payer.available_ou(&next).await.unwrap(), amount);
    assert_eq!(
        payer.reserved_fees(&public).await.unwrap(),
        2 * policy.fee_ou
    );
    assert_eq!(
        payer
            .native_sequences(&public, Operation::Movement(prepared.id))
            .await
            .unwrap(),
        vec![signed.sequence()]
    );
    let unsigned = payer
        .prepare_deposit([195; 32], 1, window, &next, prover)
        .await
        .unwrap();
    payer
        .cancel_movement(unsigned.id, &next, false)
        .await
        .unwrap();
    assert!(matches!(
        payer.movement_progress(unsigned.id).await.unwrap(),
        Progress::Cancelled
    ));
    assert_eq!(payer.available_ou(&next).await.unwrap(), amount);
    let unfunded = Window {
        relayer: address(&payment_host::address(15)),
        ..window
    };
    let no_funds = payer
        .prepare_deposit([194; 32], 1, unfunded, &next, prover)
        .await
        .unwrap();
    assert!(payer
        .sign_native(
            Operation::Movement(no_funds.id),
            &next,
            &payment_host::key(15),
            policy
        )
        .await
        .is_err());
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(15).verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    payer
        .cancel_movement(no_funds.id, &next, false)
        .await
        .unwrap();
    (payer, next)
}
