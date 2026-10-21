//! Spend earned exit notes at a different operator through the same payer
//! book. Real native intake and BFT publication establish every payment.
use super::*;
use crate::vpn::payments::shielded::{
    payer::{
        native::{FeePolicy, Operation},
        Payer,
    },
    wallet::{Receipt, Wallet},
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    config: shielded::Config,
    pk: Arc<ProvingKey<Bn254>>,
    mut index: PoolIndex,
) -> PoolIndex {
    let operator_path = fixture.directory.path().join("private-wallet");
    let wallet = Wallet::resume(&operator_path, Key::from_bytes([83; 32]), source.clone())
        .await
        .unwrap();
    let before1 = wallet.channel(1).await.unwrap();
    let before2 = wallet.channel(2).await.unwrap();
    let ids = wallet.income_ids().await.unwrap();
    assert_eq!(ids.len(), 4);
    let payer_path = fixture.directory.path().join("operator-payer");
    let payer = Payer::create(&payer_path, Key::from_bytes([93; 32]), source.clone())
        .await
        .unwrap();
    assert!(payer
        .attach_income(&wallet, &PoolIndex::default())
        .await
        .is_err());
    // Crash between the two databases: the durable one-book assignment already
    // exists; a subsequent attach must recover the unimported note exactly once.
    payer
        .assign_income_before_import(&wallet, ids[0], &index)
        .await;
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 4);
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 0);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 81);
    let other = Payer::create(
        &fixture.directory.path().join("income-other-book"),
        Key::from_bytes([95; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    assert_eq!(other.attach_income(&wallet, &index).await.unwrap(), 0);
    assert!(other.claim_income(&wallet, ids[0], &index).await.is_err());
    assert_eq!(other.available_ou(&index).await.unwrap(), 0);
    // Adding our own funds and earned income uses one selection/reservation
    // ledger. No public withdrawal or redeposit is needed to spend earnings.
    let (next, _) = super::payer_flow::deposit(fixture, &source, &pk, index, &payer, 5).await;
    index = next;
    assert_eq!(payer.available_ou(&index).await.unwrap(), 86);

    fixture
        .call(12, "bond_operator", json!([]), payment_host::STAKE)
        .await;
    let message = format!(
        "Octranet operator key v1|{}|{}|{}|1",
        fixture.domain,
        fixture.program,
        payment_host::address(12)
    );
    fixture
        .call(
            12,
            "register_operator_receipt_key",
            json!([
                STANDARD.encode(payment_host::key(12).verifying_key().as_bytes()),
                payment_host::sign(12, &message)
            ]),
            0,
        )
        .await;
    fixture
        .call(
            12,
            "create_offer",
            json!([super::super::second_tariff().hash_hex().unwrap()]),
            0,
        )
        .await;
    fixture.call(12, "append_class", json!([1, 20]), 0).await;
    fixture.call(12, "seal_offer", json!([1]), 0).await;
    let mut directory_config = fixture.payments().config;
    directory_config.offer = 1;
    let directory = Arc::new(
        fixture
            .node
            .payments(
                directory_config,
                parse_native_address(&payment_host::address(12)).unwrap(),
            )
            .unwrap(),
    );
    let second_source = Arc::new(Pool::new(directory.clone(), config.clone()).unwrap());
    let view = payer.for_operator(second_source.clone()).unwrap();
    let mut wrong_config = config;
    wrong_config.custody_cap_ou -= 1;
    let wrong_source = Arc::new(Pool::new(directory, wrong_config).unwrap());
    assert!(payer.for_operator(wrong_source).is_err());
    assert_eq!(view.available_ou(&index).await.unwrap(), 86);
    let second_path = fixture.directory.path().join("second-operator-wallet");
    let second = Wallet::create(
        &second_path,
        Key::from_bytes([94; 32]),
        second_source.clone(),
    )
    .await
    .unwrap();
    let channel = second
        .create_channel(1, payment_host::key(31).verifying_key().to_bytes(), 100)
        .await
        .unwrap();
    let quote = second
        .issue(
            channel.binding.plan,
            0,
            1_048_576,
            120_000,
            &payment_host::key(12),
        )
        .await
        .unwrap();
    let limits = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: 20,
    };
    let relayer = address(&payment_host::address(11));
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    assert!(payer
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .is_err());
    let proposal = view
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .unwrap();
    // The smallest sufficient note is the earned 51 OU note; its reservation
    // must be visible from both views and survive a repeated income attachment.
    assert_eq!(view.available_ou(&index).await.unwrap(), 35);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 35);
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 0);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 35);
    let policy = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 2 * payment_host::FEE,
        max_attempts: 2,
    };
    let signed = view
        .sign_native(
            Operation::Purchase(proposal.quote),
            &index,
            &payment_host::key(11),
            policy,
        )
        .await
        .unwrap();
    // Shared relayer bank: another view gets the same reserved signature.
    let same = payer
        .native_attempt(&payment_host::key(11).verifying_key().to_bytes(), 1)
        .await
        .unwrap();
    assert_eq!(signed.transaction(), same.transaction());
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    view.broadcast(&rpc.submission, &signed, &index)
        .await
        .unwrap();
    assert!(payer.confirmed_native(&signed).await.unwrap().is_none());
    let next = index.observe(&proposal.statement().unwrap()).unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    index = next;
    // Reconciliation is custody work. The original operator's retired offer
    // must neither confiscate earned notes nor block confirmation for operator B.
    let epoch = payer
        .reconcile_native(&signed, &index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 66);
    assert_eq!(view.available_ou(&index).await.unwrap(), 66);
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 0);
    let membership = index
        .membership(proposal.first_output_index().unwrap())
        .unwrap();
    let call = proposal.call().unwrap();
    let receipt = || Receipt {
        epoch,
        commitment: proposal.outputs()[0],
        membership: &membership,
        call: &call,
        relayer,
    };
    let received = second.receive(proposal.quote, receipt()).await.unwrap();
    assert!(received.new_note && received.new_capacity);
    let repeated = second.receive(proposal.quote, receipt()).await.unwrap();
    assert!(!repeated.new_note && !repeated.new_capacity);
    assert_eq!(
        second.channel(channel.binding.plan).await.unwrap().paid_ou,
        20
    );
    assert_eq!(
        second
            .channel(channel.binding.plan)
            .await
            .unwrap()
            .purchased,
        vec![1_048_576]
    );
    for (id, old) in [(1, before1), (2, before2)] {
        let current = wallet.channel(id).await.unwrap();
        assert_eq!(current.paid_ou, old.paid_ou);
        assert_eq!(current.purchased, old.purchased);
    }
    // A real two-input proof uses one operator-derived key and one payer key.
    // The fresh consolidated note is owned directly by the payer book.
    let notes = payer.available_notes(&index).await.unwrap();
    let own = notes.iter().find(|n| n.value_ou == 5).unwrap().commitment;
    let earned = notes.iter().find(|n| n.value_ou == 10).unwrap().commitment;
    let movement = view
        .consolidate(
            [161; 32],
            [own, earned],
            crate::vpn::payments::shielded::payer::movement::Window {
                valid_from_ms: millis(fixture),
                expires_ms: millis(fixture) + 120_000,
                relayer,
            },
            &index,
            &prover,
        )
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 51);
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 0);
    assert_eq!(view.available_ou(&index).await.unwrap(), 51);
    let signed = payer
        .sign_native(
            Operation::Movement(movement.id),
            &index,
            &payment_host::key(11),
            policy,
        )
        .await
        .unwrap();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    view.broadcast(&rpc.submission, &signed, &index)
        .await
        .unwrap();
    let next = index.observe(&movement.statement().unwrap()).unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    index = next;
    assert!(view
        .reconcile_native(&signed, &index)
        .await
        .unwrap()
        .is_some());
    assert_eq!(payer.available_ou(&index).await.unwrap(), 66);
    assert!(payer
        .available_notes(&index)
        .await
        .unwrap()
        .iter()
        .any(|n| n.value_ou == 15));
    drop(other);
    drop(view);
    drop(payer);
    drop(wallet);
    let wallet = Wallet::resume(&operator_path, Key::from_bytes([83; 32]), source.clone())
        .await
        .unwrap();
    // The book can reopen using B's view; its keys/identity are independent of
    // any one operator. Foreign earnings require their original wallet unlocked.
    let payer = Payer::resume(
        &payer_path,
        Key::from_bytes([93; 32]),
        second_source.clone(),
    )
    .await
    .unwrap();
    assert!(payer.available_ou(&index).await.is_err());
    assert_eq!(payer.attach_income(&wallet, &index).await.unwrap(), 0);
    assert_eq!(payer.available_ou(&index).await.unwrap(), 66);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(11).verifying_key().to_bytes())
            .await
            .unwrap(),
        2 * payment_host::FEE
    );
    assert!(payer
        .claim_income(&wallet, received.credit_id, &index)
        .await
        .is_err());
    Box::pin(super::runner_flow::service::run(
        fixture,
        payer,
        source,
        second_source,
        wallet,
        second,
        pk,
        index,
    ))
    .await
}
