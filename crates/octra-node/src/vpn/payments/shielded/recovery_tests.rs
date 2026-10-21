//! A real purchase commits before snapshot import while both endpoints still
//! need receipt reconciliation. No completion flags or ledger state are forged.
use super::*;
use crate::vpn::payments::shielded::{
    history::Proof,
    index::Index,
    payer::{
        movement::Window,
        native::{FeePolicy, Operation, SignedAttempt},
        Payer, Progress,
    },
    wallet::{Receipt, Wallet},
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;
use octravpn_node::payments::Authority as TrafficAuthority;
use std::path::Path;
struct Withdrawal {
    signed: SignedAttempt,
    id: [u8; 32],
    epoch: u64,
}
pub(super) struct Pending {
    signed: SignedAttempt,
    quote: [u8; 32],
    epoch: u64,
    commitment: [u8; 32],
    position: u32,
    count: u64,
    call: Call,
    channel: u64,
    withdrawal: Withdrawal,
}
fn second(fixture: &Fixture, config: shielded::Config) -> Arc<Pool> {
    let mut directory = fixture.payments().config;
    directory.offer = 1;
    Arc::new(
        Pool::new(
            Arc::new(
                fixture
                    .node
                    .payments(
                        directory,
                        parse_native_address(&payment_host::address(12)).unwrap(),
                    )
                    .unwrap(),
            ),
            config,
        )
        .unwrap(),
    )
}
pub(super) async fn prepare(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    config: shielded::Config,
    pk: Arc<ProvingKey<Bn254>>,
    payer: &Payer,
    index: &Index,
) -> Pending {
    let movement = Payer::create(
        &fixture.directory.path().join("checkpoint-movement"),
        Key::from_bytes([193; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    super::payer_flow::deposit(
        fixture,
        &source,
        &pk,
        index.view().await.unwrap().index().clone(),
        &movement,
        5,
    )
    .await;
    index.sync(128).await.unwrap();
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let current = index.view().await.unwrap();
    let withdrawal = movement
        .prepare_withdrawal(
            [194; 32],
            5,
            address(&payment_host::address(14)),
            Window {
                valid_from_ms: millis(fixture),
                expires_ms: millis(fixture) + 120_000,
                relayer: address(&payment_host::address(14)),
            },
            current.index(),
            &prover,
        )
        .await
        .unwrap();
    let signed = movement
        .sign_native(
            Operation::Movement(withdrawal.id),
            current.index(),
            &payment_host::key(14),
            FeePolicy {
                fee_ou: payment_host::FEE,
                lifetime_budget_ou: payment_host::FEE,
                max_attempts: 1,
            },
        )
        .await
        .unwrap();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    movement
        .broadcast(&rpc.submission, &signed, current.index())
        .await
        .unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    let withdrawal = Withdrawal {
        signed,
        id: withdrawal.id,
        epoch: fixture.node.snapshot().unwrap().head().cursor.epoch.0,
    };
    index.sync(128).await.unwrap();
    let b_source = second(fixture, config);
    let a = Wallet::resume(
        &fixture.directory.path().join("private-wallet"),
        Key::from_bytes([83; 32]),
        source,
    )
    .await
    .unwrap();
    let b = Wallet::resume(
        &fixture.directory.path().join("second-operator-wallet"),
        Key::from_bytes([94; 32]),
        b_source.clone(),
    )
    .await
    .unwrap();
    let channel = b
        .create_channel(1, payment_host::key(31).verifying_key().to_bytes(), 10)
        .await
        .unwrap();
    let quote = b
        .issue(
            channel.binding.plan,
            0,
            50_000,
            120_000,
            &payment_host::key(12),
        )
        .await
        .unwrap();
    let limits = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: 50_000,
        max_cost_ou: 1,
    };
    let view = payer.for_operator(b_source.clone()).unwrap();
    let current = index.view().await.unwrap();
    let proposal = view
        .prepare(
            &quote,
            &limits,
            current.index(),
            address(&payment_host::address(11)),
            &prover,
        )
        .await
        .unwrap();
    let signed = view
        .sign_native(
            Operation::Purchase(proposal.quote),
            current.index(),
            &payment_host::key(11),
            FeePolicy {
                fee_ou: payment_host::FEE,
                lifetime_budget_ou: 2 * payment_host::FEE,
                max_attempts: 2,
            },
        )
        .await
        .unwrap();
    let rpc = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    view.broadcast(&rpc.submission, &signed, current.index())
        .await
        .unwrap();
    fixture.publish(rpc.pending.transactions().unwrap()).await;
    rpc.close().await;
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0;
    fixture.publish(vec![]).await;
    index.sync(128).await.unwrap();
    let anchor = fixture.node.snapshot().unwrap().head().cursor.epoch.0;
    movement
        .retain_native(&withdrawal.signed, anchor)
        .await
        .unwrap();
    view.retain_native(&signed, anchor).await.unwrap();
    assert!(matches!(
        view.progress(proposal.quote).await.unwrap(),
        Some(Progress::Ready)
    ));
    assert_eq!(
        view.available_ou(index.view().await.unwrap().index())
            .await
            .unwrap(),
        0
    );
    let first = a.prepare_recovery(anchor, 1).await.unwrap();
    assert_eq!(first.prepared, 1);
    assert!(first.remaining > 0);
    assert_eq!(a.prepare_recovery(anchor, 8).await.unwrap().remaining, 0);
    assert_eq!(a.prepare_recovery(anchor, 8).await.unwrap().prepared, 0);
    assert_eq!(b.prepare_recovery(anchor, 8).await.unwrap().remaining, 0);
    b.retain_epoch(epoch, anchor).await.unwrap();
    let encoded = b.export_recovery(epoch).await.unwrap();
    let proof = Proof::decode(&encoded).unwrap();
    assert_eq!(proof.epoch(), epoch);
    assert_eq!(proof.anchor(), anchor);
    assert!(Proof::decode(&encoded[..encoded.len() - 1]).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(Proof::decode(&trailing).is_err());
    crate::vpn::payments::shielded::history::adversarial(&proof, &b_source).await;
    Pending {
        signed,
        quote: proposal.quote,
        epoch,
        commitment: proposal.outputs()[0],
        position: proposal.first_output_index().unwrap(),
        count: u64::from(proposal.first_output_index().unwrap()) + 2,
        call: proposal.call().unwrap(),
        channel: channel.binding.plan,
        withdrawal,
    }
}
pub(super) async fn resume(
    fixture: &Fixture,
    journal_root: &Path,
    config: shielded::Config,
    payer: &Payer,
    index: &PoolIndex,
    pending: &Pending,
) {
    let head = fixture.node.snapshot().unwrap().head().clone();
    let movement = Payer::resume(
        &journal_root.join("checkpoint-movement"),
        Key::from_bytes([193; 32]),
        payer_source(fixture, config.clone()),
    )
    .await
    .unwrap();
    assert!(fixture
        .node
        .store
        .reader()
        .transaction(
            &head,
            pending.withdrawal.signed.hash().unwrap().as_bytes(),
            32768
        )
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        movement
            .movement_progress(pending.withdrawal.id)
            .await
            .unwrap(),
        Progress::Ready
    ));
    assert_eq!(
        movement
            .confirmed_native(&pending.withdrawal.signed)
            .await
            .unwrap(),
        Some(pending.withdrawal.epoch)
    );
    assert_eq!(
        movement
            .reconcile_native(&pending.withdrawal.signed, index)
            .await
            .unwrap(),
        Some(pending.withdrawal.epoch)
    );
    assert!(matches!(
        movement
            .movement_progress(pending.withdrawal.id)
            .await
            .unwrap(),
        Progress::Paid
    ));
    assert_eq!(movement.available_ou(index).await.unwrap(), 0);
    assert_eq!(
        movement
            .reserved_fees(&payment_host::key(14).verifying_key().to_bytes())
            .await
            .unwrap(),
        payment_host::FEE
    );
    assert!(fixture
        .node
        .store
        .reader()
        .transaction(&head, pending.signed.hash().unwrap().as_bytes(), 32768)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        payer.confirmed_native(&pending.signed).await.unwrap(),
        Some(pending.epoch)
    );
    assert_eq!(
        payer
            .reconcile_native(&pending.signed, index)
            .await
            .unwrap(),
        Some(pending.epoch)
    );
    assert!(matches!(
        payer.progress(pending.quote).await.unwrap(),
        Some(Progress::Paid)
    ));
    assert_eq!(payer.available_ou(index).await.unwrap(), 3);
    let b_source = second(fixture, config);
    let b_path = journal_root.join("second-operator-wallet");
    let b = Wallet::resume(&b_path, Key::from_bytes([94; 32]), b_source.clone())
        .await
        .unwrap();
    let membership = index
        .membership_at(pending.position, pending.count)
        .unwrap();
    let receipt = || Receipt {
        epoch: pending.epoch,
        commitment: pending.commitment,
        membership: &membership,
        call: &pending.call,
        relayer: address(&payment_host::address(11)),
    };
    let accepted = b.receive(pending.quote, receipt()).await.unwrap();
    assert!(accepted.new_note && accepted.new_capacity);
    let again = b.receive(pending.quote, receipt()).await.unwrap();
    assert!(!again.new_note && !again.new_capacity);
    let info = b.channel(pending.channel).await.unwrap();
    assert_eq!(info.paid_ou, 1);
    assert_eq!(info.purchased, vec![50_000]);
    let grant = TrafficAuthority::plan(&b, &info.binding).await.unwrap();
    assert!(grant.admissible);
    grant.guard.current(&mut || Ok(())).unwrap();
    let saved = b.export_recovery(pending.epoch).await.unwrap();
    b.remove_recovery_chunk(pending.epoch).await;
    drop(b);
    let b = Wallet::resume(&b_path, Key::from_bytes([94; 32]), b_source)
        .await
        .unwrap();
    assert!(b.channel(pending.channel).await.is_err());
    b.import_recovery(&Proof::decode(&saved).unwrap())
        .await
        .unwrap();
    assert_eq!(b.channel(pending.channel).await.unwrap().paid_ou, 1);
}
fn payer_source(fixture: &Fixture, config: shielded::Config) -> Arc<Pool> {
    Arc::new(Pool::new(Arc::new(fixture.payments()), config).unwrap())
}
pub(super) async fn extend(
    fixture: &Fixture,
    journal_root: &Path,
    config: shielded::Config,
    payer: &Payer,
    pending: &Pending,
) {
    let anchor = fixture.node.snapshot().unwrap().head().cursor.epoch.0;
    assert!(anchor > fixture.node.store.reader().anchor().epoch.0);
    payer.retain_native(&pending.signed, anchor).await.unwrap();
    assert_eq!(
        payer.confirmed_native(&pending.signed).await.unwrap(),
        Some(pending.epoch)
    );
    assert!(payer
        .retain_native(&pending.signed, anchor - 1)
        .await
        .is_err());
    let source = payer_source(fixture, config.clone());
    let movement = Payer::resume(
        &journal_root.join("checkpoint-movement"),
        Key::from_bytes([193; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    movement
        .retain_native(&pending.withdrawal.signed, anchor)
        .await
        .unwrap();
    assert_eq!(
        movement
            .confirmed_native(&pending.withdrawal.signed)
            .await
            .unwrap(),
        Some(pending.withdrawal.epoch)
    );
    let a = Wallet::resume(
        &journal_root.join("private-wallet"),
        Key::from_bytes([83; 32]),
        source,
    )
    .await
    .unwrap();
    assert!(a.prepare_recovery(anchor, 8).await.unwrap().prepared > 0);
    let b = Wallet::resume(
        &journal_root.join("second-operator-wallet"),
        Key::from_bytes([94; 32]),
        second(fixture, config),
    )
    .await
    .unwrap();
    assert!(b.prepare_recovery(anchor, 8).await.unwrap().prepared > 0);
    assert_eq!(
        Proof::decode(&b.export_recovery(pending.epoch).await.unwrap())
            .unwrap()
            .anchor(),
        anchor
    );
    assert_eq!(b.channel(pending.channel).await.unwrap().paid_ou, 1);
    assert!(b.prepare_recovery(anchor - 1, 8).await.is_err());
}
