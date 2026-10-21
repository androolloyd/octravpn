//! One encrypted book, paused operator views, actual native payment and income.
use super::*;
use crate::vpn::payments::shielded::payer::service::Service;
use std::sync::atomic::AtomicUsize;

struct Paused(AtomicUsize);
#[async_trait::async_trait]
impl PrivateExchange for Paused {
    async fn exchange(&self, _: &SignedPrivateRequest) -> Result<SignedPrivateReply> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("paused operator must not receive requests")
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Existing canonical scenario owns the independent books and proof material"
)]
pub(in super::super) async fn run(
    fixture: &mut Fixture,
    payer: Payer,
    original: Arc<Pool>,
    second: Arc<Pool>,
    original_wallet: Wallet,
    income_wallet: Wallet,
    pk: Arc<ProvingKey<Bn254>>,
    initial: PoolIndex,
) -> PoolIndex {
    let payer = payer.for_operator(second.clone()).unwrap();
    let a_target = original_wallet
        .private_target(KeyPair::from_secret_bytes(&[11; 32]).public)
        .unwrap();
    let b_target = income_wallet
        .private_target(KeyPair::from_secret_bytes(&[12; 32]).public)
        .unwrap();
    let offer = second.offer(1).await.unwrap();
    let relayer = Arc::new(payment_host::key(13));
    let fees = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 4 * payment_host::FEE,
        max_attempts: 4,
    };
    let terms = Terms {
        target: b_target.clone(),
        offer: 1,
        operator_generation: offer.operator_generation,
        manifest_hash: offer.manifest_hash.clone(),
        ceiling_ou: 100,
        traffic_class: 0,
        bytes: 1_048_576,
        max_cost_ou: 20,
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 86_400_000,
        invoice_lifetime_ms: 120_000,
        relayer_public: relayer.verifying_key().to_bytes(),
        fees,
        additional: vec![],
    };
    let purchase = Purchase::create(payer.clone(), [215; 32], terms.clone())
        .await
        .unwrap();
    let mut held_terms = terms;
    held_terms.target = a_target.clone();
    held_terms.offer = 0;
    held_terms.manifest_hash = fixture.tariff.hash_hex().unwrap();
    held_terms.max_cost_ou = 10;
    let original_view = payer.for_operator(original.clone()).unwrap();
    Purchase::create(original_view.clone(), [216; 32], held_terms.clone())
        .await
        .unwrap();
    // Same signing key on another directory is a different target, not a job
    // for this view. Discovery must skip it without poisoning the valid group.
    let mut foreign_terms = held_terms;
    foreign_terms.target.directory = octravpn_core::Address::from_pubkey(&[218; 32]);
    Purchase::foreign_directory_case(original_view, [217; 32], foreign_terms).await;

    let service = fixture
        .node
        .bind_shielded_purchases(
            "127.0.0.1:0".parse().unwrap(),
            octravpn_node::payments::Config {
                control_listen: "127.0.0.1:0".parse().unwrap(),
                tunnel_listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: fixture.directory.path().join("grouped-operator-transport"),
                operator_key: Arc::new(KeyPair::from_secret_bytes(&[12; 32])),
                wireguard_secret: x25519_dalek::StaticSecret::from([214; 32]),
                ip_tunnel: None,
            },
            &income_wallet,
            shielded::wallet::rpc::Policy {
                max_channels: 16,
                max_requests: 128,
                max_ceiling_ou: 100,
                max_invoice_lifetime_ms: 120_000,
            },
        )
        .await
        .unwrap();
    let tls = tls::Server::new(service.control_addr().unwrap()).await;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let service_task = tokio::spawn(service.run(stopped));
    let rpc = super::super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    let index = Index::create(
        &fixture.directory.path().join("grouped-payer-index"),
        Key::from_bytes([214; 32]),
        second.clone(),
        IndexLimits::default(),
    )
    .await
    .unwrap();
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let control = Arc::new(
        octravpn_client::PrivateControl::new_pinned(
            &tls.origin,
            b_target.clone(),
            &tls.ca,
            vec![tls.spki],
            format!(
                "127.0.0.1:{}",
                reqwest::Url::parse(&tls.origin).unwrap().port().unwrap()
            )
            .parse()
            .unwrap(),
        )
        .unwrap(),
    );
    Box::pin(
        crate::vpn::payments::shielded::payer::runner::route::qualification(
            &fixture.directory.path().join("route-consent-book"),
            [original.clone(), second.clone()],
            Services {
                index: &index,
                submission: &rpc.submission,
                relayer: &relayer,
                prover: &prover,
                control: &*control,
            },
            millis(fixture),
        ),
    )
    .await;
    let mut runner = Service::resume(
        payer.clone(),
        index,
        rpc.submission.clone(),
        relayer.clone(),
        prover,
        control.clone(),
    )
    .await
    .unwrap()
    .with_income(original_wallet.clone())
    .unwrap()
    .with_income(income_wallet.clone())
    .unwrap();
    assert!(runner.add_operator(second, control).await.is_err());
    let paused = Arc::new(Paused(AtomicUsize::new(0)));
    runner.add_operator(original, paused.clone()).await.unwrap();
    assert_eq!(runner.status().borrow().paused, 1);
    let mut wrong_target = b_target.clone();
    wrong_target.chain_origin[0] ^= 1;
    assert!(runner.set_operator_enabled(&wrong_target, true).is_err());
    runner.set_operator_enabled(&b_target, false).unwrap();
    assert_eq!(runner.status().borrow().paused, 2);
    let waiting = runner.step().await;
    assert_eq!(
        (
            waiting.completed,
            waiting.remaining,
            waiting.paused,
            waiting.blocked
        ),
        (0, 2, 2, 0)
    );
    assert!(rpc.pending.transactions().unwrap().is_empty());
    assert_eq!(
        payer
            .reserved_fees(&relayer.verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        payer
            .available_ou(runner.view().await.unwrap().index())
            .await
            .unwrap(),
        86
    );
    runner.set_operator_enabled(&b_target, true).unwrap();
    let mut paid = false;
    for _ in 0..8 {
        let state = runner.step().await;
        assert_eq!((state.paused, state.blocked), (1, 0));
        let pending = rpc.pending.transactions().unwrap();
        if !pending.is_empty() {
            fixture.publish(pending).await;
            // This fixture publishes directly rather than running the driver.
            // Retire the queue through the driver's real post-commit callback,
            // after reauthenticating the durable record; never replay it as a
            // second purchase on the next scheduler pass.
            let head = fixture.node.head().await.unwrap();
            let record = fixture
                .node
                .publisher
                .record(head.cursor.sequence)
                .await
                .unwrap();
            rpc.pending.committed(&record, head.cursor).unwrap();
            assert!(rpc.pending.transactions().unwrap().is_empty());
            eprintln!("grouped private payer: authenticated native commit retired from its queue");
        }
        if state.completed == 1 {
            paid = true;
            break;
        }
    }
    assert!(paid);
    let done = runner.step().await;
    assert_eq!(
        (done.completed, done.remaining, done.paused, done.blocked),
        (1, 1, 1, 0)
    );
    assert!(rpc.pending.transactions().unwrap().is_empty());
    assert_eq!(paused.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        payer
            .reserved_fees(&relayer.verifying_key().to_bytes())
            .await
            .unwrap(),
        payment_host::FEE
    );
    let view = runner.view().await.unwrap();
    assert_ne!(view.index().roots(), initial.roots());
    // Existing B income funded its own purchase. Reimporting the resulting B
    // income nets back to the same 86 OU; customer bytes are not minted twice.
    assert_eq!(payer.available_ou(view.index()).await.unwrap(), 86);
    let result = view.index().clone();
    drop(view);
    assert_eq!(
        Purchase::discover(payer).await.unwrap()[0].id(),
        purchase.id()
    );
    let (_cancel, cancelled) = tokio::sync::watch::channel(true);
    runner.run(cancelled).await.unwrap();
    rpc.close().await;
    tls.close().await;
    stop.send(true).unwrap();
    service_task.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
    result
}
