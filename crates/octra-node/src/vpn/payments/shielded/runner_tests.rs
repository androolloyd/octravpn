//! Real private RPC, encrypted restart, native intake and signed-QC execution.
//! Faults occur after the operator commits, reproducing ambiguous delivery.
use super::*;
use crate::vpn::payments::shielded::{
    index::{Index, Limits as IndexLimits},
    payer::{
        self,
        native::{FeePolicy, Operation},
        runner::{client::Transport, Allowance, Purchase, Services, State, Terms},
        Payer,
    },
    wallet::Wallet,
};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::{
    payments::{
        PrivateAction, PrivateExchange, PrivateResult, SignedPrivateReply, SignedPrivateRequest,
    },
    sealed::Key,
};
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Mutex,
};
#[path = "runner_tests/bundle.rs"]
mod bundle;
#[path = "runner_tests/client.rs"]
mod client;
#[cfg(feature = "private-kernel-qualification")]
#[path = "runner_tests/exex.rs"]
pub(super) mod exex;
#[path = "runner_tests/funding.rs"]
mod funding;
#[cfg(feature = "private-kernel-qualification")]
#[path = "runner_tests/kernel.rs"]
mod kernel;
#[cfg(feature = "private-kernel-qualification")]
#[path = "runner_tests/multi_material.rs"]
mod multi_material;
#[cfg(feature = "private-kernel-qualification")]
#[path = "runner_tests/multi_observe.rs"]
mod multi_observe;
#[path = "runner_tests/service.rs"]
pub(super) mod service;
#[path = "runner_tests/tls.rs"]
mod tls;

struct Control {
    client: octravpn_client::PrivateControl,
    fault: AtomicU8,
    calls: Mutex<Vec<(SignedPrivateRequest, SignedPrivateReply)>>,
}
#[async_trait::async_trait]
impl PrivateExchange for Control {
    async fn exchange(&self, request: &SignedPrivateRequest) -> Result<SignedPrivateReply> {
        let reply = self.client.exchange(request).await?;
        self.calls
            .lock()
            .unwrap()
            .push((request.clone(), reply.clone()));
        let fault = self.fault.swap(0, Ordering::SeqCst);
        if fault == 1 {
            anyhow::bail!("cancelled after the operator committed");
        }
        if fault != 0 {
            let mut result: PrivateResult = serde_json::from_slice(&reply.verify(request)?)?;
            match &mut result {
                PrivateResult::Open { ceiling_ou, .. } if fault == 2 => *ceiling_ou += 1,
                PrivateResult::Receipt { credit_id, .. } if fault == 3 => *credit_id = [0; 32],
                PrivateResult::Quote { channel, invoice } if fault == 4 => {
                    let calls = self.calls.lock().unwrap();
                    let (earlier_request, earlier_reply) = calls.iter().find(|(request, _)| {
                        matches!(request.request.action, PrivateAction::Quote { channel: got, class: 0, .. } if got == *channel)
                    }).unwrap();
                    let PrivateResult::Quote {
                        invoice: earlier, ..
                    } = serde_json::from_slice(&earlier_reply.verify(earlier_request)?).unwrap()
                    else {
                        panic!("earlier class quote missing");
                    };
                    *invoice = earlier;
                }
                PrivateResult::Quote { invoice, .. } if fault == 5 || fault == 6 => {
                    use octra_private_payments_experimental::invoice::SignedInvoice;
                    let bytes = octravpn_core::b64::decode(invoice.as_str())?;
                    let mut quote = SignedInvoice::decode_private(&bytes)?.invoice;
                    quote.valid_from_ms += 1_000;
                    let claimant = payment_host::key(219);
                    quote.recipient_key = claimant.verifying_key().to_bytes();
                    let mut signed = SignedInvoice::sign(quote, &payment_host::key(11), &claimant)?;
                    if fault == 6 {
                        signed.claimant_signature[0] ^= 1;
                    }
                    *invoice = octravpn_core::b64::encode(&*signed.encode_private()?);
                }
                _ => panic!("wrong fault phase"),
            }
            return Ok(SignedPrivateReply::sign(
                request,
                &serde_json::to_vec(&result)?,
                &KeyPair::from_secret_bytes(&[11; 32]),
            )?);
        }
        Ok(reply)
    }
}

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    pk: Arc<ProvingKey<Bn254>>,
    initial: PoolIndex,
    pool_config: shielded::Config,
    kernel: bool,
) -> PoolIndex {
    #[cfg(not(feature = "private-kernel-qualification"))]
    assert!(!kernel, "kernel qualification feature required");
    let path = fixture.directory.path().join("private-runner-payer");
    let key = Key::from_bytes([198; 32]);
    let payer = Payer::create(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let offered = source.offer(0).await.unwrap();
    let cost = offered.tariff.classes()[0].rate_ou_per_mib;
    assert!(cost > 0);
    let funded = 2 * cost + 10;
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let fees = FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 5 * payment_host::FEE,
        max_attempts: 5,
    };
    let (payer, expected) = Box::pin(funding::run(
        fixture,
        source.clone(),
        payer,
        initial,
        &path,
        &key,
        funded,
        &prover,
        fees,
    ))
    .await;
    let index_path = fixture.directory.path().join("private-runner-index");
    let index_key = Key::from_bytes([199; 32]);
    let index = Index::create(
        &index_path,
        index_key.clone(),
        source.clone(),
        IndexLimits::default(),
    )
    .await
    .unwrap();
    // Keep these earnings separate from the older income-spending fixture.
    let operator = Wallet::create(
        &fixture.directory.path().join("private-runner-operator"),
        Key::from_bytes([200; 32]),
        source.clone(),
    )
    .await
    .unwrap();
    let terms = Terms {
        target: operator
            .private_target(KeyPair::from_secret_bytes(&[11; 32]).public)
            .unwrap(),
        offer: 0,
        operator_generation: offered.operator_generation,
        manifest_hash: offered.manifest_hash.clone(),
        ceiling_ou: 100,
        traffic_class: 0,
        bytes: 1_048_576,
        max_cost_ou: cost,
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 86_400_000,
        invoice_lifetime_ms: 120_000,
        relayer_public: payment_host::key(13).verifying_key().to_bytes(),
        fees,
        additional: vec![],
    };
    bundle::consent(&terms, &offered.tariff);
    let purchase = Purchase::create(payer.clone(), [198; 32], terms.clone())
        .await
        .unwrap();
    let mut changed = terms.clone();
    changed.ceiling_ou += 1;
    assert!(Purchase::create(payer.clone(), [198; 32], changed)
        .await
        .is_err());
    assert!(Purchase::resume(payer.clone(), [0; 32]).await.is_err());
    assert_eq!(Purchase::discover(payer.clone()).await.unwrap().len(), 1);
    Purchase::legacy_recovery_case(payer.clone(), [198; 32], terms.clone()).await;
    let receipt = purchase.receipt_identity().unwrap().public;
    assert_ne!(receipt.0, terms.relayer_public);
    #[cfg(feature = "private-kernel-qualification")]
    let ip_tunnel = kernel.then(kernel::configuration);
    #[cfg(not(feature = "private-kernel-qualification"))]
    let ip_tunnel = None;
    let service = fixture
        .node
        .bind_shielded_purchases(
            "127.0.0.1:0".parse().unwrap(),
            octravpn_node::payments::Config {
                control_listen: "127.0.0.1:0".parse().unwrap(),
                tunnel_listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: fixture.directory.path().join("private-runner-service"),
                operator_key: Arc::new(KeyPair::from_secret_bytes(&[11; 32])),
                wireguard_secret: x25519_dalek::StaticSecret::from([197; 32]),
                ip_tunnel,
            },
            &operator,
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
    #[cfg(feature = "private-kernel-qualification")]
    let addresses = kernel::Addresses {
        browser: service.browser_addr().unwrap(),
        control: service.control_addr().unwrap(),
        tunnel: service.tunnel_addr(),
    };
    #[cfg(feature = "private-kernel-qualification")]
    let payload_endpoint = if kernel {
        addresses.tunnel.to_string()
    } else {
        "127.0.0.1:9".into()
    };
    #[cfg(not(feature = "private-kernel-qualification"))]
    let payload_endpoint = "127.0.0.1:9".to_owned();
    let control = Control {
        client: tls.control(terms.target.clone()),
        fault: AtomicU8::new(2),
        calls: Mutex::new(Vec::new()),
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(service.run(stopped));
    let intake = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    let relayer = payment_host::key(13);
    let services = || Services {
        index: &index,
        submission: &intake.submission,
        control: &control,
        relayer: &relayer,
        prover: &prover,
    };
    // A valid operator signature cannot increase locally accepted spending.
    assert!(purchase.step(services()).await.is_err());
    assert!(intake.pending.transactions().unwrap().is_empty());
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        2 * payment_host::FEE
    );
    control.fault.store(1, Ordering::SeqCst);
    assert!(purchase.step(services()).await.is_err());
    drop(purchase);
    drop(payer);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let purchase = Purchase::resume(payer.clone(), [198; 32]).await.unwrap();
    assert_eq!(purchase.receipt_identity().unwrap().public, receipt);
    assert!(matches!(
        purchase.step(services()).await.unwrap(),
        State::Opened
    ));
    {
        let calls = control.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls
            .windows(2)
            .all(|pair| pair[0].0.digest().unwrap() == pair[1].0.digest().unwrap()));
    }
    let fees_before_quote = payer.reserved_fees(&terms.relayer_public).await.unwrap();
    let pending_before_quote = intake.pending.transactions().unwrap();
    fixture.node.suspend("auditing canonical history");
    assert!(purchase
        .step(services())
        .await
        .err()
        .unwrap()
        .is::<crate::published::Unavailable>());
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        fees_before_quote
    );
    assert!(intake.pending.transactions().unwrap() == pending_before_quote);
    assert!(fixture.node.resume().await.unwrap());
    control.fault.store(5, Ordering::SeqCst);
    assert!(matches!(
        purchase.step(services()).await.unwrap(),
        State::Syncing
    ));
    control.fault.store(6, Ordering::SeqCst);
    assert!(purchase.step(services()).await.is_err());
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        fees_before_quote
    );
    assert!(intake.pending.transactions().unwrap() == pending_before_quote);
    assert!(matches!(
        purchase.step(services()).await.unwrap(),
        State::Quoted
    ));
    {
        let calls = control.calls.lock().unwrap();
        let quotes: Vec<_> = calls
            .iter()
            .filter(|(r, _)| matches!(r.request.action, PrivateAction::Quote { .. }))
            .collect();
        assert_eq!(quotes.len(), 3);
        assert!(quotes
            .windows(2)
            .all(|p| p[0].0.digest().unwrap() == p[1].0.digest().unwrap()));
    }
    let client_path = fixture.directory.path().join("private-runner-client");
    let client_plan = {
        let calls = control.calls.lock().unwrap();
        let (request, reply) = &calls[0];
        let PrivateResult::Open { binding, .. } =
            serde_json::from_slice(&reply.verify(request).unwrap()).unwrap()
        else {
            panic!("not open");
        };
        octravpn_client::AcceptedPrivatePlan {
            target: terms.target.clone(),
            binding: *binding,
            tariff: offered.tariff.clone(),
            operator_generation: terms.operator_generation,
            quote_ceiling_ou: terms.ceiling_ou,
            prepaid_bytes: vec![terms.bytes, 0],
            control_url: tls.origin.clone(),
            control_ca_pem: tls.ca.clone(),
            control_spki: vec![tls.spki],
            // Preparation itself must never contact the payload endpoint.
            wireguard_endpoint: payload_endpoint,
        }
    };
    let client_options = |mode, receipt_key| octravpn_client::PrivatePaymentOptions {
        plan: client_plan.clone(),
        journal: client_path.clone(),
        receipt_key,
        interface_name: "octraprivate0".into(),
        mode,
    };
    let error = octravpn_client::PreparedPrivateClient::new(client_options(
        octravpn_client::JournalMode::Create,
        Arc::new(purchase.receipt_identity().unwrap()),
    ))
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("prepaid capacity missing"));
    let before = fixture.node.snapshot().unwrap().head().clone();
    let State::Submitted { hash } = purchase.step(services()).await.unwrap() else {
        panic!("not staged");
    };
    assert_eq!(fixture.node.snapshot().unwrap().head(), &before);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        3 * payment_host::FEE
    );
    drop(purchase);
    drop(payer);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let purchase = Purchase::resume(payer.clone(), [198; 32]).await.unwrap();
    let State::Submitted { hash: retried } = purchase.step(services()).await.unwrap() else {
        panic!("not retransmitted");
    };
    assert_eq!(hash, retried);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        3 * payment_host::FEE
    );
    assert_eq!(intake.pending.transactions().unwrap().len(), 1);
    fixture
        .publish(intake.pending.transactions().unwrap())
        .await;
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0;
    // A forged credit ID must not poison the durable successful-reply slot.
    control.fault.store(3, Ordering::SeqCst);
    assert!(purchase.step(services()).await.is_err());
    control.fault.store(1, Ordering::SeqCst);
    assert!(purchase.step(services()).await.is_err());
    drop(purchase);
    drop(payer);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let purchase = Purchase::resume(payer.clone(), [198; 32]).await.unwrap();
    let State::Credited {
        binding,
        credit_id,
        epoch: paid,
    } = purchase.step(services()).await.unwrap()
    else {
        panic!("not credited");
    };
    assert_eq!(paid, epoch);
    let admitted = octravpn_client::PreparedPrivateClient::new(client_options(
        octravpn_client::JournalMode::Resume,
        Arc::new(purchase.receipt_identity().unwrap()),
    ))
    .await
    .unwrap();
    assert_eq!(admitted.status().status.connection.sequence, 2);
    assert_eq!(admitted.status().status.purchased_totals, [1_048_576, 0]);
    assert_eq!(admitted.status().status.paid_ou, cost);
    drop(admitted);
    assert!(serde_json::from_slice::<Value>(
        &std::fs::read(client_path.join("state.json")).unwrap()
    )
    .is_err());
    let channel = operator.channel(binding.plan).await.unwrap();
    assert_eq!(channel.paid_ou, cost);
    assert_eq!(channel.purchased, vec![1_048_576, 0]);
    assert_eq!(
        payer
            .available_ou(index.view().await.unwrap().index())
            .await
            .unwrap(),
        funded - cost
    );
    {
        let calls = control.calls.lock().unwrap();
        let receipts: Vec<_> = calls
            .iter()
            .filter(|(r, _)| matches!(r.request.action, PrivateAction::Receipt { .. }))
            .collect();
        assert_eq!(receipts.len(), 3);
        assert!(receipts
            .windows(2)
            .all(|p| p[0].0.digest().unwrap() == p[1].0.digest().unwrap()));
    }
    // Commit a signed transaction before the scheduler has ever submitted it.
    // Recovery must find it without an auxiliary saved sequence/pending flag.
    let mut bundle_terms = terms.clone();
    let extra_bytes = 4096;
    let extra_cost = offered.tariff.charge(1, extra_bytes).unwrap();
    bundle_terms.additional.push(Allowance {
        traffic_class: 1,
        bytes: extra_bytes,
        max_cost_ou: extra_cost,
    });
    assert!(
        Purchase::create(payer.clone(), [198; 32], bundle_terms.clone())
            .await
            .is_err()
    );
    let second = Purchase::create(payer.clone(), [199; 32], bundle_terms.clone())
        .await
        .unwrap();
    let before_open = payer.reserved_fees(&terms.relayer_public).await.unwrap();
    let before_pending = intake.pending.transactions().unwrap();
    let second_binding = second.open(&index, &control).await.unwrap().unwrap();
    assert!(second.open(&index, &control).await.unwrap().unwrap() == second_binding);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        before_open
    );
    assert!(intake.pending.transactions().unwrap() == before_pending);
    let mut second_plan = client_plan.clone();
    second_plan.binding = second_binding;
    second_plan.prepaid_bytes = bundle_terms.prepaid(&offered.tariff).unwrap();
    let transport = Transport {
        plan: second_plan,
        journal: fixture.directory.path().join("private-second-client"),
        interface_name: "octprivate1".into(),
        hop: None,
    };
    let calls = control.calls.lock().unwrap().len();
    let mut prepared = client::prepare(&second, &transport).await;
    assert!(!prepared.resume_credit().await.unwrap());
    // The standalone scheduler cannot bypass the route's owned journal,
    // even while that journal is present and its client has not paid yet.
    assert!(second.step(services()).await.is_err());
    assert_eq!(control.calls.lock().unwrap().len(), calls);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        before_open
    );
    assert!(intake.pending.transactions().unwrap() == before_pending);
    assert!(matches!(
        prepared.step(services()).await.unwrap(),
        State::Quoted
    ));
    let invoice = {
        let calls = control.calls.lock().unwrap();
        let (request, reply) = calls.last().unwrap();
        let PrivateResult::Quote { invoice, .. } =
            serde_json::from_slice(&reply.verify(request).unwrap()).unwrap()
        else {
            panic!("not quote");
        };
        SignedInvoice::decode_private(&STANDARD.decode(invoice).unwrap()).unwrap()
    };
    let limits = Limits {
        receipt_key: second.receipt_identity().unwrap().public.0,
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: cost,
    };
    let view = index.view().await.unwrap();
    let proposal = payer
        .prepare(
            &invoice,
            &limits,
            view.index(),
            address(&payment_host::address(13)),
            &prover,
        )
        .await
        .unwrap();
    let signed = payer
        .sign_native(
            Operation::Purchase(proposal.quote),
            view.index(),
            &relayer,
            terms.fees,
        )
        .await
        .unwrap();
    let seq = signed.sequence();
    let signed_transaction = signed.transaction().clone();
    payer::qualify_reconnect(&payer, &fixture.node, &signed, false).await;
    drop(prepared);
    drop(second);
    drop(purchase);
    drop(payer);
    fixture.publish(vec![signed_transaction]).await;
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    assert_eq!(
        payer
            .native_sequences(&terms.relayer_public, Operation::Purchase(proposal.quote))
            .await
            .unwrap(),
        vec![seq]
    );
    let second = Purchase::resume(payer.clone(), [199; 32]).await.unwrap();
    let prepared = second.prepare_client(transport.clone()).await.unwrap();
    let prepared = Box::pin(bundle::finish(
        fixture,
        &payer,
        &second,
        &transport,
        prepared,
        &control,
        services(),
    ))
    .await;
    let bundled = operator.channel(transport.plan.binding.plan).await.unwrap();
    assert_eq!(bundled.purchased, vec![terms.bytes, extra_bytes]);
    assert_eq!(bundled.paid_ou, cost + extra_cost);
    // A new prepared handle must verify the exact retained payment. It cannot
    // quote, sign, stage or charge again merely to reconnect existing capacity.
    drop(prepared);
    drop(second);
    drop(payer);
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let second = Purchase::resume(payer.clone(), [199; 32]).await.unwrap();
    second.bundle_reconnect_case(&fixture.node).await;
    payer::qualify_reconnect(&payer, &fixture.node, &signed, true).await;
    let calls = control.calls.lock().unwrap().len();
    let fees = payer.reserved_fees(&terms.relayer_public).await.unwrap();
    let pending = intake.pending.transactions().unwrap();
    let mut prepared = second.prepare_client(transport.clone()).await.unwrap();
    assert!(prepared.resume_credit().await.unwrap());
    assert_eq!(control.calls.lock().unwrap().len(), calls);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        fees
    );
    assert!(intake.pending.transactions().unwrap() == pending);
    let admitted = prepared.admit().await.unwrap();
    // Six earlier preparations reserved sequences, including the interrupted
    // second-class attempts. Reopening custody must advance rather than reset
    // this independent transport counter, without buying more capacity.
    assert_eq!(admitted.status().status.connection.sequence, 7);
    assert_eq!(
        admitted.status().status.purchased_totals,
        [terms.bytes, extra_bytes]
    );
    drop(admitted);
    let mut prepared = second.prepare_client(transport.clone()).await.unwrap();
    let calls = control.calls.lock().unwrap().len();
    let fees_before_loss = payer.reserved_fees(&terms.relayer_public).await.unwrap();
    let pending_before_loss = intake.pending.transactions().unwrap();
    std::fs::remove_file(transport.journal.join("state.json")).unwrap();
    assert!(prepared.resume_credit().await.is_err());
    assert!(prepared.step(services()).await.is_err());
    assert_eq!(control.calls.lock().unwrap().len(), calls);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        fees_before_loss
    );
    assert!(intake.pending.transactions().unwrap() == pending_before_loss);
    drop(prepared);
    assert!(second.prepare_client(transport.clone()).await.is_err());
    second.lose_client_phase_case().await;
    assert!(second.step(services()).await.is_err());
    assert!(second.open(&index, &control).await.is_err());
    assert!(second.prepare_client(transport.clone()).await.is_err());
    assert_eq!(control.calls.lock().unwrap().len(), calls);
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        fees_before_loss
    );
    assert!(intake.pending.transactions().unwrap() == pending_before_loss);
    assert!(!transport.journal.join("state.json").exists());
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        5 * payment_host::FEE
    );
    assert_eq!(
        payer
            .available_ou(index.view().await.unwrap().index())
            .await
            .unwrap(),
        10 - extra_cost
    );
    let purchase = Purchase::resume(payer.clone(), [198; 32]).await.unwrap();
    // Replaying an older settled purchase preserves an execution proof already
    // extended to a later authenticated certificate.
    purchase.retain_ahead_case().await;
    let count = control.calls.lock().unwrap().len();
    assert!(
        matches!(purchase.step(services()).await.unwrap(), State::Credited { credit_id: same, .. } if same == credit_id)
    );
    assert_eq!(control.calls.lock().unwrap().len(), count);
    let admitted = octravpn_client::PreparedPrivateClient::new(client_options(
        octravpn_client::JournalMode::Resume,
        Arc::new(purchase.receipt_identity().unwrap()),
    ))
    .await
    .unwrap();
    assert_eq!(admitted.status().status.connection.sequence, 3);
    assert_eq!(admitted.status().status.purchased_totals, [1_048_576, 0]);
    drop(admitted);
    #[cfg(feature = "private-kernel-qualification")]
    let (stop, task) = if kernel {
        Box::pin(kernel::run(
            fixture,
            kernel::Operator {
                wallet: operator,
                stop,
                task,
                addresses,
                source: source.clone(),
            },
            kernel::Client {
                plan: client_plan.clone(),
                journal: client_path.clone(),
                receipt: Arc::new(purchase.receipt_identity().unwrap()),
                purchases: [hash.clone(), signed.hash().unwrap()],
            },
        ))
        .await
    } else {
        (stop, task)
    };
    assert!(index.sync(128).await.unwrap().complete);
    assert_ne!(
        index.view().await.unwrap().index().roots(),
        expected.roots()
    );
    let final_index = index.view().await.unwrap().index().clone();
    let raw = std::fs::read(path.join("wallet.sqlite")).unwrap();
    let consent = serde_json::to_vec(&terms).unwrap();
    assert!(!raw.windows(consent.len()).any(|part| part == consent));
    drop(second);
    drop(purchase);
    let jobs = Purchase::discover(payer.clone()).await.unwrap();
    assert_eq!(jobs.len(), 2);
    drop(jobs);
    let service_index_path = fixture.directory.path().join("private-service-index");
    Index::create(
        &service_index_path,
        key.clone(),
        source.clone(),
        IndexLimits::default(),
    )
    .await
    .unwrap()
    .close()
    .await;
    let master_path = fixture.directory.path().join("private-service-master.key");
    let signer_path = fixture.directory.path().join("private-service-relayer.key");
    let proving_path = fixture.directory.path().join("private-service.pk");
    crate::storage::publish(&master_path, &[198; 32]).unwrap();
    crate::storage::publish(&signer_path, &relayer.to_bytes()).unwrap();
    {
        use ark_serialize::CanonicalSerialize;
        let mut encoded = Vec::new();
        pk.serialize_compressed(&mut encoded).unwrap();
        crate::storage::publish(&proving_path, &encoded).unwrap();
    }
    let startup = crate::vpn::payments::shielded::payer::startup::Config {
        application: fixture.payments().config,
        pool: pool_config,
        operator_public: terms.target.operator.0,
        wallet: path.clone(),
        index: service_index_path,
        master_key: master_path,
        relayer_key: signer_path,
        proving_key: proving_path,
        index_limits: IndexLimits::default(),
        index_seed: None,
        control_url: tls.origin.clone(),
        control_ca_pem: tls.ca.clone(),
        control_spki: vec![tls.spki],
        control_pin: Some(
            format!(
                "127.0.0.1:{}",
                reqwest::Url::parse(&tls.origin).unwrap().port().unwrap()
            )
            .parse()
            .unwrap(),
        ),
        spend_operator_income: false,
    };
    // Startup never manufactures missing stores or overwrites an existing book.
    assert!(startup.initialize(&fixture.node).await.is_err());
    let mut needs_income = startup.clone();
    needs_income.spend_operator_income = true;
    assert!(needs_income
        .resume(intake.submission.clone())
        .await
        .is_err());
    drop(payer);
    let mut resumed = startup.resume(intake.submission.clone()).await.unwrap();
    let observed = resumed.status();
    let count = intake.pending.transactions().unwrap().len();
    let recovered = resumed.step().await;
    assert_eq!(recovered.completed, 2); // Deposit and the standalone purchase.
    assert_eq!(recovered.remaining, 1); // Route-owned purchase retains its phase.
    assert_eq!(recovered.blocked, 1); // Missing child state cannot be bypassed.
    assert_eq!(observed.borrow().completed, 2);
    assert_eq!(intake.pending.transactions().unwrap().len(), count);
    // Shutdown consumes the same service, releases its exclusive index lease,
    // and must not poll, create another job or send any control request.
    let (_stop, stopped) = tokio::sync::watch::channel(true);
    resumed.run(stopped).await.unwrap();
    let mut fresh = startup.clone();
    fresh.wallet = fixture.directory.path().join("private-consent-payer");
    fresh.index = fixture.directory.path().join("private-consent-index");
    let offline_calls = control.calls.lock().unwrap().len();
    let offline_pending = intake.pending.transactions().unwrap();
    fixture
        .node
        .suspend("offline payer initialization and consent");
    fresh.initialize(&fixture.node).await.unwrap();
    assert!(fresh.initialize(&fixture.node).await.is_err());
    assert!(fixture.node.snapshot().is_err());
    assert!(Index::resume(&fresh.index, key.clone(), source.clone())
        .await
        .is_err());
    let request = || crate::vpn::payments::shielded::payer::startup::Request::Purchase {
        id: [201; 32],
        terms: Box::new(terms.clone()),
    };
    fresh.consent(&fixture.node, vec![request()]).await.unwrap();
    fresh.consent(&fixture.node, vec![request()]).await.unwrap();
    let mut rejected = terms.clone();
    rejected.max_cost_ou -= 1;
    assert!(fresh
        .consent(
            &fixture.node,
            vec![
                crate::vpn::payments::shielded::payer::startup::Request::Purchase {
                    id: [201; 32],
                    terms: Box::new(rejected),
                }
            ]
        )
        .await
        .is_err());
    assert!(fixture.node.snapshot().is_err());
    assert_eq!(control.calls.lock().unwrap().len(), offline_calls);
    assert!(intake.pending.transactions().unwrap() == offline_pending);
    let mut missing_index = fresh.clone();
    missing_index.index = fixture.directory.path().join("missing-startup-index");
    assert!(missing_index
        .prepare_with_income(intake.submission.clone(), None)
        .await
        .is_err());
    assert!(!missing_index.index.exists());
    let mut unfunded_service = fresh
        .prepare_with_income(intake.submission.clone(), None)
        .await
        .unwrap();
    assert!(unfunded_service.view().await.is_err());
    // Startup owns the existing custody and immutable jobs, but a suspended
    // chain cannot open the spending index or contact the operator. Cancelling
    // this wait must leave it resumable when actual node admission arrives.
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(25),
        unfunded_service.step(),
    )
    .await
    .is_err());
    assert_eq!(control.calls.lock().unwrap().len(), offline_calls);
    assert!(intake.pending.transactions().unwrap() == offline_pending);
    assert!(fixture.node.snapshot().is_err());
    assert!(fixture.node.resume().await.unwrap());
    assert_eq!(unfunded_service.step().await.remaining, 1); // Open.
    assert_eq!(unfunded_service.step().await.remaining, 1); // Quote.
    let blocked = unfunded_service.step().await; // No owned notes: no signature.
    assert_eq!(blocked.blocked, 1);
    assert_eq!(blocked.completed, 0);
    assert_eq!(intake.pending.transactions().unwrap().len(), count);
    let (cancel, cancelled) = tokio::sync::watch::channel(false);
    let service_task = tokio::spawn(unfunded_service.run(cancelled));
    cancel.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), service_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let empty = Payer::resume(&fresh.wallet, key.clone(), source.clone())
        .await
        .unwrap();
    assert_eq!(empty.reserved_fees(&terms.relayer_public).await.unwrap(), 0);
    drop(empty);
    let payer = Payer::resume(&path, key, source.clone()).await.unwrap();
    assert_eq!(
        payer.reserved_fees(&terms.relayer_public).await.unwrap(),
        5 * payment_host::FEE
    );
    drop(payer);
    index.close().await;
    crate::vpn::payments::shielded::index::qualification(
        &fixture.node,
        index_path,
        index_key,
        source,
        &final_index,
    )
    .await;
    intake.close().await;
    tls.close().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
    final_index
}
