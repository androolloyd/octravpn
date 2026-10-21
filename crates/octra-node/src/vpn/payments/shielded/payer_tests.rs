//! Real proofs, custody, canonical QCs and encrypted payer restart. No native
//! submission acknowledgement is substituted for a final note placement.
use super::*;
use crate::vpn::payments::shielded::{
    payer::{Incoming, Payer, Progress},
    wallet::{Receipt, Wallet},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_private_payments_experimental::pool::transaction::Prover;
use octravpn_core::sealed::Key;
use octravpn_core::{
    payments::{
        PrivateAction, PrivateRequest, PrivateResult, PrivateTarget, SignedPrivateReply,
        SignedPrivateRequest,
    },
    KeyPair,
};

struct Rpc {
    origin: String,
    http: reqwest::Client,
    target: PrivateTarget,
    key: KeyPair,
    from: u64,
}
pub(super) struct Recovery {
    requests: [SignedPrivateRequest; 3],
    payloads: [String; 3],
    pub(super) index: PoolIndex,
}
pub(super) async fn replay(fixture: &Fixture, operator: &Wallet, recovery: Recovery) {
    let service = fixture
        .node
        .bind_shielded_purchases(
            "127.0.0.1:0".parse().unwrap(),
            octravpn_node::payments::Config {
                control_listen: "127.0.0.1:0".parse().unwrap(),
                tunnel_listen: "127.0.0.1:0".parse().unwrap(),
                data_dir: fixture.directory.path().join("private-purchase-service"),
                operator_key: Arc::new(KeyPair::from_secret_bytes(&[11; 32])),
                wireguard_secret: x25519_dalek::StaticSecret::from([95; 32]),
                ip_tunnel: None,
            },
            operator,
            crate::vpn::payments::shielded::wallet::rpc::Policy {
                max_channels: 1,
                max_requests: 1,
                max_ceiling_ou: 100,
                max_invoice_lifetime_ms: 120_000,
            },
        )
        .await
        .unwrap();
    let rpc = Rpc {
        origin: format!("http://{}", service.control_addr().unwrap()),
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        target: recovery.requests[0].request.target.clone(),
        key: KeyPair::from_secret_bytes(&[27; 32]),
        from: recovery.requests[0].request.valid_from_ms,
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(service.run(stopped));
    // Old exact requests recover despite tighter limits. Fresh allocations
    // cannot exceed the new policy, and must not create a partial quote.
    for (request, expected) in recovery.requests.iter().zip(&recovery.payloads) {
        assert_eq!(&rpc.send(request).await.payload, expected);
    }
    rpc.refused(&rpc.request(
        12,
        PrivateAction::Open {
            offer: 0,
            ceiling_ou: 1,
        },
    ))
    .await;
    let PrivateAction::Quote { channel, .. } = recovery.requests[1].request.action else {
        panic!("not quote");
    };
    rpc.refused(&rpc.request(
        13,
        PrivateAction::Quote {
            channel,
            class: 0,
            bytes: 1,
            validity_ms: 1000,
        },
    ))
    .await;
    stop.send(true).unwrap();
    job.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
}
impl Rpc {
    fn request(&self, id: u8, action: PrivateAction) -> SignedPrivateRequest {
        SignedPrivateRequest::sign(
            PrivateRequest {
                target: self.target.clone(),
                id: [id; 32],
                valid_from_ms: self.from,
                expires_ms: self.from + 86_400_000,
                action,
            },
            &self.key,
        )
        .unwrap()
    }
    async fn send(&self, request: &SignedPrivateRequest) -> SignedPrivateReply {
        let response = self
            .http
            .post(format!("{}/shielded/purchase", self.origin))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "request {}",
            request.request.id[0]
        );
        let reply: SignedPrivateReply = response.json().await.unwrap();
        reply.verify(request).unwrap();
        reply
    }
    async fn refused(&self, request: &SignedPrivateRequest) {
        let response = self
            .http
            .post(format!("{}/shielded/purchase", self.origin))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
}

pub(super) async fn deposit(
    fixture: &mut Fixture,
    source: &Arc<Pool>,
    pk: &ProvingKey<Bn254>,
    index: PoolIndex,
    payer: &Payer,
    amount: u64,
) -> (PoolIndex, u64) {
    let receive = payer.address().await.unwrap();
    let draft = envelope::Draft::new(
        pool::decode_field(&receive.owner).unwrap(),
        amount,
        &receive.view_public,
    )
    .unwrap();
    let call = Call {
        quote: [0; 32],
        valid_from_ms: millis(fixture),
        expires_ms: millis(fixture) + 120_000,
        payout: address(&payment_host::address(12)),
        deposit_ou: amount,
        withdraw_ou: 0,
        boxes: [draft.ciphertext.clone(), String::new()],
    };
    let relayer = address(&payment_host::address(12));
    let context = call
        .context(&source.origin(), &address(source.circle()), &relayer)
        .unwrap();
    let note = draft.bind(&context);
    let first = index.roots().2;
    let (circuit, next) = index
        .prepare(source.domain(), &[], &[note], amount, 0, context)
        .unwrap();
    let proof = proof(&circuit, pk);
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    let membership = next.membership(first.try_into().unwrap()).unwrap();
    let incoming = || Incoming {
        slot: receive.slot,
        epoch,
        commitment: pool::encode_field(circuit.statement.outputs[0]),
        membership: &membership,
        output: 0,
        call: &call,
        relayer,
    };
    assert!(payer.receive(incoming()).await.is_err());
    call_pool(
        fixture,
        source.circle(),
        12,
        "exchange",
        args(&circuit, &call, &proof),
        amount,
    )
    .await;
    assert!(payer.receive(incoming()).await.unwrap());
    assert!(!payer.receive(incoming()).await.unwrap());
    (next, receive.slot)
}

pub(super) async fn run(
    fixture: &mut Fixture,
    source: Arc<Pool>,
    pk: Arc<ProvingKey<Bn254>>,
    index: PoolIndex,
    operator: &Wallet,
) -> Recovery {
    let path = fixture.directory.path().join("private-payer");
    let key = Key::from_bytes([86; 32]);
    let payer = Payer::create(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let prover = Prover::new(pk.clone(), &wire::key(&pk.vk).unwrap()).unwrap();
    let (mut index, first_slot) = deposit(fixture, &source, &pk, index, &payer, 60).await;
    assert_eq!(payer.available_ou(&index).await.unwrap(), 60);
    assert!(payer.available_ou(&PoolIndex::default()).await.is_err());
    let service_path = fixture.directory.path().join("private-purchase-service");
    let config = || octravpn_node::payments::Config {
        control_listen: "127.0.0.1:0".parse().unwrap(),
        tunnel_listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: service_path.clone(),
        operator_key: Arc::new(KeyPair::from_secret_bytes(&[11; 32])),
        wireguard_secret: x25519_dalek::StaticSecret::from([95; 32]),
        ip_tunnel: None,
    };
    let policy = crate::vpn::payments::shielded::wallet::rpc::Policy {
        max_channels: 16,
        max_requests: 32,
        max_ceiling_ou: 100,
        max_invoice_lifetime_ms: 120_000,
    };
    let service = fixture
        .node
        .bind_shielded_purchases("127.0.0.1:0".parse().unwrap(), config(), operator, policy)
        .await
        .unwrap();
    let mut rpc = Rpc {
        origin: format!("http://{}", service.control_addr().unwrap()),
        http: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        target: operator
            .private_target(KeyPair::from_secret_bytes(&[11; 32]).public)
            .unwrap(),
        key: KeyPair::from_secret_bytes(&[27; 32]),
        from: millis(fixture),
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(service.run(stopped));
    let open = payer
        .record_request(rpc.request(
            1,
            PrivateAction::Open {
                offer: 0,
                ceiling_ou: 100,
            },
        ))
        .await
        .unwrap();
    let (opened, again) = tokio::join!(rpc.send(&open), rpc.send(&open));
    assert_eq!(opened.payload, again.payload);
    let PrivateResult::Open { binding, .. } =
        serde_json::from_slice(&opened.verify(&open).unwrap()).unwrap()
    else {
        panic!("not open");
    };
    let channel = operator.channel(binding.plan).await.unwrap();
    assert_eq!(channel.receipt_key, rpc.key.public.0);
    let reused = rpc.request(
        1,
        PrivateAction::Open {
            offer: 0,
            ceiling_ou: 99,
        },
    );
    rpc.refused(&reused).await;
    assert!(payer.record_request(reused).await.is_err());
    rpc.refused(&rpc.request(
        9,
        PrivateAction::Open {
            offer: 0,
            ceiling_ou: 101,
        },
    ))
    .await;
    let mut wrong = rpc.request(
        10,
        PrivateAction::Open {
            offer: 0,
            ceiling_ou: 10,
        },
    );
    wrong.request.target.chain_origin[0] ^= 1;
    let wrong = SignedPrivateRequest::sign(wrong.request, &rpc.key).unwrap();
    rpc.refused(&wrong).await;
    assert!(payer.record_request(wrong).await.is_err());
    let quote_request = payer
        .record_request(rpc.request(
            2,
            PrivateAction::Quote {
                channel: channel.binding.plan,
                class: 0,
                bytes: 1_048_576,
                validity_ms: 120_000,
            },
        ))
        .await
        .unwrap();
    let other = SignedPrivateRequest::sign(
        quote_request.request.clone(),
        &KeyPair::from_secret_bytes(&[28; 32]),
    )
    .unwrap();
    rpc.refused(&other).await;
    // Discard one response, then retry concurrently: only one claimant/ceiling
    // reservation is allowed, even if the first delivery was ambiguous.
    let _ = rpc.send(&quote_request).await;
    let (quoted, again) = tokio::join!(rpc.send(&quote_request), rpc.send(&quote_request));
    assert_eq!(quoted.payload, again.payload);
    let PrivateResult::Quote { invoice, .. } =
        serde_json::from_slice(&quoted.verify(&quote_request).unwrap()).unwrap()
    else {
        panic!("not quote");
    };
    let quote = octra_private_payments_experimental::invoice::SignedInvoice::decode_private(
        &STANDARD.decode(invoice).unwrap(),
    )
    .unwrap();
    let limits = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: 10,
    };
    let relayer = address(&payment_host::address(11));
    let proposal = payer
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .unwrap();
    let id = proposal.quote;
    assert!(matches!(
        payer.progress(id).await.unwrap(),
        Some(Progress::Ready)
    ));
    assert_eq!(payer.available_ou(&index).await.unwrap(), 0);
    let retry = payer
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .unwrap();
    assert_eq!(proposal.parameters(), retry.parameters());
    let enlarged = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: 11,
    };
    assert!(payer
        .prepare(&quote, &enlarged, &index, relayer, &prover)
        .await
        .is_err());
    let change_slot = proposal.change_slot().unwrap();
    assert_ne!(change_slot, first_slot);
    drop(payer);
    let wrong = Payer::resume(&path, Key::from_bytes([87; 32]), source.clone())
        .await
        .err()
        .unwrap();
    assert!(
        wrong.to_string().contains("authentication failed"),
        "{wrong}"
    );
    let payer = Payer::resume(&path, key.clone(), source.clone())
        .await
        .unwrap();
    let saved = payer.saved_request([2; 32], rpc.key.public).await.unwrap();
    assert_eq!(saved.digest().unwrap(), quote_request.digest().unwrap());
    assert_eq!(
        payer
            .prepare(&quote, &limits, &index, relayer, &prover)
            .await
            .unwrap()
            .parameters(),
        proposal.parameters()
    );

    // A competing append invalidates the exposed proof. Rebase keeps exactly
    // the same reserved inputs and change key; the old proof cannot buy twice.
    let old_index = index;
    let (next, _) = deposit(fixture, &source, &pk, old_index.clone(), &payer, 1).await;
    index = next;
    assert!(payer
        .prepare(&quote, &limits, &old_index, relayer, &prover)
        .await
        .is_err());
    let rebased = payer
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .unwrap();
    assert_eq!(rebased.change_slot(), Some(change_slot));
    assert_ne!(rebased.parameters(), proposal.parameters());
    let old = fixture.transaction(
        11,
        source.circle(),
        OpType::CircleCall,
        proposal.parameters().clone(),
        0,
        b"exchange".to_vec(),
    );
    let before = fixture.node.snapshot().unwrap().head().clone();
    let draft = Arc::new(
        fixture
            .node
            .proposal_draft(
                &fixture.graph,
                Policy {
                    protocol: fixture.protocol,
                    genesis_time: Some(GENESIS_SECONDS),
                },
                payment_host::address(1).as_bytes(),
                fixture.now + 10.,
            )
            .await
            .unwrap(),
    );
    let refused = fixture
        .native
        .build_proposal(draft, vec![old.clone()])
        .await
        .unwrap();
    assert_eq!(refused.refused(), std::slice::from_ref(&old));
    assert!(refused.held().is_empty());
    assert!(refused.execution().transactions.is_empty());
    assert_eq!(fixture.node.snapshot().unwrap().head(), &before);
    assert_eq!(
        payer.available_ou(&index).await.unwrap(),
        1,
        "stale proposal changed canonical pool"
    );
    let first = rebased.first_output_index().unwrap();
    let next = index.observe(&rebased.statement().unwrap()).unwrap();
    let member = next.membership(first).unwrap();
    let change = next.membership(first + 1).unwrap();
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    assert!(payer
        .complete(id, &index, epoch, &member, Some(&change))
        .await
        .is_err());
    let call = rebased.call().unwrap();
    let evidence = Receipt {
        epoch,
        commitment: rebased.outputs()[0],
        membership: &member,
        call: &call,
        relayer,
    }
    .evidence()
    .unwrap();
    let receipt_request = payer
        .record_request(rpc.request(
            3,
            PrivateAction::Receipt {
                channel: channel.binding.plan,
                quote: id,
                evidence,
            },
        ))
        .await
        .unwrap();
    rpc.refused(&receipt_request).await;
    assert_eq!(
        operator
            .channel(channel.binding.plan)
            .await
            .unwrap()
            .paid_ou,
        0
    );
    let native_policy = crate::vpn::payments::shielded::payer::native::FeePolicy {
        fee_ou: payment_host::FEE,
        lifetime_budget_ou: 4 * payment_host::FEE,
        max_attempts: 4,
    };
    let native = payer
        .sign_native(
            crate::vpn::payments::shielded::payer::native::Operation::Purchase(id),
            &index,
            &payment_host::key(11),
            native_policy,
        )
        .await
        .unwrap();
    let intake = super::super::rpc_admission::Rpc::open(fixture, fixture.native.clone()).await;
    payer
        .broadcast(&intake.submission, &native, &index)
        .await
        .unwrap();
    assert!(payer.confirmed_native(&native).await.unwrap().is_none());
    rpc.refused(&receipt_request).await;
    fixture
        .publish(intake.pending.transactions().unwrap())
        .await;
    intake.close().await;
    assert_eq!(payer.confirmed_native(&native).await.unwrap(), Some(epoch));
    index = next;
    let (received, again) = tokio::join!(rpc.send(&receipt_request), rpc.send(&receipt_request));
    assert_eq!(received.payload, again.payload);
    assert_eq!(
        operator
            .channel(channel.binding.plan)
            .await
            .unwrap()
            .paid_ou,
        10
    );
    stop.send(true).unwrap();
    job.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
    let service = fixture
        .node
        .bind_shielded_purchases("127.0.0.1:0".parse().unwrap(), config(), operator, policy)
        .await
        .unwrap();
    rpc.origin = format!("http://{}", service.control_addr().unwrap());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(service.run(stopped));
    assert_eq!(rpc.send(&open).await.payload, opened.payload);
    assert_eq!(rpc.send(&quote_request).await.payload, quoted.payload);
    assert_eq!(rpc.send(&receipt_request).await.payload, received.payload);
    payer
        .receive(Incoming {
            slot: change_slot,
            epoch,
            commitment: rebased.outputs()[1],
            membership: &change,
            output: 1,
            call: &call,
            relayer,
        })
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 51);

    // This change is already funding a later intent. Finalizing the first one
    // must not erase that reservation and offer the same fifty OU again.
    let second = operator
        .issue(
            channel.binding.plan,
            0,
            1_048_576,
            120_000,
            &payment_host::key(11),
        )
        .await
        .unwrap();
    let pending = payer
        .prepare(&second, &limits, &index, relayer, &prover)
        .await
        .unwrap();
    assert_eq!(payer.available_ou(&index).await.unwrap(), 1);
    assert_eq!(
        payer.reconcile_native(&native, &index).await.unwrap(),
        Some(epoch)
    );
    assert_eq!(
        payer.reconcile_native(&native, &index).await.unwrap(),
        Some(epoch)
    );
    assert_eq!(
        payer.available_ou(&index).await.unwrap(),
        1,
        "finalizing old change reset a later reservation"
    );
    assert!(matches!(
        payer.progress(id).await.unwrap(),
        Some(Progress::Paid)
    ));
    assert!(payer
        .prepare(&quote, &limits, &index, relayer, &prover)
        .await
        .is_err());
    assert!(payer.expire(pending.quote, &index).await.is_err());

    #[allow(clippy::cast_precision_loss)] // Fixture milliseconds fit f64 exactly.
    let expired = (second.invoice.expires_ms / 1000 + 1) as f64;
    fixture.publish_at(vec![], expired).await;
    assert!(
        payer.expire(pending.quote, &index).await.is_err(),
        "clock progress alone invalidated exposed roots"
    );
    let (next, _) = deposit(fixture, &source, &pk, index, &payer, 1).await;
    index = next;
    payer.expire(pending.quote, &index).await.unwrap();
    assert!(matches!(
        payer.progress(pending.quote).await.unwrap(),
        Some(Progress::Expired)
    ));
    assert_eq!(payer.available_ou(&index).await.unwrap(), 52);

    // Two inputs, an exact purchase, and no change exercise consolidation-free
    // spending across separate received notes without a second debit on retry.
    let bytes = 5 * 1_048_576 + 1;
    let third = operator
        .issue(
            channel.binding.plan,
            0,
            bytes,
            120_000,
            &payment_host::key(11),
        )
        .await
        .unwrap();
    let large = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: bytes,
        max_cost_ou: 51,
    };
    let final_purchase = payer
        .prepare(&third, &large, &index, relayer, &prover)
        .await
        .unwrap();
    assert!(final_purchase.change_slot().is_none());
    let next = index.observe(&final_purchase.statement().unwrap()).unwrap();
    let member = next
        .membership(final_purchase.first_output_index().unwrap())
        .unwrap();
    let epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    call_pool(
        fixture,
        source.circle(),
        11,
        "exchange",
        final_purchase.parameters().clone(),
        0,
    )
    .await;
    index = next;
    payer
        .complete(final_purchase.quote, &index, epoch, &member, None)
        .await
        .unwrap();
    let call = final_purchase.call().unwrap();
    operator
        .receive(
            final_purchase.quote,
            Receipt {
                epoch,
                commitment: final_purchase.outputs()[0],
                membership: &member,
                call: &call,
                relayer,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        operator
            .channel(channel.binding.plan)
            .await
            .unwrap()
            .paid_ou,
        61
    );
    assert_eq!(payer.available_ou(&index).await.unwrap(), 1);
    let fourth = operator
        .issue(channel.binding.plan, 0, 1, 120_000, &payment_host::key(11))
        .await
        .unwrap();
    let tiny = Limits {
        receipt_key: channel.receipt_key,
        traffic_class: 0,
        max_bytes: 1,
        max_cost_ou: 1,
    };
    let cancel = payer
        .prepare(&fourth, &tiny, &index, relayer, &prover)
        .await
        .unwrap();
    assert!(
        payer.cancel(cancel.quote, &index).await.is_err(),
        "current exposed proof was abandoned unsafely"
    );
    let (next, _) = deposit(fixture, &source, &pk, index, &payer, 1).await;
    index = next;
    payer.cancel(cancel.quote, &index).await.unwrap();
    assert!(matches!(
        payer.progress(cancel.quote).await.unwrap(),
        Some(Progress::Cancelled)
    ));
    assert_eq!(payer.available_ou(&index).await.unwrap(), 2);
    assert!(payer
        .prepare(&fourth, &tiny, &index, relayer, &prover)
        .await
        .is_err());
    drop(payer);
    let payer = Payer::resume(&path, key, source).await.unwrap();
    assert!(matches!(
        payer.progress(id).await.unwrap(),
        Some(Progress::Paid)
    ));
    assert!(matches!(
        payer.progress(pending.quote).await.unwrap(),
        Some(Progress::Expired)
    ));
    assert_eq!(payer.available_ou(&index).await.unwrap(), 2);
    assert!(payer.address().await.unwrap().slot > pending.change_slot().unwrap());
    let raw = std::fs::read(path.join("wallet.sqlite-wal")).unwrap_or_default();
    assert!(!raw.windows(12).any(|b| b == b"change_slot\""));
    let wire = serde_json::to_vec(&quote_request).unwrap();
    for file in ["wallet.sqlite", "wallet.sqlite-wal"] {
        let raw = std::fs::read(path.join(file)).unwrap_or_default();
        assert!(!raw.windows(wire.len()).any(|bytes| bytes == wire));
    }
    stop.send(true).unwrap();
    job.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
    Recovery {
        requests: [open, quote_request, receipt_request],
        payloads: [opened.payload, quoted.payload, received.payload],
        index,
    }
}
