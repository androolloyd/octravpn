//! Actual Node/Native/QC publication and historical private-note authority.
//! Fixed native keys and ephemeral proof setup are local test material only.
use super::*;
use crate::vpn::payments::shielded::{self, Inclusion, Limits, Pool};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use octra_node_runtime::circle_assets::CanonicalAssets;
use octra_private_payments_experimental::{
    invoice::{Consent, Invoice, Settlement, SignedInvoice},
    native_stealth,
    pool::{self, call::Call, envelope, wire, Domain, PoolCircuit, PoolIndex, Spend, SpendKey},
};
use rand::rngs::OsRng;

fn compiled(source: &str) -> Vec<u8> {
    STANDARD
        .decode(
            octra_node_runtime::program::build::legacy(source.as_bytes(), true, true).unwrap()
                ["bytecode"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
}
async fn call_pool(
    fixture: &mut Fixture,
    address: &str,
    who: u8,
    method: &str,
    params: Value,
    amount: u64,
) -> Value {
    let tx = fixture.transaction(
        who,
        address,
        OpType::CircleCall,
        params,
        amount,
        method.as_bytes().to_vec(),
    );
    fixture.publish(vec![tx]).await
}
fn proof(circuit: &PoolCircuit, key: &ProvingKey<Bn254>) -> String {
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), key, &mut OsRng)
            .unwrap();
    assert!(octra_node_runtime::groth16::verify(
        &wire::key(&key.vk).unwrap(),
        &wire::proof(&proof).unwrap(),
        &wire::inputs(&circuit.statement)
    ));
    STANDARD.encode(wire::proof(&proof).unwrap())
}
fn args(circuit: &PoolCircuit, call: &Call, proof: &str) -> Value {
    let s = &circuit.statement;
    let field = |f| hex::encode(pool::encode_field(f));
    json!([
        field(s.new_notes),
        field(s.new_spent),
        s.new_count,
        s.withdraw,
        std::str::from_utf8(&call.payout).unwrap(),
        call.valid_from_ms,
        call.expires_ms,
        hex::encode(call.quote),
        field(s.authorization),
        field(s.nullifiers[0]),
        field(s.nullifiers[1]),
        field(s.outputs[0]),
        field(s.outputs[1]),
        call.boxes[0],
        call.boxes[1],
        proof
    ])
}
fn address(value: &str) -> [u8; 47] {
    value.as_bytes().try_into().unwrap()
}
fn millis(fixture: &Fixture) -> u64 {
    octra_node_protocol::consensus::policy::time_of_seconds(fixture.now)
        .unwrap()
        .try_into()
        .unwrap()
}

#[tokio::test]
async fn canonical_shielded_purchase_requires_real_history_and_survives_spend_expiry_and_resume() {
    Box::pin(private_scenario(false)).await;
}

#[cfg(feature = "private-kernel-qualification")]
#[tokio::test]
#[ignore = "requires the isolated Linux fixture in docker/native-vpn/private-kernel.sh"]
async fn canonical_shielded_kernel_transport_survives_client_operator_restart() {
    Box::pin(private_scenario(true)).await;
}

async fn private_scenario(kernel: bool) {
    let mut fixture = Box::pin(Fixture::with_capacity(
        None,
        Application::Circle,
        4 * payment_host::STAKE,
    ))
    .await;
    #[cfg(feature = "private-kernel-qualification")]
    if kernel {
        runner_flow::exex::start(&fixture.node, fixture.directory.path()).await;
    }
    let directory = Arc::new(fixture.payments());
    let origin: [u8; 32] = hex::decode(&fixture.domain).unwrap().try_into().unwrap();
    let sample_domain = Domain::new(&origin, &address(&payment_host::address(14))).unwrap();
    let sample_key = SpendKey::random();
    let sample_note = pool::Note::new(sample_key.owner(sample_domain), 1, &[9; 32]).unwrap();
    let (sample, _) = PoolIndex::default()
        .prepare(sample_domain, &[], &[sample_note], 1, 0, [9; 32])
        .unwrap();
    let pk = Arc::new(
        Groth16::<Bn254>::generate_random_parameters_with_reduction(sample, &mut OsRng).unwrap(),
    );
    let vk = wire::key(&pk.vk).unwrap();
    let code = compiled(&pool::app::source(&origin, &vk, 1_000_000).unwrap());
    let factory_payload = super::super::circle_tests::payload(&compiled(pool::app::FACTORY));
    let deploy = octra_node_protocol::circle_program::Deploy::from_document(
        &octra_node_protocol::native_json::Document::parse(
            &serde_json::to_vec(&factory_payload).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let snapshot = fixture.node.snapshot().unwrap();
    let nonce = account_store::load(
        &StateBatch::from_snapshot(snapshot.state().clone()),
        payment_host::address(11).as_bytes(),
    )
    .unwrap()
    .unwrap()
    .nonce
    .successor();
    let factory =
        String::from_utf8(deploy.id(payment_host::address(11).as_bytes(), nonce)).unwrap();
    let tx = fixture.transaction(
        11,
        &factory,
        OpType::CircleDeploy,
        factory_payload,
        0,
        vec![],
    );
    fixture.publish(vec![tx]).await;
    let spawned = call_pool(
        &mut fixture,
        &factory,
        11,
        "deploy_pool",
        json!([STANDARD
            .encode(serde_json::to_vec(&super::super::circle_tests::payload(&code)).unwrap())]),
        0,
    )
    .await;
    let pool_address = spawned["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"] == "ShieldedPoolDeployed")
        .unwrap()["values"][0]
        .as_str()
        .unwrap()
        .to_owned();
    call_pool(&mut fixture, &pool_address, 11, "initialize", json!([]), 0).await;
    let config = shielded::Config {
        circle: pool_address.clone(),
        factory,
        custody_cap_ou: 1_000_000,
        verification_key_b64: STANDARD.encode(&vk),
        verification_key_sha256: hex::encode(Sha256::digest(&vk)),
    };
    let mut wrong_pin = config.clone();
    wrong_pin.verification_key_sha256 = "f".repeat(64);
    assert!(Pool::new(directory.clone(), wrong_pin).is_err());
    let mut wrong_terms = config.clone();
    wrong_terms.custody_cap_ou -= 1;
    let wrong_pool = Pool::new(directory.clone(), wrong_terms).unwrap();
    let source = Arc::new(Pool::new(directory.clone(), config.clone()).unwrap());
    let domain = source.domain();
    let recipient = address(&pool_address);
    let relayer = address(&payment_host::address(11));
    let payer = SpendKey::random();
    let operator = SpendKey::random();
    let claimant = payment_host::key(41);
    let view = native_stealth::view_secret(&[41; 32]);
    let payer_view = native_stealth::view_secret(&[42; 32]);
    let draft = envelope::Draft::new(
        payer.owner(domain),
        100,
        &native_stealth::view_public(&payer_view),
    )
    .unwrap();
    let deposit_call = Call {
        quote: [0; 32],
        valid_from_ms: millis(&fixture),
        expires_ms: millis(&fixture) + 120_000,
        payout: address(&payment_host::address(12)),
        deposit_ou: 100,
        withdraw_ou: 0,
        boxes: [draft.ciphertext.clone(), String::new()],
    };
    let context = deposit_call
        .context(&origin, &recipient, &address(&payment_host::address(12)))
        .unwrap();
    let funded_note = draft.bind(&context);
    let (deposit, mut index) = PoolIndex::default()
        .prepare(
            domain,
            &[],
            std::slice::from_ref(&funded_note),
            100,
            0,
            context,
        )
        .unwrap();
    let deposit_proof = proof(&deposit, &pk);
    call_pool(
        &mut fixture,
        &pool_address,
        12,
        "exchange",
        args(&deposit, &deposit_call, &deposit_proof),
        100,
    )
    .await;

    let terms = directory.offer(0).await.unwrap();
    let tariff = terms.tariff.clone();
    let destination = Settlement::ShieldedPool {
        circle: recipient,
        note_owner: pool::encode_field(operator.owner(domain)),
    };
    let invoice = Invoice {
        chain_origin: origin,
        directory_circle: address(&fixture.program),
        operator_key: payment_host::key(11).verifying_key().to_bytes(),
        bond_generation: terms.operator_generation,
        offer: 0,
        tariff_hash: hex::decode(&terms.manifest_hash)
            .unwrap()
            .try_into()
            .unwrap(),
        receipt_key: payment_host::key(21).verifying_key().to_bytes(),
        recipient_key: claimant.verifying_key().to_bytes(),
        settlement: destination.clone(),
        nonce: [77; 32],
        traffic_class: 0,
        bytes: 1_048_576,
        rate_ou_per_mib: 10,
        valid_from_ms: terms.canonical_ms,
        expires_ms: terms.canonical_ms + 120_000,
    };
    let consent = Consent {
        chain_origin: origin,
        directory_circle: invoice.directory_circle,
        operator_key: invoice.operator_key,
        bond_generation: invoice.bond_generation,
        offer: 0,
        tariff_hash: invoice.tariff_hash,
        receipt_key: invoice.receipt_key,
        settlement: destination,
        traffic_class: 0,
        rate_ou_per_mib: 10,
        max_bytes: 1_048_576,
        max_cost_ou: 10,
        canonical_ms: terms.canonical_ms,
        active_from_ms: terms.offer_start_ms,
        purchase_deadline_ms: None,
    };
    let signed = SignedInvoice::sign(invoice, &payment_host::key(11), &claimant).unwrap();
    let purchase = pool::purchase::prepare(&signed, &consent).unwrap();
    let change = envelope::Draft::new(
        payer.owner(domain),
        90,
        &native_stealth::view_public(&payer_view),
    )
    .unwrap();
    let call = purchase.call(Some(&change), address(&payment_host::address(12)));
    let context = call.context(&origin, &recipient, &relayer).unwrap();
    let notes = [purchase.output.bind(&context), change.bind(&context)];
    let (payment, proposed) = index
        .prepare(
            domain,
            &[Spend {
                note: &funded_note,
                key: &payer,
                index: 0,
            }],
            &notes,
            0,
            0,
            context,
        )
        .unwrap();
    let payment_proof = proof(&payment, &pk);
    let membership = proposed.membership(1).unwrap();
    let limits = Limits {
        receipt_key: signed.invoice.receipt_key,
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: 10,
    };
    let payment_epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    let commitment = pool::encode_field(notes[0].commitment(domain));
    let inclusion = || Inclusion {
        epoch: payment_epoch,
        commitment,
        membership: &membership,
        call: &call,
        relayer,
        invoice: &signed,
        tariff: &tariff,
        limits: &limits,
        spend_key: &operator,
        view_secret: &view,
    };
    assert!(
        source.confirm(inclusion()).await.is_err(),
        "speculative proof minted funding"
    );
    call_pool(
        &mut fixture,
        &pool_address,
        11,
        "exchange",
        args(&payment, &call, &payment_proof),
        0,
    )
    .await;
    index = index.observe(&payment.statement).unwrap();
    let funded = source.confirm(inclusion()).await.unwrap();
    assert!(wrong_pool.confirm(inclusion()).await.is_err());
    assert!(funded.admissible());
    assert_eq!(funded.note().value(), 10);
    assert_eq!(funded.bytes, 1_048_576);
    assert_eq!(funded.amount_ou, 10);
    assert_eq!(funded.epoch, payment_epoch);
    assert_eq!(funded.quote, purchase.quote);
    let credit_id = funded.credit_id;
    let mut called = false;
    funded
        .with_current(|_| {
            called = true;
            Ok(())
        })
        .unwrap();
    assert!(called);
    let mut corrupt = membership.clone();
    let mut one = [0; 32];
    one[31] = 1;
    corrupt.siblings[0] += pool::decode_field(&one).unwrap();
    assert!(source
        .confirm(Inclusion {
            membership: &corrupt,
            ..inclusion()
        })
        .await
        .is_err());
    assert!(source
        .confirm(Inclusion {
            epoch: payment_epoch - 1,
            ..inclusion()
        })
        .await
        .is_err());
    let wrong = SpendKey::random();
    assert!(source
        .confirm(Inclusion {
            spend_key: &wrong,
            ..inclusion()
        })
        .await
        .is_err());
    let wrong_limits = Limits {
        receipt_key: payment_host::key(22).verifying_key().to_bytes(),
        traffic_class: 0,
        max_bytes: 1_048_576,
        max_cost_ou: 10,
    };
    assert!(source
        .confirm(Inclusion {
            limits: &wrong_limits,
            ..inclusion()
        })
        .await
        .is_err());
    let mut public_call = purchase.call(Some(&change), address(&payment_host::address(12)));
    public_call.deposit_ou = 10;
    assert!(source
        .confirm(Inclusion {
            call: &public_call,
            ..inclusion()
        })
        .await
        .is_err());
    let mut changed_head = fixture.node.snapshot().unwrap().head().clone();
    changed_head.cursor.epoch.0 += 1;
    assert!(CanonicalAssets::at(directory.history.clone(), changed_head)
        .await
        .is_err());

    // Spent operator income remains a final purchase; credit identity is the
    // note itself rather than a recyclable wallet, transaction or epoch slot.
    let withdraw_call = Call {
        quote: [0; 32],
        valid_from_ms: millis(&fixture),
        expires_ms: millis(&fixture) + 120_000,
        payout: address(&payment_host::address(14)),
        deposit_ou: 0,
        withdraw_ou: 10,
        boxes: [String::new(), String::new()],
    };
    let context = withdraw_call
        .context(&origin, &recipient, &relayer)
        .unwrap();
    let (withdraw, _) = index
        .prepare(
            domain,
            &[Spend {
                note: &notes[0],
                key: &operator,
                index: 1,
            }],
            &[],
            0,
            10,
            context,
        )
        .unwrap();
    let withdraw_proof = proof(&withdraw, &pk);
    call_pool(
        &mut fixture,
        &pool_address,
        11,
        "exchange",
        args(&withdraw, &withdraw_call, &withdraw_proof),
        0,
    )
    .await;
    assert!(
        !funded.admissible(),
        "a new publication did not revoke the held funding lease"
    );
    let after_spend = source.confirm(inclusion()).await.unwrap();
    assert!(
        source
            .confirm(Inclusion {
                epoch: payment_epoch + 1,
                ..inclusion()
            })
            .await
            .is_err(),
        "old note accepted under a later creation epoch"
    );
    assert!(after_spend.admissible());
    assert_eq!(after_spend.credit_id, credit_id);
    index = index.observe(&withdraw.statement).unwrap();

    // Wallet key slots are reserved before issuing terms. Neither a quote nor
    // a speculative proof buys traffic; one canonical note buys bytes once.
    use octravpn_core::sealed::Key;
    use shielded::wallet::{Receipt, Wallet};
    let wallet_path = fixture.directory.path().join("private-wallet");
    let service_path = fixture.directory.path().join("private-transport");
    let wallet_key = Key::from_bytes([83; 32]);
    Box::pin(startup_flow::run(&fixture, config.clone())).await;
    let wallet = Wallet::create(&wallet_path, wallet_key.clone(), source.clone())
        .await
        .unwrap();
    assert!(
        Wallet::resume(&wallet_path, wallet_key.clone(), source.clone())
            .await
            .is_err()
    );
    let channel = wallet
        .create_channel(0, payment_host::key(25).verifying_key().to_bytes(), 100)
        .await
        .unwrap();
    let cid = channel.binding.plan;
    use octravpn_core::payments::{
        Connect, SignedConnect, SignedShieldedStatus, SignedUsage, Usage,
    };
    use octravpn_node::payments::{
        Authority as TrafficAuthority, Funds, Settlement as TrafficSettlement,
    };
    let service_config = || octravpn_node::payments::Config {
        control_listen: "127.0.0.1:0".parse().unwrap(),
        tunnel_listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: service_path.clone(),
        operator_key: Arc::new(octravpn_core::KeyPair::from_secret_bytes(&[11; 32])),
        wireguard_secret: x25519_dalek::StaticSecret::from([93; 32]),
        ip_tunnel: None,
    };
    let mut exposed = service_config();
    exposed.control_listen = "0.0.0.0:0".parse().unwrap();
    assert!(wallet.bind_service(exposed).await.is_err());
    assert!(!service_path.exists());
    let mut detached_directory = fixture.payments();
    detached_directory.shared = Arc::new(crate::Shared::new());
    let detached_pool = Arc::new(Pool::new(Arc::new(detached_directory), config.clone()).unwrap());
    let detached_wallet = Wallet::create(
        &fixture.directory.path().join("detached-wallet"),
        wallet_key.clone(),
        detached_pool,
    )
    .await
    .unwrap();
    assert!(fixture
        .node
        .bind_shielded(
            "127.0.0.1:0".parse().unwrap(),
            service_config(),
            &detached_wallet
        )
        .await
        .is_err());
    assert!(!service_path.exists());
    drop(detached_wallet);
    let service = fixture
        .node
        .bind_shielded("127.0.0.1:0".parse().unwrap(), service_config(), &wallet)
        .await
        .unwrap();
    let control_origin = format!("http://{}", service.control_addr().unwrap());
    let (service_stop, stopped) = tokio::sync::watch::channel(false);
    let service_job = tokio::spawn(service.run(stopped));
    let meter_path = service_path.join(hex::encode(
        channel.binding.session_id().unwrap().as_bytes(),
    ));
    let client_key = octravpn_core::KeyPair::from_secret_bytes(&[25; 32]);
    let usage = |bytes| {
        SignedUsage::sign(
            Usage::from_binding(channel.binding.clone(), 0, 1, bytes).unwrap(),
            &client_key,
        )
        .unwrap()
    };
    assert!(TrafficSettlement::confirm(&wallet, usage(1)).await.is_err());
    let empty = TrafficAuthority::plan(&wallet, &channel.binding)
        .await
        .unwrap();
    assert_eq!(empty.redeemed_totals, [0, 0]);
    assert!(matches!(
        empty.funds,
        Funds::Shielded {
            quote_ceiling_ou: 100,
            paid_ou: 0
        }
    ));
    let meter = wallet
        .open_meter(cid, meter_path.clone(), false)
        .await
        .unwrap();
    assert!(meter.reserve_class(0, 1).await.is_err());
    let private_quote = wallet
        .issue(cid, 0, 1_048_576, 120_000, &payment_host::key(11))
        .await
        .unwrap();
    let unfunded_quote = wallet
        .issue(cid, 0, 1_048_576, 120_000, &payment_host::key(11))
        .await
        .unwrap();
    assert_ne!(
        private_quote.invoice.recipient_key,
        unfunded_quote.invoice.recipient_key
    );
    assert_ne!(private_quote.invoice.nonce, unfunded_quote.invoice.nonce);
    let quote_id = private_quote.id().unwrap();
    let fresh = directory.offer(0).await.unwrap();
    let private_consent = Consent {
        chain_origin: origin,
        directory_circle: address(&fixture.program),
        operator_key: payment_host::key(11).verifying_key().to_bytes(),
        bond_generation: fresh.operator_generation,
        offer: 0,
        tariff_hash: hex::decode(&fresh.manifest_hash)
            .unwrap()
            .try_into()
            .unwrap(),
        receipt_key: channel.receipt_key,
        settlement: private_quote.invoice.settlement.clone(),
        traffic_class: 0,
        rate_ou_per_mib: fresh.tariff.classes()[0].rate_ou_per_mib,
        max_bytes: 1_048_576,
        max_cost_ou: 10,
        canonical_ms: fresh.canonical_ms,
        active_from_ms: fresh.offer_start_ms,
        purchase_deadline_ms: None,
    };
    let private_purchase = pool::purchase::prepare(&private_quote, &private_consent).unwrap();
    let change80 = envelope::Draft::new(
        payer.owner(domain),
        80,
        &native_stealth::view_public(&payer_view),
    )
    .unwrap();
    let private_call = private_purchase.call(Some(&change80), address(&payment_host::address(12)));
    let context = private_call.context(&origin, &recipient, &relayer).unwrap();
    let private_notes = [
        private_purchase.output.bind(&context),
        change80.bind(&context),
    ];
    let (private_payment, next_index) = index
        .prepare(
            domain,
            &[Spend {
                note: &notes[1],
                key: &payer,
                index: 2,
            }],
            &private_notes,
            0,
            0,
            context,
        )
        .unwrap();
    let private_proof = proof(&private_payment, &pk);
    let private_membership = next_index.membership(3).unwrap();
    let private_commitment = pool::encode_field(private_notes[0].commitment(domain));
    let private_epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    let receipt = || Receipt {
        epoch: private_epoch,
        commitment: private_commitment,
        membership: &private_membership,
        call: &private_call,
        relayer,
    };
    assert!(wallet.receive(quote_id, receipt()).await.is_err());
    assert_eq!(wallet.channel(cid).await.unwrap().paid_ou, 0);
    call_pool(
        &mut fixture,
        &pool_address,
        11,
        "exchange",
        args(&private_payment, &private_call, &private_proof),
        0,
    )
    .await;
    index = next_index;
    let (first, retry) = tokio::join!(
        wallet.receive(quote_id, receipt()),
        wallet.receive(quote_id, receipt())
    );
    let first = first.unwrap();
    let retry = retry.unwrap();
    assert_eq!(u8::from(first.new_note) + u8::from(retry.new_note), 1);
    assert_eq!(
        u8::from(first.new_capacity) + u8::from(retry.new_capacity),
        1
    );
    assert_eq!(first.credit_id, retry.credit_id);
    assert!(wallet
        .receive(unfunded_quote.id().unwrap(), receipt())
        .await
        .is_err());
    let bought = wallet.channel(cid).await.unwrap();
    assert_eq!(bought.paid_ou, 10);
    assert_eq!(bought.purchased, [1_048_576, 0]);
    wallet.reconcile_meter(cid, &meter).await.unwrap();
    meter
        .reserve_class(0, 100)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(meter.reserve_class(1, 1).await.is_err());
    drop(meter);
    let meter = wallet
        .open_meter(cid, meter_path.clone(), true)
        .await
        .unwrap();
    assert_eq!(meter.snapshot().unwrap().committed_totals, [100, 0]);
    drop(meter);

    // Shared service resumes this exact encrypted meter; no separate counter
    // store or public channel-balance fiction is introduced by admission.
    let request = SignedConnect::sign(
        Connect {
            binding: channel.binding.clone(),
            sequence: 1,
            wireguard_key: [94; 32],
        },
        &client_key,
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let response = http
        .post(format!("{control_origin}/payments/connect"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let response = http
        .post(format!("{control_origin}/shielded/connect"))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let status: SignedShieldedStatus = response.json().await.unwrap();
    status.verify().unwrap();
    assert_eq!(status.status.connection, request.request);
    assert_eq!(status.status.purchased_totals, [1_048_576, 0]);
    assert_eq!(status.status.committed_totals, [100, 0]);
    assert_eq!(status.status.paid_ou, 10);
    assert_eq!(status.status.quote_ceiling_ou, 100);
    let excess = http
        .post(format!("{control_origin}/shielded/usage"))
        .json(&usage(1_048_577))
        .send()
        .await
        .unwrap();
    assert!(!excess.status().is_success());
    let covered = http
        .post(format!("{control_origin}/shielded/usage"))
        .json(&usage(1_048_576))
        .send()
        .await
        .unwrap();
    assert!(covered.status().is_success());
    assert_eq!(
        covered.json::<Value>().await.unwrap(),
        json!({"prepaid":true})
    );
    let held_grant = TrafficAuthority::plan(&wallet, &channel.binding)
        .await
        .unwrap();
    let mut handoffs = 0;
    held_grant
        .guard
        .current(&mut || {
            handoffs += 1;
            Ok(())
        })
        .unwrap();

    // A distinct, real payment to the same quote is still our owned money,
    // but its signed byte entitlement must not be granted a second time.
    let change70 = envelope::Draft::new(
        payer.owner(domain),
        70,
        &native_stealth::view_public(&payer_view),
    )
    .unwrap();
    let duplicate_call =
        private_purchase.call(Some(&change70), address(&payment_host::address(12)));
    let context = duplicate_call
        .context(&origin, &recipient, &relayer)
        .unwrap();
    let duplicate_notes = [
        private_purchase.output.bind(&context),
        change70.bind(&context),
    ];
    let (duplicate_payment, duplicate_index) = index
        .prepare(
            domain,
            &[Spend {
                note: &private_notes[1],
                key: &payer,
                index: 4,
            }],
            &duplicate_notes,
            0,
            0,
            context,
        )
        .unwrap();
    let duplicate_proof = proof(&duplicate_payment, &pk);
    let duplicate_membership = duplicate_index.membership(5).unwrap();
    let duplicate_epoch = fixture.node.snapshot().unwrap().head().cursor.epoch.0 + 1;
    call_pool(
        &mut fixture,
        &pool_address,
        11,
        "exchange",
        args(&duplicate_payment, &duplicate_call, &duplicate_proof),
        0,
    )
    .await;
    let extra = wallet
        .receive(
            quote_id,
            Receipt {
                epoch: duplicate_epoch,
                commitment: pool::encode_field(duplicate_notes[0].commitment(domain)),
                membership: &duplicate_membership,
                call: &duplicate_call,
                relayer,
            },
        )
        .await
        .unwrap();
    assert!(!held_grant.guard.live());
    assert!(held_grant
        .guard
        .current(&mut || {
            handoffs += 1;
            Ok(())
        })
        .is_err());
    assert_eq!(handoffs, 1);
    let refreshed = TrafficAuthority::plan(&wallet, &channel.binding)
        .await
        .unwrap();
    refreshed
        .guard
        .current(&mut || {
            handoffs += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(handoffs, 2);
    assert!(extra.new_note && !extra.new_capacity);
    assert_eq!(
        wallet.channel(cid).await.unwrap().purchased,
        bought.purchased
    );

    let rpc_recovery = Box::pin(payer_flow::run(
        &mut fixture,
        source.clone(),
        pk.clone(),
        duplicate_index,
        &wallet,
    ))
    .await;
    let runner_index = Box::pin(runner_flow::run(
        &mut fixture,
        source.clone(),
        pk.clone(),
        rpc_recovery.index.clone(),
        config.clone(),
        kernel,
    ))
    .await;
    let journal_index = Box::pin(movement_flow::run(
        &mut fixture,
        source.clone(),
        pk.clone(),
        runner_index,
    ))
    .await;
    let income_index = Box::pin(native_journal_flow::run(
        &mut fixture,
        source.clone(),
        pk.clone(),
        journal_index,
    ))
    .await;

    // Database pages and WAL receive ciphertext only, including invoice and
    // relationship fields. A key mismatch cannot reinterpret/reset the book.
    let raw_db = std::fs::read(wallet_path.join("wallet.sqlite")).unwrap();
    let raw_wal = std::fs::read(wallet_path.join("wallet.sqlite-wal")).unwrap_or_default();
    let encoded_quote = private_quote.encode_private().unwrap();
    for bytes in [&raw_db, &raw_wal] {
        for secret in [
            encoded_quote.as_slice(),
            bought.tariff.canonical_bytes().unwrap().as_slice(),
        ] {
            assert!(!bytes.windows(secret.len()).any(|chunk| chunk == secret));
        }
    }
    assert!(std::fs::read(meter_path.join("meter.json"))
        .unwrap()
        .starts_with(b"OVPNSE01"));
    service_stop.send(true).unwrap();
    service_job.await.unwrap().unwrap();
    assert!(fixture.node.resume().await.unwrap());
    drop(wallet);
    let error = Wallet::resume(&wallet_path, Key::from_bytes([84; 32]), source.clone())
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("authentication failed"),
        "{error}"
    );
    let wallet = Wallet::resume(&wallet_path, wallet_key.clone(), source.clone())
        .await
        .unwrap();
    assert_eq!(wallet.channel(cid).await.unwrap().paid_ou, 10);
    Box::pin(payer_flow::replay(&fixture, &wallet, rpc_recovery)).await;
    let next_quote = wallet
        .issue(cid, 0, 1_048_576, 120_000, &payment_host::key(11))
        .await
        .unwrap();
    assert_ne!(
        next_quote.invoice.recipient_key,
        private_quote.invoice.recipient_key
    );
    assert_ne!(
        next_quote.invoice.recipient_key,
        unfunded_quote.invoice.recipient_key
    );
    drop(wallet);
    #[allow(clippy::cast_precision_loss)] // Fixture milliseconds fit f64 exactly.
    let later = ((signed.invoice.expires_ms + 1000) as f64 / 1000.).max(fixture.now + 10.);
    fixture.publish_at(vec![], later).await;
    let expired_quote = source.confirm(inclusion()).await.unwrap();
    assert!(
        expired_quote.admissible(),
        "quote expiry erased a prior canonical purchase"
    );
    assert_eq!(expired_quote.credit_id, credit_id);
    fixture
        .node
        .suspend("private funding fixture lost synchronization");
    assert!(!expired_quote.admissible());
    assert!(source.confirm(inclusion()).await.is_err());
    assert!(fixture.node.resume().await.unwrap());
    assert!(!expired_quote.admissible());
    assert!(source.confirm(inclusion()).await.unwrap().admissible());
    fixture
        .call(11, "request_operator_unstake", json!([]), 0)
        .await;
    let retired = source.confirm(inclusion()).await.unwrap();
    assert_eq!(retired.credit_id, credit_id);
    assert!(!retired.admissible());
    assert!(retired.with_current(|_| Ok(())).is_err());
    let final_index = Box::pin(income_flow::run(
        &mut fixture,
        source.clone(),
        config.clone(),
        pk.clone(),
        income_index,
    ))
    .await;
    let recovery = Box::pin(index_flow::run(
        &mut fixture,
        source.clone(),
        pk.clone(),
        final_index,
    ))
    .await;
    Box::pin(bootstrap_flow::run(
        &mut fixture,
        source.clone(),
        config.clone(),
        pk.clone(),
        recovery,
    ))
    .await;
    #[cfg(feature = "private-kernel-qualification")]
    if kernel {
        runner_flow::exex::finish(&fixture.node, fixture.directory.path()).await;
    }
    fixture.node.shutdown().await.unwrap();

    // Reopen the actual canonical/ExEx stores. The immutable purchase ID and
    // historical clock must survive, while the operator's stop remains final.
    // shutdown suspends services; dropping the old node releases its exclusive
    // writer lock. Historical readers and revoked leases may remain alive.
    let Fixture {
        node,
        directory: retained_files,
        graph,
        ..
    } = fixture;
    drop(node);
    let store = CanonicalStore::open(
        &retained_files.path().join("node.db"),
        directory.history.chain(),
    )
    .await
    .unwrap();
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&retained_files.path().join("exex.db"))
            .await
            .unwrap(),
    );
    let reopened = Node::open(
        store,
        Authority {
            chain: directory.history.chain().clone(),
        },
        circle_host::runtime(),
        Arc::new(UnavailableHost),
        checkpoints,
    )
    .await
    .unwrap()
    .with_view_graph(graph)
    .unwrap();
    assert!(reopened.resume().await.unwrap());
    #[cfg(feature = "private-kernel-qualification")]
    if kernel {
        runner_flow::exex::reopened(&reopened, retained_files.path()).await;
    }
    let restarted_directory = Arc::new(
        reopened
            .payments(directory.config.clone(), directory.operator.clone())
            .unwrap(),
    );
    let restarted = Arc::new(Pool::new(restarted_directory, config).unwrap());
    let recovered = restarted.confirm(inclusion()).await.unwrap();
    assert_eq!(recovered.credit_id, credit_id);
    assert_eq!(recovered.purchased_ms, funded.purchased_ms);
    assert!(!recovered.admissible());
    let recovered_wallet = Wallet::resume(&wallet_path, wallet_key, restarted)
        .await
        .unwrap();
    let retired_grant = TrafficAuthority::plan(&recovered_wallet, &channel.binding)
        .await
        .unwrap();
    assert!(!retired_grant.admissible);
    assert!(retired_grant.guard.current(&mut || Ok(())).is_err());
    assert_eq!(
        recovered_wallet.channel(cid).await.unwrap().purchased,
        bought.purchased
    );
    let meter = recovered_wallet
        .open_meter(cid, meter_path, true)
        .await
        .unwrap();
    assert_eq!(meter.snapshot().unwrap().committed_totals, [100, 0]);
    assert!(recovered_wallet
        .issue(cid, 0, 1, 60_000, &payment_host::key(11))
        .await
        .is_err());
    assert!(
        source.confirm(inclusion()).await.is_err(),
        "closed node still minted funding authority"
    );
    reopened.shutdown().await.unwrap();
}

#[path = "shielded/movement_tests.rs"]
mod movement_flow;
#[path = "shielded/native_journal_tests.rs"]
mod native_journal_flow;
#[path = "shielded/payer_tests.rs"]
mod payer_flow;

#[path = "shielded/income_tests.rs"]
mod income_flow;

#[path = "shielded/index_tests.rs"]
mod index_flow;

#[path = "shielded/bootstrap_tests.rs"]
mod bootstrap_flow;

#[path = "shielded/income_floor_tests.rs"]
mod income_floor_flow;

#[path = "shielded/recovery_tests.rs"]
mod recovery_flow;

#[path = "shielded/startup_tests.rs"]
mod startup_flow;

#[path = "shielded/runner_tests.rs"]
mod runner_flow;
