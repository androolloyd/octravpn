//! Initialize and seal consent on the real reopened signed checkpoint before
//! it has any serving publication. Public leaf hints never authorize money.
use super::*;
use crate::vpn::payments::shielded::payer::{
    runner::{self, route},
    startup,
};
use octravpn_client::{MultiRoutePins, PrivateEndpoint};

pub(super) async fn run(
    fixture: &Fixture,
    original: Arc<Pool>,
    source: Arc<Pool>,
    pool: shielded::Config,
    seed: &Seed,
) -> (std::path::PathBuf, Key) {
    let node = &fixture.node;
    assert!(node.snapshot().is_err());
    let head = node.head().await.unwrap();
    let root = fixture.directory.path();
    let key = Key::from_bytes([243; 32]);
    let master = root.join("offline-master.key");
    let relayer = root.join("offline-relayer.key");
    let public = root.join("offline-public.seed");
    crate::storage::publish(&master, &[243; 32]).unwrap();
    crate::storage::publish(&relayer, &payment_host::key(13).to_bytes()).unwrap();
    crate::storage::publish(&public, &seed.encode().unwrap()).unwrap();
    let initial_endpoint = endpoint(0);
    let config = startup::Config {
        application: fixture.payments().config,
        pool,
        operator_public: KeyPair::from_secret_bytes(&[11; 32]).public.0,
        wallet: root.join("offline-payer"),
        index: root.join("offline-index"),
        master_key: master,
        relayer_key: relayer,
        proving_key: root.join("proving-key-not-needed-for-consent.pk"),
        index_limits: IndexLimits::default(),
        index_seed: Some(public),
        control_url: initial_endpoint.control_url,
        control_ca_pem: initial_endpoint.control_ca_pem,
        control_spki: initial_endpoint.control_spki,
        control_pin: Some(initial_endpoint.pins.control),
        spend_operator_income: false,
    };
    let wrong = root.join("wrong-node-index");
    assert!(Index::initialize(
        &wrong,
        key.clone(),
        original,
        config.index_limits,
        Some(seed),
        node
    )
    .await
    .is_err());
    assert!(!wrong.exists());
    let empty = root.join("offline-empty-index");
    assert!(Index::initialize(
        &empty,
        key.clone(),
        source.clone(),
        config.index_limits,
        None,
        node
    )
    .await
    .is_err());
    assert!(!empty.exists());
    for at in [8, 40, 48, 96] {
        let mut bytes = seed.encode().unwrap();
        bytes[at] ^= 1;
        let path = root.join(format!("offline-bad-{at}"));
        let bad = Seed::decode(&bytes, config.index_limits).unwrap();
        assert!(Index::initialize(
            &path,
            key.clone(),
            source.clone(),
            config.index_limits,
            Some(&bad),
            node
        )
        .await
        .is_err());
        assert!(!path.exists());
    }
    assert!(node
        .quarantine_root_at(&head, "catchup_apply_failed:invalid")
        .await
        .unwrap());
    assert!(config.initialize(node).await.is_err());
    assert!(!config.wallet.exists() && !config.index.exists());
    let ticket = node.root_quarantine_ticket();
    assert!(node.shared.complete_catchup(&ticket));
    assert!(node.snapshot().is_err());
    config.initialize(node).await.unwrap();
    assert!(config.initialize(node).await.is_err());
    assert!(node.snapshot().is_err());
    assert!(Index::resume(&config.index, key.clone(), source.clone())
        .await
        .is_err());
    let index = Index::initialize(
        &root.join("offline-direct-index"),
        key.clone(),
        source.clone(),
        config.index_limits,
        Some(seed),
        node,
    )
    .await
    .unwrap();
    assert!(index.view().await.is_err());
    assert!(index.sync(1).await.is_err());
    index.close().await;
    let payer = Payer::resume(&config.wallet, key, source.clone())
        .await
        .unwrap();
    assert!(runner::Purchase::discover(payer.clone())
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(13).verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    drop(payer);

    // Initialization does not need proving material. Route consent seals its
    // existing path, but parsing the key belongs to service startup.
    assert!(!config.proving_key.exists());
    let unparsed = b"deliberately invalid proving key: offline consent must not parse it";
    crate::storage::publish(&config.proving_key, unparsed).unwrap();

    let mut configs = Vec::new();
    let mut intents = Vec::new();
    for i in 0..2 {
        let mut hop = config.clone();
        let endpoint = endpoint(i);
        hop.operator_public = KeyPair::from_secret_bytes(&[11 + i; 32]).public.0;
        hop.control_url.clone_from(&endpoint.control_url);
        hop.control_ca_pem.clone_from(&endpoint.control_ca_pem);
        hop.control_spki.clone_from(&endpoint.control_spki);
        hop.control_pin = Some(endpoint.pins.control);
        let tariff = if i == 0 {
            fixture.tariff.clone()
        } else {
            second_tariff()
        };
        let terms = runner::Terms {
            target: octravpn_core::payments::PrivateTarget {
                pool: octravpn_core::payments::Deployment {
                    domain: hex::encode(source.domain().digest()),
                    program: octravpn_core::parse_native_address(&hop.pool.circle).unwrap(),
                },
                directory: octravpn_core::parse_native_address(&hop.application.program).unwrap(),
                operator: octravpn_core::PublicKey(hop.operator_public),
                chain_origin: source.origin(),
            },
            offer: u64::from(i),
            operator_generation: 1,
            manifest_hash: tariff.hash_hex().unwrap(),
            ceiling_ou: 100,
            traffic_class: 0,
            bytes: 1_048_576,
            max_cost_ou: tariff.charge(0, 1_048_576).unwrap(),
            valid_from_ms: millis(fixture),
            expires_ms: millis(fixture) + 86_400_000,
            invoice_lifetime_ms: 120_000,
            relayer_public: payment_host::key(13).verifying_key().to_bytes(),
            fees: FeePolicy {
                fee_ou: payment_host::FEE,
                lifetime_budget_ou: 10 * payment_host::FEE,
                max_attempts: 10,
            },
            additional: vec![],
        };
        intents.push(startup::route::Consent {
            purchase_id: [240 + i; 32],
            terms,
            tariff,
            endpoint,
            journal: root.join(format!("offline-client-{i}")),
            interface_name: format!("octoffline{i}"),
        });
        configs.push(hop);
    }
    let route_config = startup::route::Config {
        id: [239; 32],
        hops: configs,
        chain_dns: std::collections::BTreeMap::new(),
    };
    route_config.consent(node, intents, false).await.unwrap();
    let payer = Payer::resume(&config.wallet, Key::from_bytes([243; 32]), source)
        .await
        .unwrap();
    let second = &route_config.hops[1];
    let other_source = Arc::new(
        Pool::new(
            Arc::new(
                node.payments(
                    second.application.clone(),
                    octravpn_core::Address::from_pubkey(&second.operator_public),
                )
                .unwrap(),
            ),
            second.pool.clone(),
        )
        .unwrap(),
    );
    let other = payer.for_operator(other_source).unwrap();
    assert_eq!(
        runner::Purchase::discover(payer.clone())
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        runner::Purchase::discover(other.clone())
            .await
            .unwrap()
            .len(),
        1
    );
    let route = route::Route::resume_stored([239; 32], vec![payer.clone(), other])
        .await
        .unwrap();
    assert_eq!(route.hop_count(), 2);
    assert_eq!(
        payer
            .reserved_fees(&payment_host::key(13).verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    assert_eq!(node.head().await.unwrap(), head);
    assert!(node.snapshot().is_err());
    assert_eq!(std::fs::read(&config.proving_key).unwrap(), unparsed);
    (config.index, Key::from_bytes([243; 32]))
}

fn endpoint(i: u8) -> PrivateEndpoint {
    let name = format!("offline-{i}.invalid");
    let cert = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
    PrivateEndpoint {
        control_url: format!("https://{name}:443/"),
        control_ca_pem: cert.cert.pem(),
        control_spki: vec![octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(
            cert.cert.der(),
        )
        .unwrap()],
        wireguard_endpoint: format!("8.8.{}.4:51820", 4 + i),
        pins: MultiRoutePins {
            control: format!("8.8.{}.4:443", 4 + i).parse().unwrap(),
            wireguard: format!("8.8.{}.4:51820", 4 + i).parse().unwrap(),
        },
    }
}
