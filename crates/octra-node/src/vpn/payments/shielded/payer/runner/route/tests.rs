//! Called by the real two-operator canonical fixture. This stage makes no
//! purchase: it checks offline consent, exact cold resume and scheduler refusal.
use super::*;
use crate::vpn::payments::shielded::Pool;
use octravpn_core::{
    payments::{
        Deployment, PrivateExchange, PrivateTarget, SignedPrivateReply, SignedPrivateRequest,
    },
    sealed::Key,
};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct NoNetwork(AtomicUsize);
#[async_trait::async_trait]
impl PrivateExchange for NoNetwork {
    async fn exchange(&self, _: &SignedPrivateRequest) -> Result<SignedPrivateReply> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("route consent cannot contact an operator")
    }
}

pub(crate) async fn qualification<A: crate::Host>(
    path: &Path,
    sources: [Arc<Pool>; 2],
    services: super::super::Services<'_, A>,
    now: u64,
) {
    let key = Key::from_bytes([238; 32]);
    let payer = Payer::create(path, key.clone(), sources[0].clone())
        .await
        .unwrap();
    let mut templates = Vec::new();
    for (i, source) in sources.iter().enumerate() {
        let offer = source.offer(i as u64).await.unwrap();
        let name = format!("route-operator-{i}.invalid");
        let cert = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
        let terms = Terms {
            target: PrivateTarget {
                chain_origin: source.origin,
                pool: Deployment {
                    domain: hex::encode(source.domain.digest()),
                    program: octravpn_core::parse_native_address(source.circle()).unwrap(),
                },
                directory: octravpn_core::parse_native_address(&source.directory.config.program)
                    .unwrap(),
                operator: offer.receipt_key.unwrap(),
            },
            offer: i as u64,
            operator_generation: offer.operator_generation,
            manifest_hash: offer.manifest_hash.clone(),
            ceiling_ou: 100,
            traffic_class: 0,
            bytes: 1_048_576,
            max_cost_ou: offer.tariff.charge(0, 1_048_576).unwrap(),
            valid_from_ms: now,
            expires_ms: now + 86_400_000,
            invoice_lifetime_ms: 120_000,
            relayer_public: services.relayer.verifying_key().to_bytes(),
            fees: super::super::super::native::FeePolicy {
                fee_ou: 1000,
                lifetime_budget_ou: 4000,
                max_attempts: 4,
            },
            additional: vec![],
        };
        let endpoint = PrivateEndpoint {
            control_url: format!("https://{name}:443/"),
            control_ca_pem: cert.cert.pem(),
            control_spki: vec![octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(
                cert.cert.der(),
            )
            .unwrap()],
            wireguard_endpoint: format!("8.8.{}.4:51820", i + 4),
            pins: octravpn_client::MultiRoutePins {
                control: format!("8.8.{}.4:443", i + 4).parse().unwrap(),
                wireguard: format!("8.8.{}.4:51820", i + 4).parse().unwrap(),
            },
        };
        templates.push((terms, offer.tariff.clone(), endpoint));
    }
    let inputs = |payer: &Payer, first: u8| {
        templates
            .iter()
            .enumerate()
            .map(|(i, (terms, tariff, endpoint))| Hop {
                payer: payer.for_operator(sources[i].clone()).unwrap(),
                purchase_id: [first + i as u8; 32],
                terms: terms.clone(),
                tariff: tariff.clone(),
                endpoint: endpoint.clone(),
                journal: path
                    .parent()
                    .unwrap()
                    .join(format!("route-client-{first}-{i}")),
                interface_name: format!("octrc{i}"),
            })
            .collect::<Vec<_>>()
    };
    for mutation in 0..7 {
        let mut hops = inputs(&payer, 230);
        match mutation {
            0 => hops[1].terms.max_cost_ou -= 1,
            1 => hops[1].endpoint.pins.control = hops[0].endpoint.pins.control,
            2 => hops[1].journal = hops[0].journal.clone(),
            3 => {
                hops[1].terms.relayer_public = ed25519_dalek::SigningKey::from_bytes(&[239; 32])
                    .verifying_key()
                    .to_bytes();
            }
            4 => hops[1].interface_name = "tailscale0".into(),
            5 => hops[1].endpoint.control_spki.clear(),
            _ => hops[1].purchase_id = hops[0].purchase_id,
        }
        assert!(
            Route::create([241; 32], hops).await.is_err(),
            "preflight mutation {mutation}"
        );
        assert!(Purchase::discover(payer.clone()).await.unwrap().is_empty());
    }
    let blocked = NoNetwork(AtomicUsize::new(0));
    {
        let other = Payer::create(
            &path.with_file_name("separate-route-book"),
            Key::from_bytes([239; 32]),
            sources[1].clone(),
        )
        .await
        .unwrap();
        let mut hops = inputs(&payer, 236);
        hops[1].payer = other.clone();
        assert!(Route::create([244; 32], hops).await.is_err());
        let mut hops = inputs(&payer, 236);
        hops[1].payer = other;
        hops[1].terms.relayer_public = ed25519_dalek::SigningKey::from_bytes(&[239; 32])
            .verifying_key()
            .to_bytes();
        let separate = Route::create([244; 32], hops).await.unwrap();
        separate.check().await.unwrap();
    }
    let solo = Purchase::create(payer.clone(), [222; 32], templates[0].0.clone())
        .await
        .unwrap();
    assert!(Route::create([245; 32], inputs(&payer, 222)).await.is_err());
    super::require_unowned(&solo).await.unwrap();
    drop(solo);
    let service = || super::super::Services {
        control: &blocked,
        index: services.index,
        submission: services.submission,
        relayer: services.relayer,
        prover: services.prover,
    };
    let partial = Route::prepare([241; 32], inputs(&payer, 230)).unwrap();
    partial.require_fresh_jobs().await.unwrap();
    assert!(!partial.initialize(false).await.unwrap());
    partial
        .claim(&partial.purchases[0], 0, false, false)
        .await
        .unwrap();
    assert!(partial.check().await.is_err());
    assert!(partial.purchases[0]
        .open(services.index, &blocked)
        .await
        .is_err());
    assert!(partial.purchases[0].step(service()).await.is_err());
    assert_eq!(blocked.0.load(Ordering::SeqCst), 0);
    drop(partial);
    drop(payer);
    // All original handles close before reopening the actual encrypted book.
    let payer = Payer::resume(path, key, sources[0].clone()).await.unwrap();
    let route = Route::resume([241; 32], inputs(&payer, 230)).await.unwrap();
    assert_eq!(route.hop_count(), 2);
    route.check().await.unwrap();
    let books = || {
        inputs(&payer, 230)
            .into_iter()
            .map(|hop| hop.payer)
            .collect::<Vec<_>>()
    };
    let restored = Route::resume_stored([241; 32], books()).await.unwrap();
    assert_eq!(restored.hop_count(), 2);
    assert!(restored.profiles()[1].target == templates[1].0.target);
    restored.check().await.unwrap();
    drop(restored);
    let mut wrong = books();
    wrong.swap(0, 1);
    assert!(Route::resume_stored([241; 32], wrong).await.is_err());
    assert!(Route::resume_stored([240; 32], books()).await.is_err());
    let raw: Vec<u8> =
        sqlx::query_scalar("SELECT value FROM wallet_records WHERE kind=? AND tag=?")
            .bind(i64::from(INTENT))
            .bind(route.tag().unwrap().as_slice())
            .fetch_one(&payer.0.disk.pool)
            .await
            .unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());
    for hop in &route.consent.hops {
        assert!(!raw
            .windows(hop.endpoint.control_url.len())
            .any(|part| part == hop.endpoint.control_url.as_bytes()));
    }
    for purchase in &route.purchases {
        assert!(purchase.open(services.index, &blocked).await.is_err());
        assert!(purchase.step(service()).await.is_err());
    }
    assert_eq!(
        payer
            .reserved_fees(&services.relayer.verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    assert_eq!(blocked.0.load(Ordering::SeqCst), 0);
    for mutation in 0..4 {
        let mut hops = inputs(&payer, 230);
        match mutation {
            0 => hops.swap(0, 1),
            1 => hops[1].interface_name = "octchanged".into(),
            2 => hops[1].terms.max_cost_ou += 1,
            _ => hops[1].endpoint.control_url = "https://changed.invalid:443/".into(),
        }
        assert!(
            Route::resume([241; 32], hops).await.is_err(),
            "resume mutation {mutation}"
        );
    }
    // The network plan and armed marker are one encrypted transaction. Check
    // actual book close/reopen and refuse a previously armed missing plan.
    let marker_path = path.with_file_name("route-network-marker");
    let marker_key = Key::from_bytes([250; 32]);
    let marker = Payer::create(&marker_path, marker_key.clone(), sources[0].clone())
        .await
        .unwrap();
    let recorded = Route::create([250; 32], inputs(&marker, 250))
        .await
        .unwrap();
    let network = network(&recorded);
    recorded.network_state(Some(&network)).await.unwrap();
    assert!(recorded.load().await.unwrap().network_armed);
    assert!(recorded.load().await.unwrap().network.is_some());
    let mut bad = serde_json::to_value(&network).unwrap();
    bad["bypasses"][0]["address"] = serde_json::json!("7.7.7.7");
    let bad = serde_json::from_value(bad).unwrap();
    assert!(recorded.network_state(Some(&bad)).await.is_err());
    recorded.check().await.unwrap();
    drop(recorded);
    drop(marker);
    let marker = Payer::resume(&marker_path, marker_key, sources[0].clone())
        .await
        .unwrap();
    let books = || {
        inputs(&marker, 250)
            .into_iter()
            .map(|hop| hop.payer)
            .collect()
    };
    let recorded = Route::resume_stored([250; 32], books()).await.unwrap();
    recorded
        .load()
        .await
        .unwrap()
        .network
        .unwrap()
        .validate(&recorded.profiles())
        .unwrap();
    recorded.network_state(None).await.unwrap();
    assert!(!recorded.load().await.unwrap().network_armed);
    recorded.network_state(Some(&network)).await.unwrap();
    let mut saved = recorded.load().await.unwrap();
    saved.network = None;
    let disk = &marker.0.disk;
    let mut tx = disk.begin().await.unwrap();
    disk.replace(&mut tx, INTENT, &recorded.tag().unwrap(), &saved)
        .await
        .unwrap();
    disk.commit(tx).await.unwrap();
    assert!(recorded.check().await.is_err());
    assert!(Route::resume_stored([250; 32], books()).await.is_err());
    assert!(recorded.network_state(Some(&network)).await.is_err());
    assert!(recorded.purchases[0].step(service()).await.is_err());
    assert_eq!(
        marker
            .reserved_fees(&services.relayer.verifying_key().to_bytes())
            .await
            .unwrap(),
        0
    );
    // Missing previously committed ownership must not become a new job.
    remove(
        &route.purchases[1].payer,
        OWNER,
        route.purchases[1].tag(OWNER, 0).unwrap(),
    )
    .await;
    assert!(route.check().await.is_err());
    assert!(route.purchases[1]
        .open(services.index, &blocked)
        .await
        .is_err());
    assert!(route.purchases[1].step(service()).await.is_err());
    assert!(Route::resume([241; 32], inputs(&payer, 230)).await.is_err());
    let missing = Route::create([242; 32], inputs(&payer, 232)).await.unwrap();
    remove(
        &missing.purchases[1].payer,
        super::super::JOB,
        missing.purchases[1].tag(super::super::JOB, 0).unwrap(),
    )
    .await;
    assert!(missing.check().await.is_err());
    assert!(missing.purchases[1]
        .open(services.index, &blocked)
        .await
        .is_err());
    assert!(missing.purchases[1].step(service()).await.is_err());
    assert!(Route::resume([242; 32], inputs(&payer, 232)).await.is_err());
    let erased = Route::create([243; 32], inputs(&payer, 234)).await.unwrap();
    remove(&erased.root, INTENT, erased.tag().unwrap()).await;
    assert!(erased.check().await.is_err());
    assert!(Route::resume([243; 32], inputs(&payer, 234)).await.is_err());
    assert!(Route::create([243; 32], inputs(&payer, 234)).await.is_err());
    let mut tx = payer.0.disk.begin().await.unwrap();
    assert!(payer
        .0
        .disk
        .load::<Saved>(&mut tx, INTENT, &erased.tag().unwrap())
        .await
        .unwrap()
        .is_none());
    tx.rollback().await.unwrap();
    for i in 0..2 {
        assert!(!path
            .parent()
            .unwrap()
            .join(format!("route-client-230-{i}"))
            .exists());
    }
    assert_eq!(blocked.0.load(Ordering::SeqCst), 0);
}

fn network(route: &Route) -> octravpn_client::PrivateRouteNetwork {
    let profiles = route.profiles();
    let entry = profiles[0].endpoint.pins.wireguard;
    let controls = profiles
        .iter()
        .map(|p| p.endpoint.pins.control)
        .collect::<Vec<_>>();
    let peers = profiles[1..]
        .iter()
        .map(|p| p.endpoint.pins.wireguard)
        .collect::<Vec<_>>();
    let names = profiles
        .iter()
        .map(|p| p.interface_name.clone())
        .collect::<Vec<_>>();
    let mut hash = Sha256::new();
    hash.update(b"Octranet private route network v1\0");
    hash.update(
        serde_json::to_vec(&(entry, controls, peers, names, super::driver::SOCKET_MARK)).unwrap(),
    );
    let scope: [u8; 32] = hash.finalize().into();
    let addresses =
        std::collections::BTreeSet::from([*entry.ip(), *profiles[0].endpoint.pins.control.ip()]);
    serde_json::from_value(serde_json::json!({"version":1,"scope":scope,"mark":super::driver::SOCKET_MARK,
        "namespace":{"boot":"00000000-0000-0000-0000-000000000000","network":1},
        "bypasses":addresses.iter().map(|ip|serde_json::json!({"address":ip,"device":"eth0","index":1,"gateway":null})).collect::<Vec<_>>()
    })).unwrap()
}

async fn remove(payer: &Payer, kind: u8, tag: [u8; 32]) {
    let _gate = payer.0.gate.lock().await;
    let mut tx = payer.0.disk.begin().await.unwrap();
    assert_eq!(
        sqlx::query("DELETE FROM wallet_records WHERE kind=? AND tag=?")
            .bind(i64::from(kind))
            .bind(tag.as_slice())
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    payer.0.disk.commit(tx).await.unwrap();
}
