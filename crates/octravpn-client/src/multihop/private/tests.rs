use super::*;
use octravpn_core::{payments::Tariff, Address, KeyPair};

fn options(root: &Path) -> Options {
    let hops = (0..2_u8)
        .map(|i| {
            let (mut plan, _, _) = crate::payments::private::tests::plan();
            let key = Arc::new(KeyPair::from_secret_bytes(&[i + 60; 32]));
            let operator = KeyPair::from_secret_bytes(&[i + 70; 32]);
            plan.target.operator = operator.public;
            plan.binding.payer = Address::from_pubkey(&key.public.0);
            plan.binding.plan = u64::from(i) + 1;
            plan.tariff = Tariff::new(
                Address::from_pubkey(&operator.public.0),
                plan.tariff.classes().to_vec(),
                vec![],
            )
            .unwrap();
            plan.binding.manifest_hash = plan.tariff.hash_hex().unwrap();
            let name = format!("operator-{i}.invalid");
            let cert = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
            plan.control_url = format!("https://{name}:443/");
            plan.control_ca_pem = cert.cert.pem();
            plan.control_spki =
                vec![
                    octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(cert.cert.der())
                        .unwrap(),
                ];
            plan.wireguard_endpoint = format!("8.8.{}.4:51820", i + 4);
            PrivatePaymentOptions {
                plan,
                journal: root.join(format!("hop-{i}")),
                receipt_key: key,
                interface_name: format!("octprivate{i}"),
                mode: JournalMode::Create,
            }
        })
        .collect();
    Options {
        journal: root.join("route"),
        hops,
        pins: vec![
            RoutePins {
                wireguard: "8.8.4.4:51820".parse().unwrap(),
                control: "8.8.4.4:443".parse().unwrap(),
            },
            RoutePins {
                wireguard: "8.8.5.4:51820".parse().unwrap(),
                control: "8.8.5.4:443".parse().unwrap(),
            },
        ],
        mode: JournalMode::Create,
    }
}
fn resume(options: &mut Options) {
    options.mode = JournalMode::Resume;
    for hop in &mut options.hops {
        hop.mode = JournalMode::Resume;
    }
}

#[test]
fn private_routes_accept_independent_octranet_pools_and_do_not_infer_operator_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = options(dir.path());
    let entry_operator = o.hops[0].plan.target.operator;
    let exit = &mut o.hops[1].plan;
    exit.target.pool.program = Address::from_pubkey(&[91; 32]);
    exit.target.pool.domain = "b".repeat(64);
    exit.target.directory = Address::from_pubkey(&[92; 32]);
    exit.binding.deployment = exit.target.pool.clone();
    validate(&o).unwrap();
    // A provider may operate several endpoints. Independent sessions, receipt
    // keys and IPs are enforced; different public keys cannot prove ownership.
    let exit = &mut o.hops[1].plan;
    exit.target.operator = entry_operator;
    exit.tariff = Tariff::new(
        Address::from_pubkey(&entry_operator.0),
        exit.tariff.classes().to_vec(),
        vec![],
    )
    .unwrap();
    exit.binding.manifest_hash = exit.tariff.hash_hex().unwrap();
    validate(&o).unwrap();
    o.hops[1].plan.target.chain_origin[0] ^= 1;
    assert!(validate(&o).is_err());
}
#[test]
fn private_route_requires_independent_hops_and_complete_transport_pins_before_io() {
    let dir = tempfile::tempdir().unwrap();
    for change in 0..13 {
        let mut o = options(dir.path());
        validate(&o).unwrap();
        match change {
            0 => {
                o.pins.pop();
            }
            1 => o.hops[1].receipt_key = o.hops[0].receipt_key.clone(),
            2 => o.hops[1].journal = o.journal.clone(),
            3 => o.hops[1].interface_name = o.hops[0].interface_name.clone(),
            4 => o.hops[1].plan.target.operator = o.hops[0].plan.target.operator,
            5 => o.hops[1].plan.target.chain_origin[0] ^= 1,
            6 => o.pins[1].wireguard.set_port(9),
            7 => o.pins[1].control = "127.0.0.1:443".parse().unwrap(),
            8 => o.hops[1].plan.control_url = "http://operator-1.invalid/".into(),
            9 => o.hops[1].plan.control_spki.clear(),
            10 => o.hops[1].mode = JournalMode::Resume,
            11 => o.hops[1].interface_name = "tailscale0".into(),
            _ => o.hops[1].receipt_key = Arc::new(KeyPair::from_secret_bytes(&[93; 32])),
        }
        assert!(validate(&o).is_err(), "mutation {change}");
        assert!(!o.journal.exists());
        assert!(o.hops.iter().all(|hop| !hop.journal.exists()));
    }
}
#[tokio::test]
async fn private_route_identity_is_encrypted_and_refuses_changed_order_keys_pins_or_caps() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = options(dir.path());
    let pins = validate(&o).unwrap();
    let mtus = mtu::route_mtus(2).unwrap();
    let held = lease(&o, &pins, &mtus).unwrap();
    held.check().await.unwrap();
    assert!(lease(&o, &pins, &mtus).is_err());
    let raw = std::fs::read(o.journal.join("state.json")).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());
    for hop in &o.hops {
        assert!(!raw
            .windows(hop.plan.binding.payer.display().len())
            .any(|w| w == hop.plan.binding.payer.display().as_bytes()));
        assert!(!raw
            .windows(hop.plan.control_url.len())
            .any(|w| w == hop.plan.control_url.as_bytes()));
    }
    drop(held);
    resume(&mut o);
    drop(lease(&o, &pins, &mtus).unwrap());
    o.hops.swap(0, 1);
    assert!(lease(&o, &pins, &mtus).is_err());
    o.hops.swap(0, 1);
    o.hops[1].plan.prepaid_bytes[0] += 1;
    assert!(lease(&o, &pins, &mtus).is_err());
    o.hops[1].plan.prepaid_bytes[0] -= 1;
    let key = o.hops[1].receipt_key.clone();
    o.hops[1].receipt_key = Arc::new(KeyPair::from_secret_bytes(&[91; 32]));
    assert!(lease(&o, &pins, &mtus).is_err());
    o.hops[1].receipt_key = key;
    let mut changed = pins.clone();
    changed[1].control.set_port(444);
    assert!(lease(&o, &changed, &mtus).is_err());
    assert!(lease(&o, &pins, &[1280, 1074]).is_err());
    assert!(journal::Lease::identity(&o.journal, o.mode, serde_json::json!([]), None).is_err());
    assert_eq!(std::fs::read(o.journal.join("state.json")).unwrap(), raw);
    let held = lease(&o, &pins, &mtus).unwrap();
    std::fs::remove_file(o.journal.join("state.json")).unwrap();
    assert!(held.check().await.is_err());
    drop(held);
    assert!(lease(&o, &pins, &mtus).is_err());
}
#[tokio::test]
async fn every_private_hop_prepares_encrypted_state_without_dns_or_payment() {
    let dir = tempfile::tempdir().unwrap();
    let o = options(dir.path());
    let pins = validate(&o).unwrap();
    let mtus = mtu::route_mtus(2).unwrap();
    let mut local = Vec::new();
    // Both origins are .invalid and pins are public. Local preparation must
    // finish without making a control request, creating TUNs or buying bytes.
    for ((hop, pin), mtu) in o.hops.into_iter().zip(pins).zip(mtus) {
        let path = hop.journal.clone();
        local.push(
            private_runner::Local::new(hop, Some(pin), mtu)
                .await
                .unwrap(),
        );
        assert!(serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(path.join("state.json")).unwrap()
        )
        .is_err());
    }
    assert_eq!(local.len(), 2);
}
#[test]
fn private_route_does_not_accept_missing_pins_or_a_public_plan() {
    let dir = tempfile::tempdir().unwrap();
    let o = options(dir.path());
    let hop = &o.hops[0];
    let doc = serde_json::json!({"journal":o.journal,"hops":[{
        "plan":hop.plan,"journal":hop.journal,"receipt_key":"missing","interface_name":hop.interface_name
    }]});
    assert!(serde_json::from_value::<RoutePlan>(doc).is_err());
    let mut public = serde_json::to_value(&hop.plan).unwrap();
    public.as_object_mut().unwrap().remove("target");
    assert!(serde_json::from_value::<crate::AcceptedPrivatePlan>(public).is_err());
}
