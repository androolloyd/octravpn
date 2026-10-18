use super::*;
use octravpn_core::{
    payments::{Deployment, PlanBinding, Tariff, TrafficClass},
    Address, KeyPair,
};

fn options(directory: &Path) -> Options {
    let hops = (0..2_u8)
        .map(|index| {
            let payer = Arc::new(KeyPair::from_secret_bytes(&[index + 5; 32]));
            let operator = KeyPair::from_secret_bytes(&[index + 15; 32]);
            let tariff = Tariff::new(
                Address::from_pubkey(&operator.public.0),
                vec![TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: 1_048_576,
                }],
                vec![],
            )
            .unwrap();
            PaymentOptions {
                plan: crate::AcceptedPlan {
                    binding: PlanBinding {
                        deployment: Deployment {
                            domain: "a".repeat(64),
                            program: Address::from_pubkey(&[1; 32]),
                        },
                        payer: Address::from_pubkey(&payer.public.0),
                        generation: 1,
                        plan: u64::from(index + 1),
                        offer: u64::from(index + 1),
                        manifest_hash: tariff.hash_hex().unwrap(),
                    },
                    tariff,
                    original_budget_ou: 200_000,
                    prepaid_bytes: vec![100_000],
                    control_url: "http://127.0.0.1/".into(),
                    wireguard_endpoint: format!("8.8.{}.4:51820", index + 4),
                },
                journal: directory.join(format!("hop-{index}")),
                receipt_key: payer,
                interface_name: format!("octroute{index}"),
                mode: crate::JournalMode::Create,
            }
        })
        .collect();
    Options {
        journal: directory.join("route"),
        hops,
        mode: crate::JournalMode::Create,
    }
}
fn pins() -> Vec<Pins> {
    vec![
        Pins {
            wireguard: "8.8.4.4:51820".parse().unwrap(),
            control: "127.0.0.1:8000".parse().unwrap(),
        },
        Pins {
            wireguard: "8.8.5.4:51820".parse().unwrap(),
            control: "127.0.0.1:8001".parse().unwrap(),
        },
    ]
}
fn resume(options: &mut Options) {
    options.mode = crate::JournalMode::Resume;
    for hop in &mut options.hops {
        hop.mode = crate::JournalMode::Resume;
    }
}
#[test]
fn each_route_requires_independent_plans_keys_paths_and_interfaces() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = options(dir.path());
    validate(&value).unwrap();
    value.hops[1].receipt_key = value.hops[0].receipt_key.clone();
    assert!(validate(&value).is_err());
    value = options(dir.path());
    value.hops[1].journal = value.journal.clone();
    assert!(validate(&value).is_err());
    value = options(dir.path());
    value.hops[1].interface_name = value.hops[0].interface_name.clone();
    assert!(validate(&value).is_err());
    value = options(dir.path());
    value.hops[1].plan.binding = value.hops[0].plan.binding.clone();
    value.hops[1].plan.tariff = value.hops[0].plan.tariff.clone();
    assert!(validate(&value).is_err());
}
#[test]
fn downstream_peers_cannot_overlap_any_direct_management_pin() {
    let mut pins = pins();
    validate_pins(&pins).unwrap();
    pins[0].control = pins[1].wireguard;
    assert!(validate_pins(&pins).is_err());
    pins = self::pins();
    pins[1].wireguard = pins[0].wireguard;
    assert!(validate_pins(&pins).is_err());
}
#[tokio::test]
async fn composite_identity_survives_restart_and_refuses_reorder_reprice_or_repin() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = options(dir.path());
    let pins = pins();
    let mtus = mtu::route_mtus(2).unwrap();
    let lease = journal::Lease::open(&value, &pins, &mtus).unwrap();
    lease.check().await.unwrap();
    assert!(journal::Lease::open(&value, &pins, &mtus).is_err());
    drop(lease);
    resume(&mut value);
    drop(journal::Lease::open(&value, &pins, &mtus).unwrap());
    value.hops.swap(0, 1);
    assert!(journal::Lease::open(&value, &pins, &mtus).is_err());
    value.hops.swap(0, 1);
    value.hops[0].plan.prepaid_bytes[0] += 1;
    assert!(journal::Lease::open(&value, &pins, &mtus).is_err());
    value.hops[0].plan.prepaid_bytes[0] -= 1;
    let mut changed = pins.clone();
    changed[1].wireguard.set_port(51821);
    assert!(journal::Lease::open(&value, &changed, &mtus).is_err());
    assert!(journal::Lease::open(&value, &pins, &[1280, 1074]).is_err());
    let lease = journal::Lease::open(&value, &pins, &mtus).unwrap();
    std::fs::remove_file(value.journal.join("state.json")).unwrap();
    assert!(lease.check().await.is_err());
    drop(lease);
    assert!(journal::Lease::open(&value, &pins, &mtus).is_err());
}
#[tokio::test]
async fn all_hop_journals_can_be_prepared_without_contacting_or_paying_an_operator() {
    let dir = tempfile::tempdir().unwrap();
    let value = options(dir.path());
    // Port0 cannot serve control; preparation still succeeds without network.
    let mut prepared = Vec::new();
    for (mut hop, pin) in value.hops.into_iter().zip(pins()) {
        let path = hop.journal.clone();
        hop.plan.control_url = "http://127.0.0.1:0/".into();
        let pin = Pins {
            control: "127.0.0.1:0".parse().unwrap(),
            ..pin
        };
        prepared.push(Prepared::new(hop, Some(pin), 1075).await.unwrap());
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.join("state.json")).unwrap()).unwrap();
        assert_eq!(state["payload"]["authorized_bytes"], serde_json::json!([0]));
        assert_eq!(state["payload"]["receipts"], serde_json::json!([null]));
        assert_eq!(state["payload"]["connection_sequence"], 1);
    }
    assert_eq!(prepared.len(), 2);
}
