use super::*;
use crate::{payments::Journal, private_runner::Plan, wireguard};
use octravpn_core::{
    payments::{Deployment, ShieldedStatus, Tariff, TrafficClass},
    Address,
};

pub(crate) fn plan() -> (Plan, Arc<KeyPair>, KeyPair) {
    let key = Arc::new(KeyPair::from_secret_bytes(&[9; 32]));
    let operator = KeyPair::from_secret_bytes(&[7; 32]);
    let tariff = Tariff::new(
        Address::from_pubkey(&operator.public.0),
        vec![TrafficClass {
            name: "default".into(),
            rate_ou_per_mib: 1,
        }],
        vec![],
    )
    .unwrap();
    let pool = Deployment {
        domain: "ab".repeat(32),
        program: Address::from_pubkey(&[1; 32]),
    };
    let plan = Plan {
        target: PrivateTarget {
            chain_origin: [8; 32],
            pool: pool.clone(),
            directory: Address::from_pubkey(&[3; 32]),
            operator: operator.public,
        },
        binding: octravpn_core::payments::PlanBinding {
            deployment: pool,
            payer: Address::from_pubkey(&key.public.0),
            generation: 1,
            plan: 2,
            offer: 3,
            manifest_hash: tariff.hash_hex().unwrap(),
        },
        tariff,
        operator_generation: 1,
        quote_ceiling_ou: 1000,
        prepaid_bytes: vec![128],
        control_url: "https://localhost:9/".into(),
        control_ca_pem: String::new(),
        control_spki: vec![[1; 32]],
        wireguard_endpoint: "127.0.0.1:51820".into(),
    };
    (plan, key, operator)
}
fn packet(length: usize) -> Vec<u8> {
    let mut p = vec![0; length];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[1, 1, 1, 1]);
    p[20..22].copy_from_slice(&1234_u16.to_be_bytes());
    p[22..24].copy_from_slice(&53_u16.to_be_bytes());
    p[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
    let mut sum: u32 = p[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p
}
fn status(plan: &Plan, connection: octravpn_core::payments::Connect) -> ShieldedStatus {
    ShieldedStatus {
        connection,
        server_wireguard_key: [5; 32],
        tariff: plan.tariff.clone(),
        operator_generation: 1,
        quote_ceiling_ou: plan.quote_ceiling_ou,
        paid_ou: 100,
        purchased_totals: vec![128],
        committed_totals: vec![0],
        held_totals: vec![0],
        canonical_ms: 1000,
        service_sequence: 1,
    }
}

#[test]
fn private_transport_encrypts_all_records_and_resumes_uncertain_handoffs() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let (plan, key, operator) = plan();
    let mut j = Journal::open_private(&path, &plan, key.clone(), OpenMode::Create).unwrap();
    let connect = j.connect(wireguard::public_key(&key)).unwrap();
    let view = SignedShieldedStatus::sign(status(&plan, connect.request), &operator).unwrap();
    j.observe_private_status(&view).unwrap();
    let authorizations = j.purchases().unwrap();
    let bytes = packet(40);
    let pending = j
        .reserve(&bytes, octravpn_core::payments::Direction::Outbound)
        .unwrap();
    drop(pending);
    drop(j);
    let raw = std::fs::read(path.join("state.json")).unwrap();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_err());
    assert!(!raw
        .windows(plan.binding.payer.display().len())
        .any(|p| p == plan.binding.payer.display().as_bytes()));
    assert!(Journal::open(
        &path,
        plan.binding.clone(),
        plan.tariff.clone(),
        plan.quote_ceiling_ou,
        plan.prepaid_bytes.clone(),
        key.clone(),
        OpenMode::Resume
    )
    .is_err());
    assert!(Journal::open_private(
        &path,
        &plan,
        Arc::new(KeyPair::from_secret_bytes(&[10; 32])),
        OpenMode::Resume
    )
    .is_err());
    let mut changed = plan.clone();
    changed.target.chain_origin[0] ^= 1;
    assert!(Journal::open_private(&path, &changed, key.clone(), OpenMode::Resume).is_err());
    assert_eq!(std::fs::read(path.join("state.json")).unwrap(), raw);
    let mut j = Journal::open_private(&path, &plan, key.clone(), OpenMode::Resume).unwrap();
    assert_eq!(j.held_totals().unwrap(), vec![40]);
    assert_eq!(j.totals(), [0]);
    assert_eq!(
        serde_json::to_vec(&j.purchases().unwrap()).unwrap(),
        serde_json::to_vec(&authorizations).unwrap()
    );
    let connect = j.connect(wireguard::public_key(&key)).unwrap();
    assert_eq!(connect.request.sequence, 2);
    let view = SignedShieldedStatus::sign(status(&plan, connect.request), &operator).unwrap();
    j.observe_private_status(&view).unwrap();
    let reservation = j
        .reserve(&bytes, octravpn_core::payments::Direction::Outbound)
        .unwrap();
    j.confirm(reservation).unwrap();
    assert_eq!(j.totals(), [40]);
    assert_eq!(j.held_totals().unwrap(), vec![40]);
    assert!(j
        .reserve(&packet(80), octravpn_core::payments::Direction::Outbound)
        .err()
        .unwrap()
        .is::<crate::payments::PrepaidExhausted>());
    drop(j);
    let mut raw = std::fs::read(path.join("state.json")).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    std::fs::write(path.join("state.json"), &raw).unwrap();
    assert!(Journal::open_private(&path, &plan, key, OpenMode::Resume).is_err());
}

#[test]
fn private_status_refuses_regression_and_conflicting_slots_without_changing_local_caps() {
    let root = tempfile::tempdir().unwrap();
    let (plan, key, operator) = plan();
    let mut j = Journal::open_private(
        &root.path().join("plan"),
        &plan,
        key.clone(),
        OpenMode::Create,
    )
    .unwrap();
    let connect = j.connect(wireguard::public_key(&key)).unwrap();
    let mut base = status(&plan, connect.request);
    base.service_sequence = 2;
    base.committed_totals = vec![40];
    j.observe_private_status(&SignedShieldedStatus::sign(base.clone(), &operator).unwrap())
        .unwrap();
    for mutation in 0..9 {
        let mut changed = base.clone();
        match mutation {
            0 => changed.canonical_ms -= 1,
            1 => changed.service_sequence -= 1,
            2 => changed.committed_totals[0] -= 1,
            3 => changed.committed_totals[0] += 1,
            4 => changed.purchased_totals[0] -= 1,
            5 => changed.paid_ou -= 1,
            6 => changed.quote_ceiling_ou += 1,
            7 => changed.server_wireguard_key = [6; 32],
            _ => changed.operator_generation += 1,
        }
        assert!(
            j.observe_private_status(&SignedShieldedStatus::sign(changed, &operator).unwrap())
                .is_err(),
            "mutation {mutation}"
        );
        assert_eq!(j.authorized_totals(), [0]);
        assert_eq!(j.totals(), [0]);
    }
    let mut allowed = base;
    allowed.held_totals = vec![3];
    allowed.canonical_ms += 1;
    j.observe_private_status(&SignedShieldedStatus::sign(allowed.clone(), &operator).unwrap())
        .unwrap();
    allowed.service_sequence += 1;
    allowed.committed_totals[0] += 1;
    j.observe_private_status(&SignedShieldedStatus::sign(allowed, &operator).unwrap())
        .unwrap();
    j.purchases().unwrap();
    assert_eq!(j.authorized_totals(), [128]);
    assert_eq!(j.totals(), [0]);
}

#[test]
fn private_post_install_failure_poison_preserves_durable_connection_watermark() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let (plan, key, _) = plan();
    let mut j = Journal::open_private(&path, &plan, key.clone(), OpenMode::Create).unwrap();
    j.store.fail_after_install();
    assert!(j.connect(wireguard::public_key(&key)).is_err());
    assert!(j.purchases().is_err());
    drop(j);
    let mut j = Journal::open_private(&path, &plan, key.clone(), OpenMode::Resume).unwrap();
    assert_eq!(
        j.connect(wireguard::public_key(&key))
            .unwrap()
            .request
            .sequence,
        2
    );
    assert_eq!(j.authorized_totals(), [0]);
}
