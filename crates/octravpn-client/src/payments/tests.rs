use super::*;
use octravpn_core::{
    payments::{Deployment, IpPrefix, Protocol, Selector, SignedStatus, Status, TrafficClass},
    Address,
};
use std::{fs, net::Ipv4Addr, path::PathBuf};

struct Fixture {
    root: tempfile::TempDir,
    path: PathBuf,
    binding: PlanBinding,
    tariff: Tariff,
    key: Arc<KeyPair>,
    operator: Arc<KeyPair>,
    budget: u64,
    prepaid: Vec<u64>,
}

impl Fixture {
    fn new(budget: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let key = Arc::new(KeyPair::from_secret_bytes(&[0x9d; 32]));
        let operator = Arc::new(KeyPair::from_secret_bytes(&[7; 32]));
        let tariff = Tariff::new(
            Address::from_pubkey(&operator.public.0),
            vec![
                TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: 1,
                },
                TrafficClass {
                    name: "premium".into(),
                    rate_ou_per_mib: 10,
                },
            ],
            vec![Selector {
                prefix: IpPrefix::new(Ipv4Addr::new(8, 8, 8, 8).into(), 32).unwrap(),
                protocol: Protocol::Udp,
                port: Some(53),
                traffic_class: 1,
            }],
        )
        .unwrap();
        let binding = PlanBinding {
            deployment: Deployment {
                domain: "a".repeat(64),
                program: Address::from_pubkey(&[1; 32]),
            },
            payer: Address::from_pubkey(&key.public.0),
            generation: 1,
            plan: 2,
            offer: 3,
            manifest_hash: tariff.hash_hex().unwrap(),
        };
        Self {
            path: root.path().join("plan"),
            root,
            binding,
            tariff,
            key,
            operator,
            budget,
            prepaid: vec![1024, 1024],
        }
    }

    fn open(&self, mode: OpenMode) -> Result<Journal> {
        Journal::open(
            &self.path,
            self.binding.clone(),
            self.tariff.clone(),
            self.budget,
            self.prepaid.clone(),
            self.key.clone(),
            mode,
        )
    }

    fn state(&self) -> Envelope {
        serde_json::from_slice(&fs::read(self.path.join("state.json")).unwrap()).unwrap()
    }

    fn replace(&self, state: State) {
        let envelope = Envelope {
            checksum: checksum(&state).unwrap(),
            payload: state,
        };
        fs::write(
            self.path.join("state.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn service_equivocation_is_durably_retained_and_refuses_more_payment() {
    let fixture = Fixture::new(10_000);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let base = Status {
        binding: fixture.binding.clone(),
        connect_sequence: 1,
        client_wireguard_key: [11; 32],
        server_wireguard_key: [12; 32],
        tariff: fixture.tariff.clone(),
        original_budget_ou: fixture.budget,
        remaining_ou: fixture.budget,
        committed_totals: vec![0, 0],
        redeemed_totals: fixture.prepaid.clone(),
        canonical_ms: 100,
        claim_deadline_ms: 1_000,
    };
    let missing = SignedStatus::sign(base.clone(), &fixture.operator).unwrap();
    assert!(journal.observe_service_status(&missing, 1).is_err());
    let wrong_generation =
        SignedStatus::sign_with_receipts(base.clone(), &fixture.operator, 2, 1).unwrap();
    assert!(journal
        .observe_service_status(&wrong_generation, 1)
        .is_err());
    let first = SignedStatus::sign_with_receipts(base.clone(), &fixture.operator, 1, 1).unwrap();
    journal.observe_service_status(&first, 1).unwrap();
    let mut changed = base;
    changed.committed_totals[0] = 1;
    let conflicting = SignedStatus::sign_with_receipts(changed, &fixture.operator, 1, 1).unwrap();
    assert!(journal.observe_service_status(&conflicting, 1).is_err());
    let [a, b] = journal.state.service_conflict.clone().unwrap();
    assert!(SignedServiceReceipt::slash_params(&a, &b).is_ok());
    assert!(journal.observe_service_status(&first, 1).is_err());
    drop(journal);
    let exported = service_evidence(&fixture.path).unwrap();
    assert_eq!(exported["method"], "slash_double_service_receipt");
    assert_eq!(exported["params"][0], fixture.binding.plan);
    assert_eq!(exported["params"][1], 0);
    let recovered = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(recovered.state.service_conflict, Some([a, b]));
}

/// A complete UDP datagram with a valid IPv4 header checksum. IPv4 permits a
/// zero UDP checksum; the tunnel authenticates the complete raw packet.
fn packet(premium: bool, inbound: bool, payload: usize) -> Vec<u8> {
    let remote = if premium { [8, 8, 8, 8] } else { [1, 1, 1, 1] };
    let local = [198, 18, 0, 2];
    let mut packet = vec![0; 28 + payload];
    let length = u16::try_from(packet.len()).unwrap();
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    let (source, destination, source_port, destination_port) = if inbound {
        (remote, local, 53_u16, 40_000_u16)
    } else {
        (local, remote, 40_000_u16, 53_u16)
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(length - 20).to_be_bytes());
    let mut sum = packet[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[test]
fn explicit_purchases_precede_delivery_and_retry_identically_across_restart() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let ordinary = packet(false, false, 8);
    assert!(journal.check(&ordinary, Direction::Outbound).is_err());
    let first = journal.connect([3; 32]).unwrap();
    first.verify().unwrap();
    assert_eq!(first.request.sequence, 1);
    let purchases = journal.purchases().unwrap();
    assert_eq!(journal.totals(), [0, 0]);
    assert_eq!(journal.authorized_totals(), fixture.prepaid);
    assert_eq!(purchases.len(), 2);
    for (class, receipt) in purchases.iter().enumerate() {
        receipt.verify().unwrap();
        assert_eq!(receipt.usage.total_bytes, fixture.prepaid[class]);
        assert!(receipt
            .usage
            .signing_message()
            .unwrap()
            .starts_with("Octranet prepaid v1|"));
    }
    let persisted = fs::read(fixture.path.join("state.json")).unwrap();
    assert_eq!(journal.purchases().unwrap(), purchases);
    assert_eq!(
        fs::read(fixture.path.join("state.json")).unwrap(),
        persisted
    );
    let outgoing = packet(true, false, 10);
    let incoming = packet(true, true, 14);
    journal.count(&ordinary, Direction::Outbound).unwrap();
    journal.count(&outgoing, Direction::Outbound).unwrap();
    journal.count(&incoming, Direction::Inbound).unwrap();
    let totals = vec![
        ordinary.len() as u64,
        (outgoing.len() + incoming.len()) as u64,
    ];
    assert_eq!(journal.totals(), totals);
    assert_eq!(journal.purchases().unwrap(), purchases);
    assert_eq!(journal.remaining_ou().unwrap(), 98);
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(resumed.totals(), totals);
    assert_eq!(resumed.purchases().unwrap(), purchases);
    assert_eq!(resumed.connect([4; 32]).unwrap().request.sequence, 2);
    assert_eq!(resumed.authorized_totals(), fixture.prepaid);
    assert_eq!(resumed.remaining_ou().unwrap(), 98);
}

#[test]
fn finite_class_targets_and_aggregate_purchase_price_are_checked_before_creation() {
    for (budget, target) in [
        (1, vec![1024, 1024]),
        (100, vec![1]),
        (100, vec![0, 0]),
        (1, vec![0, u64::MAX]),
    ] {
        let mut fixture = Fixture::new(budget);
        fixture.prepaid = target;
        assert!(fixture.open(OpenMode::Create).is_err());
        assert!(!fixture.path.exists());
    }
}

#[test]
fn zero_unspent_ou_keeps_only_the_purchased_byte_allowance() {
    let mut fixture = Fixture::new(1);
    fixture.prepaid = vec![56, 0];
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.purchases().unwrap();
    assert_eq!(journal.remaining_ou().unwrap(), 0);
    let ordinary = packet(false, false, 0);
    journal.count(&ordinary, Direction::Outbound).unwrap();
    journal
        .count(&packet(false, true, 0), Direction::Inbound)
        .unwrap();
    assert!(journal.check(&ordinary, Direction::Outbound).is_err());
    assert!(journal
        .check(&packet(true, false, 0), Direction::Outbound)
        .is_err());
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(resumed.purchases().unwrap().len(), 1);
    assert!(resumed.check(&ordinary, Direction::Outbound).is_err());
    assert_eq!(resumed.remaining_ou().unwrap(), 0);
}

#[test]
fn pending_and_uncertain_handoffs_consume_prepaid_bytes_but_not_new_purchases() {
    let mut fixture = Fixture::new(1);
    fixture.prepaid = vec![56, 0];
    let raw = packet(false, false, 0);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let purchases = journal.purchases().unwrap();
    let reservation = journal.reserve(&raw, Direction::Outbound).unwrap();
    assert_eq!(journal.held_totals().unwrap(), [28, 0]);
    assert_eq!(journal.purchases().unwrap(), purchases);
    journal.cancel(reservation).unwrap();
    assert_eq!(journal.held_totals().unwrap(), [0, 0]);
    let _uncertain = journal.reserve(&raw, Direction::Outbound).unwrap();
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(resumed.uncertain_totals(), [28, 0]);
    assert_eq!(resumed.totals(), [0, 0]);
    assert_eq!(resumed.purchases().unwrap(), purchases);
    resumed.count(&raw, Direction::Outbound).unwrap();
    assert!(resumed.check(&raw, Direction::Outbound).is_err());
    assert_eq!(resumed.authorized_totals(), [56, 0]);
}

#[test]
fn ambiguous_purchase_commit_is_poisoned_and_resume_keeps_identical_signatures() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.store.fail_after_install();
    assert!(journal.purchases().is_err());
    assert!(journal.purchases().is_err());
    assert!(journal.connect([1; 32]).is_err());
    let installed = fixture
        .state()
        .payload
        .receipts
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(installed.len(), 2);
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(resumed.purchases().unwrap(), installed);
    assert_eq!(resumed.totals(), [0, 0]);
    assert_eq!(resumed.authorized_totals(), fixture.prepaid);
}

#[test]
fn failed_purchase_write_and_invalid_packets_do_not_release_authorization() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.store.fail_next_write();
    assert!(journal.purchases().is_err());
    assert!(journal.pending_receipts().is_err());
    assert_eq!(fixture.state().payload.authorized_bytes, [0, 0]);
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    let purchases = resumed.purchases().unwrap();
    let mut invalid = packet(false, false, 0);
    invalid[10] ^= 1;
    assert!(resumed.count(&invalid, Direction::Outbound).is_err());
    assert_eq!(resumed.totals(), [0, 0]);
    assert_eq!(resumed.purchases().unwrap(), purchases);
}

#[test]
fn installed_confirmation_recovers_without_recounting_or_reauthorizing() {
    let mut fixture = Fixture::new(1);
    fixture.prepaid = vec![56, 0];
    let raw = packet(false, false, 0);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let purchases = journal.purchases().unwrap();
    let reservation = journal.reserve(&raw, Direction::Outbound).unwrap();
    journal.store.fail_after_install();
    assert!(journal.confirm(reservation).is_err());
    assert!(journal.check(&raw, Direction::Outbound).is_err());
    drop(journal);
    let mut resumed = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(resumed.totals(), [28, 0]);
    assert_eq!(resumed.uncertain_totals(), [0, 0]);
    assert_eq!(resumed.purchases().unwrap(), purchases);
    resumed.count(&raw, Direction::Outbound).unwrap();
    assert!(resumed.check(&raw, Direction::Outbound).is_err());
    assert_eq!(resumed.authorized_totals(), [56, 0]);
}

#[test]
fn postpaid_versions_and_lease_markers_are_never_reinterpreted() {
    let fixture = Fixture::new(100);
    drop(fixture.open(OpenMode::Create).unwrap());
    let state = fixture.state().payload;
    let mut legacy = state.clone();
    legacy.version = 1;
    fixture.replace(legacy);
    assert!(fixture.open(OpenMode::Resume).is_err());
    fixture.replace(state);
    fs::write(
        fixture.path.join("writer.lock"),
        b"Octranet client payment journal v1\n",
    )
    .unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
}

#[test]
fn immutable_binding_tariff_original_budget_and_key_are_required_on_resume() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let purchases = journal.purchases().unwrap();
    drop(journal);
    let mut bindings = Vec::new();
    for field in 0..6 {
        let mut binding = fixture.binding.clone();
        match field {
            0 => binding.deployment.domain = "c".repeat(64),
            1 => binding.deployment.program = Address::from_pubkey(&[9; 32]),
            2 => binding.payer = Address::from_pubkey(&[9; 32]),
            3 => binding.generation += 1,
            4 => binding.plan += 1,
            _ => binding.offer += 1,
        }
        bindings.push(binding);
    }
    for binding in bindings {
        assert!(Journal::open(
            &fixture.path,
            binding,
            fixture.tariff.clone(),
            fixture.budget,
            fixture.prepaid.clone(),
            fixture.key.clone(),
            OpenMode::Resume
        )
        .is_err());
    }
    assert!(Journal::open(
        &fixture.path,
        fixture.binding.clone(),
        fixture.tariff.clone(),
        99,
        fixture.prepaid.clone(),
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    assert!(Journal::open(
        &fixture.path,
        fixture.binding.clone(),
        fixture.tariff.clone(),
        100,
        fixture.prepaid.clone(),
        Arc::new(KeyPair::from_secret_bytes(&[8; 32])),
        OpenMode::Resume
    )
    .is_err());
    let mut classes = fixture.tariff.classes().to_vec();
    classes[0].rate_ou_per_mib += 1;
    let tariff = Tariff::new(
        fixture.tariff.operator().clone(),
        classes,
        fixture.tariff.selectors().to_vec(),
    )
    .unwrap();
    let mut binding = fixture.binding.clone();
    binding.manifest_hash = tariff.hash_hex().unwrap();
    assert!(Journal::open(
        &fixture.path,
        binding,
        tariff,
        100,
        fixture.prepaid.clone(),
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    let mut changed_target = fixture.prepaid.clone();
    changed_target[0] += 1;
    assert!(Journal::open(
        &fixture.path,
        fixture.binding.clone(),
        fixture.tariff.clone(),
        fixture.budget,
        changed_target,
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    let mut journal = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(journal.totals(), [0, 0]);
    assert_eq!(journal.authorized_totals(), fixture.prepaid);
    assert_eq!(journal.purchases().unwrap(), purchases);
}

#[test]
fn one_writer_only_and_missing_or_partial_initialization_never_resets() {
    let fixture = Fixture::new(100);
    assert!(fixture.open(OpenMode::Resume).is_err());
    let journal = fixture.open(OpenMode::Create).unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
    assert!(fixture.open(OpenMode::Create).is_err());
    drop(journal);
    drop(fixture.open(OpenMode::Resume).unwrap());
    fs::remove_file(fixture.path.join("state.json")).unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
    assert!(fixture.open(OpenMode::Create).is_err());
    let empty = Fixture::new(100);
    fs::create_dir(&empty.path).unwrap();
    assert!(empty.open(OpenMode::Create).is_err());
    assert!(empty.open(OpenMode::Resume).is_err());
    let missing_lock = Fixture::new(100);
    drop(missing_lock.open(OpenMode::Create).unwrap());
    fs::remove_file(missing_lock.path.join("writer.lock")).unwrap();
    assert!(missing_lock.open(OpenMode::Resume).is_err());
    assert!(!missing_lock.path.join("writer.lock").exists());
}

#[test]
fn missing_live_state_or_lease_stops_authorization_without_recreation() {
    for remove in ["state.json", "writer.lock"] {
        let fixture = Fixture::new(100);
        let mut journal = fixture.open(OpenMode::Create).unwrap();
        journal.purchases().unwrap();
        journal
            .count(&packet(false, false, 0), Direction::Outbound)
            .unwrap();
        fs::remove_file(fixture.path.join(remove)).unwrap();
        assert!(journal.purchases().is_err());
        assert!(journal.connect([1; 32]).is_err());
        assert!(journal.pending_receipts().is_err());
        assert!(!fixture.path.join(remove).exists());
    }
}

#[test]
fn corrupt_truncated_unknown_or_forged_state_is_refused_without_repair() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.purchases().unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.purchases().unwrap();
    drop(journal);
    let original = fs::read(fixture.path.join("state.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["payload"]["connection_sequence"] = serde_json::json!(50);
    for raw in [b"{".to_vec(), serde_json::to_vec(&value).unwrap()] {
        fs::write(fixture.path.join("state.json"), &raw).unwrap();
        assert!(fixture.open(OpenMode::Resume).is_err());
        assert_eq!(fs::read(fixture.path.join("state.json")).unwrap(), raw);
    }
    fs::write(fixture.path.join("state.json"), &original).unwrap();
    let mut forged = fixture.state().payload;
    forged.receipts[0].as_mut().unwrap().usage.total_bytes += 1;
    forged.authorized_bytes[0] += 1;
    forged.local_bytes[0] += 1;
    fixture.replace(forged);
    // A recomputed unkeyed checksum cannot forge a payer authorization.
    assert!(fixture.open(OpenMode::Resume).is_err());
    fs::write(fixture.path.join("state.json"), &original).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["payload"]["extra"] = serde_json::json!(true);
    fs::write(
        fixture.path.join("state.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
}

#[test]
fn receipt_snapshot_invariants_are_checked_even_with_a_valid_checksum() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.purchases().unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.purchases().unwrap();
    drop(journal);
    let state = fixture.state().payload;
    let mut invalid = Vec::new();
    let mut changed = state.clone();
    changed.authorized_bytes[0] += 1;
    invalid.push(changed);
    let mut changed = state.clone();
    changed.receipts[0] = None;
    invalid.push(changed);
    let mut changed = state.clone();
    changed.usage_sequence += 1;
    invalid.push(changed);
    let mut changed = state.clone();
    changed.local_bytes.pop();
    invalid.push(changed);
    let mut changed = state.clone();
    changed.receipts[0].as_mut().unwrap().usage.plan += 1;
    let changed_usage = changed.receipts[0].as_ref().unwrap().usage.clone();
    changed.receipts[0] = Some(SignedUsage::sign(changed_usage, &fixture.key).unwrap());
    invalid.push(changed);
    for changed in invalid {
        fixture.replace(changed);
        assert!(fixture.open(OpenMode::Resume).is_err());
    }
    fixture.replace(state);
    fixture.open(OpenMode::Resume).unwrap();
}

#[test]
fn exhausted_connection_sequence_and_invalid_keys_do_not_modify_journal() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let before = fs::read(fixture.path.join("state.json")).unwrap();
    assert!(journal.connect([0; 32]).is_err());
    assert_eq!(fs::read(fixture.path.join("state.json")).unwrap(), before);
    let mut next = journal.state.clone();
    next.connection_sequence = u64::MAX;
    journal.commit(next).unwrap();
    assert!(journal.connect([1; 32]).is_err());
    assert_eq!(journal.state.connection_sequence, u64::MAX);
    let purchases = journal.purchases().unwrap();
    assert_eq!(journal.purchases().unwrap(), purchases);
}

#[test]
fn signing_secret_is_not_persisted_and_mismatched_key_objects_are_refused() {
    use base64::Engine as _;
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.purchases().unwrap();
    journal.connect([1; 32]).unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.purchases().unwrap();
    let text = fs::read_to_string(fixture.path.join("state.json")).unwrap();
    assert!(!text.contains(&hex::encode([0x9d; 32])));
    assert!(!text.contains(&base64::engine::general_purpose::STANDARD.encode([0x9d; 32])));
    assert!(!text.contains("secret"));
    let other = Fixture::new(100);
    let mut mismatch = KeyPair::from_secret_bytes(&[6; 32]);
    mismatch.public = fixture.key.public;
    assert!(Journal::open(
        &other.path,
        other.binding.clone(),
        other.tariff.clone(),
        100,
        other.prepaid.clone(),
        Arc::new(mismatch),
        OpenMode::Create
    )
    .is_err());
    assert!(!other.path.exists());
}

#[cfg(unix)]
#[test]
fn storage_refuses_symlinks_hardlinks_and_nonprivate_permissions() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    for name in ["state.json", "writer.lock"] {
        for attack in ["symlink", "hardlink", "permissions"] {
            let fixture = Fixture::new(100);
            drop(fixture.open(OpenMode::Create).unwrap());
            let path = fixture.path.join(name);
            let backup = fixture.root.path().join("backup");
            match attack {
                "symlink" => {
                    fs::rename(&path, &backup).unwrap();
                    symlink(&backup, &path).unwrap();
                }
                "hardlink" => {
                    fs::hard_link(&path, &backup).unwrap();
                }
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            assert!(fixture.open(OpenMode::Resume).is_err(), "{name}: {attack}");
        }
    }
    let fixture = Fixture::new(100);
    drop(fixture.open(OpenMode::Create).unwrap());
    assert_eq!(fs::metadata(&fixture.path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(fixture.path.join("state.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(fixture.path.join("writer.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
    let fixture = Fixture::new(100);
    drop(fixture.open(OpenMode::Create).unwrap());
    let backup = fixture.root.path().join("backup");
    fs::rename(&fixture.path, &backup).unwrap();
    symlink(&backup, &fixture.path).unwrap();
    assert!(fixture.open(OpenMode::Resume).is_err());
}

#[test]
fn control_only_stock_journal_cannot_reinterpret_a_local_tun_journal() {
    let fixture = Fixture::new(100);
    let framed = fixture.open(OpenMode::Create).unwrap();
    drop(framed);
    let plan = crate::payment_runner::Plan {
        binding: fixture.binding.clone(),
        tariff: fixture.tariff.clone(),
        operator_generation: 1,
        original_budget_ou: fixture.budget,
        prepaid_bytes: fixture.prepaid.clone(),
        control_url: "http://127.0.0.1/".into(),
        control_ca_pem: None,
        wireguard_endpoint: "127.0.0.1:51820".into(),
    };
    assert!(
        Journal::open_stock(&fixture.path, &plan, fixture.key.clone(), OpenMode::Resume).is_err()
    );
    let path = fixture.root.path().join("stock");
    let mut stock =
        Journal::open_stock(&path, &plan, fixture.key.clone(), OpenMode::Create).unwrap();
    let first = stock.connect([21; 32]).unwrap();
    first.verify_stock().unwrap();
    assert!(first.verify().is_err());
    let purchases = stock.purchases().unwrap();
    assert!(!purchases.is_empty());
    assert!(stock.totals().iter().all(|bytes| *bytes == 0));
    drop(stock);
    assert!(Journal::open(
        &path,
        fixture.binding.clone(),
        fixture.tariff.clone(),
        fixture.budget,
        fixture.prepaid.clone(),
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    let mut stock = Journal::open_stock(&path, &plan, fixture.key, OpenMode::Resume).unwrap();
    let second = stock.connect([22; 32]).unwrap();
    assert!(second.request.sequence > first.request.sequence);
    assert_eq!(stock.purchases().unwrap(), purchases);
    assert!(stock.totals().iter().all(|bytes| *bytes == 0));
}
