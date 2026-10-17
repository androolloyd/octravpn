use super::*;
use octravpn_core::{
    payments::{Deployment, IpPrefix, Protocol, Selector, TrafficClass},
    Address,
};
use std::{fs, net::Ipv4Addr, path::PathBuf};

struct Fixture {
    root: tempfile::TempDir,
    path: PathBuf,
    binding: PlanBinding,
    tariff: Tariff,
    key: Arc<KeyPair>,
    budget: u64,
}

impl Fixture {
    fn new(budget: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let key = Arc::new(KeyPair::from_secret_bytes(&[0x9d; 32]));
        let tariff = Tariff::new(
            Address::from_pubkey(&[7; 32]),
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
            budget,
        }
    }

    fn open(&self, mode: OpenMode) -> Result<Journal> {
        Journal::open(
            &self.path,
            self.binding.clone(),
            self.tariff.clone(),
            self.budget,
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
fn confirmed_raw_counters_receipts_and_connection_sequences_survive_restart() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let first = journal.connect([3; 32]).unwrap();
    first.verify().unwrap();
    assert_eq!(first.request.sequence, 1);
    assert_eq!(fixture.state().payload.connection_sequence, 1);
    assert_eq!(journal.binding(), &fixture.binding);
    let ordinary = packet(false, false, 8);
    let outgoing = packet(true, false, 10);
    let incoming = packet(true, true, 14);
    assert_eq!(journal.count(&ordinary, Direction::Outbound).unwrap(), 0);
    assert_eq!(journal.count(&outgoing, Direction::Outbound).unwrap(), 1);
    assert_eq!(journal.count(&incoming, Direction::Inbound).unwrap(), 1);
    let totals = vec![
        ordinary.len() as u64,
        (outgoing.len() + incoming.len()) as u64,
    ];
    assert_eq!(journal.totals(), totals);
    let receipts = journal.receipts(&[u64::MAX, 40]).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].usage.total_bytes, totals[0]);
    assert_eq!(receipts[1].usage.total_bytes, 40);
    assert_eq!(journal.authorized_totals(), [totals[0], 40]);
    assert_eq!(fixture.state().payload.authorized_bytes, [totals[0], 40]);
    let receipts = journal.receipts(&totals).unwrap();
    assert_eq!(receipts[0].usage.sequence, 1);
    assert_eq!(receipts[1].usage.sequence, 3);
    assert_eq!(journal.remaining_ou().unwrap(), 98);
    let second = journal.connect([4; 32]).unwrap();
    assert_eq!(second.request.sequence, 2);
    assert_eq!(
        first.request.binding.session_id().unwrap(),
        second.request.binding.session_id().unwrap()
    );
    drop(journal);
    let mut recovered = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(recovered.totals(), totals);
    assert_eq!(recovered.authorized_totals(), totals);
    assert_eq!(recovered.pending_receipts().unwrap(), receipts);
    assert_eq!(recovered.receipts(&totals).unwrap(), receipts);
    for receipt in recovered.pending_receipts().unwrap() {
        receipt.verify().unwrap();
    }
    assert_eq!(recovered.connect([5; 32]).unwrap().request.sequence, 3);
    assert_eq!(recovered.remaining_ou().unwrap(), 98);
}

#[test]
fn operator_overstatement_is_capped_and_regression_is_atomic() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let ordinary = packet(false, false, 1);
    let premium = packet(true, false, 2);
    journal.count(&ordinary, Direction::Outbound).unwrap();
    journal.count(&premium, Direction::Outbound).unwrap();
    let receipts = journal.receipts(&[u64::MAX, u64::MAX]).unwrap();
    assert_eq!(journal.authorized_totals(), journal.totals());
    let authorized = journal.authorized_totals().to_vec();
    journal.count(&ordinary, Direction::Outbound).unwrap();
    journal.count(&premium, Direction::Outbound).unwrap();
    let before = fs::read(fixture.path.join("state.json")).unwrap();
    // Class zero could advance, but the later class regression rejects the
    // complete batch and cannot burn sequence numbers or publish half of it.
    assert!(journal.receipts(&[u64::MAX, authorized[1] - 1]).is_err());
    assert_eq!(journal.authorized_totals(), authorized);
    assert_eq!(journal.pending_receipts().unwrap(), receipts);
    assert_eq!(fs::read(fixture.path.join("state.json")).unwrap(), before);
    assert!(journal.receipts(&[u64::MAX]).is_err());
    let updated = journal.receipts(&[u64::MAX, u64::MAX]).unwrap();
    assert_eq!(updated[0].usage.sequence, 3);
    assert_eq!(updated[1].usage.sequence, 4);
    assert_eq!(updated[0].usage.total_bytes, 2 * ordinary.len() as u64);
    assert_eq!(updated[1].usage.total_bytes, 2 * premium.len() as u64);
    assert_eq!(fixture.state().payload.usage_sequence, 4);
}

#[test]
fn preflight_dropped_and_invalid_packets_do_not_become_billable() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    let bytes = packet(true, false, 40);
    assert_eq!(journal.check(&bytes, Direction::Outbound).unwrap(), 1);
    assert_eq!(journal.totals(), [0, 0]);
    assert!(journal.receipts(&[0, u64::MAX]).unwrap().is_empty());
    let before = fs::read(fixture.path.join("state.json")).unwrap();
    let mut invalid = bytes.clone();
    invalid[10] ^= 1;
    assert!(journal.count(&invalid, Direction::Outbound).is_err());
    assert!(journal
        .count(&bytes[..bytes.len() - 1], Direction::Outbound)
        .is_err());
    assert_eq!(journal.totals(), [0, 0]);
    assert_eq!(fs::read(fixture.path.join("state.json")).unwrap(), before);
    drop(journal);
    let journal = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(journal.totals(), [0, 0]);
    assert_eq!(journal.authorized_totals(), [0, 0]);
}

#[test]
fn aggregate_original_budget_cannot_reset_on_receipt_or_reconnect() {
    let fixture = Fixture::new(1);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    assert_eq!(journal.remaining_ou().unwrap(), 0);
    let before = journal.totals().to_vec();
    assert!(journal
        .check(&packet(true, false, 0), Direction::Outbound)
        .is_err());
    assert!(journal
        .count(&packet(true, false, 0), Direction::Outbound)
        .is_err());
    assert_eq!(journal.totals(), before);
    journal.receipts(&[u64::MAX, u64::MAX]).unwrap();
    journal.connect([1; 32]).unwrap();
    drop(journal);
    let mut journal = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(journal.remaining_ou().unwrap(), 0);
    assert!(journal
        .count(&packet(true, true, 0), Direction::Inbound)
        .is_err());
    // Cumulative rounding permits more default bytes within the first MiB.
    journal
        .count(&packet(false, true, 0), Direction::Inbound)
        .unwrap();
    assert_eq!(journal.remaining_ou().unwrap(), 0);
}

#[test]
fn immutable_binding_tariff_original_budget_and_key_are_required_on_resume() {
    let fixture = Fixture::new(100);
    drop(fixture.open(OpenMode::Create).unwrap());
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
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    assert!(Journal::open(
        &fixture.path,
        fixture.binding.clone(),
        fixture.tariff.clone(),
        100,
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
        fixture.key.clone(),
        OpenMode::Resume
    )
    .is_err());
    let journal = fixture.open(OpenMode::Resume).unwrap();
    assert_eq!(journal.totals(), [0, 0]);
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
        journal
            .count(&packet(false, false, 0), Direction::Outbound)
            .unwrap();
        fs::remove_file(fixture.path.join(remove)).unwrap();
        assert!(journal.receipts(&[u64::MAX, 0]).is_err());
        assert!(journal.connect([1; 32]).is_err());
        assert!(journal.pending_receipts().is_err());
        assert!(!fixture.path.join(remove).exists());
    }
}

#[test]
fn corrupt_truncated_unknown_or_forged_state_is_refused_without_repair() {
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.receipts(&[u64::MAX, 0]).unwrap();
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
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.receipts(&[u64::MAX, 0]).unwrap();
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
fn exhausted_sequences_and_invalid_connect_keys_do_not_modify_journal() {
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
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    let mut next = journal.state.clone();
    next.usage_sequence = u64::MAX;
    next.authorized_bytes[0] = 1;
    next.receipts[0] = Some(
        SignedUsage::sign(
            Usage::from_binding(fixture.binding.clone(), 0, u64::MAX, 1).unwrap(),
            &fixture.key,
        )
        .unwrap(),
    );
    journal.commit(next).unwrap();
    let before = fs::read(fixture.path.join("state.json")).unwrap();
    assert!(journal.receipts(&[u64::MAX, 0]).is_err());
    assert_eq!(journal.authorized_totals(), [1, 0]);
    assert_eq!(fs::read(fixture.path.join("state.json")).unwrap(), before);
}

#[test]
fn signing_secret_is_not_persisted_and_mismatched_key_objects_are_refused() {
    use base64::Engine as _;
    let fixture = Fixture::new(100);
    let mut journal = fixture.open(OpenMode::Create).unwrap();
    journal.connect([1; 32]).unwrap();
    journal
        .count(&packet(false, false, 0), Direction::Outbound)
        .unwrap();
    journal.receipts(&[u64::MAX, 0]).unwrap();
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
