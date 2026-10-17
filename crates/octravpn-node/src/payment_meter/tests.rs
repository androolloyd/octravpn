use super::*;
use octravpn_core::payments::{IpPrefix, Protocol, Selector, TrafficClass, BYTES_PER_MIB};
use std::{os::unix::fs::PermissionsExt, path::Path};

fn tariff() -> Tariff {
    Tariff::new(
        Address::from_pubkey(&[1; 32]),
        vec![
            TrafficClass {
                name: "default".into(),
                rate_ou_per_mib: 1,
            },
            TrafficClass {
                name: "premium".into(),
                rate_ou_per_mib: 2,
            },
        ],
        vec![],
    )
    .unwrap()
}
fn binding(tariff: &Tariff) -> Binding {
    Binding {
        deployment: Deployment {
            domain: "ab".repeat(32),
            program: Address::from_pubkey(&[2; 32]),
        },
        payer: Address::from_pubkey(&[3; 32]),
        generation: 1,
        plan: 8,
        offer: 4,
        manifest_hash: tariff.hash_hex().unwrap(),
    }
}
async fn open(path: &Path, budget: u64) -> Arc<Meter> {
    let tariff = tariff();
    Meter::open(path.into(), binding(&tariff), tariff, budget, vec![0, 0])
        .await
        .unwrap()
}
async fn dropped_ticket_finished(meter: &Arc<Meter>) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while Arc::strong_count(meter) != 1 || meter.snapshot().unwrap().pending_totals != [0, 0] {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn delivered_counts_persist_and_pending_restart_never_becomes_billable() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 3).await;
    meter
        .reserve_class(0, 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let abandoned = meter.reserve_class(1, BYTES_PER_MIB).await.unwrap();
    assert_eq!(meter.snapshot().unwrap().capacity_charge_ou, 3);
    assert_eq!(meter.snapshot().unwrap().committed_charge_ou, 1);
    drop(abandoned);
    dropped_ticket_finished(&meter).await;
    let cancelled = meter.snapshot().unwrap();
    assert_eq!(cancelled.capacity_charge_ou, 3);
    assert_eq!(cancelled.committed_totals, [1, 0]);
    assert_eq!(cancelled.uncertain_totals, [0, BYTES_PER_MIB]);
    drop(meter);
    let restarted = open(&path, 3).await;
    let snapshot = restarted.snapshot().unwrap();
    assert_eq!(snapshot.committed_totals, [1, 0]);
    assert_eq!(snapshot.uncertain_totals, [0, BYTES_PER_MIB]);
    assert_eq!(snapshot.pending_totals, [0, 0]);
    assert_eq!(snapshot.committed_charge_ou, 1);
    assert_eq!(snapshot.capacity_charge_ou, 3);
    assert!(restarted.reserve_class(1, 1).await.is_err());
    // Cumulative rounding permits additional bytes only inside already reserved
    // class capacity; reconnecting cannot create another free MiB.
    restarted
        .reserve_class(0, BYTES_PER_MIB - 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(restarted.reserve_class(0, 1).await.is_err());
}

#[tokio::test]
async fn explicit_cancellation_persists_without_charging_failed_forwarding() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 1).await;
    meter
        .reserve_class(0, BYTES_PER_MIB)
        .await
        .unwrap()
        .cancel()
        .await
        .unwrap();
    assert_eq!(meter.snapshot().unwrap().capacity_charge_ou, 0);
    drop(meter);
    let restarted = open(&path, 1).await;
    assert_eq!(restarted.snapshot().unwrap().committed_totals, [0, 0]);
    assert_eq!(restarted.snapshot().unwrap().uncertain_totals, [0, 0]);
    restarted
        .reserve_class(0, BYTES_PER_MIB)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(restarted.reserve_class(0, 1).await.is_err());
}

#[tokio::test]
async fn dropped_handoff_remains_uncertain_after_another_write_and_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 2).await;
    // A task may disappear after handing a packet to an async send without
    // learning whether it succeeded. Dropping cannot release that capacity.
    drop(meter.reserve_class(0, BYTES_PER_MIB).await.unwrap());
    dropped_ticket_finished(&meter).await;
    assert_eq!(meter.snapshot().unwrap().committed_charge_ou, 0);
    assert_eq!(meter.snapshot().unwrap().capacity_charge_ou, 1);
    meter
        .reserve_class(0, BYTES_PER_MIB)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let snapshot = meter.snapshot().unwrap();
    assert_eq!(snapshot.committed_totals, [BYTES_PER_MIB, 0]);
    assert_eq!(snapshot.uncertain_totals, [BYTES_PER_MIB, 0]);
    assert_eq!(snapshot.committed_charge_ou, 1);
    assert_eq!(snapshot.capacity_charge_ou, 2);
    assert!(meter.reserve_class(0, 1).await.is_err());
    drop(meter);
    let restarted = open(&path, 2).await;
    assert_eq!(restarted.snapshot().unwrap(), snapshot);
    assert!(restarted.reserve_class(0, 1).await.is_err());
}

#[tokio::test]
async fn canonical_floors_resolve_uncertainty_and_cannot_move_backwards() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 3).await;
    drop(meter.reserve_class(1, BYTES_PER_MIB).await.unwrap());
    dropped_ticket_finished(&meter).await;
    drop(meter);
    let tariff = tariff();
    let restarted = Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        3,
        vec![0, BYTES_PER_MIB],
    )
    .await
    .unwrap();
    let snapshot = restarted.snapshot().unwrap();
    assert_eq!(snapshot.committed_totals, [0, BYTES_PER_MIB]);
    assert_eq!(snapshot.uncertain_totals, [0, 0]);
    assert_eq!(snapshot.capacity_charge_ou, 2);
    drop(restarted);
    assert!(Meter::open(path, binding(&tariff), tariff, 3, vec![0, 0])
        .await
        .is_err());
}

#[tokio::test]
async fn immutable_binding_budget_tariff_and_exclusive_writer_are_enforced() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 3).await;
    let tariff = tariff();
    assert!(Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        3,
        vec![0, 0]
    )
    .await
    .is_err());
    drop(meter);
    for field in 0..5 {
        let mut changed = binding(&tariff);
        match field {
            0 => changed.generation += 1,
            1 => changed.plan += 1,
            2 => changed.offer += 1,
            3 => changed.payer = Address::from_pubkey(&[8; 32]),
            _ => changed.deployment.domain = "cd".repeat(32),
        }
        assert!(
            Meter::open(path.clone(), changed, tariff.clone(), 3, vec![0, 0])
                .await
                .is_err()
        );
    }
    assert!(Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        4,
        vec![0, 0]
    )
    .await
    .is_err());
    let other = Tariff::new(
        tariff.operator().clone(),
        vec![TrafficClass {
            name: "changed".into(),
            rate_ou_per_mib: 1,
        }],
        vec![],
    )
    .unwrap();
    assert!(
        Meter::open(path.clone(), binding(&tariff), other, 3, vec![0])
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::metadata(path.join("meter.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    assert_eq!(
        std::fs::metadata(path.join("meter.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
}

#[tokio::test]
async fn corrupted_or_missing_records_and_symlinked_files_do_not_reset_counters() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 1).await;
    meter
        .reserve_class(0, 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    drop(meter);
    let original = std::fs::read(path.join("meter.json")).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
    envelope["sha256"] = serde_json::json!("00".repeat(32));
    std::fs::write(
        path.join("meter.json"),
        serde_json::to_vec(&envelope).unwrap(),
    )
    .unwrap();
    let tariff = tariff();
    assert!(Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        1,
        vec![0, 0]
    )
    .await
    .is_err());
    std::fs::remove_file(path.join("meter.json")).unwrap();
    assert!(Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        1,
        vec![0, 0]
    )
    .await
    .is_err());
    let outside = root.path().join("outside");
    std::fs::write(&outside, &original).unwrap();
    std::os::unix::fs::symlink(&outside, path.join("meter.json")).unwrap();
    assert!(Meter::open(path, binding(&tariff), tariff, 1, vec![0, 0])
        .await
        .is_err());
    assert_eq!(std::fs::read(outside).unwrap(), original);
}

#[tokio::test]
async fn concurrent_directions_share_one_budget_and_refusal_is_atomic() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 1).await;
    let before = std::fs::read(path.join("meter.json")).unwrap();
    assert!(meter.reserve_class(2, 1).await.is_err());
    assert_eq!(std::fs::read(path.join("meter.json")).unwrap(), before);
    let (left, right) = tokio::join!(
        meter.reserve_class(0, BYTES_PER_MIB),
        meter.reserve_class(0, BYTES_PER_MIB)
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let ticket = left.or(right).unwrap();
    ticket.commit().await.unwrap();
    assert_eq!(
        meter.snapshot().unwrap().committed_totals,
        [BYTES_PER_MIB, 0]
    );
    assert_eq!(meter.snapshot().unwrap().capacity_charge_ou, 1);
}

#[tokio::test]
async fn failed_commit_poisons_live_meter_and_restores_uncertain_capacity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let meter = open(&path, 1).await;
    let ticket = meter.reserve_class(0, BYTES_PER_MIB).await.unwrap();
    // Inject the IO error at the real journal boundary; the durable pre-send
    // pending record must remain conservative without billing it as delivery.
    meter.disk.fail_next_write();
    assert!(ticket.commit().await.is_err());
    assert!(meter.snapshot().is_err());
    assert!(meter.reserve_class(0, 1).await.is_err());
    drop(meter);
    let restarted = open(&path, 1).await;
    let snapshot = restarted.snapshot().unwrap();
    assert_eq!(snapshot.committed_totals, [0, 0]);
    assert_eq!(snapshot.uncertain_totals, [BYTES_PER_MIB, 0]);
    assert_eq!(snapshot.capacity_charge_ou, 1);
    assert!(restarted.reserve_class(0, 1).await.is_err());
}

#[tokio::test]
async fn directory_rename_does_not_redirect_writes_into_another_plan() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan");
    let moved = root.path().join("original-plan");
    let meter = open(&path, 1).await;
    let ticket = meter.reserve_class(0, 1).await.unwrap();
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("meter.json"), b"another plan").unwrap();
    ticket.commit().await.unwrap();
    assert_eq!(
        std::fs::read(path.join("meter.json")).unwrap(),
        b"another plan"
    );
    drop(meter);
    let reopened = open(&moved, 1).await;
    assert_eq!(reopened.snapshot().unwrap().committed_totals, [1, 0]);
}

fn udp_packet(inbound: bool) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    let (source, destination, source_port, destination_port) = if inbound {
        ([1, 1, 1, 1], [198, 18, 0, 2], 443_u16, 50_000_u16)
    } else {
        ([198, 18, 0, 2], [1, 1, 1, 1], 50_000_u16, 443_u16)
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    let mut sum = packet[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

#[tokio::test]
async fn packet_reservation_counts_raw_ip_octets_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let base = tariff();
    let tariff = Tariff::new(
        base.operator().clone(),
        base.classes().to_vec(),
        vec![Selector {
            prefix: IpPrefix::new("1.1.1.1".parse().unwrap(), 32).unwrap(),
            protocol: Protocol::Udp,
            port: Some(443),
            traffic_class: 1,
        }],
    )
    .unwrap();
    let meter = Meter::open(
        root.path().join("plan"),
        binding(&tariff),
        tariff,
        3,
        vec![0, 0],
    )
    .await
    .unwrap();
    meter
        .reserve(&udp_packet(false), Direction::Outbound)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    meter
        .reserve(&udp_packet(true), Direction::Inbound)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let before = meter.snapshot().unwrap();
    assert_eq!(before.committed_totals, [0, 56]);
    assert_eq!(before.committed_charge_ou, 1);
    assert!(meter.reserve(&[0; 28], Direction::Outbound).await.is_err());
    assert_eq!(meter.snapshot().unwrap(), before);
}
