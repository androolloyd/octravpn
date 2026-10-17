use super::*;
use octravpn_core::payments::{IpPrefix, Protocol, Selector, TrafficClass, BYTES_PER_MIB};
use octravpn_core::{
    payments::{Connect, Usage},
    KeyPair,
};
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

fn connect_request(meter: &Meter, sequence: u64, wireguard_key: [u8; 32]) -> SignedConnect {
    SignedConnect::sign(
        Connect {
            binding: meter.binding().clone(),
            sequence,
            wireguard_key,
        },
        &KeyPair::from_secret_bytes(&[31; 32]),
    )
    .unwrap()
}
fn usage_receipt(meter: &Meter, class: u8, sequence: u64, bytes: u64) -> SignedUsage {
    SignedUsage::sign(
        Usage::from_binding(meter.binding().clone(), class, sequence, bytes).unwrap(),
        &KeyPair::from_secret_bytes(&[31; 32]),
    )
    .unwrap()
}
async fn bounded(path: &Path, canonical: Vec<u64>, credit: Credit) -> Arc<Meter> {
    let tariff = tariff();
    Meter::open_with_credit(path.into(), binding(&tariff), tariff, 10, canonical, credit)
        .await
        .unwrap()
}

#[tokio::test]
async fn resume_requires_existing_private_directory_lease_and_journal() {
    let root = tempfile::tempdir().unwrap();
    let credit = Credit {
        max_unacknowledged_bytes: 100,
        max_unacknowledged_ou: 2,
    };
    let tariff = tariff();
    let missing = root.path().join("absent");
    assert!(Meter::resume_with_credit(
        missing.clone(),
        binding(&tariff),
        tariff.clone(),
        10,
        vec![0, 0],
        credit
    )
    .await
    .is_err());
    assert!(!missing.exists(), "recovery never creates a plan directory");
    let empty = root.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Meter::resume_with_credit(
        empty.clone(),
        binding(&tariff),
        tariff.clone(),
        10,
        vec![0, 0],
        credit
    )
    .await
    .is_err());
    assert_eq!(
        std::fs::read_dir(&empty).unwrap().count(),
        0,
        "no lease or journal is created"
    );
    let path = root.path().join("valid");
    let meter = bounded(&path, vec![0, 0], credit).await;
    meter
        .connect(connect_request(&meter, 1, [41; 32]))
        .await
        .unwrap();
    meter
        .reserve_class(0, 64)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let before = meter.snapshot().unwrap();
    assert!(
        Meter::resume_with_credit(
            path.clone(),
            binding(&tariff),
            tariff.clone(),
            10,
            vec![0, 0],
            credit
        )
        .await
        .is_err(),
        "a writer must retain exclusivity"
    );
    drop(meter);
    let resumed = Meter::resume_with_credit(
        path,
        binding(&tariff),
        tariff.clone(),
        10,
        vec![0, 0],
        credit,
    )
    .await
    .unwrap();
    assert_eq!(resumed.snapshot().unwrap(), before);
    drop(resumed);
    for lost in ["meter.lock", "meter.json"] {
        let path = root.path().join(lost);
        drop(bounded(&path, vec![0, 0], credit).await);
        std::fs::remove_file(path.join(lost)).unwrap();
        let retained = if lost == "meter.lock" {
            "meter.json"
        } else {
            "meter.lock"
        };
        let before = std::fs::read(path.join(retained)).unwrap();
        assert!(Meter::resume_with_credit(
            path.clone(),
            binding(&tariff),
            tariff.clone(),
            10,
            vec![0, 0],
            credit
        )
        .await
        .is_err());
        assert!(
            !path.join(lost).exists(),
            "missing {lost} is never recreated"
        );
        assert_eq!(std::fs::read(path.join(retained)).unwrap(), before);
        assert_eq!(
            std::fs::read_dir(path).unwrap().count(),
            1,
            "recovery leaves no new files"
        );
    }
}

#[tokio::test]
async fn nonpaying_credit_stops_reconnect_and_receipts_resume_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("credit");
    let credit = Credit {
        max_unacknowledged_bytes: 100,
        max_unacknowledged_ou: 2,
    };
    let meter = bounded(&path, vec![0, 0], credit).await;
    let initial = connect_request(&meter, 1, [41; 32]);
    meter.connect(initial.clone()).await.unwrap();
    assert!(meter.connect_is_current(&initial));
    meter
        .reserve_class(0, 90)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let before = meter.snapshot().unwrap();
    assert!(meter.reserve_class(0, 11).await.is_err());
    assert_eq!(meter.snapshot().unwrap(), before);
    let rotated = connect_request(&meter, 2, [42; 32]);
    meter.connect(rotated.clone()).await.unwrap();
    assert!(!meter.connect_is_current(&initial));
    assert!(meter.check_connect(&initial).is_err());
    assert!(meter.connect(initial.clone()).await.is_err());
    assert!(meter.connect_is_current(&rotated));
    assert!(meter.reserve_class(0, 11).await.is_err());
    assert!(meter.authorizations().unwrap().is_empty());
    let receipt = usage_receipt(&meter, 0, 1, 90);
    meter.accept_usage(receipt.clone()).await.unwrap();
    meter.accept_usage(receipt).await.unwrap();
    meter
        .reserve_class(0, 100)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(meter.reserve_class(0, 1).await.is_err());
    let receipt = usage_receipt(&meter, 0, 2, 190);
    meter.accept_usage(receipt.clone()).await.unwrap();
    assert!(
        meter
            .accept_usage(usage_receipt(&meter, 0, 3, 191))
            .await
            .is_err(),
        "no payment for undelivered bytes"
    );
    meter
        .accept_usage(usage_receipt(&meter, 0, 1, 190))
        .await
        .unwrap();
    meter
        .accept_usage(usage_receipt(&meter, 0, 3, 189))
        .await
        .unwrap();
    assert_eq!(meter.authorizations().unwrap(), [receipt.clone()]);
    drop(meter);
    let restarted = bounded(&path, vec![0, 0], credit).await;
    assert!(restarted.connect_is_current(&rotated));
    assert!(restarted.check_connect(&initial).is_err());
    assert_eq!(restarted.authorizations().unwrap(), [receipt]);
    restarted
        .reserve_class(0, 100)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(restarted.reserve_class(0, 1).await.is_err());
    let wrong = SignedUsage::sign(
        Usage::from_binding(restarted.binding().clone(), 0, 4, 290).unwrap(),
        &KeyPair::from_secret_bytes(&[32; 32]),
    )
    .unwrap();
    assert!(restarted.accept_usage(wrong).await.is_err());
    drop(restarted);
    let tariff = tariff();
    assert!(Meter::open(
        path.clone(),
        binding(&tariff),
        tariff.clone(),
        10,
        vec![0, 0]
    )
    .await
    .is_err());
    assert!(Meter::open_with_credit(
        path,
        binding(&tariff),
        tariff,
        10,
        vec![0, 0],
        Credit {
            max_unacknowledged_bytes: 101,
            ..credit
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn larger_canonical_authorization_wins_over_higher_sequence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("authorization");
    let meter = open(&path, 3).await;
    meter
        .connect(connect_request(&meter, 1, [41; 32]))
        .await
        .unwrap();
    meter
        .reserve_class(0, 100)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let smaller = usage_receipt(&meter, 0, 100, 50);
    meter.accept_usage(smaller.clone()).await.unwrap();
    let larger = usage_receipt(&meter, 0, 1, 100);
    meter.check_usage(&larger).unwrap();
    meter.accept_usage(larger.clone()).await.unwrap();
    meter.check_usage(&smaller).unwrap();
    meter.accept_usage(smaller).await.unwrap();
    assert_eq!(meter.authorizations().unwrap(), [larger.clone()]);
    drop(meter);
    let restarted = open(&path, 3).await;
    assert_eq!(restarted.authorizations().unwrap(), [larger]);
}

#[tokio::test]
async fn credit_counts_uncertain_capacity_and_aggregate_class_charges() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("credit");
    let credit = Credit {
        max_unacknowledged_bytes: u64::MAX,
        max_unacknowledged_ou: 1,
    };
    let meter = bounded(&path, vec![0, 0], credit).await;
    let request = connect_request(&meter, 1, [41; 32]);
    meter.connect(request).await.unwrap();
    meter
        .reserve_class(0, 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let before = meter.snapshot().unwrap();
    assert!(
        meter.reserve_class(1, 1).await.is_err(),
        "two classes share one OU exposure limit"
    );
    assert_eq!(meter.snapshot().unwrap(), before);
    meter
        .accept_usage(usage_receipt(&meter, 0, 1, 1))
        .await
        .unwrap();
    drop(meter.reserve_class(1, 1).await.unwrap());
    dropped_ticket_finished(&meter).await;
    assert_eq!(meter.snapshot().unwrap().committed_totals, [1, 0]);
    assert_eq!(meter.snapshot().unwrap().uncertain_totals, [0, 1]);
    assert!(
        meter
            .accept_usage(usage_receipt(&meter, 1, 1, 1))
            .await
            .is_err(),
        "uncertainty is never billable delivery"
    );
    assert!(
        meter.reserve_class(0, BYTES_PER_MIB).await.is_err(),
        "uncertain capacity still consumes OU credit"
    );
    drop(meter);
    let restarted = bounded(&path, vec![0, 0], credit).await;
    assert!(restarted.reserve_class(0, BYTES_PER_MIB).await.is_err());
}

#[tokio::test]
async fn canonical_redemption_authorizes_credit_without_resetting_delivery() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("credit");
    let credit = Credit {
        max_unacknowledged_bytes: 64,
        max_unacknowledged_ou: 1,
    };
    let meter = bounded(&path, vec![128, 0], credit).await;
    meter
        .reserve_class(0, 64)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert!(meter.reserve_class(0, 1).await.is_err());
    meter.reconcile(vec![192, 0]).await.unwrap();
    assert!(meter.authorizations().unwrap().is_empty());
    meter
        .reserve_class(0, 64)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(meter.snapshot().unwrap().committed_totals, [256, 0]);
    assert_eq!(meter.snapshot().unwrap().redeemed_totals, [192, 0]);
    assert!(meter.reserve_class(0, 1).await.is_err());
    drop(meter);
    let restarted = bounded(&path, vec![192, 0], credit).await;
    assert_eq!(restarted.snapshot().unwrap().committed_totals, [256, 0]);
    assert!(restarted.reserve_class(0, 1).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::await_holding_lock,
    reason = "Deliberately stalls the blocking writer to cancel rotation before persistence."
)]
async fn cancelled_rotation_stays_suspended_until_new_watermark_is_durable() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("rotation");
    let meter = open(&path, 3).await;
    let initial = connect_request(&meter, 1, [41; 32]);
    meter.connect(initial.clone()).await.unwrap();
    let rotation = connect_request(&meter, 2, [42; 32]);
    let mut conflict = initial.request.clone();
    conflict.wireguard_key = [43; 32];
    let conflict = SignedConnect::sign(conflict, &KeyPair::from_secret_bytes(&[31; 32])).unwrap();
    assert!(meter.check_connect(&conflict).is_err());
    assert!(meter.connect(conflict).await.is_err());
    assert!(meter.connect_is_current(&initial));
    // Hold the writer so cancellation lands after the pending gate is set but
    // before the blocking filesystem operation can durably install the key.
    let writer = meter.writer.lock();
    let task_meter = meter.clone();
    let task_request = rotation.clone();
    let task = tokio::spawn(async move { task_meter.connect(task_request).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !meter.connect_pending.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!meter.connect_is_current(&initial));
    assert!(meter.check_connect(&initial).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!meter.connect_is_current(&initial));
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !meter.connect_is_current(&rotation) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!meter.connect_is_current(&initial));
    assert!(meter.check_connect(&initial).is_err());
    dropped_ticket_finished(&meter).await;
    drop(meter);
    let restarted = open(&path, 3).await;
    assert!(restarted.connect_is_current(&rotation));
    assert!(restarted.check_connect(&initial).is_err());
}

#[tokio::test]
async fn failed_rotation_or_authorization_persistence_poisons_admission() {
    let root = tempfile::tempdir().unwrap();
    let meter = open(&root.path().join("rotation"), 3).await;
    let initial = connect_request(&meter, 1, [41; 32]);
    meter.connect(initial.clone()).await.unwrap();
    meter.disk.fail_next_write();
    assert!(meter
        .connect(connect_request(&meter, 2, [42; 32]))
        .await
        .is_err());
    assert!(!meter.connect_is_current(&initial));
    assert!(meter.reserve_class(0, 1).await.is_err());
    let meter = open(&root.path().join("authorization"), 3).await;
    meter
        .connect(connect_request(&meter, 1, [41; 32]))
        .await
        .unwrap();
    meter
        .reserve_class(0, 1)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    meter.disk.fail_next_write();
    assert!(meter
        .accept_usage(usage_receipt(&meter, 0, 1, 1))
        .await
        .is_err());
    assert!(meter.authorizations().is_err());
    assert!(meter.reserve_class(0, 1).await.is_err());
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
