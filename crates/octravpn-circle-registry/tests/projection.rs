#![cfg(feature = "host")]

use octra_exex::{
    sqlite::SqliteCheckpoints, sqlite_source::SqliteEpochSource, ChainIdentity, CommittedEpoch,
    Cursor, EpochId, ExEx, ExExManager, Sequence, StateRoot,
};
use octravpn_circle_registry::{
    projection::{CircleEvent, RegistryProjection},
    publish, retire, Offer, OperatorRecord, PublishRequest, EVENT_TOPIC,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{sync::Arc, time::Duration};

fn address(last: char) -> String {
    format!("oct{}{last}", "1".repeat(43))
}
fn registry_circle() -> String {
    // A real native Circle ID whose cycled encoding exceeds a wallet digest.
    "octJfWXtvbohUBeXcvDAWJQ71Pog5ueFWDrzqgnn6x1yPeJ".into()
}
fn chain() -> ChainIdentity {
    ChainIdentity {
        chain_id: "private-vpn-fork".into(),
        genesis_root: StateRoot([1; 32]),
    }
}
fn anchor() -> Cursor {
    Cursor {
        sequence: Sequence(0),
        epoch: EpochId(0),
        state_root: StateRoot([1; 32]),
    }
}
fn offer() -> Offer {
    Offer {
        settlement_circle: address('4'),
        control_url: "https://vpn.example/control".into(),
        wireguard_endpoint: "203.0.113.7:51820".into(),
        wireguard_key_hex: "11".repeat(32),
        receipt_key_hex: "22".repeat(32),
        region: "CA".into(),
        exit: true,
        relay: false,
        price_ou_per_mib: 100,
    }
}
fn record() -> OperatorRecord {
    publish(
        None,
        &address('2'),
        1,
        PublishRequest {
            expected_revision: 0,
            offer: offer(),
        },
    )
    .unwrap()
}
fn event(record: &OperatorRecord) -> CircleEvent {
    CircleEvent {
        circle: registry_circle(),
        code_hash: "a".repeat(64),
        topic: EVENT_TOPIC.into(),
        data: serde_json::to_vec(record).unwrap(),
    }
}
fn epoch(sequence: u64, events: Vec<CircleEvent>) -> CommittedEpoch<CircleEvent> {
    CommittedEpoch {
        chain: chain(),
        cursor: Cursor {
            sequence: Sequence(sequence),
            epoch: EpochId(sequence),
            state_root: StateRoot([sequence as u8 + 1; 32]),
        },
        parent_root: StateRoot([sequence as u8; 32]),
        events,
    }
}
async fn projection(path: &std::path::Path) -> RegistryProjection {
    RegistryProjection::open(path, chain(), registry_circle(), "a".repeat(64), anchor())
        .await
        .unwrap()
}

#[tokio::test]
async fn source_exex_and_registry_index_recover_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let db = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(temporary.path().join("chain.sqlite"))
                .create_if_missing(true),
        )
        .await
        .unwrap();
    let source = Arc::new(
        SqliteEpochSource::open(db.clone(), chain(), anchor())
            .await
            .unwrap(),
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&temporary.path().join("checkpoints.sqlite"))
            .await
            .unwrap(),
    );
    let path = temporary.path().join("registry.sqlite");
    let index = projection(&path).await;
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    manager.register(index.clone()).await.unwrap();
    let first = epoch(1, vec![event(&record())]);
    let mut tx = db.begin().await.unwrap();
    source.append(&mut tx, &first).await.unwrap();
    tx.commit().await.unwrap();
    manager.notify_commit();
    tokio::time::timeout(Duration::from_secs(2), async {
        while index.head().await.unwrap() != first.cursor {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        manager
            .stop(&format!("vpn-registry/{}", registry_circle()))
            .await
            .unwrap(),
        first.cursor
    );
    assert_eq!(index.operator(&address('2')).await.unwrap(), Some(record()));
    drop(manager);

    let reopened = projection(&path).await;
    let mut replay = reopened.clone();
    replay.on_epoch(&first).await.unwrap();
    let retired = retire(&record(), &address('2'), 2, 1).unwrap();
    let second = epoch(2, vec![event(&retired)]);
    let mut tx = db.begin().await.unwrap();
    source.append(&mut tx, &second).await.unwrap();
    tx.commit().await.unwrap();
    let mut restarted = ExExManager::new(source, checkpoints).unwrap();
    restarted.register(reopened.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while reopened.head().await.unwrap() != second.cursor {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        reopened.operator(&address('2')).await.unwrap(),
        Some(retired)
    );
    restarted
        .stop(&format!("vpn-registry/{}", registry_circle()))
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_event_rolls_back_the_entire_batch_and_code_binding_is_pinned() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("registry.sqlite");
    let mut index = projection(&path).await;
    let valid = event(&record());
    let mut wrong = valid.clone();
    wrong.code_hash = "b".repeat(64);
    assert!(index
        .on_epoch(&epoch(1, vec![valid.clone(), wrong]))
        .await
        .is_err());
    assert_eq!(index.head().await.unwrap(), anchor());
    assert_eq!(index.operator(&address('2')).await.unwrap(), None);
    let mut unrelated = valid.clone();
    unrelated.circle = address('7');
    let first = epoch(1, vec![unrelated, valid]);
    index.on_epoch(&first).await.unwrap();
    index.on_epoch(&first).await.unwrap();
    let mut changed = first.clone();
    changed.events.clear();
    assert!(index.on_epoch(&changed).await.is_err());
    assert!(
        RegistryProjection::open(&path, chain(), registry_circle(), "b".repeat(64), anchor())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn skips_bad_epochs_and_revision_gaps_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let mut index = projection(&temporary.path().join("registry.sqlite")).await;
    assert!(index.on_epoch(&epoch(2, vec![])).await.is_err());
    let mut revised = record();
    revised.revision = 3;
    assert!(index
        .on_epoch(&epoch(1, vec![event(&revised)]))
        .await
        .is_err());
    let mut revised = record();
    revised.updated_epoch = 2;
    assert!(index
        .on_epoch(&epoch(1, vec![event(&revised)]))
        .await
        .is_err());
    assert_eq!(index.head().await.unwrap(), anchor());
    assert!(index.operator("oct-invalid").await.is_err());
}
