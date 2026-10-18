use std::{path::Path, sync::Arc, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine};
use octra_exex::{
    native_history::{NativeEpochSource, NativeHistory, NativeTransaction},
    sqlite::SqliteCheckpoints,
    ChainIdentity, CheckpointStore, CommittedEpoch, CommittedEpochSource, ExEx, ExExManager,
    ExtensionStatus, Sequence, StateRoot,
};
use octra_node_protocol::{
    consensus::{policy::Protocol, reward, reward_attribution::legacy},
    oce1::Writer,
    transaction::Nonce,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};

fn fixture() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native-history.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], sources["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], sources["files"]);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/node-port");
    for (name, hash) in fixture["adapter_sha256"].as_object().unwrap() {
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(root.join(name)).unwrap())),
            *hash
        );
    }
    fixture["cases"].clone()
}

fn parse(value: &Value) -> NativeHistory {
    NativeHistory::parse_with_rewards(&serde_json::to_vec(value).unwrap(), &authority).unwrap()
}

// Independent fixture policy, deliberately not read from the native export or
// its reward recipients. The native physical qualifier uses the same chosen
// policy and records its actual unchanged epoch_source result separately.
#[expect(
    clippy::unnecessary_wraps,
    reason = "HistoricalRewardAuthority callbacks return a fallible result"
)]
fn authority(_: u64) -> octra_exex::Result<legacy::Authority> {
    Ok(legacy::Authority {
        protocol: Protocol::default(),
        validator_activation_epoch: None,
        validator_pubkeys: vec![
            (
                b"fixture".to_vec(),
                STANDARD.encode([b'a'; 32]).into_bytes(),
            ),
            (
                b"validatorB".to_vec(),
                STANDARD.encode([b'b'; 32]).into_bytes(),
            ),
        ],
    })
}

fn reward_wire(source: &octra_node_protocol::consensus::RewardSource) -> Vec<u8> {
    let mut writer = Writer::new();
    reward::put(&mut writer, source).unwrap();
    writer.into_bytes()
}

fn chain() -> ChainIdentity {
    // The source starts at native epoch zero, so its explicit Genesis origin
    // must name the fixture's actual folded root rather than an unrelated key.
    let cases = fixture();
    let root = hex::decode(cases["full"]["anchor"]["state_root"].as_str().unwrap()).unwrap();
    ChainIdentity::genesis(
        "native-storage-fixture",
        StateRoot(root.try_into().unwrap()),
    )
}

async fn pool(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .busy_timeout(Duration::from_secs(2)),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn native_head_crash_window_and_paginated_reopen_preserve_committed_history() {
    let cases = fixture();
    assert_eq!(cases["after_head"], cases["after_recovery"]);
    for name in [
        "before_head",
        "future",
        "oversize",
        "pruned",
        "writer_active",
        "auxiliary_pending",
    ] {
        assert!(
            !cases["refusals"][name].as_str().unwrap().is_empty(),
            "{name}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let connection = pool(&db).await;
    let first = parse(&cases["first_page"]);
    let anchor = first.anchor().clone();
    let source = NativeEpochSource::open(connection.clone(), chain(), anchor.clone())
        .await
        .unwrap();
    let committed = source.import(&first).await.unwrap();
    assert_eq!(committed.sequence, Sequence(1));
    assert!(source.import(&first).await.is_err());
    assert_eq!(source.native_head().await.unwrap().epoch, 1);
    drop(source);
    connection.close().await;
    let connection = pool(&db).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), anchor)
        .await
        .unwrap();
    assert_eq!(source.head().await.unwrap(), committed);
    assert_eq!(
        source
            .import(&parse(&cases["remaining"]))
            .await
            .unwrap()
            .sequence,
        Sequence(3)
    );
    assert!(source
        .load(Sequence(2))
        .await
        .unwrap()
        .unwrap()
        .events
        .is_empty());
    assert_eq!(
        source
            .load(Sequence(3))
            .await
            .unwrap()
            .unwrap()
            .events
            .len(),
        2
    );
    assert_eq!(
        source.import(&parse(&cases["caught_up"])).await.unwrap(),
        source.head().await.unwrap()
    );
    drop(source);
    connection.close().await;
}

#[tokio::test]
async fn interrupted_page_rolls_back_events_and_native_binding_together() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let connection = pool(&dir.path().join("history.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER interrupt_page BEFORE INSERT ON exex_committed_epoch WHEN NEW.sequence='0000000000000002' BEGIN SELECT RAISE(ABORT,'injected storage failure'); END")
        .execute(&connection).await.unwrap();
    assert!(source.import(&history).await.is_err());
    assert_eq!(source.head().await.unwrap().sequence, Sequence(0));
    assert_eq!(source.native_head().await.unwrap(), *history.anchor());
    assert!(source.load(Sequence(1)).await.unwrap().is_none());
    let metadata: i64 = sqlx::query_scalar("SELECT count(*) FROM exex_native_reward")
        .fetch_one(&connection)
        .await
        .unwrap();
    assert_eq!(metadata, 0);
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM exex_native_export_version")
        .fetch_one(&connection)
        .await
        .unwrap();
    assert_eq!(versions, 0);
    sqlx::query("DROP TRIGGER interrupt_page")
        .execute(&connection)
        .await
        .unwrap();
    assert_eq!(source.import(&history).await.unwrap().sequence, Sequence(3));
}

#[test]
fn modified_identity_commitments_links_and_missing_history_fail_closed() {
    let cases = fixture();
    let mutations = [
        ("/epochs/0/transactions/0/transaction", json!("{}")),
        ("/epochs/0/transactions/0/identity", json!("{}")),
        ("/epochs/0/transactions/0/hash", json!("a".repeat(64))),
        ("/epochs/0/transactions/0/txid", json!(100)),
        ("/epochs/0/transactions/0/proof", json!("unchecked")),
        ("/epochs/0/parent_root", json!("a".repeat(64))),
        ("/epochs/0/parent_commit", json!("other-tree")),
        ("/epochs/0/start_txid", json!(100)),
        ("/epochs/0/boundary/txid_hi", json!(-1)),
        ("/epochs/0/boundary/ledger_root", json!("other-ledger")),
        ("/epochs/0/boundary/index_hash", json!("a".repeat(64))),
        ("/head/irmin_commit", json!("other-tree")),
        ("/epochs", json!([])),
        ("/head_commit_id", json!("")),
        ("/format", json!("untrusted-v2")),
    ];
    for (path, replacement) in mutations {
        let mut changed = cases["full"].clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        assert!(
            NativeHistory::parse_with_rewards(&serde_json::to_vec(&changed).unwrap(), &authority)
                .is_err(),
            "{path}"
        );
    }
    let mut skipped = cases["full"].clone();
    skipped["epochs"].as_array_mut().unwrap().remove(1);
    assert!(
        NativeHistory::parse_with_rewards(&serde_json::to_vec(&skipped).unwrap(), &authority)
            .is_err()
    );
    let mut duplicate = cases["full"].clone();
    duplicate["epochs"]
        .as_array_mut()
        .unwrap()
        .insert(0, cases["full"]["epochs"][0].clone());
    assert!(NativeHistory::parse_with_rewards(
        &serde_json::to_vec(&duplicate).unwrap(),
        &authority
    )
    .is_err());
}

#[tokio::test]
async fn native_legacy_reward_metadata_matches_actual_export_and_survives_reopen() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    assert!(NativeHistory::parse(&serde_json::to_vec(&cases["full"]).unwrap()).is_err());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("rewards.db");
    let connection = pool(&db).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    drop(source);
    connection.close().await;
    let connection = pool(&db).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    let expected = cases["reward_sources"].as_array().unwrap();
    assert_eq!(expected.len(), 3);
    for (index, expected) in expected.iter().enumerate() {
        let sequence = Sequence(index as u64 + 1);
        let raw = STANDARD
            .decode(
                cases["full"]["epochs"][index]["epoch_header"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(expected["header_sha256"], hex::encode(Sha256::digest(&raw)));
        let source = source
            .reward_source(sequence, &authority)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reward_wire(&source),
            STANDARD
                .decode(expected["source"].as_str().unwrap())
                .unwrap()
        );
        assert_eq!(expected["epoch"].as_u64().unwrap(), sequence.0);
    }
    // Rebinding old missing evidence under a weighted activation is forbidden.
    let weighted = |epoch| {
        let mut selected = authority(epoch)?;
        selected.validator_activation_epoch = Some(Nonce::new(2).unwrap());
        Ok(selected)
    };
    assert!(source
        .reward_source(Sequence(1), &weighted)
        .await
        .unwrap()
        .is_some());
    assert!(source.reward_source(Sequence(2), &weighted).await.is_err());
    assert!(NativeHistory::parse_with_rewards(
        &serde_json::to_vec(&cases["full"]).unwrap(),
        &weighted
    )
    .is_err());
    let wrong_keys = |epoch| {
        let mut selected = authority(epoch)?;
        selected.validator_pubkeys[0].1 = STANDARD.encode([b'c'; 32]).into_bytes();
        Ok(selected)
    };
    assert!(source
        .reward_source(Sequence(1), &wrong_keys)
        .await
        .is_err());
}

#[tokio::test]
async fn v1_explicitly_lacks_rewards_and_v2_cannot_silently_lose_or_change_metadata() {
    let cases = fixture();
    let mut old = cases["full"].clone();
    old["format"] = json!("octra-exex-history-v1");
    for epoch in old["epochs"].as_array_mut().unwrap() {
        epoch.as_object_mut().unwrap().remove("epoch_header");
    }
    let old = NativeHistory::parse(&serde_json::to_vec(&old).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let connection = pool(&dir.path().join("v1.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), old.anchor().clone())
        .await
        .unwrap();
    source.import(&old).await.unwrap();
    assert!(source
        .reward_source(Sequence(1), &authority)
        .await
        .unwrap()
        .is_none());

    for mutation in [
        "header",
        "hash",
        "source",
        "binding",
        "outbox",
        "missing",
        "missing_version_and_reward",
        "valid_other_transaction",
        "rehashed_header",
    ] {
        let connection = pool(&dir.path().join(format!("{mutation}.db"))).await;
        let history = parse(&cases["full"]);
        let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
            .await
            .unwrap();
        source.import(&history).await.unwrap();
        let command = match mutation {
            "header" => "UPDATE exex_native_reward SET header=x'7b7d' WHERE sequence='0000000000000001'",
            "hash" => "UPDATE exex_native_reward SET header_hash=zeroblob(32) WHERE sequence='0000000000000001'",
            "source" => "UPDATE exex_native_reward SET source=x'00' WHERE sequence='0000000000000001'",
            "binding" => "UPDATE exex_native_reward SET binding=x'7b7d' WHERE sequence='0000000000000001'",
            "outbox" => "UPDATE exex_committed_epoch SET events=x'5b5d' WHERE sequence='0000000000000001'",
            "missing" | "missing_version_and_reward" => "DELETE FROM exex_native_reward WHERE sequence='0000000000000001'",
            "valid_other_transaction" | "rehashed_header" => "SELECT 1",
            _ => unreachable!(),
        };
        sqlx::query(command).execute(&connection).await.unwrap();
        if mutation == "missing_version_and_reward" {
            sqlx::query("DELETE FROM exex_native_export_version WHERE sequence='0000000000000001'")
                .execute(&connection)
                .await
                .unwrap();
            NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
                .await
                .unwrap();
        }
        if mutation == "valid_other_transaction" {
            let mut event = cases["full"]["epochs"][2]["transactions"][0].clone();
            event["txid"] = cases["full"]["epochs"][0]["transactions"][0]["txid"].clone();
            let valid: NativeTransaction = serde_json::from_value(event.clone()).unwrap();
            valid.validate().unwrap();
            sqlx::query(
                "UPDATE exex_committed_epoch SET events=? WHERE sequence='0000000000000001'",
            )
            .bind(serde_json::to_vec(&vec![event]).unwrap())
            .execute(&connection)
            .await
            .unwrap();
        }
        if mutation == "rehashed_header" {
            let raw = STANDARD
                .decode(cases["full"]["epochs"][0]["epoch_header"].as_str().unwrap())
                .unwrap();
            let mut header: Value = serde_json::from_slice(&raw).unwrap();
            header["parent_commit"] = json!("other-parent");
            let raw = serde_json::to_vec(&header).unwrap();
            sqlx::query("UPDATE exex_native_reward SET header=?,header_hash=? WHERE sequence='0000000000000001'")
                .bind(&raw).bind(Sha256::digest(&raw).as_slice()).execute(&connection).await.unwrap();
        }
        assert!(
            source.reward_source(Sequence(1), &authority).await.is_err(),
            "{mutation}"
        );
        assert!(
            source
                .reward_source(Sequence(2), &authority)
                .await
                .unwrap()
                .is_some(),
            "unaffected next record: {mutation}"
        );
    }
}

#[tokio::test]
async fn prefeature_native_history_migrates_once_and_reopen_cannot_heal_deleted_markers() {
    let mut old = fixture()["full"].clone();
    old["format"] = json!("octra-exex-history-v1");
    for epoch in old["epochs"].as_array_mut().unwrap() {
        epoch.as_object_mut().unwrap().remove("epoch_header");
    }
    let history = NativeHistory::parse(&serde_json::to_vec(&old).unwrap()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let connection = pool(&directory.path().join("migration.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    drop(source);
    // Reproduce the exact pre-feature schema: retained native binding/outbox,
    // with neither of the later reward/version tables installed.
    for table in ["exex_native_reward", "exex_native_export_version"] {
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(&connection)
            .await
            .unwrap();
    }
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    assert!(source
        .reward_source(Sequence(1), &authority)
        .await
        .unwrap()
        .is_none());
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM exex_native_export_version ORDER BY sequence")
            .fetch_all(&connection)
            .await
            .unwrap();
    assert_eq!(versions, vec![1; old["epochs"].as_array().unwrap().len()]);
    sqlx::query("DELETE FROM exex_native_export_version WHERE sequence='0000000000000001'")
        .execute(&connection)
        .await
        .unwrap();
    drop(source);
    let reopened = NativeEpochSource::open(connection, chain(), history.anchor().clone())
        .await
        .unwrap();
    assert!(reopened
        .reward_source(Sequence(1), &authority)
        .await
        .is_err());
    assert!(reopened
        .reward_source(Sequence(2), &authority)
        .await
        .unwrap()
        .is_none());
    assert!(reopened
        .reward_source(Sequence(999_999), &authority)
        .await
        .unwrap()
        .is_none());
}

#[test]
fn exported_native_header_fields_are_bound_before_reward_derivation() {
    let cases = fixture();
    for (field, replacement) in [
        ("id", json!(2)),
        ("state_root", json!("wrong")),
        ("prev_state_root", json!("wrong")),
        ("parent_commit", json!("wrong")),
        ("start_txid", json!("5")),
        ("tx_count", json!(0)),
        ("reward_source", json!({"members":[]})),
    ] {
        let mut changed = cases["full"].clone();
        let raw = STANDARD
            .decode(changed["epochs"][0]["epoch_header"].as_str().unwrap())
            .unwrap();
        let mut header: Value = serde_json::from_slice(&raw).unwrap();
        header[field] = replacement;
        changed["epochs"][0]["epoch_header"] =
            json!(STANDARD.encode(serde_json::to_vec(&header).unwrap()));
        assert!(
            NativeHistory::parse_with_rewards(&serde_json::to_vec(&changed).unwrap(), &authority)
                .is_err(),
            "{field}"
        );
    }
}

#[tokio::test]
async fn missing_outbox_and_changed_binding_cannot_reset_progress() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let connection = pool(&dir.path().join("history.db")).await;
    let source = NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    assert!(
        NativeEpochSource::open(connection.clone(), chain(), history.head().clone())
            .await
            .is_err()
    );
    sqlx::query("DELETE FROM exex_committed_epoch")
        .execute(&connection)
        .await
        .unwrap();
    assert!(source.import(&parse(&cases["caught_up"])).await.is_err());
}

struct DurableSink {
    pool: SqlitePool,
    fail_after_write: bool,
}
impl ExEx<NativeTransaction> for DurableSink {
    fn name(&self) -> &'static str {
        "native-history-test"
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) -> Result<(), String> {
        let value = serde_json::to_string(epoch).unwrap();
        sqlx::query("INSERT INTO sink(sequence,payload) VALUES(?,?) ON CONFLICT DO NOTHING")
            .bind(epoch.cursor.sequence.0 as i64)
            .bind(&value)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        let saved: String = sqlx::query_scalar("SELECT payload FROM sink WHERE sequence=?")
            .bind(epoch.cursor.sequence.0 as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        if saved != value {
            return Err("replay changed a committed payload".into());
        }
        if self.fail_after_write {
            return Err("injected crash after sink write".into());
        }
        Ok(())
    }
}

async fn wait_status(manager: &ExExManager<NativeTransaction>, failed: bool) {
    let mut status = manager.status("native-history-test").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let done = match &*status.borrow() {
                ExtensionStatus::Failed { .. } => failed,
                ExtensionStatus::Running { checkpoint } => {
                    !failed && checkpoint.sequence == Sequence(3)
                }
                _ => false,
            };
            if done {
                break;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn consumer_restart_replays_sink_write_without_skipping_empty_epochs() {
    let cases = fixture();
    let history = parse(&cases["full"]);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("history.db");
    let connection = pool(&db).await;
    sqlx::query("CREATE TABLE sink(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL)")
        .execute(&connection)
        .await
        .unwrap();
    let source = Arc::new(
        NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
            .await
            .unwrap(),
    );
    let checkpoints = Arc::new(
        SqliteCheckpoints::open(&dir.path().join("checkpoints.db"))
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    manager
        .register(DurableSink {
            pool: connection.clone(),
            fail_after_write: true,
        })
        .await
        .unwrap();
    source.import(&history).await.unwrap();
    manager.notify_commit();
    wait_status(&manager, true).await;
    assert!(manager.stop("native-history-test").await.is_err());
    assert!(checkpoints
        .load(&chain(), "native-history-test")
        .await
        .unwrap()
        .is_none());
    drop(manager);
    drop(source);
    connection.close().await;
    let connection = pool(&db).await;
    let source = Arc::new(
        NativeEpochSource::open(connection.clone(), chain(), history.anchor().clone())
            .await
            .unwrap(),
    );
    let mut manager = ExExManager::new(source, checkpoints).unwrap();
    manager
        .register(DurableSink {
            pool: connection.clone(),
            fail_after_write: false,
        })
        .await
        .unwrap();
    // Registration discovers persisted backlog even with no new commit wakeup.
    wait_status(&manager, false).await;
    assert_eq!(
        manager.stop("native-history-test").await.unwrap().sequence,
        Sequence(3)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sink")
        .fetch_one(&connection)
        .await
        .unwrap();
    assert_eq!(count, 3);
}
