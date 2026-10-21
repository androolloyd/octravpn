//! Exercise the production file archive, its canonical source and its actual
//! SQLite checkpoint, including reopen without duplicating sink effects.
use super::*;
use crate::{archive::Archive, Host, Node};
use octra_exex::{
    native_history::NativeTransaction, CheckpointStore, CommittedEpoch, CommittedEpochSource,
    ExtensionStatus, Sequence,
};
use std::{collections::BTreeMap, path::Path, time::Duration};
const DIRECTORY: &str = "private-exex";

pub(in super::super) async fn start<A: Host>(node: &Node<A>, root: &Path) {
    node.register(Archive::new(root.join(DIRECTORY)))
        .await
        .unwrap();
}
pub(super) async fn verify<A: Host>(
    node: &Node<A>,
    root: &Path,
    purchases: &[String],
    pool: &str,
) -> Value {
    let tip = node.head().await.unwrap().cursor;
    let source = node.store.source();
    let mut status = node.extension_status(Archive::NAME).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match status.borrow().clone() {
                ExtensionStatus::Running { checkpoint } if checkpoint == tip => break,
                ExtensionStatus::Failed { reason, .. } => {
                    panic!("private archive failed: {reason}")
                }
                ExtensionStatus::Stopped { .. } => panic!("private archive stopped"),
                _ => {}
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let checkpoint = octra_exex::sqlite::SqliteCheckpoints::open(&root.join("exex.db"))
        .await
        .unwrap();
    assert_eq!(
        checkpoint
            .load(node.store.chain(), Archive::NAME)
            .await
            .unwrap(),
        Some(tip)
    );
    checkpoint.close().await;
    let anchor = source.anchor().await.unwrap();
    for sequence in anchor.sequence.0 + 1..=tip.sequence.0 {
        let expected = source.load(Sequence(sequence)).await.unwrap().unwrap();
        let bytes =
            std::fs::read(root.join(DIRECTORY).join(format!("{sequence:016x}.json"))).unwrap();
        let got: CommittedEpoch<NativeTransaction> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(got, *expected);
    }
    let mut files = BTreeMap::new();
    let mut found = BTreeMap::new();
    let mut evidence = Vec::new();
    for entry in std::fs::read_dir(root.join(DIRECTORY)).unwrap() {
        let path = entry.unwrap().path();
        assert_eq!(path.extension().unwrap(), "json");
        let bytes = std::fs::read(&path).unwrap();
        files.insert(
            path.file_name().unwrap().to_str().unwrap().to_owned(),
            hex::encode(Sha256::digest(&bytes)),
        );
        let event: CommittedEpoch<NativeTransaction> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event.chain, *node.store.chain());
        assert!(event.cursor.sequence.0 <= tip.sequence.0);
        for native in &event.events {
            native.validate().unwrap();
            if purchases.contains(&native.hash) {
                let tx = octra_node_protocol::transaction::Transaction::from_document(
                    &octra_node_protocol::native_json::Document::parse(&native.transaction)
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(tx.to, pool.as_bytes());
                assert_eq!(tx.op_type, OpType::CircleCall);
                assert_eq!(tx.encrypted_data.as_deref(), Some(b"exchange".as_slice()));
                assert_eq!(tx.amount, 0.into());
                let receipt: Value =
                    serde_json::from_slice(native.receipt.as_ref().unwrap()).unwrap();
                assert_eq!(receipt["success"], true);
                assert_eq!(receipt["method"], "exchange");
                assert_eq!(receipt["contract"], pool);
                assert!(receipt.get("program").is_none());
                assert!(found
                    .insert(native.hash.clone(), event.cursor.sequence.0)
                    .is_none());
                evidence.push(event.clone());
            }
        }
    }
    assert_eq!(found.len(), purchases.len());
    std::fs::write(
        "/evidence/exex-purchases.json",
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    json!({"checkpoint":tip,"retained_epochs_verified":tip.sequence.0-anchor.sequence.0,
        "purchases":purchases,"pool":pool,"files":files})
}
fn accepted() -> (Vec<String>, String) {
    let report: Value =
        serde_json::from_slice(&std::fs::read("/evidence/private-kernel.json").unwrap()).unwrap();
    let facts = &report["exex"];
    (
        serde_json::from_value(facts["purchases"].clone()).unwrap(),
        facts["pool"].as_str().unwrap().to_owned(),
    )
}
pub(in super::super) async fn finish<A: Host>(node: &Node<A>, root: &Path) {
    let (purchases, pool) = accepted();
    let report = verify(node, root, &purchases, &pool).await;
    std::fs::write(
        "/evidence/exex-final.json",
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
pub(in super::super) async fn reopened<A: Host>(node: &Node<A>, root: &Path) {
    let before: Value =
        serde_json::from_slice(&std::fs::read("/evidence/exex-final.json").unwrap()).unwrap();
    let (purchases, pool) = accepted();
    start(node, root).await;
    let after = verify(node, root, &purchases, &pool).await;
    assert_eq!(before, after);
    std::fs::write("/evidence/exex-reopen.json", serde_json::to_vec_pretty(&json!({
        "canonical_and_checkpoint_reopened":true,"sink_files_unchanged":true,
        "checkpoint":after["checkpoint"],"purchase_transactions":purchases.len(),
        "retained_epochs_verified":after["retained_epochs_verified"],"archive_files":after["files"].as_object().unwrap().len(),
    })).unwrap()).unwrap();
}
