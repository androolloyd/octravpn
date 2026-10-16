//! Real signed QCs at the publication boundary. Execution and validator
//! activation are supplied local fixtures, not a running peer consensus driver.
use std::sync::Arc;

use octra_exex::{
    native_history::NativeTransaction, ChainIdentity, CommittedEpochSource, Sequence, StateRoot,
};
use octra_node_protocol::{
    consensus::{codec::Wire, Finalize},
    native_json::Document,
    transaction::Transaction,
};
use octra_node_runtime::{
    canonical::{CanonicalStore, Head, ReliefSource},
    finality::{EpochRules, Error, ExecutedEpoch, Publisher, ReceiptRules, ValidatorHistory},
    state_batch::StateBatch,
};
use serde_json::Value;
#[path = "common/finality_host.rs"]
mod common;
use common::{certificate, root, sign, Authority};

fn transaction_fixture() -> Vec<NativeTransaction> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../octra-exex/tests/fixtures/native-history.json"
    ))
    .unwrap();
    let mut transactions: Vec<NativeTransaction> = fixture["cases"]["full"]["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|epoch| {
            serde_json::from_value::<Vec<NativeTransaction>>(epoch["transactions"].clone()).unwrap()
        })
        .collect();
    transactions.sort_by(|a, b| {
        let decode =
            |raw: &[u8]| Transaction::from_document(&Document::parse(raw).unwrap()).unwrap();
        decode(&a.transaction)
            .compare_consensus(&decode(&b.transaction))
            .unwrap()
    });
    for (i, tx) in transactions.iter_mut().enumerate() {
        tx.txid = i as i64;
    }
    assert!(transactions.len() > 1);
    transactions
}
async fn fixture(path: &std::path::Path) -> (Arc<CanonicalStore>, Authority) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    state.set(&[b"fixture"], b"genesis".to_vec()).unwrap();
    state.acknowledge_commit().unwrap();
    let chain = ChainIdentity::genesis(
        "finality-publication-fixture",
        StateRoot(root(None, &state, &[])),
    );
    let authority = Authority {
        seed: 1,
        chain: chain.clone(),
    };
    let store = CanonicalStore::create(path, chain, state.snapshot(), 0)
        .await
        .unwrap();
    (Arc::new(store), authority)
}
fn execution(
    base: &Head,
    mut state: StateBatch,
    transactions: Vec<NativeTransaction>,
) -> ExecutedEpoch {
    state.begin().unwrap();
    state
        .set(
            &[b"fixture"],
            (base.cursor.epoch.0 + 1).to_string().into_bytes(),
        )
        .unwrap();
    let mut rejected = Transaction::from_document(
        &Document::parse(&transaction_fixture()[0].transaction).unwrap(),
    )
    .unwrap();
    rejected.from = b"z-rejected".to_vec();
    let consensus_receipts = (0..2)
        .map(|i| {
            rejected.nonce = octra_node_protocol::transaction::Nonce::new(i + 1).unwrap();
            octra_node_protocol::transaction_outcome::encode_rejection(
                &octra_node_protocol::transaction_outcome::Rejection {
                    position: transactions.len() as i64 + i,
                    tx: rejected.clone(),
                    error_type: b"failed".to_vec(),
                    reason: b"development fixture rejection".to_vec(),
                    charged: false,
                },
            )
            .unwrap()
        })
        .collect();
    ExecutedEpoch {
        epoch_observation: None,
        metrics: octra_node_protocol::metrics::Epoch::default(),
        vm_receipts: std::collections::BTreeMap::default(),
        reward_source: common::reward_source(1),
        state: state.snapshot(),
        transactions,
        consensus_receipts,
        date: 10,
        message: b"publication fixture".to_vec(),
    }
}
async fn unchanged(store: &CanonicalStore, base: &Head) {
    assert_eq!(store.head().await.unwrap(), *base);
    assert_eq!(store.source().head().await.unwrap(), base.cursor);
    assert!(store
        .source()
        .load(Sequence(base.cursor.sequence.0 + 1))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn bounded_ranges_and_projected_history_reauthenticate_the_same_committed_epoch() {
    use octra_node_runtime::canonical::{HistoryQuery, HistoryReadError};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded.db");
    let (store, authority) = fixture(&path).await;
    let publisher = Arc::new(
        Publisher::open(store.clone(), authority.clone())
            .await
            .unwrap(),
    );
    let (base, state) = store.snapshot().await.unwrap();
    let executed = execution(&base, state, transaction_fixture());
    let finalized = certificate(&base, &executed, &authority).encode().unwrap();
    let head = publisher
        .prepare(&base, &finalized, executed.clone())
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let reader = store.reader();
    let lengths = reader.record_lengths(&head).await.unwrap();
    assert!(
        lengths.events > 0
            && lengths.receipts > 0
            && lengths.reward > 0
            && lengths.certificate == finalized.len()
    );
    let mut forged = head.clone();
    forged.cursor.state_root = StateRoot([99; 32]);
    assert!(reader.record_lengths(&forged).await.is_err());
    let record = publisher
        .record_bounded(head.cursor.sequence, 32 * 1024 * 1024)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record,
        publisher.record(head.cursor.sequence).await.unwrap()
    );
    let raw_tx_bytes = record
        .txs_json
        .iter()
        .map(|raw| raw.len() + 64)
        .sum::<usize>();
    assert!(publisher
        .record_bounded(head.cursor.sequence, raw_tx_bytes - 1)
        .await
        .unwrap()
        .is_none());
    let query = HistoryQuery::default();
    // A large configured limit with a small matching result must remain valid.
    let page = reader
        .transactions_projected(
            &head,
            &query,
            100_001,
            0,
            8 * 1024 * 1024,
            |epoch, tx| async move {
                assert_eq!(epoch.cursor.epoch.0, 1);
                Ok::<_, octra_node_runtime::canonical::Error>((tx.hash, 64))
            },
        )
        .await
        .unwrap();
    assert_eq!(page.total, executed.transactions.len() as u64);
    assert_eq!(page.rows.len(), executed.transactions.len());
    let refusal = reader
        .transactions_projected(
            &head,
            &query,
            100_001,
            0,
            page.rows.len() * 64 - 1,
            |_, tx| async move { Ok::<_, octra_node_runtime::canonical::Error>((tx.hash, 64)) },
        )
        .await;
    assert!(matches!(refusal, Err(HistoryReadError::ResponseLimit)));
    let rejections = reader
        .rejections_projected(&head, &query, 100_001, 0, 8 * 1024 * 1024, |row| {
            let publisher = publisher.clone();
            async move {
                let authenticated = publisher.record(row.head.cursor.sequence).await?;
                let raw =
                    octra_node_protocol::transaction_outcome::encode_rejection(&row.rejection)
                        .unwrap();
                assert!(authenticated.receipts_json.contains(&raw));
                Ok::<_, Error>((row.rejection.position, 8))
            }
        })
        .await
        .unwrap();
    assert_eq!((rejections.total, rejections.rows.len()), (2, 2));
    // Scalar length guards must refuse oversized auxiliary bytes before a JSON
    // decoder loads them. The refusal is operational, never a missing epoch.
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT events FROM exex_committed_epoch WHERE sequence='0000000000000001'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE exex_committed_epoch SET events=zeroblob(?) WHERE sequence='0000000000000001'",
    )
    .bind(4 * 1024 * 1024 + 8 * 64 + 1)
    .execute(&db)
    .await
    .unwrap();
    assert!(
        matches!(publisher.record_bounded(head.cursor.sequence,64).await,Err(Error::Unavailable(reason)) if reason=="canonical archive exceeds bounded read budget")
    );
    sqlx::query("UPDATE exex_committed_epoch SET events=? WHERE sequence='0000000000000001'")
        .bind(original)
        .execute(&db)
        .await
        .unwrap();
    let mut corrupted = finalized.clone();
    corrupted[0] ^= 1;
    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind(corrupted)
        .execute(&db)
        .await
        .unwrap();
    assert!(
        publisher
            .record_bounded(head.cursor.sequence, 32 * 1024 * 1024)
            .await
            .is_err(),
        "length hints must not bypass QC authentication"
    );
    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind(finalized)
        .execute(&db)
        .await
        .unwrap();
    publisher.audit().await.unwrap();
}

struct MissingHistory;
#[async_trait::async_trait]
impl ValidatorHistory for MissingHistory {
    async fn resolve(&self, _: &Head, _: u64, _: ReliefSource) -> Result<EpochRules, String> {
        Err("activation history is unavailable".into())
    }
}

#[tokio::test]
async fn rejects_certificates_and_execution_that_do_not_share_one_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let (store, authority) = fixture(&dir.path().join("node.db")).await;
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let (base, state) = store.snapshot().await.unwrap();
    let executed = execution(&base, state, transaction_fixture());
    let valid = certificate(&base, &executed, &authority);
    let missing = Publisher::open(store.clone(), MissingHistory)
        .await
        .unwrap();
    assert!(matches!(
        missing
            .prepare(&base, &valid.encode().unwrap(), executed.clone())
            .await,
        Err(Error::Authority(_))
    ));
    unchanged(&store, &base).await;
    for mutation in [
        "signature",
        "quorum",
        "duplicate",
        "chain",
        "previous",
        "state",
        "transactions",
        "receipts",
        "txid",
        "epoch",
        "proposer",
        "parent",
        "outsider",
    ] {
        let mut bad = valid.clone();
        match mutation {
            "chain" => {
                bad.chain_id = b"other-chain".to_vec();
                bad.header.chain_id.clone_from(&bad.chain_id);
            }
            "previous" => bad.header.prev_state_root[0] ^= 1,
            "state" => bad.header.proposed_state_root[0] ^= 1,
            "transactions" => bad.header.tx_list_hash[0] ^= 1,
            "receipts" => bad.header.receipt_root[0] ^= 1,
            "txid" => bad.header.txid_hi += 1,
            "epoch" => {
                bad.epoch_id += 1;
                bad.header.epoch_id += 1;
            }
            "proposer" => bad.header.creator_addr = b"outsider".to_vec(),
            "parent" => bad.header.parent_commit_hash[0] ^= 1,
            _ => {}
        }
        sign(
            &mut bad,
            if mutation == "outsider" {
                11
            } else {
                authority.seed
            },
        );
        match mutation {
            "signature" => bad.precommits[0].signature[0] ^= 1,
            "quorum" => {
                bad.precommits.pop();
            }
            "duplicate" => bad.precommits[2] = bad.precommits[0].clone(),
            _ => {}
        }
        assert!(
            publisher
                .prepare(&base, &bad.encode().unwrap(), executed.clone())
                .await
                .is_err(),
            "{mutation}"
        );
        unchanged(&store, &base).await;
    }
    for mutation in ["archive", "txid", "order", "receipt", "state"] {
        let mut bad = executed.clone();
        match mutation {
            "archive" => bad.transactions[0].transaction.push(b' '),
            "txid" => bad.transactions[0].txid += 1,
            "order" => bad.transactions.reverse(),
            "receipt" => bad.consensus_receipts.reverse(),
            "state" => {
                let mut state = StateBatch::from_snapshot(bad.state);
                state.begin().unwrap();
                state.set(&[b"fixture"], b"forged".to_vec()).unwrap();
                bad.state = state.snapshot();
            }
            _ => unreachable!(),
        }
        assert!(
            publisher
                .prepare(&base, &valid.encode().unwrap(), bad)
                .await
                .is_err(),
            "{mutation}"
        );
        unchanged(&store, &base).await;
    }
    // Even a valid QC cannot turn an invalid outcome partition into a commit.
    let mut bad_outcome = executed.clone();
    let tx = Transaction::from_document(
        &Document::parse(&executed.transactions[0].transaction).unwrap(),
    )
    .unwrap();
    bad_outcome.consensus_receipts.push(
        octra_node_protocol::transaction_outcome::encode_rejection(
            &octra_node_protocol::transaction_outcome::Rejection {
                position: 0,
                tx,
                error_type: b"failed".to_vec(),
                reason: b"duplicate confirmed transaction".to_vec(),
                charged: false,
            },
        )
        .unwrap(),
    );
    let cert = certificate(&base, &bad_outcome, &authority)
        .encode()
        .unwrap();
    assert!(matches!(
        publisher.prepare(&base, &cert, bad_outcome).await,
        Err(Error::Invalid(_))
    ));
    let mut unavailable = executed.clone();
    unavailable.consensus_receipts = vec![b"{".to_vec()];
    let cert = certificate(&base, &unavailable, &authority)
        .encode()
        .unwrap();
    assert!(matches!(
        publisher.prepare(&base, &cert, unavailable).await,
        Err(Error::Unavailable(_))
    ));
    unchanged(&store, &base).await;
    let mut trailing = valid.encode().unwrap();
    trailing.push(0);
    assert!(publisher
        .prepare(&base, &trailing, executed.clone())
        .await
        .is_err());
    let wrong = Publisher::open(
        store.clone(),
        Authority {
            seed: 11,
            chain: authority.chain.clone(),
        },
    )
    .await
    .unwrap();
    assert!(wrong
        .prepare(&base, &valid.encode().unwrap(), executed.clone())
        .await
        .is_err());
    // A dropped preparation exposes neither the epoch nor its receipts/ExEx.
    drop(
        publisher
            .prepare(&base, &valid.encode().unwrap(), executed.clone())
            .await
            .unwrap(),
    );
    unchanged(&store, &base).await;
    let head = publisher
        .prepare(&base, &valid.encode().unwrap(), executed.clone())
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    assert_eq!(head.cursor.epoch.0, 1);
    assert_eq!(
        store.certificate(head.cursor.sequence).await.unwrap(),
        valid.encode().unwrap()
    );
    assert!(publisher
        .prepare(&base, &valid.encode().unwrap(), executed)
        .await
        .is_err());
    publisher.audit().await.unwrap();
    assert!(matches!(
        Publisher::open(store, MissingHistory).await,
        Err(Error::Authority(_))
    ));
}

#[tokio::test]
async fn restart_reauthenticates_history_and_detects_missing_or_modified_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let (store, authority) = fixture(&path).await;
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    for epoch in 1..=3 {
        let (base, state) = store.snapshot().await.unwrap();
        let executed = execution(
            &base,
            state,
            if epoch == 1 {
                transaction_fixture()
            } else {
                vec![]
            },
        );
        let cert = certificate(&base, &executed, &authority).encode().unwrap();
        publisher
            .prepare(&base, &cert, executed)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    let head = store.head().await.unwrap();
    drop(publisher);
    Arc::try_unwrap(store).ok().unwrap().close().await;
    let store = Arc::new(CanonicalStore::open(&path, &authority.chain).await.unwrap());
    assert_eq!(store.head().await.unwrap(), head);
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    assert!(Publisher::open(
        store.clone(),
        Authority {
            seed: 11,
            chain: authority.chain.clone()
        }
    )
    .await
    .is_err());
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    let original = store.certificate(Sequence(1)).await.unwrap();
    let mut bad = Finalize::decode(&original).unwrap();
    bad.precommits[0].signature[0] ^= 1;
    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind(bad.encode().unwrap())
        .execute(&db)
        .await
        .unwrap();
    // The head is unchanged, but an already-audited prefix is no longer safe.
    assert_eq!(store.head().await.unwrap(), head);
    assert!(publisher.audit().await.is_err());
    sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=1")
        .bind(original)
        .execute(&db)
        .await
        .unwrap();
    publisher.audit().await.unwrap();
    sqlx::query("UPDATE node_consensus_receipts SET receipts=? WHERE sequence=2")
        .bind(b"[]".as_slice())
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(store.head().await.unwrap(), head);
    assert!(publisher.audit().await.is_err());
    assert!(Publisher::open(store.clone(), authority.clone())
        .await
        .is_err());
    sqlx::query("DELETE FROM node_consensus_receipts WHERE sequence=2")
        .execute(&db)
        .await
        .unwrap();
    assert!(Publisher::open(store, authority).await.is_err());
}

#[tokio::test]
async fn receipt_storage_failure_rolls_back_state_history_and_exex() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let (store, authority) = fixture(&path).await;
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("CREATE TABLE node_consensus_receipts(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence), receipts BLOB NOT NULL)").execute(&db).await.unwrap();
    sqlx::query("CREATE TRIGGER refuse_receipts BEFORE INSERT ON node_consensus_receipts BEGIN SELECT RAISE(ABORT,'injected receipt persistence failure'); END").execute(&db).await.unwrap();
    let (base, state) = store.snapshot().await.unwrap();
    let executed = execution(&base, state, transaction_fixture());
    let cert = certificate(&base, &executed, &authority).encode().unwrap();
    assert!(publisher
        .prepare(&base, &cert, executed.clone())
        .await
        .is_err());
    unchanged(&store, &base).await;
    sqlx::query("DROP TRIGGER refuse_receipts")
        .execute(&db)
        .await
        .unwrap();
    publisher
        .prepare(&base, &cert, executed)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    publisher.audit().await.unwrap();
}

#[derive(Clone)]
struct ReceiptAuthority {
    authority: Authority,
    crypto: bool,
    available: bool,
}
#[async_trait::async_trait]
impl ValidatorHistory for ReceiptAuthority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        let mut rules = self.authority.resolve(parent, epoch, relief).await?;
        if !self.available {
            return Err("receipt history unavailable".into());
        }
        rules.receipts = ReceiptRules {
            required: true,
            crypto_active: self.crypto,
            stealth_minimum: 5000.into(),
        };
        Ok(rules)
    }
}

#[tokio::test]
async fn valid_quorum_cannot_bypass_receipt_bindings_or_missing_rule_history() {
    use octra_node_protocol::preverify_receipt::{Binding, Receipt};
    let dir = tempfile::tempdir().unwrap();
    let (store, authority) = fixture(&dir.path().join("node.db")).await;
    let (base, state) = store.snapshot().await.unwrap();
    let mut item = transaction_fixture().remove(0);
    let mut tx = Transaction::from_document(&Document::parse(&item.transaction).unwrap()).unwrap();
    tx.op_type = octra_node_protocol::transaction::OpType::Encrypt;
    item.identity = tx.identity_bytes().unwrap();
    item.transaction = item.identity.clone();
    item.proof = octra_exex::native_history::ArchiveProof::Exact;
    item.hash = hex::encode(tx.hash().unwrap());
    let receipt = Receipt::for_tx(
        &tx,
        Binding::Unbound,
        Binding::Unbound.input_hash(&tx).unwrap(),
        Binding::Unbound.output_hash(&tx, b"ok").unwrap(),
        true,
        vec![],
        &5000.into(),
    )
    .unwrap();
    let mut executed = execution(&base, state, vec![item]);
    executed.consensus_receipts.insert(0, receipt.canonical());
    let policy = ReceiptAuthority {
        authority: authority.clone(),
        crypto: false,
        available: true,
    };
    let publisher = Publisher::open(store.clone(), policy.clone())
        .await
        .unwrap();
    for mutation in ["missing", "parse", "input", "output", "cost", "orphan"] {
        let mut candidate = executed.clone();
        let mut r = receipt.clone();
        match mutation {
            "input" => r.input_hash = vec![b'0'; 64],
            "output" => r.output_hash = vec![b'0'; 64],
            "cost" => r.cost.bytes += 1,
            "orphan" => r.tx_hash = vec![b'0'; 64],
            _ => (),
        }
        candidate.consensus_receipts[0] = r.canonical();
        if mutation == "missing" {
            candidate.consensus_receipts.remove(0);
        }
        if mutation == "parse" {
            candidate.consensus_receipts[0] = b"{}".to_vec();
        }
        let certificate = certificate(&base, &candidate, &authority).encode().unwrap();
        let error = publisher
            .prepare(&base, &certificate, candidate)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error,Error::Invalid(ref reason) if reason.contains("catchup preverify mismatch")),
            "{mutation}: {error}"
        );
        unchanged(&store, &base).await;
    }
    let certificate = certificate(&base, &executed, &authority).encode().unwrap();
    let absent = Publisher::open(
        store.clone(),
        ReceiptAuthority {
            available: false,
            ..policy.clone()
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        absent.prepare(&base, &certificate, executed.clone()).await,
        Err(Error::Authority(_))
    ));
    let active = Publisher::open(
        store.clone(),
        ReceiptAuthority {
            crypto: true,
            ..policy.clone()
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(active.prepare(&base,&certificate,executed.clone()).await,Err(Error::Invalid(reason)) if reason.contains("receipt_state_binding_missing"))
    );
    unchanged(&store, &base).await;
    publisher
        .prepare(&base, &certificate, executed)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    publisher.audit().await.unwrap();
    assert!(matches!(
        Publisher::open(
            store.clone(),
            ReceiptAuthority {
                available: false,
                ..policy.clone()
            }
        )
        .await,
        Err(Error::Authority(_))
    ));
    assert!(Publisher::open(
        store,
        ReceiptAuthority {
            crypto: true,
            ..policy
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn committed_history_serves_bundles_ranges_and_rejects_reward_corruption() {
    use octra_node_runtime::{finality::history::History, finality_queries::Range};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.db");
    let (store, authority) = fixture(&path).await;
    let publisher = Publisher::open(store.clone(), authority.clone())
        .await
        .unwrap();
    assert!(matches!(
        publisher.range(1, 16).await.unwrap(),
        Range::NotFound
    ));
    assert!(publisher.bundle(&[0; 32]).await.unwrap().is_none());
    assert_eq!(
        publisher.root(0).await.unwrap().unwrap(),
        authority.chain.genesis_root().unwrap().0
    );
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    sqlx::query("CREATE TABLE node_epoch_rewards(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence), proposal BLOB NOT NULL UNIQUE, source BLOB NOT NULL)").execute(&db).await.unwrap();
    sqlx::query("CREATE TRIGGER refuse_rewards BEFORE INSERT ON node_epoch_rewards BEGIN SELECT RAISE(ABORT,'injected reward persistence failure'); END").execute(&db).await.unwrap();
    let (base, state) = store.snapshot().await.unwrap();
    let executed = execution(&base, state, transaction_fixture());
    let mut finalized = certificate(&base, &executed, &authority);
    finalized.header.proto_version = 3;
    sign(&mut finalized, authority.seed);
    let certificate = finalized.encode().unwrap();
    assert!(publisher
        .prepare(&base, &certificate, executed.clone())
        .await
        .is_err());
    unchanged(&store, &base).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='node_consensus_receipts'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        count, 0,
        "receipt table creation must roll back with reward failure"
    );
    sqlx::query("DROP TRIGGER refuse_rewards")
        .execute(&db)
        .await
        .unwrap();
    let mut wrong = executed.clone();
    wrong.reward_source.reward_members[0].reward_weight = 2.into();
    assert!(publisher
        .prepare(&base, &certificate, wrong)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("reward source does not match legacy finality"));
    let prepared = publisher
        .prepare(&base, &certificate, executed.clone())
        .await
        .unwrap();
    drop(prepared);
    unchanged(&store, &base).await;
    assert!(publisher
        .bundle(&finalized.proposal_id.clone().try_into().unwrap())
        .await
        .unwrap()
        .is_none());
    publisher
        .prepare(&base, &certificate, executed.clone())
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let bundle = publisher
        .bundle(&finalized.proposal_id.clone().try_into().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bundle.txs_json,
        executed
            .transactions
            .iter()
            .map(|tx| tx.transaction.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(bundle.receipts_json, executed.consensus_receipts);
    for _ in 2..=18 {
        let (base, state) = store.snapshot().await.unwrap();
        let executed = execution(&base, state, vec![]);
        let mut finalized = common::certificate(&base, &executed, &authority);
        finalized.header.proto_version = 3;
        sign(&mut finalized, authority.seed);
        publisher
            .prepare(&base, &finalized.encode().unwrap(), executed)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
    }
    let Range::Found {
        records,
        next_epoch,
    } = publisher.range(1, i64::MAX).await.unwrap()
    else {
        panic!("missing range")
    };
    assert_eq!(records.len(), 16);
    assert_eq!(next_epoch, Some(17));
    assert_eq!(
        records[0]
            .finality
            .as_ref()
            .unwrap()
            .finalize
            .encode()
            .unwrap(),
        certificate
    );
    assert_eq!(records[0].reward_source, Some(executed.reward_source));
    assert_eq!(
        publisher.root(1).await.unwrap().unwrap(),
        records[0].state_root
    );
    let Range::Found {
        records,
        next_epoch,
    } = publisher.range(17, 16).await.unwrap()
    else {
        panic!("missing tail")
    };
    assert_eq!(records.len(), 2);
    assert_eq!(next_epoch, Some(19));
    for (from, max) in [(-1, 16), (0, 16), (19, 16), (1, 0), (1, -1), (i64::MAX, 16)] {
        assert!(matches!(
            publisher.range(from, max).await.unwrap(),
            Range::NotFound
        ));
    }
    assert!(publisher.root(-1).await.unwrap().is_none());
    assert!(publisher.root(19).await.unwrap().is_none());
    publisher.audit().await.unwrap();
    let source: Vec<u8> =
        sqlx::query_scalar("SELECT source FROM node_epoch_rewards WHERE sequence=1")
            .fetch_one(&db)
            .await
            .unwrap();
    sqlx::query("UPDATE node_epoch_rewards SET source=? WHERE sequence=1")
        .bind(b"broken".as_slice())
        .execute(&db)
        .await
        .unwrap();
    assert!(publisher.range(1, 16).await.is_err());
    assert!(publisher.root(1).await.is_err());
    assert!(publisher
        .bundle(&finalized.proposal_id.clone().try_into().unwrap())
        .await
        .is_err());
    assert!(Publisher::open(store.clone(), authority.clone())
        .await
        .is_err());
    sqlx::query("UPDATE node_epoch_rewards SET source=? WHERE sequence=1")
        .bind(&source)
        .execute(&db)
        .await
        .unwrap();
    publisher.audit().await.unwrap();
    sqlx::query("UPDATE node_epoch_rewards SET proposal=? WHERE sequence=1")
        .bind([0u8; 32].as_slice())
        .execute(&db)
        .await
        .unwrap();
    assert!(publisher.record(Sequence(1)).await.is_err());
    sqlx::query("DELETE FROM node_epoch_rewards WHERE sequence=1")
        .execute(&db)
        .await
        .unwrap();
    assert!(Publisher::open(store, authority).await.is_err());
}
