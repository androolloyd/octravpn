//! In-memory adapters are fixtures only. The node must supply persistent
//! canonical history and a durable CAS checkpoint store in production.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use octra_exex::{
    ChainIdentity, CheckpointStore, CommittedEpoch, CommittedEpochSource, Cursor, EpochId, Error,
    ExEx, ExExManager, ExtensionStatus, Result, Sequence, StateRoot,
};
use tokio::sync::{watch, Mutex, Notify};

fn chain() -> ChainIdentity {
    ChainIdentity {
        chain_id: "fixture-chain".into(),
        genesis_root: StateRoot([0; 32]),
    }
}

fn root(sequence: u64) -> StateRoot {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&sequence.to_be_bytes());
    StateRoot(bytes)
}

fn cursor(sequence: u64) -> Cursor {
    Cursor {
        sequence: Sequence(sequence),
        epoch: EpochId(100 + sequence),
        state_root: root(sequence),
    }
}

#[derive(Default)]
struct Source {
    records: Mutex<BTreeMap<u64, Arc<CommittedEpoch<u64>>>>,
    hidden: Mutex<Option<u64>>,
}

impl Source {
    async fn append(&self, count: u64) {
        for _ in 0..count {
            let mut records = self.records.lock().await;
            let next = records.len() as u64 + 1;
            records.insert(
                next,
                Arc::new(CommittedEpoch {
                    chain: chain(),
                    cursor: cursor(next),
                    parent_root: root(next - 1),
                    events: vec![next],
                }),
            );
        }
    }
}

#[async_trait]
impl CommittedEpochSource<u64> for Source {
    fn chain(&self) -> ChainIdentity {
        chain()
    }
    async fn anchor(&self) -> Result<Cursor> {
        Ok(cursor(0))
    }
    async fn head(&self) -> Result<Cursor> {
        Ok(self
            .records
            .lock()
            .await
            .values()
            .next_back()
            .map_or(cursor(0), |e| e.cursor))
    }
    async fn load(&self, sequence: Sequence) -> Result<Option<Arc<CommittedEpoch<u64>>>> {
        if *self.hidden.lock().await == Some(sequence.0) {
            return Ok(None);
        }
        Ok(self.records.lock().await.get(&sequence.0).cloned())
    }
}

#[derive(Default)]
struct Checkpoints {
    values: Mutex<BTreeMap<String, Cursor>>,
}

fn key(chain: &ChainIdentity, extension: &str) -> String {
    format!("{}:{:?}:{extension}", chain.chain_id, chain.genesis_root)
}

#[async_trait]
impl CheckpointStore for Checkpoints {
    async fn load(&self, chain: &ChainIdentity, extension: &str) -> Result<Option<Cursor>> {
        Ok(self
            .values
            .lock()
            .await
            .get(&key(chain, extension))
            .copied())
    }
    async fn compare_and_save(
        &self,
        chain: &ChainIdentity,
        extension: &str,
        expected: Option<Cursor>,
        next: Cursor,
    ) -> Result<()> {
        let mut values = self.values.lock().await;
        let key = key(chain, extension);
        if values.get(&key).copied() != expected {
            return Err(Error::Store("checkpoint compare-and-swap conflict".into()));
        }
        values.insert(key, next);
        Ok(())
    }
}

struct Recorder {
    name: &'static str,
    seen: Arc<Mutex<Vec<u64>>>,
    fail: Option<u64>,
    pause: Option<(Arc<Notify>, Arc<Notify>)>,
    panic: bool,
}

impl Recorder {
    fn new(name: &'static str, seen: &Arc<Mutex<Vec<u64>>>) -> Self {
        Self {
            name,
            seen: seen.clone(),
            fail: None,
            pause: None,
            panic: false,
        }
    }
}

impl ExEx<u64> for Recorder {
    fn name(&self) -> &str {
        self.name
    }
    async fn on_epoch(&mut self, epoch: &CommittedEpoch<u64>) -> std::result::Result<(), String> {
        assert!(!self.panic, "fixture sink panic");
        if let Some((entered, resume)) = self.pause.take() {
            entered.notify_one();
            resume.notified().await;
        }
        self.seen.lock().await.push(epoch.cursor.sequence.0);
        if self.fail == Some(epoch.cursor.sequence.0) {
            Err("fixture sink failure".into())
        } else {
            Ok(())
        }
    }
}

async fn reached(receiver: &mut watch::Receiver<ExtensionStatus>, sequence: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match receiver.borrow_and_update().clone() {
                ExtensionStatus::Running { checkpoint } if checkpoint.sequence.0 >= sequence => {
                    return
                }
                ExtensionStatus::Failed { reason, .. } => panic!("extension failed: {reason}"),
                _ => {}
            }
            receiver.changed().await.unwrap();
        }
    })
    .await
    .expect("extension should make progress");
}

async fn failed(receiver: &mut watch::Receiver<ExtensionStatus>) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                *receiver.borrow_and_update(),
                ExtensionStatus::Failed { .. }
            ) {
                return;
            }
            receiver.changed().await.unwrap();
        }
    })
    .await
    .expect("extension failure should be visible");
}

#[tokio::test]
async fn replays_commits_that_precede_registration() {
    let source = Arc::new(Source::default());
    source.append(5).await;
    let checkpoints = Arc::new(Checkpoints::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut manager = ExExManager::new(source, checkpoints.clone()).unwrap();
    manager.register(Recorder::new("vpn", &seen)).await.unwrap();
    reached(&mut manager.status("vpn").unwrap(), 5).await;
    assert_eq!(*seen.lock().await, vec![1, 2, 3, 4, 5]);
    assert_eq!(manager.stop("vpn").await.unwrap(), cursor(5));
    assert_eq!(
        checkpoints.load(&chain(), "vpn").await.unwrap(),
        Some(cursor(5))
    );
}

#[tokio::test]
async fn slow_extension_replays_coalesced_wakeups_without_blocking_other_extensions() {
    let source = Arc::new(Source::default());
    let checkpoints = Arc::new(Checkpoints::default());
    let slow_seen = Arc::new(Mutex::new(Vec::new()));
    let fast_seen = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut slow = Recorder::new("vpn", &slow_seen);
    slow.pause = Some((entered.clone(), resume.clone()));
    let mut manager = ExExManager::new(source.clone(), checkpoints).unwrap();
    manager.register(slow).await.unwrap();
    manager
        .register(Recorder::new("indexer", &fast_seen))
        .await
        .unwrap();
    source.append(1).await;
    manager.notify_commit();
    entered.notified().await;
    for _ in 0..128 {
        source.append(1).await;
        manager.notify_commit();
    }
    reached(&mut manager.status("indexer").unwrap(), 129).await;
    assert!(slow_seen.lock().await.is_empty());
    resume.notify_one();
    reached(&mut manager.status("vpn").unwrap(), 129).await;
    assert_eq!(*slow_seen.lock().await, (1..=129).collect::<Vec<_>>());
    manager.stop("vpn").await.unwrap();
    manager.stop("indexer").await.unwrap();
}

#[tokio::test]
async fn failed_callback_keeps_checkpoint_and_is_replayed_on_restart() {
    let source = Arc::new(Source::default());
    source.append(3).await;
    let checkpoints = Arc::new(Checkpoints::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    let mut recorder = Recorder::new("vpn", &seen);
    recorder.fail = Some(2);
    manager.register(recorder).await.unwrap();
    failed(&mut manager.status("vpn").unwrap()).await;
    assert!(matches!(
        manager.stop("vpn").await,
        Err(Error::Extension { .. })
    ));
    assert_eq!(
        checkpoints.load(&chain(), "vpn").await.unwrap(),
        Some(cursor(1))
    );
    // Reuse stores across a fresh manager: the sink can see sequence 2 twice.
    let mut restart = ExExManager::new(source, checkpoints).unwrap();
    restart.register(Recorder::new("vpn", &seen)).await.unwrap();
    reached(&mut restart.status("vpn").unwrap(), 3).await;
    assert_eq!(*seen.lock().await, vec![1, 2, 2, 3]);
    restart.stop("vpn").await.unwrap();
}

#[tokio::test]
async fn a_retained_history_gap_fails_instead_of_advancing() {
    let source = Arc::new(Source::default());
    source.append(2).await;
    *source.hidden.lock().await = Some(1);
    let checkpoints = Arc::new(Checkpoints::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut manager = ExExManager::new(source, checkpoints.clone()).unwrap();
    manager.register(Recorder::new("vpn", &seen)).await.unwrap();
    failed(&mut manager.status("vpn").unwrap()).await;
    assert!(matches!(
        manager.stop("vpn").await,
        Err(Error::Gap(Sequence(1)))
    ));
    assert!(seen.lock().await.is_empty());
    assert_eq!(checkpoints.load(&chain(), "vpn").await.unwrap(), None);
}

#[tokio::test]
async fn wrong_chain_parent_sequence_and_epoch_are_rejected() {
    for mutation in 0..4 {
        let source = Arc::new(Source::default());
        source.append(1).await;
        {
            let mut records = source.records.lock().await;
            let epoch = Arc::make_mut(records.get_mut(&1).unwrap());
            match mutation {
                0 => epoch.chain.genesis_root = root(999),
                1 => epoch.parent_root = root(999),
                2 => epoch.cursor.sequence = Sequence(2),
                _ => epoch.cursor.epoch = EpochId(100),
            }
        }
        let checkpoints = Arc::new(Checkpoints::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut manager = ExExManager::new(source, checkpoints.clone()).unwrap();
        manager.register(Recorder::new("vpn", &seen)).await.unwrap();
        failed(&mut manager.status("vpn").unwrap()).await;
        assert!(matches!(
            manager.stop("vpn").await,
            Err(Error::InvalidEvent(Sequence(1)))
        ));
        assert!(seen.lock().await.is_empty());
        assert_eq!(checkpoints.load(&chain(), "vpn").await.unwrap(), None);
    }
}

#[tokio::test]
async fn bad_checkpoint_root_and_future_checkpoint_are_rejected_at_registration() {
    for checkpoint in [
        Cursor {
            state_root: root(999),
            ..cursor(1)
        },
        cursor(3),
    ] {
        let source = Arc::new(Source::default());
        source.append(2).await;
        let checkpoints = Arc::new(Checkpoints::default());
        checkpoints
            .values
            .lock()
            .await
            .insert(key(&chain(), "vpn"), checkpoint);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut manager = ExExManager::new(source, checkpoints).unwrap();
        assert!(matches!(
            manager.register(Recorder::new("vpn", &seen)).await,
            Err(Error::InvalidCheckpoint(_))
        ));
        assert_eq!(manager.extension_count(), 0);
        assert!(seen.lock().await.is_empty());
    }
}

#[tokio::test]
async fn checkpoint_cas_conflict_is_visible_and_does_not_report_progress() {
    let source = Arc::new(Source::default());
    let checkpoints = Arc::new(Checkpoints::default());
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut recorder = Recorder::new("vpn", &seen);
    recorder.pause = Some((entered.clone(), resume.clone()));
    let mut manager = ExExManager::new(source.clone(), checkpoints.clone()).unwrap();
    manager.register(recorder).await.unwrap();
    source.append(1).await;
    manager.notify_commit();
    entered.notified().await;
    checkpoints
        .values
        .lock()
        .await
        .insert(key(&chain(), "vpn"), cursor(1));
    resume.notify_one();
    let mut status = manager.status("vpn").unwrap();
    failed(&mut status).await;
    assert!(
        matches!(*status.borrow(), ExtensionStatus::Failed { checkpoint, .. } if checkpoint == cursor(0))
    );
    assert!(matches!(manager.stop("vpn").await, Err(Error::Store(_))));
}

#[tokio::test]
async fn empty_epochs_are_delivered_and_duplicate_names_are_rejected() {
    let source = Arc::new(Source::default());
    source.append(1).await;
    Arc::make_mut(source.records.lock().await.get_mut(&1).unwrap())
        .events
        .clear();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut manager = ExExManager::new(source, Arc::new(Checkpoints::default())).unwrap();
    manager.register(Recorder::new("vpn", &seen)).await.unwrap();
    assert!(matches!(
        manager.register(Recorder::new("vpn", &seen)).await,
        Err(Error::DuplicateExtension(_))
    ));
    reached(&mut manager.status("vpn").unwrap(), 1).await;
    assert_eq!(*seen.lock().await, vec![1]);
    manager.stop("vpn").await.unwrap();
}

#[tokio::test]
async fn panicking_extension_is_reported_without_advancing_its_checkpoint() {
    let source = Arc::new(Source::default());
    source.append(1).await;
    let checkpoints = Arc::new(Checkpoints::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut recorder = Recorder::new("vpn", &seen);
    recorder.panic = true;
    let mut manager = ExExManager::new(source, checkpoints.clone()).unwrap();
    manager.register(recorder).await.unwrap();
    failed(&mut manager.status("vpn").unwrap()).await;
    assert!(matches!(manager.stop("vpn").await, Err(Error::Task(_))));
    assert_eq!(checkpoints.load(&chain(), "vpn").await.unwrap(), None);
}

#[tokio::test]
async fn stopping_an_idle_extension_completes_without_a_commit() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut manager = ExExManager::new(
        Arc::new(Source::default()),
        Arc::new(Checkpoints::default()),
    )
    .unwrap();
    manager.register(Recorder::new("vpn", &seen)).await.unwrap();
    let mut status = manager.status("vpn").unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), manager.stop("vpn"))
            .await
            .unwrap()
            .unwrap(),
        cursor(0)
    );
    assert!(
        matches!(*status.borrow_and_update(), ExtensionStatus::Stopped { checkpoint } if checkpoint == cursor(0))
    );
    assert!(seen.lock().await.is_empty());
}

#[tokio::test]
async fn shutdown_signals_all_workers_and_finishes_checkpoints_despite_one_failure() {
    let source = Arc::new(Source::default());
    source.append(1).await;
    let checkpoints = Arc::new(Checkpoints::default());
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let busy_seen = Arc::new(Mutex::new(Vec::new()));
    let idle_seen = Arc::new(Mutex::new(Vec::new()));
    let failed_seen = Arc::new(Mutex::new(Vec::new()));
    let mut busy = Recorder::new("a-busy", &busy_seen);
    busy.pause = Some((entered.clone(), resume.clone()));
    let mut broken = Recorder::new("b-failed", &failed_seen);
    broken.fail = Some(1);
    let mut manager = ExExManager::new(source, checkpoints.clone()).unwrap();
    manager.register(busy).await.unwrap();
    manager.register(broken).await.unwrap();
    manager
        .register(Recorder::new("c-idle", &idle_seen))
        .await
        .unwrap();
    entered.notified().await;
    failed(&mut manager.status("b-failed").unwrap()).await;
    let mut idle = manager.status("c-idle").unwrap();
    reached(&mut idle, 1).await;
    let busy = manager.status("a-busy").unwrap();
    {
        let shutdown = manager.shutdown();
        tokio::pin!(shutdown);
        tokio::select! {
            result = &mut shutdown => panic!("busy callback must finish first: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if matches!(*idle.borrow_and_update(), ExtensionStatus::Stopped { .. }) { break; }
                    idle.changed().await.unwrap();
                }
            }) => result.unwrap(),
        }
        assert!(busy_seen.lock().await.is_empty());
        resume.notify_one();
        assert!(matches!(shutdown.await, Err(Error::Extension { .. })));
    }
    assert!(
        matches!(*busy.borrow(), ExtensionStatus::Stopped { checkpoint } if checkpoint == cursor(1))
    );
    assert_eq!(
        checkpoints.load(&chain(), "a-busy").await.unwrap(),
        Some(cursor(1))
    );
    assert_eq!(
        checkpoints.load(&chain(), "c-idle").await.unwrap(),
        Some(cursor(1))
    );
    assert_eq!(checkpoints.load(&chain(), "b-failed").await.unwrap(), None);
    assert_eq!(manager.extension_count(), 0);
}
