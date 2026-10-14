use async_trait::async_trait;
use octra_node_protocol::transaction::{Nonce, OpType, Transaction};
use octra_node_runtime::preverify::{
    Availability, Binding, Limits, Pool, Priority, Verification, Worker,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::{sync::oneshot, task::JoinHandle};

fn tx(i: usize) -> Transaction {
    Transaction {
        from: b"octFrom".to_vec(),
        to: b"octFrom".to_vec(),
        amount: 0.into(),
        nonce: Nonce::new(i as i64 + 1).unwrap(),
        ou: 3000.into(),
        timestamp: 1.,
        signature: b"sig".to_vec(),
        public_key: Some(b"pub".to_vec()),
        message: None,
        op_type: if i == 7 {
            OpType::Standard
        } else {
            OpType::KeySwitch
        },
        encrypted_data: Some(b"payload".to_vec()),
    }
}
fn hash(tx: &Transaction) -> Vec<u8> {
    hex::encode(tx.hash().unwrap()).into_bytes()
}
#[derive(Default)]
struct State {
    calls: Vec<Value>,
    jobs: BTreeMap<usize, oneshot::Sender<String>>,
    source: i64,
    mode: String,
}
#[derive(Clone)]
struct Controlled(Arc<Mutex<State>>);
#[async_trait]
impl Worker for Controlled {
    type Artifact = i64;
    type Prepared = i64;
    fn eligible(&self, tx: &Transaction) -> bool {
        tx.op_type != OpType::Standard
    }
    async fn verify(
        &self,
        priority: Priority,
        tx: &Transaction,
    ) -> Result<Verification<i64>, String> {
        let (artifact, receiver) = {
            let mut state = self.0.lock().unwrap();
            let i = (tx.nonce.get() - 1) as usize;
            state.calls.push(json!([
                i,
                match priority {
                    Priority::Required => "required",
                    Priority::Speculative => "speculative",
                }
            ]));
            let (sender, receiver) = oneshot::channel();
            assert!(state.jobs.insert(i, sender).is_none(), "duplicate worker");
            (Arc::new(state.source), receiver)
        };
        match receiver.await.map_err(|_| "worker stopped")?.as_str() {
            "error" => Err("worker unavailable".into()),
            "panic" => panic!("planned worker exit"),
            "stale" => Ok(Verification::Stale),
            "rejected" => Ok(Verification::Rejected(artifact, "invalid proof".into())),
            _ => Ok(Verification::Ready(artifact)),
        }
    }
    async fn bind(&self, _: &Transaction, artifact: &i64) -> Result<Binding<i64>, String> {
        let state = self.0.lock().unwrap();
        Ok(match state.mode.as_str() {
            "invalid" => Binding::Invalid("invalid proof".into()),
            "changed" => Binding::SourceChanged,
            "error" => return Err("binding failed".into()),
            _ if *artifact == state.source => Binding::Bound(*artifact),
            _ => Binding::SourceChanged,
        })
    }
}
fn availability(a: Result<Availability<i64>, String>) -> Value {
    match a {
        Ok(Availability::Unmanaged) => json!("unmanaged"),
        Ok(Availability::Pending) => json!("pending"),
        Ok(Availability::Ready(a)) => json!({"ready":a}),
        Ok(Availability::Invalid(e)) => json!({"invalid":e}),
        Err(e) => json!({"error":e}),
    }
}
async fn settle() {
    for _ in 0..40 {
        tokio::task::yield_now().await;
    }
}
fn indices(j: &Value) -> Vec<usize> {
    j["indices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect()
}
fn make(limits: Limits) -> (Pool<Controlled>, Controlled, Arc<AtomicU64>) {
    let worker = Controlled(Arc::new(Mutex::new(State {
        source: 1,
        mode: "source".into(),
        ..State::default()
    })));
    let clock = Arc::new(AtomicU64::new(0));
    let now = clock.clone();
    let pool = Pool::new(
        worker.clone(),
        limits,
        Arc::new(move || f64::from(u32::try_from(now.load(Ordering::SeqCst)).unwrap())),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    (pool, worker, clock)
}
#[tokio::test]
async fn native_shared_job_traces() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/preverify.json")).unwrap();
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        json!(hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/preverify-oracle.ml"
        ))))
    );
    for (case_index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let (pool, worker, clock) = make(Limits {
            running: input["running"].as_u64().unwrap() as usize,
            queued: input["queued"].as_u64().unwrap() as usize,
            complete: input["complete"].as_u64().unwrap() as usize,
        });
        let mut waiters: BTreeMap<String, JoinHandle<Value>> = BTreeMap::new();
        let mut finished: BTreeMap<String, Value> = BTreeMap::new();
        for (step_index, j) in input["steps"].as_array().unwrap().iter().enumerate() {
            clock.store(j["time"].as_u64().unwrap(), Ordering::SeqCst);
            let i = j["index"].as_u64().unwrap() as usize;
            let result = match j["kind"].as_str().unwrap() {
                "admit" => availability(pool.admit(&tx(i))),
                "observe" => availability(pool.observe(&tx(i)).await),
                "wait" => {
                    let p = pool.clone();
                    waiters.insert(
                        j["id"].as_str().unwrap().into(),
                        tokio::spawn(async move { availability(p.wait(&tx(i)).await) }),
                    );
                    Value::Null
                }
                "collect" => {
                    let p = pool.clone();
                    let txs: Vec<_> = indices(j).into_iter().map(tx).collect();
                    waiters.insert(
                        j["id"].as_str().unwrap().into(),
                        tokio::spawn(async move {
                            match p.collect(&txs).await {
                                Ok(items) => json!(items
                                    .into_iter()
                                    .map(|(h, a)| json!([
                                        (0..8).find(|i| hash(&tx(*i)) == h).unwrap(),
                                        *a
                                    ]))
                                    .collect::<Vec<_>>()),
                                Err(e) => json!({"error":e}),
                            }
                        }),
                    );
                    Value::Null
                }
                "cancel" => {
                    if let Some(task) = waiters.get(j["id"].as_str().unwrap()) {
                        task.abort();
                    }
                    Value::Null
                }
                "source" => {
                    worker.0.lock().unwrap().source = j["value"].as_i64().unwrap();
                    Value::Null
                }
                "bind" => {
                    worker.0.lock().unwrap().mode = j["mode"].as_str().unwrap().into();
                    Value::Null
                }
                "retain" => {
                    let keep: Vec<_> = indices(j).into_iter().map(|i| hash(&tx(i))).collect();
                    pool.retain(|h| keep.iter().any(|v| v == h));
                    Value::Null
                }
                "resolve" => {
                    let sender = worker.0.lock().unwrap().jobs.remove(&i);
                    if let Some(sender) = sender {
                        sender.send(j["mode"].as_str().unwrap().into()).unwrap();
                        json!(true)
                    } else {
                        json!(false)
                    }
                }
                _ => Value::Null,
            };
            settle().await;
            let done: Vec<_> = waiters
                .iter()
                .filter(|(_, t)| t.is_finished())
                .map(|(id, _)| id.clone())
                .collect();
            for id in done {
                let value = match waiters.remove(&id).unwrap().await {
                    Ok(v) => v,
                    Err(e) if e.is_cancelled() => json!("cancelled"),
                    Err(e) => panic!("waiter failed: {e}"),
                };
                finished.insert(id, value);
            }
            let mut waits = finished.clone();
            for id in waiters.keys() {
                waits.insert(id.clone(), json!("pending"));
            }
            let stats = pool.stats();
            let artifacts: Vec<_> = (0..8)
                .map(|i| pool.artifact(&tx(i)).unwrap().map(|a| *a))
                .collect();
            let state = json!({"stats":[stats.pending,stats.queued,stats.running,stats.ready,stats.invalid],"artifacts":artifacts,"calls":worker.0.lock().unwrap().calls,"waiters":waits});
            assert_eq!(
                json!({"result":result,"state":state}),
                case["expected"][step_index],
                "case {case_index}, step {step_index}: {j}"
            );
        }
        for task in waiters.values() {
            task.abort();
        }
        pool.shutdown();
        settle().await;
    }
}

#[tokio::test]
async fn shutdown_wakes_running_and_queued_waiters_and_cancels_workers() {
    let (pool, worker, _) = make(Limits {
        running: 1,
        queued: 3,
        complete: 1,
    });
    pool.admit(&tx(0)).unwrap();
    pool.admit(&tx(1)).unwrap();
    settle().await;
    let first = pool.clone();
    let second = pool.clone();
    let running = tokio::spawn(async move { first.wait(&tx(0)).await });
    let queued = tokio::spawn(async move { second.wait(&tx(1)).await });
    settle().await;
    pool.shutdown();
    settle().await;
    assert_eq!(
        running.await.unwrap(),
        Err("preverification pool closed".into())
    );
    assert_eq!(
        queued.await.unwrap(),
        Err("preverification pool closed".into())
    );
    assert!(worker
        .0
        .lock()
        .unwrap()
        .jobs
        .values()
        .all(oneshot::Sender::is_closed));
    assert_eq!(
        pool.stats(),
        octra_node_runtime::preverify::Stats::default()
    );
    assert!(pool.admit(&tx(7)).is_err());
    assert!(pool.observe(&tx(7)).await.is_err());
    assert!(pool.collect(&[]).await.is_err());
}

#[tokio::test]
async fn dropping_last_owner_cancels_workers() {
    let (pool, worker, _) = make(Limits {
        running: 1,
        queued: 1,
        complete: 1,
    });
    pool.admit(&tx(0)).unwrap();
    settle().await;
    drop(pool);
    settle().await;
    assert!(worker.0.lock().unwrap().jobs[&0].is_closed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_share_one_verification() {
    let (pool, worker, _) = make(Limits {
        running: 2,
        queued: 3,
        complete: 2,
    });
    let barrier = Arc::new(tokio::sync::Barrier::new(65));
    let mut waiters = Vec::new();
    for _ in 0..64 {
        let pool = pool.clone();
        let barrier = barrier.clone();
        waiters.push(tokio::spawn(async move {
            barrier.wait().await;
            pool.admit(&tx(0)).unwrap();
            pool.wait(&tx(0)).await
        }));
    }
    barrier.wait().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let job = worker.0.lock().unwrap().jobs.remove(&0);
            if let Some(job) = job {
                job.send("ready".into()).unwrap();
                break;
            }
            tokio::task::yield_now().await;
        }
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().unwrap(), Availability::Ready(1));
        }
    })
    .await
    .unwrap();
    assert_eq!(worker.0.lock().unwrap().calls.len(), 1);
    assert_eq!(pool.stats().ready, 1);
}

struct DelayedBinding {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl Worker for DelayedBinding {
    type Artifact = ();
    type Prepared = ();
    fn eligible(&self, _: &Transaction) -> bool {
        true
    }
    async fn verify(&self, _: Priority, _: &Transaction) -> Result<Verification<()>, String> {
        Ok(Verification::Ready(Arc::new(())))
    }
    async fn bind(&self, _: &Transaction, (): &()) -> Result<Binding<()>, String> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(Binding::Bound(()))
    }
}
#[tokio::test]
async fn shutdown_during_binding_cannot_return_ready() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let pool = Pool::new(
        DelayedBinding {
            entered: entered.clone(),
            release: release.clone(),
        },
        Limits {
            running: 1,
            queued: 1,
            complete: 1,
        },
        Arc::new(|| 0.),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    pool.admit(&tx(0)).unwrap();
    settle().await;
    let p = pool.clone();
    let pending = tokio::spawn(async move { p.observe(&tx(0)).await });
    entered.notified().await;
    pool.shutdown();
    release.notify_one();
    assert_eq!(
        pending.await.unwrap(),
        Err("preverification pool closed".into())
    );
    assert_eq!(
        pool.stats(),
        octra_node_runtime::preverify::Stats::default()
    );
}
