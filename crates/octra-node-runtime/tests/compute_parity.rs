use octra_node_runtime::compute::{Limits, Pool, Priority};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::oneshot, task::JoinHandle};
fn priority(j: &Value) -> Priority {
    if j["priority"] == "required" {
        Priority::Required
    } else {
        Priority::Speculative
    }
}
fn pool(limits: Limits) -> Pool {
    Pool::new(limits, tokio::runtime::Handle::current()).unwrap()
}
async fn settle() {
    for _ in 0..40 {
        tokio::task::yield_now().await;
    }
}
#[derive(Default)]
struct Work {
    started: Vec<usize>,
    jobs: BTreeMap<usize, oneshot::Sender<bool>>,
}
#[tokio::test]
async fn native_compute_traces() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/compute.json")).unwrap();
    check_fixture(
        &fixture,
        include_bytes!("../../../scripts/node-port/compute-oracle.ml"),
    )
    .await;
}
async fn check_fixture(fixture: &Value, oracle: &[u8]) {
    let pin: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    assert_eq!(fixture["upstream_commit"], pin["upstream_commit"]);
    assert_eq!(fixture["source_sha256"], pin["files"]);
    assert_eq!(fixture["instrumentation"], json!({}));
    assert_eq!(
        fixture["oracle_sha256"],
        json!(hex::encode(Sha256::digest(oracle)))
    );
    for (case_index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let input = &case["input"];
        let pool = pool(Limits {
            capacity: input["capacity"].as_u64().unwrap() as usize,
            required: input["required"].as_u64().unwrap() as usize,
            speculative: input["speculative"].as_u64().unwrap() as usize,
            required_burst: input["burst"].as_u64().unwrap() as usize,
        });
        let work = Arc::new(Mutex::new(Work::default()));
        let mut callers: BTreeMap<usize, JoinHandle<Value>> = BTreeMap::new();
        let mut finished: BTreeMap<String, Value> = BTreeMap::new();
        for (step_index, j) in input["steps"].as_array().unwrap().iter().enumerate() {
            let id = j["id"].as_u64().unwrap() as usize;
            let result = match j["kind"].as_str().unwrap() {
                "start" => {
                    let p = pool.clone();
                    let work = work.clone();
                    let priority = priority(j);
                    callers.insert(
                        id,
                        tokio::spawn(async move {
                            match p
                                .run_async(priority, move || async move {
                                    let receiver = {
                                        let mut work = work.lock().unwrap();
                                        work.started.push(id);
                                        let (sender, receiver) = oneshot::channel();
                                        work.jobs.insert(id, sender);
                                        receiver
                                    };
                                    assert!(
                                        !receiver.await.unwrap_or(true),
                                        "planned worker failure"
                                    );
                                    id
                                })
                                .await
                            {
                                Ok(result) => json!(result),
                                Err(_) => json!("failed"),
                            }
                        }),
                    );
                    Value::Null
                }
                "cancel" => {
                    if let Some(caller) = callers.get(&id) {
                        caller.abort();
                    }
                    Value::Null
                }
                "resolve" => {
                    let sender = work.lock().unwrap().jobs.remove(&id);
                    if let Some(sender) = sender {
                        sender.send(j["fail"].as_bool().unwrap()).unwrap();
                        json!(true)
                    } else {
                        json!(false)
                    }
                }
                "try" => json!(pool.try_run_sync(priority(j), || id)),
                _ => Value::Null,
            };
            settle().await;
            let done: Vec<_> = callers
                .iter()
                .filter(|(_, c)| c.is_finished())
                .map(|(id, _)| *id)
                .collect();
            for id in done {
                let result = match callers.remove(&id).unwrap().await {
                    Ok(result) => result,
                    Err(e) if e.is_cancelled() => json!("cancelled"),
                    Err(e) => panic!("caller failed: {e}"),
                };
                finished.insert(id.to_string(), result);
            }
            let mut values = finished.clone();
            for id in callers.keys() {
                values.insert(id.to_string(), json!("pending"));
            }
            let stats = pool.stats();
            let state = json!({"stats":[stats.active,stats.required_waiting,stats.speculative_waiting,stats.required_streak],"started":work.lock().unwrap().started,"callers":values});
            assert_eq!(
                json!({"result":result,"state":state}),
                case["expected"][step_index],
                "case {case_index}, step {step_index}: {j}"
            );
        }
        for caller in callers.values() {
            caller.abort();
        }
        settle().await;
        let senders = std::mem::take(&mut work.lock().unwrap().jobs);
        for (_, sender) in senders {
            let _ = sender.send(false);
        }
        settle().await;
        assert_eq!(pool.stats().active, 0);
    }
}

#[tokio::test]
async fn exact_native_pvac_channel_limits_and_fairness() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/pvac-admission.json")).unwrap();
    assert_eq!(
        fixture["builder_image"],
        "sha256:e61194220c65f9f0b8034a4816fb15d47dfe7dda8ece1087d9850b6d838bae95"
    );
    for (name, bytes) in [
        (
            "generator_sha256",
            include_bytes!("../../../scripts/node-port/pvac-admission-fixtures.py").as_slice(),
        ),
        (
            "runner_sha256",
            include_bytes!("../../../scripts/node-port/native-oracle.py").as_slice(),
        ),
    ] {
        assert_eq!(fixture[name], hex::encode(Sha256::digest(bytes)), "{name}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), canonical(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            value => value.clone(),
        }
    }
    const DIGEST: &str = "90294df8c6edd15182b99f91f66baa956daea0c7b439a76ba4e177da7b54b81c";
    let inputs = Value::Array(cases.iter().map(|case| case["input"].clone()).collect());
    assert_eq!(fixture["input_sha256"], DIGEST);
    assert_eq!(
        hex::encode(Sha256::digest(
            serde_json::to_vec(&canonical(&inputs)).unwrap()
        )),
        DIGEST
    );
    for case in cases {
        let limits = Limits::proof(case["input"]["capacity"].as_u64().unwrap() as usize);
        assert_eq!(
            limits.required,
            case["input"]["required"].as_u64().unwrap() as usize
        );
        assert_eq!(
            limits.speculative,
            case["input"]["speculative"].as_u64().unwrap() as usize
        );
        assert_eq!(
            limits.required_burst,
            case["input"]["burst"].as_u64().unwrap() as usize
        );
    }
    check_fixture(
        &fixture,
        include_bytes!("../../../scripts/node-port/pvac-admission-oracle.ml"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_threaded_caller_keeps_capacity_until_cpu_work_stops() {
    let pool = pool(Limits {
        capacity: 1,
        required: 1,
        speculative: 1,
        required_burst: 1,
    });
    let (started, ready) = oneshot::channel();
    let (finish, done) = oneshot::channel();
    let p = pool.clone();
    let caller = tokio::spawn(async move {
        p.run_threaded(Priority::Required, move || {
            started.send(()).unwrap();
            done.blocking_recv().unwrap();
            7
        })
        .await
    });
    ready.await.unwrap();
    caller.abort();
    let _ = caller.await;
    assert_eq!(pool.stats().active, 1);
    assert_eq!(pool.try_run_sync(Priority::Required, || 99), None);
    let p = pool.clone();
    let queued = tokio::spawn(async move { p.run_async(Priority::Required, || async { 8 }).await });
    finish.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), queued)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Some(8)
    );
    assert_eq!(pool.stats().active, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronous_and_async_workers_share_capacity_and_release_after_panic() {
    let pool = pool(Limits {
        capacity: 1,
        required: 2,
        speculative: 1,
        required_burst: 1,
    });
    let (started, ready) = oneshot::channel();
    let (finish, done) = oneshot::channel();
    let p = pool.clone();
    let first = tokio::spawn(async move {
        p.run_async(Priority::Speculative, move || async move {
            started.send(()).unwrap();
            done.await.unwrap();
            1
        })
        .await
    });
    ready.await.unwrap();
    let p = pool.clone();
    let blocking = tokio::task::spawn_blocking(move || {
        p.run_sync(Priority::Required, || panic!("planned synchronous failure"))
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.stats().required_waiting == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(pool.stats().active, 1);
    finish.send(()).unwrap();
    assert_eq!(first.await.unwrap().unwrap(), Some(1));
    assert!(blocking.await.unwrap_err().is_panic());
    assert_eq!(pool.stats().active, 0);
    assert_eq!(pool.try_run_sync(Priority::Required, || 2), Some(2));
}
