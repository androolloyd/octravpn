use octra_node_runtime::consensus_work::{OutputPump, ProposalGate};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{oneshot, Notify},
    task::JoinHandle,
};

struct Waiter {
    task: Option<JoinHandle<Value>>,
    result: Value,
}
async fn gate_trace(input: &Value) -> Value {
    let gate = Arc::new(ProposalGate::default());
    let relevant = Arc::new(AtomicBool::new(true));
    let checks = Arc::new(Mutex::new(Vec::<String>::new()));
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let jobs = Arc::new(Mutex::new(BTreeMap::<
        String,
        oneshot::Sender<Result<i64, ()>>,
    >::new()));
    let mut waiters = BTreeMap::<String, Waiter>::new();
    let mut results = vec![];
    for step in input["steps"].as_array().unwrap() {
        let id = step["id"].as_str().unwrap().to_owned();
        let answer = match step["op"].as_str().unwrap() {
            "enqueue" => {
                let gate = gate.clone();
                let relevant = relevant.clone();
                let checks = checks.clone();
                let calls = calls.clone();
                let jobs = jobs.clone();
                let name = id.clone();
                let task = tokio::spawn(async move {
                    match gate
                        .run(
                            || {
                                checks.lock().unwrap().push(name.clone());
                                relevant.load(Ordering::SeqCst)
                            },
                            || async {
                                calls.lock().unwrap().push(name.clone());
                                let (send, recv) = oneshot::channel();
                                jobs.lock().unwrap().insert(name.clone(), send);
                                Some(recv.await.unwrap())
                            },
                        )
                        .await
                    {
                        None => Value::Null,
                        Some(Ok(value)) => json!(value),
                        Some(Err(())) => json!("error"),
                    }
                });
                waiters.insert(
                    id,
                    Waiter {
                        task: Some(task),
                        result: json!("pending"),
                    },
                );
                Value::Null
            }
            "cancel" => {
                if let Some(task) = waiters.get(&id).and_then(|w| w.task.as_ref()) {
                    task.abort();
                }
                Value::Null
            }
            "relevant" => {
                relevant.store(step["value"].as_bool().unwrap(), Ordering::SeqCst);
                Value::Null
            }
            "resolve" => json!(jobs.lock().unwrap().remove(&id).is_some_and(|job| job
                .send(if step["error"].as_bool().unwrap() {
                    Err(())
                } else {
                    Ok(step["value"].as_i64().unwrap())
                })
                .is_ok())),
            _ => Value::Null,
        };
        for _ in 0..40 {
            tokio::task::yield_now().await;
        }
        for waiter in waiters.values_mut() {
            if waiter.task.as_ref().is_some_and(JoinHandle::is_finished) {
                waiter.result = match waiter.task.take().unwrap().await {
                    Ok(v) => v,
                    Err(e) if e.is_cancelled() => json!("cancelled"),
                    Err(e) => panic!("gate task failed: {e}"),
                };
            }
        }
        let waits = waiters
            .iter()
            .map(|(name, w)| (name.clone(), w.result.clone()))
            .collect::<serde_json::Map<_, _>>();
        results.push(json!({"answer":answer,"checks":checks.lock().unwrap().clone(),"calls":calls.lock().unwrap().clone(),"waiters":waits}));
    }
    let pending = waiters
        .values_mut()
        .filter_map(|w| w.task.take())
        .collect::<Vec<_>>();
    for task in &pending {
        task.abort();
    }
    for task in pending {
        let _ = task.await;
    }
    json!(results)
}
#[tokio::test]
async fn native_async_proposal_gate_preserves_order_cancellation_and_relevance() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../octra-node-protocol/tests/fixtures/driver-work.json"
    ))
    .unwrap();
    let mut total = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        if case["input"]["kind"] != "gate" {
            continue;
        }
        assert_eq!(
            gate_trace(&case["input"]).await,
            case["expected"],
            "native gate trace {index}"
        );
        total += 1;
    }
    assert_eq!(total, 82);
}
#[tokio::test]
async fn output_pump_coalesces_joiners_and_recovers_after_cancellation_error_and_panic() {
    let pump = Arc::new(OutputPump::default());
    let entered = Arc::new(Notify::new());
    let finish = Arc::new(Notify::new());
    let turns = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let pump = pump.clone();
        let entered = entered.clone();
        let finish = finish.clone();
        let turns = turns.clone();
        async move {
            pump.run(|| {
                let entered = entered.clone();
                let finish = finish.clone();
                let turns = turns.clone();
                async move {
                    let turn = turns.fetch_add(1, Ordering::SeqCst);
                    if turn == 0 {
                        entered.notify_one();
                        finish.notified().await;
                    }
                    Ok::<_, String>(())
                }
            })
            .await
        }
    });
    entered.notified().await;
    for _ in 0..64 {
        assert!(!pump
            .run(|| async {
                panic!("joiner must not execute its callback");
                #[allow(unreachable_code)]
                Ok::<_, String>(())
            })
            .await
            .unwrap());
    }
    finish.notify_one();
    assert!(task.await.unwrap().unwrap());
    assert_eq!(turns.load(Ordering::SeqCst), 2);
    assert!(pump.idle());
    assert!(pump.run(|| async { Err::<(), _>("failed") }).await.is_err());
    assert!(pump.idle());
    let pending = tokio::spawn({
        let pump = pump.clone();
        let entered = entered.clone();
        async move {
            pump.run(|| async {
                entered.notify_one();
                std::future::pending::<Result<(), String>>().await
            })
            .await
        }
    });
    entered.notified().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert!(pump.idle());
    let panic = tokio::spawn({
        let pump = pump.clone();
        async move {
            pump.run(|| async {
                panic!("fixture panic");
                #[allow(unreachable_code)]
                Ok::<_, String>(())
            })
            .await
        }
    });
    assert!(panic.await.unwrap_err().is_panic());
    assert!(pump.idle());
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        pump.run(|| async { Ok::<_, String>(()) })
    )
    .await
    .unwrap()
    .unwrap());
}
