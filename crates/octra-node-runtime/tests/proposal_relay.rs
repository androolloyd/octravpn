use futures::future::BoxFuture;
use octra_node_runtime::proposal_relay::{ProposalRelay, RelayIo};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tokio::sync::oneshot;

struct Pending {
    status: Arc<Mutex<&'static str>>,
    reply: Option<oneshot::Sender<bool>>,
}
struct Guard(Arc<Mutex<&'static str>>);
impl Drop for Guard {
    fn drop(&mut self) {
        let mut status = self.0.lock().unwrap();
        if *status == "pending" {
            *status = "cancelled";
        }
    }
}
fn pending() -> (Pending, BoxFuture<'static, bool>) {
    let (send, recv) = oneshot::channel();
    let status = Arc::new(Mutex::new("pending"));
    let guard = Guard(status.clone());
    (
        Pending {
            status,
            reply: Some(send),
        },
        Box::pin(async move {
            let error = recv.await.expect("fixture retains pending replies");
            *guard.0.lock().unwrap() = if error { "error" } else { "done" };
            error
        }),
    )
}
fn resolve(pending: Option<&mut Pending>, error: bool) -> bool {
    pending
        .and_then(|p| p.reply.take())
        .is_some_and(|reply| reply.send(error).is_ok())
}
#[derive(Default)]
struct Io {
    now: Mutex<f64>,
    calls: Mutex<Vec<i64>>,
    sends: Mutex<Vec<Pending>>,
    timers: Mutex<Vec<(f64, Pending)>>,
    warnings: Mutex<Vec<String>>,
    panic: AtomicBool,
}
impl RelayIo<i64> for Io {
    fn now(&self) -> f64 {
        *self.now.lock().unwrap()
    }
    fn send(&self, value: i64) -> BoxFuture<'static, Result<(), Vec<u8>>> {
        assert!(
            !self.panic.swap(false, Ordering::SeqCst),
            "fixture I/O panic"
        );
        self.calls.lock().unwrap().push(value);
        let (pending, wait) = pending();
        self.sends.lock().unwrap().push(pending);
        Box::pin(async move {
            if wait.await {
                Err(b"Failure(\"peer disconnected\")".to_vec())
            } else {
                Ok(())
            }
        })
    }
    fn wait(&self, seconds: f64) -> BoxFuture<'static, ()> {
        let (pending, wait) = pending();
        self.timers.lock().unwrap().push((seconds, pending));
        Box::pin(async move {
            wait.await;
        })
    }
    fn warn(&self, reason: &[u8]) {
        self.warnings.lock().unwrap().push(hex::encode(reason));
    }
}
async fn settle() {
    for _ in 0..40 {
        tokio::task::yield_now().await;
    }
}
async fn trace(input: &Value) -> Value {
    let io = Arc::new(Io::default());
    let relay = ProposalRelay::new(io.clone());
    let mut results = vec![];
    for step in input["steps"].as_array().unwrap() {
        let generation = step["generation"].as_i64().unwrap();
        let index = step["index"].as_u64().unwrap() as usize;
        let answer = match step["op"].as_str().unwrap() {
            "offer" => {
                relay.offer(
                    generation,
                    hex::decode(step["key"].as_str().unwrap()).unwrap(),
                    step["value"].as_i64().unwrap(),
                );
                Value::Null
            }
            "progress" => {
                relay.progress(generation);
                Value::Null
            }
            "open" => {
                relay.open(generation);
                Value::Null
            }
            "close" => {
                relay.close();
                Value::Null
            }
            "clock" => {
                *io.now.lock().unwrap() = step["now"].as_str().unwrap().parse().unwrap();
                Value::Null
            }
            "resolve" => json!(resolve(
                io.sends.lock().unwrap().get_mut(index),
                step["error"].as_bool().unwrap()
            )),
            "expire" => json!(resolve(
                io.timers.lock().unwrap().get_mut(index).map(|(_, p)| p),
                false
            )),
            _ => Value::Null,
        };
        settle().await;
        results.push(json!({"answer":answer,"calls":io.calls.lock().unwrap().clone(),
            "sends":io.sends.lock().unwrap().iter().map(|p|*p.status.lock().unwrap()).collect::<Vec<_>>(),
            "timers":io.timers.lock().unwrap().iter().map(|(seconds,p)|json!([format!("{:016x}",seconds.to_bits()),*p.status.lock().unwrap()])).collect::<Vec<_>>(),
            "warnings":io.warnings.lock().unwrap().clone()}));
    }
    drop(relay);
    settle().await;
    assert!(io
        .sends
        .lock()
        .unwrap()
        .iter()
        .all(|p| *p.status.lock().unwrap() != "pending"));
    assert!(io
        .timers
        .lock()
        .unwrap()
        .iter()
        .all(|(_, p)| *p.status.lock().unwrap() != "pending"));
    json!(results)
}
#[tokio::test]
async fn native_relay_traces_match_send_timeout_cancellation_failure_and_retry() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../octra-node-protocol/tests/fixtures/driver-work.json"
    ))
    .unwrap();
    let mut count = 0;
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        if case["input"]["kind"] != "async_relay" {
            continue;
        }
        let actual = trace(&case["input"]).await;
        for (step, (actual, expected)) in actual
            .as_array()
            .unwrap()
            .iter()
            .zip(case["expected"].as_array().unwrap())
            .enumerate()
        {
            assert_eq!(
                actual, expected,
                "native relay trace {index} step {step}: {}",
                case["input"]["steps"][step]
            );
        }
        count += 1;
    }
    assert_eq!(count, 98);
}
#[tokio::test]
async fn relay_yields_handles_panics_and_cancels_on_last_owner_drop() {
    let io = Arc::new(Io::default());
    let relay = ProposalRelay::new(io.clone());
    relay.offer(0, b"before-start".to_vec(), 0);
    assert!(io.calls.lock().unwrap().is_empty());
    relay.close();
    settle().await;
    assert!(io.calls.lock().unwrap().is_empty());
    relay.open(0);
    io.panic.store(true, Ordering::SeqCst);
    relay.offer(0, b"panic".to_vec(), 1);
    relay.offer(0, b"after".to_vec(), 2);
    settle().await;
    assert_eq!(*io.calls.lock().unwrap(), vec![2]);
    assert_eq!(
        *io.warnings.lock().unwrap(),
        vec![hex::encode("relay I/O panicked")]
    );
    assert_eq!(
        *io.timers.lock().unwrap()[0].1.status.lock().unwrap(),
        "cancelled"
    );
    let owner = relay.clone();
    drop(relay);
    settle().await;
    assert_eq!(
        *io.sends.lock().unwrap()[0].status.lock().unwrap(),
        "pending"
    );
    drop(owner);
    settle().await;
    assert_eq!(
        *io.sends.lock().unwrap()[0].status.lock().unwrap(),
        "cancelled"
    );
    assert_eq!(
        *io.timers.lock().unwrap()[1].1.status.lock().unwrap(),
        "cancelled"
    );
}
