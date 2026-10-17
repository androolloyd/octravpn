//! Actual owned processes under independent FHE actor and shared PVAC lanes.
//! Fault probes qualify lifecycle/admission, never a cryptographic verdict.
#![cfg(all(feature = "test-helpers", unix))]
#[path = "common/crypto_worker.rs"]
mod common;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_runtime::crypto_worker::{Fault, Limits, Pool};
use octra_node_runtime::private_crypto::isolated;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct Running {
    cancelled: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<Result<u32, String>>>,
}
impl Running {
    fn start(pool: Arc<Pool>, required: bool, path: &Path) -> Self {
        let cancelled = Arc::new(AtomicBool::new(false));
        let stopped = cancelled.clone();
        let ready = path.to_string_lossy().into_owned();
        let task = thread::spawn(move || {
            let _scope = pool.scope(false, stopped);
            pool.test_proof_fault(
                required,
                Fault::StartedDelay {
                    millis: 30_000,
                    ready,
                },
            )
        });
        Self {
            cancelled,
            task: Some(task),
        }
    }
    fn stop(mut self) {
        self.cancelled.store(true, Ordering::Release);
        assert!(self.task.take().unwrap().join().unwrap().is_err());
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "owned worker did not reach expected state"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn required_queue_and_speculative_busy_share_capacity_without_blocking_fhe_actor() {
    let pool = common::pool();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["operation"] == "proof" && case["expected"].get("ok").is_some())
        .unwrap()["input"];
    let decode = |name: &str| STANDARD.decode(input[name].as_str().unwrap()).unwrap();
    let public = decode("public");
    let cipher = decode("delta");
    let proof = decode("proof");
    let commitment = decode("commitment");
    let blinding = decode("blinding");
    let amount = input["amount"].as_str().unwrap().parse().unwrap();
    let strict = input["strict"].as_bool().unwrap();
    let math = if input["math"] == true {
        octra_hfhe::scalar::ScalarRule::Wide
    } else {
        octra_hfhe::scalar::ScalarRule::Prior
    };
    let key = {
        let _scope = common::scope(false);
        isolated::proof_pubkey(&public).unwrap()
    };
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("speculative");
    let running = Running::start(pool.clone(), false, &marker);
    wait(|| marker.exists());
    assert_eq!(pool.proof_stats().active, 1);
    let required = {
        let pool = pool.clone();
        thread::spawn(move || {
            let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
            isolated::verify_amount(
                &key,
                &amount,
                &isolated::AmountProof {
                    cipher: &cipher,
                    proof: &proof,
                    commitment: &commitment,
                    blinding: &blinding,
                },
                strict,
                math,
            )
        })
    };
    wait(|| pool.proof_stats().required_waiting == 1);
    {
        let _scope = common::scope(false);
        let started = Instant::now();
        assert!(pool
            .test_proof_fault(false, Fault::SessionId)
            .unwrap_err()
            .contains("busy"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "speculative try must not wait behind required work"
        );
        assert!(
            pool.test_fault(Fault::SessionId).is_ok(),
            "native FHE actor is independent of occupied proof channel"
        );
    }
    running.stop();
    assert!(required.join().unwrap().is_ok());
    assert_eq!(pool.proof_stats().active, 0);
}

#[test]
fn configured_two_proof_workers_and_one_fhe_task_coexist_then_reap_independently() {
    let pool = Pool::open(
        &common::executable(),
        Limits {
            capacity: 2,
            timeout_seconds: 30.,
            rss_mb: 9216,
        },
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let one = directory.path().join("one");
    let two = directory.path().join("two");
    let first = Running::start(pool.clone(), true, &one);
    wait(|| one.exists());
    let second = Running::start(pool.clone(), true, &two);
    wait(|| two.exists());
    assert_eq!(pool.proof_stats().active, 2);
    let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
    assert!(pool.test_proof_fault(false, Fault::SessionId).is_err());
    assert!(pool.test_fault(Fault::SessionId).is_ok());
    assert_eq!(pool.proof_stats().active, 2);
    first.stop();
    assert_eq!(pool.proof_stats().active, 1);
    assert!(pool.test_proof_fault(false, Fault::SessionId).is_ok());
    second.stop();
    assert_eq!(pool.proof_stats().active, 0);
}
