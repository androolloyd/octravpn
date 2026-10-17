//! Actual packaged process boundary with native proof material. This qualifies
//! local callback execution/resource ownership, not public-network readiness.
#[path = "common/crypto_worker.rs"]
mod common;
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_runtime::{circle::HfheBackend, circle_hfhe::Backend};
use serde_json::{json, Value};
// These scenarios both exercise the native process-global Circle verifier lane.
// Isolate their unrelated fixture work; production nonblocking admission stays unchanged.
static CIRCLE_PROOF_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn bytes(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn circle_proof_request() -> Value {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["operation"] == "proof" && case["expected"].get("ok").is_some())
        .unwrap()["input"];
    json!({"action":"verify_bound","cap":input["cap"],"math":input["math"],"hfhe_pairs":true,"strict":input["strict"],"pubkey_b64":input["public"],"ciphertext":String::from_utf8(bytes(&input["delta"])).unwrap(),"proof":String::from_utf8(bytes(&input["proof"])).unwrap(),"amount_commitment":String::from_utf8(bytes(&input["commitment"])).unwrap()})
}
#[test]
fn isolated_circle_proofs_preserve_genuine_rejection_and_operational_envelopes() {
    let _proof_fixture = CIRCLE_PROOF_TEST
        .lock()
        .expect("Circle proof fixture mutex poisoned");
    let mut request = circle_proof_request();
    let expected = Backend.call(&request).unwrap();
    assert_eq!(
        expected,
        json!({"ok":true,"value":true}),
        "genuine pinned native amount proof must actually verify"
    );
    let pool = common::pool();
    let isolated = Backend::isolated(pool.clone());
    assert_eq!(
        isolated.call(&request).unwrap()["class"],
        "unavailable",
        "no implicit current_exe or local fallback"
    );
    {
        let _scope = common::scope(false);
        assert_eq!(isolated.call(&request).unwrap(), expected);
        request["proof"] = json!("zkzp_v2|invalid");
        assert_eq!(
            isolated.call(&request).unwrap(),
            json!({"ok":true,"value":false})
        );
        assert_eq!(
            isolated.call(&json!([])).unwrap(),
            Backend.call(&json!([])).unwrap()
        );
    }
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let _scope = pool.scope(false, cancelled);
    assert_eq!(isolated.call(&request).unwrap()["class"], "unavailable");
}

#[test]
fn actual_octb_key_decode_arithmetic_and_serialization_stay_inside_the_process() {
    use octra_node_protocol::{circle_storage::StorageTable, octb::Instruction as I};
    use octra_node_runtime::octb::{self, Context, Machine, Options, Value as Cell};
    use std::sync::Arc;
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["operation"] == "proof" && case["expected"].get("ok").is_some())
        .unwrap()["input"];
    let raw = bytes(&input["public"]);
    let original =
        octra_node_runtime::private_crypto::decode_cipher(&bytes(&input["delta"]), false, true)
            .unwrap();
    let expected = original
        .add_constant(octra_hfhe::field::Fp::ONE, true)
        .unwrap()
        .add_constant(octra_hfhe::field::Fp::ONE, true)
        .unwrap()
        .to_bytes()
        .unwrap();
    struct Host(Arc<[u8]>);
    impl octb::Host for Host {
        fn fhe_key(&mut self, _: &[u8]) -> Result<Option<octb::FheKeySource>, octb::Unavailable> {
            Ok(Some(octb::FheKeySource::Bytes(self.0.clone())))
        }
    }
    let mut machine = Machine::new(
        Context::default(),
        Options {
            is_view: true,
            math: true,
            limit: 20_000_000,
            ..Options::default()
        },
        StorageTable::new(0),
    );
    machine.regs[1] = Cell::string(b"registered".to_vec());
    machine.regs[3] = Cell::string(STANDARD.encode(original.to_bytes().unwrap()).into_bytes());
    machine.regs[5] = Cell::int(1);
    let _scope = common::scope(true);
    assert!(machine
        .run(
            &[
                I::FheLoadPk(0, 1),
                I::FheDeser(2, 3),
                I::FheAddConst(4, 0, 2, 5),
                I::FheAddConst(7, 0, 4, 5),
                I::FheSer(8, 7),
                I::Stop()
            ],
            &mut Host(raw.into()),
            None
        )
        .unwrap());
    assert_eq!(
        machine.regs[8].bytes().unwrap(),
        STANDARD.encode(expected).as_bytes()
    );
}

#[test]
fn private_transition_facade_preserves_exact_native_rejection_and_fails_closed_after_cancel() {
    use octra_hfhe::scalar::ScalarRule;
    use octra_node_runtime::private_crypto::{self as local, isolated};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private-crypto.json")).unwrap();
    let input = &fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["input"]["operation"] == "proof" && case["expected"].get("ok").is_some())
        .unwrap()["input"];
    let public = bytes(&input["public"]);
    let cipher = bytes(&input["delta"]);
    let genuine = bytes(&input["proof"]);
    let commitment = bytes(&input["commitment"]);
    let blinding = bytes(&input["blinding"]);
    let amount = input["amount"].as_str().unwrap().parse().unwrap();
    let strict = input["strict"].as_bool().unwrap();
    let rule = if input["math"] == true {
        ScalarRule::Wide
    } else {
        ScalarRule::Prior
    };
    let native_key = local::proof_pubkey(&public).unwrap();
    let pool = common::pool();
    let cancelled = Arc::new(AtomicBool::new(false));
    let _scope = pool.scope(false, cancelled.clone());
    let key = isolated::proof_pubkey(&public).unwrap();
    for proof in [&genuine[..], b"zkzp_v2|invalid".as_slice()] {
        let payload = local::AmountProof {
            cipher: &cipher,
            proof,
            commitment: &commitment,
            blinding: &blinding,
        };
        let expected = local::verify_amount(&native_key, &amount, &payload, strict, rule);
        let actual = isolated::verify_amount(&key, &amount, &payload, strict, rule);
        match expected {
            Ok(()) => assert!(actual.is_ok()),
            Err(local::Error::Rejected(reason)) => {
                assert_eq!(actual, Err(isolated::Error::Rejected(reason)));
            }
            Err(error) => panic!("pinned native fixture unavailable: {error}"),
        }
    }
    cancelled.store(true, Ordering::Release);
    assert!(
        matches!(
            isolated::verify_amount(
                &key,
                &amount,
                &local::AmountProof {
                    cipher: &cipher,
                    proof: &genuine,
                    commitment: &commitment,
                    blinding: &blinding
                },
                strict,
                rule
            ),
            Err(isolated::Error::Unavailable(_))
        ),
        "scoped cancellation must not fall back to the local primitive"
    );
}
#[cfg(all(feature = "test-helpers", unix))]
mod lifecycle {
    use super::common;
    use octra_node_runtime::crypto_worker::{Fault, Limits, Pool};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    fn pool() -> Arc<Pool> {
        Pool::open(
            &common::executable(),
            Limits {
                capacity: 1,
                timeout_seconds: 1.,
                rss_mb: 64,
            },
        )
        .unwrap()
    }
    fn reaped(pid: u32) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD,
            "worker must already have been reaped by its owner"
        );
    }
    #[test]
    fn persistent_session_reuse_idle_retirement_and_drop_reap_actual_children() {
        let pool = pool();
        let cancelled = Arc::new(AtomicBool::new(false));
        let scope = pool.scope(false, cancelled);
        let first = pool.test_fault(Fault::SessionId).unwrap();
        assert_eq!(
            pool.test_fault(Fault::SessionId).unwrap(),
            first,
            "same owned process serves successive frames"
        );
        let deadline = Instant::now() + Duration::from_secs(12);
        while pool.session_pid(false).is_some() {
            assert!(
                Instant::now() < deadline,
                "native ten-second idle retirement"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        reaped(first);
        let next = pool.test_fault(Fault::SessionId).unwrap();
        assert_ne!(next, first);
        drop(scope);
        drop(pool);
        reaped(next);
    }

    #[test]
    fn idle_view_releases_native_active_capacity_for_update_and_oneshot_callbacks() {
        use octra_node_runtime::{circle::HfheBackend, circle_hfhe::Backend};
        let pool = pool();
        let view = {
            let _scope = pool.scope(true, Arc::new(AtomicBool::new(false)));
            pool.test_fault(Fault::SessionId).unwrap()
        };
        let update = {
            let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
            pool.test_fault(Fault::SessionId).unwrap()
        };
        assert_ne!(view, update);
        assert_eq!(pool.session_pid(true), Some(view));
        assert_eq!(pool.session_pid(false), Some(update));
        // Both cached children remain alive, but neither owns the capacity-one
        // active slot. This callback uses the independent one-shot transport.
        let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
        let backend = Backend::isolated(pool.clone());
        assert_eq!(
            backend.call(&serde_json::json!([])).unwrap()["class"],
            "rejected"
        );
        assert_eq!(pool.session_pid(true), Some(view));
        assert_eq!(pool.session_pid(false), Some(update));
    }
    #[test]
    fn deadline_protocol_failure_and_death_retire_sessions_before_recovery() {
        for fault in [
            Fault::Delay(3000),
            Fault::Malformed,
            Fault::Oversize,
            Fault::Exit,
        ] {
            let pool = pool();
            let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
            let pid = pool.test_fault(Fault::SessionId).unwrap();
            let started = Instant::now();
            assert!(
                pool.test_fault(fault.clone()).is_err(),
                "{fault:?} must be operational failure"
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "bounded deadline/reap: {fault:?}"
            );
            assert!(pool.session_pid(false).is_none());
            reaped(pid);
            assert_ne!(
                pool.test_fault(Fault::SessionId).unwrap(),
                pid,
                "failure never supplies a verdict or poisons later owned work"
            );
        }
    }
    #[test]
    fn cancellation_of_either_nested_owner_is_preserved() {
        for outer_cancel in [false, true] {
            let pool = pool();
            let outer = Arc::new(AtomicBool::new(false));
            let inner = Arc::new(AtomicBool::new(false));
            let _outer = pool.scope(false, outer.clone());
            let _inner = pool.scope(true, inner.clone());
            if outer_cancel {
                outer.store(true, Ordering::Release);
            } else {
                inner.store(true, Ordering::Release);
            }
            assert!(pool.test_fault(Fault::SessionId).is_err());
            assert!(pool.session_pid(false).is_none() && pool.session_pid(true).is_none());
        }
    }

    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    fn started(path: &std::path::Path) {
        let until = Instant::now() + Duration::from_secs(2);
        while !path.exists() {
            assert!(
                Instant::now() < until,
                "actual worker must enter delayed operation"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn active_process_is_reaped_on_caller_cancellation_and_urgent_update() {
        for urgent in [false, true] {
            let pool = pool();
            let cancelled = Arc::new(AtomicBool::new(false));
            let directory = tempfile::tempdir().unwrap();
            let ready = directory.path().join("active");
            std::thread::scope(|threads| {
                let _cancel = Cancel(cancelled.clone());
                let delayed = threads.spawn(|| {
                    let _scope = pool.scope(true, cancelled.clone());
                    pool.test_fault(Fault::StartedDelay {
                        millis: 3000,
                        ready: ready.to_str().unwrap().into(),
                    })
                });
                started(&ready);
                let pid = std::fs::read_to_string(&ready)
                    .unwrap()
                    .parse::<u32>()
                    .unwrap();
                if urgent {
                    let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
                    assert_ne!(
                        pool.test_fault(Fault::SessionId).unwrap(),
                        pid,
                        "native urgent update proceeds only after retiring its abandoned view"
                    );
                } else {
                    cancelled.store(true, Ordering::Release);
                }
                assert!(delayed.join().unwrap().is_err());
                assert!(pool.session_pid(true).is_none());
                reaped(pid);
            });
        }
    }

    #[test]
    fn circle_preflight_finishes_deterministic_errors_before_speculative_busy() {
        use octra_node_runtime::{circle::HfheBackend, circle_hfhe::Backend};
        let _proof_fixture = super::CIRCLE_PROOF_TEST
            .lock()
            .expect("Circle proof fixture mutex poisoned");
        let pool = Pool::open(
            &common::executable(),
            Limits {
                capacity: 1,
                timeout_seconds: 30.,
                rss_mb: 9216,
            },
        )
        .unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("proof-active");
        std::thread::scope(|threads| {
            let _cancel = Cancel(cancelled.clone());
            let holder = threads.spawn(|| {
                let _scope = pool.scope(false, cancelled.clone());
                pool.test_proof_fault(
                    false,
                    Fault::StartedDelay {
                        millis: 30_000,
                        ready: ready.to_str().unwrap().into(),
                    },
                )
            });
            started(&ready);
            let pid = std::fs::read_to_string(&ready)
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
            let backend = Backend::isolated(pool.clone());
            let genuine = super::circle_proof_request();
            let mut malformed = genuine.clone();
            malformed["proof"] = serde_json::json!("zkzp_v2|invalid");
            assert_eq!(
                backend.call(&malformed).unwrap(),
                serde_json::json!({"ok":true,"value":false}),
                "native parses malformed zero proof before trying busy proof channel"
            );
            malformed = genuine.clone();
            malformed["pubkey_b64"] = serde_json::json!("AA==");
            assert_eq!(
                backend.call(&malformed).unwrap()["class"],
                "rejected",
                "argument rejection precedes callback/proof admission"
            );
            assert_eq!(
                backend.call(&genuine).unwrap(),
                serde_json::json!({"ok":false,"class":"unavailable","error":"proof worker busy"}),
                "a genuine prepared proof must actually attempt the occupied speculative channel"
            );
            let mut range = genuine;
            range["action"] = serde_json::json!("verify_range");
            range["proof"] = serde_json::json!("rp_v1|AA==");
            assert_eq!(
                backend.call(&range).unwrap(),
                serde_json::json!({"ok":false,"class":"unavailable","error":"proof worker busy"}),
                "native range preflight validates only prefix/base64, not proof structure before admission"
            );
            assert_eq!(pool.proof_stats().active, 1);
            cancelled.store(true, Ordering::Release);
            assert!(holder.join().unwrap().is_err());
            reaped(pid);
        });
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_rss_limit_kills_and_reaps_the_actual_child() {
        let pool = pool();
        let _scope = pool.scope(false, Arc::new(AtomicBool::new(false)));
        let pid = pool.test_fault(Fault::SessionId).unwrap();
        let error = pool.test_fault(Fault::Memory).unwrap_err();
        assert!(error.contains("memory limit exceeded"), "{error}");
        assert!(pool.session_pid(false).is_none());
        reaped(pid);
    }
}
