//! Exhaustive cheatcode tests — one or two per Foundry analogue.

use octraforge::{
    forge_std::{
        assertions::{
            assert_approx_eq_abs, assert_approx_eq_rel, assert_contains, assert_eq, assert_ge,
            assert_gt, assert_lt, assert_ne,
        },
        std_utils::{bound, keccak, sha256},
    },
    invariant::run_invariant,
    ForgeCtx,
};
use serde_json::json;

#[test]
fn warp_and_roll_epoch() {
    let mut ctx = ForgeCtx::new();
    assert_eq(&ctx.current_epoch(), &1);
    ctx.warp_epoch(100);
    assert_eq(&ctx.current_epoch(), &100);
    ctx.roll_epoch(5);
    assert_eq(&ctx.current_epoch(), &105);
    ctx.skip(10);
    assert_eq(&ctx.current_epoch(), &115);
}

#[test]
fn prank_with_origin_sets_both() {
    let mut ctx = ForgeCtx::new();
    ctx.prank_with_origin("octCALLER", "octORIGIN");
    let caller = ctx.take_pranked_caller();
    let origin = ctx.take_pranked_origin();
    assert_eq(&caller.as_deref(), &Some("octCALLER"));
    assert_eq(&origin.as_deref(), &Some("octORIGIN"));
}

#[test]
fn sticky_prank_survives_calls_until_stop() {
    let mut ctx = ForgeCtx::new();
    ctx.start_prank_with_origin("octCALL", "octORG");
    let c1 = ctx.take_pranked_caller();
    let o1 = ctx.take_pranked_origin();
    let c2 = ctx.take_pranked_caller();
    assert!(c1.is_some());
    assert!(o1.is_some());
    assert!(c2.is_some()); // still sticky
    ctx.stop_prank();
    let c3 = ctx.take_pranked_caller();
    assert!(c3.is_none());
}

#[test]
fn deal_and_balance() {
    let mut ctx = ForgeCtx::new();
    ctx.deal("octX", 1_234_567);
    assert_eq(&ctx.balance("octX"), &1_234_567);
}

#[test]
fn hoax_combines_deal_and_prank() {
    let mut ctx = ForgeCtx::new();
    ctx.hoax_with("octX", 500_000);
    assert_eq(&ctx.balance("octX"), &500_000);
    assert_eq(&ctx.take_pranked_caller().as_deref(), &Some("octX"));
}

#[test]
fn make_addr_labels_the_address() {
    let mut ctx = ForgeCtx::new();
    let alice = ctx.make_addr("alice");
    assert!(ctx
        .get_label(alice.display())
        .is_some_and(|l| l == "alice"));
}

#[test]
fn snapshot_revert_restores_state() {
    let mut ctx = ForgeCtx::new();
    ctx.deal("octA", 100);
    let snap = ctx.snapshot();
    ctx.deal("octA", 999);
    assert_eq(&ctx.balance("octA"), &999);
    assert!(ctx.revert_to(snap));
    assert_eq(&ctx.balance("octA"), &100);
}

#[test]
fn named_snapshots_work() {
    let mut ctx = ForgeCtx::new();
    ctx.deal("octA", 100);
    ctx.snapshot_named("pre");
    ctx.deal("octA", 200);
    assert!(ctx.revert_to_named("pre"));
    assert_eq(&ctx.balance("octA"), &100);
}

#[test]
fn mock_submit_ok_returns_canned() {
    let mut ctx = ForgeCtx::new();
    ctx.mock_submit_ok(
        "register_endpoint",
        vec![json!({"name": "EndpointRegistered", "addr": "octFAKE"})],
        "deadbeef",
    );
    // Build a tx with method = register_endpoint; the canned response
    // returns immediately without touching the chain state.
    let tx = json!({
        "kind": "contract_call",
        "from": "octFAKE",
        "to": "octPROG",
        "method": "register_endpoint",
        "params": ["1.2.3.4", "00".repeat(32), "00".repeat(32), "00".repeat(32), "r", 100u64],
        "value": 0u64,
        "fee": 10u64,
        "nonce": 0u64,
    });
    let r = ctx.submit(tx).unwrap();
    assert_eq(&r.hash.as_str(), &"deadbeef");
    assert!(r.find_event("EndpointRegistered").is_some());
    // The chain state is NOT updated because the call was mocked.
    let s = ctx.app.state.read();
    assert!(s.endpoints.is_empty());
}

#[test]
fn mock_submit_revert_short_circuits() {
    let mut ctx = ForgeCtx::new();
    ctx.mock_submit_revert("register_endpoint", "mocked failure");
    ctx.expect_revert("mocked failure");
    let tx = json!({
        "kind": "contract_call",
        "from": "octX",
        "to": "octPROG",
        "method": "register_endpoint",
        "params": [],
        "value": 0u64,
        "fee": 0u64,
        "nonce": 0u64,
    });
    let r = ctx.submit(tx).unwrap();
    assert!(r.hash.is_empty());
}

#[test]
fn mock_view_returns_canned() {
    let mut ctx = ForgeCtx::new();
    ctx.mock_view("get_params", json!({"min_session_deposit": 42u64}));
    let v = ctx
        .view("get_params", vec![])
        .unwrap();
    assert_eq(&v["min_session_deposit"].as_u64(), &Some(42));
}

#[test]
fn expect_no_emit_passes_when_no_event() {
    let mut ctx = ForgeCtx::new();
    ctx.expect_no_emit("SessionSettled");
    ctx.mock_submit_ok("anything", vec![], "h");
    let r = ctx.submit(json!({
        "kind": "contract_call",
        "from": "x", "to": "x", "method": "anything",
        "params": [], "value": 0u64, "fee": 0u64, "nonce": 0u64,
    }));
    assert!(r.is_ok());
}

#[test]
fn expect_no_emit_fails_when_event_present() {
    let mut ctx = ForgeCtx::new();
    ctx.expect_no_emit("X");
    ctx.mock_submit_ok("foo", vec![json!({"name": "X"})], "h");
    let r = ctx.submit(json!({
        "kind": "contract_call",
        "from": "x", "to": "x", "method": "foo",
        "params": [], "value": 0u64, "fee": 0u64, "nonce": 0u64,
    }));
    assert!(r.is_err());
}

#[test]
fn expect_emit_fields_strict_match() {
    let mut ctx = ForgeCtx::new();
    ctx.expect_emit_fields(
        "EndpointRegistered",
        vec![("addr", json!("octFAKE")), ("region", json!("eu-west"))],
    );
    ctx.mock_submit_ok(
        "register_endpoint",
        vec![json!({
            "name": "EndpointRegistered",
            "addr": "octFAKE",
            "region": "eu-west",
        })],
        "h",
    );
    let r = ctx.submit(json!({
        "kind": "contract_call",
        "from": "x", "to": "x", "method": "register_endpoint",
        "params": [], "value": 0u64, "fee": 0u64, "nonce": 0u64,
    }));
    r.unwrap();
}

#[test]
fn expect_emit_fields_mismatch_fails() {
    let mut ctx = ForgeCtx::new();
    ctx.expect_emit_fields("X", vec![("k", json!("expected"))]);
    ctx.mock_submit_ok("foo", vec![json!({"name": "X", "k": "actual"})], "h");
    let r = ctx.submit(json!({
        "kind": "contract_call",
        "from": "x", "to": "x", "method": "foo",
        "params": [], "value": 0u64, "fee": 0u64, "nonce": 0u64,
    }));
    assert!(r.is_err());
}

#[test]
fn forks_isolate_state() {
    let mut ctx = ForgeCtx::new();
    ctx.deal("octA", 100);
    let mainnet = ctx.create_fork("mainnet");

    ctx.deal("octA", 999);
    let testnet = ctx.create_fork("testnet");

    // Switch back to mainnet — balance should be 100.
    ctx.select_fork(mainnet);
    assert_eq(&ctx.balance("octA"), &100);

    // Switch to testnet — balance should be 999.
    ctx.select_fork(testnet);
    assert_eq(&ctx.balance("octA"), &999);

    assert_eq(&ctx.active_fork(), &Some(testnet));
}

#[test]
fn record_and_take_logs() {
    let mut ctx = ForgeCtx::new();
    ctx.record_logs();
    ctx.mock_submit_ok("foo", vec![json!({"name": "A"}), json!({"name": "B"})], "h");
    let _ = ctx.submit(json!({
        "kind": "contract_call",
        "from": "x", "to": "x", "method": "foo",
        "params": [], "value": 0u64, "fee": 0u64, "nonce": 0u64,
    }));
    let logs = ctx.take_logs();
    assert_eq(&logs.len(), &2);
}

#[test]
fn assertion_library_smoke() {
    // Each helper exercised at least once.
    assert_eq(&1u64, &1u64);
    assert_ne(&1u64, &2u64);
    assert_gt(&3u64, &2u64);
    assert_ge(&3u64, &3u64);
    assert_lt(&1u64, &2u64);
    assert_approx_eq_abs(100, 102, 5);
    assert_approx_eq_rel(1_000_000, 1_010_000, 200);
    assert_contains("hello world", "world");
}

#[test]
fn bound_clamps_into_range() {
    let mut ctx = ForgeCtx::new();
    let _ = &mut ctx;
    for i in 0..1000u64 {
        let v = bound(i, 10, 20);
        assert!((10..=20).contains(&v), "{i} → {v}");
    }
}

#[test]
fn sha256_known_vector() {
    let h = sha256(b"abc");
    assert_eq(
        &hex::encode(h).as_str(),
        &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    assert_eq(&keccak(b"abc"), &h);
}

#[test]
fn store_builder_writes_directly() {
    let mut ctx = ForgeCtx::new();
    ctx.store().balance("octX", 42);
    assert_eq(&ctx.balance("octX"), &42);
}

#[test]
fn invariant_runner_checks_balance_monotonic() {
    let mut ctx = ForgeCtx::new();
    ctx.deal("octV", 1_000_000);
    let initial = ctx.balance("octV");
    run_invariant(
        &mut ctx,
        5,  // 5 runs
        3,  // 3 steps per run
        |c, _step| {
            // Step: pretend a session opens; just bump the chain epoch.
            c.roll_epoch(1);
        },
        |c| {
            // Invariant: balance of "octV" is unchanged.
            let bal = c.balance("octV");
            if bal == initial {
                Ok(())
            } else {
                Err(format!("balance changed to {bal}"))
            }
        },
    );
}

#[test]
fn ou_recorder_round_trip() {
    use octraforge::OuRecorder;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ou.snap");
    let mut r = OuRecorder::default();
    r.add("test_a", 1234);
    r.write(&p).unwrap();
    let r2 = OuRecorder::load(&p).unwrap();
    assert_eq(&r.costs, &r2.costs);
}
