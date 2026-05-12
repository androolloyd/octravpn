// Uniform `Result<(), String>` signature + `&mut FuzzState` for all op
// helpers keeps the dispatch in `run_one_op` simple; some helpers don't
// need the mutability or the return type but the symmetry is worth it.
#![allow(clippy::unnecessary_wraps, clippy::needless_pass_by_ref_mut)]

//! Random-AML-call fuzz target.
//!
//! Drives long sequences of register/create/add/open/settle/claim
//! against the mock chain and asserts the canonical invariants
//! (`aml_invariants::check_all`) hold after every step.
//!
//! Foundry's invariant tests do this against Solidity; ours do it
//! against the AML mock interpreter — same shape, same guarantees.
//!
//! Run with:
//!     cargo test -p octraforge --test aml_fuzz -- --nocapture
//!
//! The default budget is small enough to fit inside `cargo test`'s
//! per-test timeout. Set `OCTRAVPN_FUZZ_BUDGET=10000` for a deep run.

use octraforge::{aml_invariants, ForgeCtx};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::json;

const N_VALIDATORS: usize = 3;
const N_CLIENTS: usize = 2;

fn validator_addr(i: usize) -> String {
    format!("octV{i:040x}")
}
fn client_addr(i: usize) -> String {
    format!("octC{i:040x}")
}

#[derive(Debug)]
struct FuzzState {
    /// Tailnet ids we've created.
    tailnets: Vec<String>,
    /// Validator addresses we've registered as endpoints.
    registered: Vec<String>,
    /// Sessions opened (still open).
    open_sessions: Vec<(String, String, String)>, // (sid, tid, client)
}

fn op_count_from_env(default: usize) -> usize {
    std::env::var("OCTRAVPN_FUZZ_BUDGET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[test]
fn fuzz_random_aml_call_sequences_preserve_invariants() {
    let budget = op_count_from_env(200);
    let seed = std::env::var("OCTRAVPN_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xCAFE_BABEu64);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut ctx = ForgeCtx::new();
    // Pre-promote N validators on the mock chain.
    for i in 0..N_VALIDATORS {
        ctx.become_octra_validator(&validator_addr(i));
    }

    let mut fz = FuzzState {
        tailnets: Vec::new(),
        registered: Vec::new(),
        open_sessions: Vec::new(),
    };

    for step in 0..budget {
        let op = rng.gen_range(0..7);
        let _ = run_one_op(&mut ctx, &mut fz, &mut rng, op);
        // Verify all invariants hold after every step.
        aml_invariants::check_all(&ctx).unwrap_or_else(|e| {
            panic!(
                "invariant violated at step {step} (seed={seed}, op={op}): {e}"
            );
        });
    }
}

fn run_one_op(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
    op: u8,
) -> Result<(), String> {
    match op {
        0 => op_register_endpoint(ctx, fz, rng),
        1 => op_create_tailnet(ctx, fz, rng),
        2 => op_add_member(ctx, fz, rng),
        3 => op_configure_exit(ctx, fz, rng),
        4 => op_open_session(ctx, fz, rng),
        5 => op_settle_session(ctx, fz, rng),
        6 => op_deposit_to_tailnet(ctx, fz, rng),
        _ => Ok(()),
    }
}

fn op_register_endpoint(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    let idx = rng.gen_range(0..N_VALIDATORS);
    let addr = validator_addr(idx);
    if fz.registered.contains(&addr) {
        return Ok(());
    }
    ctx.prank(&addr);
    if ctx
        .call_register_endpoint(
            &format!("1.2.3.{idx}:51820"),
            &"de".repeat(32),
            &"aa".repeat(32),
            &"bb".repeat(32),
            "global",
            100,
        )
        .is_ok()
    {
        fz.registered.push(addr);
    }
    Ok(())
}

fn op_create_tailnet(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    let owner = client_addr(rng.gen_range(0..N_CLIENTS));
    ctx.prank(&owner);
    let deposit = 100 + rng.gen_range(0..1000);
    if let Ok(r) = ctx.call_create_tailnet(&"ab".repeat(32), deposit) {
        if let Some(tid) = r.event_str("TailnetCreated", "tailnet_id") {
            fz.tailnets.push(tid);
        }
    }
    Ok(())
}

fn op_add_member(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    if fz.tailnets.is_empty() {
        return Ok(());
    }
    let tid = fz.tailnets[rng.gen_range(0..fz.tailnets.len())].clone();
    let owner = ctx
        .view("get_tailnet", vec![json!(tid)])
        .ok()
        .and_then(|v| v.get("owner").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default();
    let member = client_addr(rng.gen_range(0..N_CLIENTS));
    ctx.prank(&owner);
    let _ = ctx.call_add_member(&tid, &member);
    Ok(())
}

fn op_configure_exit(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    if fz.tailnets.is_empty() || fz.registered.is_empty() {
        return Ok(());
    }
    let tid = fz.tailnets[rng.gen_range(0..fz.tailnets.len())].clone();
    let owner = ctx
        .view("get_tailnet", vec![json!(tid)])
        .ok()
        .and_then(|v| v.get("owner").and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_default();
    let exit = fz.registered[rng.gen_range(0..fz.registered.len())].clone();
    ctx.prank(&owner);
    let _ = ctx.call_configure_tailnet_exit(&tid, &exit);
    Ok(())
}

fn op_open_session(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    if fz.tailnets.is_empty() || fz.registered.is_empty() {
        return Ok(());
    }
    let tid = fz.tailnets[rng.gen_range(0..fz.tailnets.len())].clone();
    let exit = fz.registered[rng.gen_range(0..fz.registered.len())].clone();
    let client = client_addr(rng.gen_range(0..N_CLIENTS));
    let deposit = 10u64 + rng.gen_range(0..100u64);
    ctx.prank(&client);
    if let Ok(r) = ctx.call_open_session(&tid, &[&"aa".repeat(32)], &"bb".repeat(32), deposit) {
        if let Some(sid) = r.event_str("SessionOpened", "session_id") {
            fz.open_sessions.push((sid, tid, exit));
        }
    }
    Ok(())
}

fn op_settle_session(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    if fz.open_sessions.is_empty() {
        return Ok(());
    }
    let i = rng.gen_range(0..fz.open_sessions.len());
    let (sid, _tid, exit) = fz.open_sessions.remove(i);
    // settle for a few bytes — exit handler enforces total_paid <= deposit
    let bytes = 1u64 + rng.gen_range(0..3u64);
    let blind = "11".repeat(32);
    let _ = ctx.call_settle_session(&sid, 1, bytes, &blind, &[(&exit, &"00".repeat(32), 10_000)]);
    Ok(())
}

fn op_deposit_to_tailnet(
    ctx: &mut ForgeCtx,
    fz: &mut FuzzState,
    rng: &mut StdRng,
) -> Result<(), String> {
    if fz.tailnets.is_empty() {
        return Ok(());
    }
    let tid = fz.tailnets[rng.gen_range(0..fz.tailnets.len())].clone();
    let depositor = client_addr(rng.gen_range(0..N_CLIENTS));
    let amount = 1 + rng.gen_range(0..200);
    ctx.prank(&depositor);
    let _ = ctx.call_deposit_to_tailnet(&tid, amount);
    Ok(())
}
