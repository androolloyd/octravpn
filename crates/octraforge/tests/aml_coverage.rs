//! AML branch coverage smoke test — drives a representative flow and
//! confirms the recorder captured the expected branches.
//!
//! NOTE: the coverage recorder is a process-wide global. We run all
//! coverage assertions inside one test so concurrent `cargo test`
//! workers don't race on it.

use octraforge::{aml_coverage, ForgeCtx};
use std::path::PathBuf;

fn aml_source() -> String {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let p = PathBuf::from(manifest)
        .ancestors()
        .nth(2)
        .unwrap()
        .join("program")
        .join("main.aml");
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn coverage_records_branches_during_happy_and_revert_paths() {
    aml_coverage::enable();

    // ----- 1. Happy path: register, create tailnet, open session ------
    let mut ctx = ForgeCtx::new();
    ctx.become_octra_validator("octV");
    ctx.prank("octV");
    ctx.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "eu-west",
        100,
    )
    .unwrap();

    ctx.prank("octOWN");
    let tid = ctx
        .call_create_tailnet(&"ab".repeat(32), 2000)
        .unwrap()
        .event_u64("TailnetCreated", "tailnet_id")
        .unwrap();
    ctx.prank("octOWN");
    ctx.call_add_member(tid, "octCLI").unwrap();
    ctx.prank("octOWN");
    ctx.call_configure_tailnet_exit(tid, "octV").unwrap();
    ctx.prank("octCLI");
    ctx.call_open_session(tid, "octV", 1000).unwrap();

    // ----- 2. Revert path: unprivileged register_endpoint ------------
    let mut ctx2 = ForgeCtx::new();
    ctx2.prank("octR");
    let _ = ctx2.call_register_endpoint_simple(
        "1.2.3.4:51820",
        &"de".repeat(32),
        "x",
        100,
    );

    let rec = aml_coverage::finish().unwrap();
    let report = aml_coverage::report(&rec, &aml_source());

    let reg = report
        .per_method
        .get("register_endpoint")
        .expect("register_endpoint in report");
    assert!(
        reg.branches_hit >= 3,
        "expected ≥3 register_endpoint branches hit, got {} / {}",
        reg.branches_hit,
        reg.branches_total
    );

    let open = report
        .per_method
        .get("open_session")
        .expect("open_session in report");
    assert!(
        open.branches_hit >= 4,
        "expected ≥4 open_session branches hit, got {} / {}",
        open.branches_hit,
        open.branches_total
    );

    assert!(report.percent() > 0.0, "0% coverage; recorder wired correctly?");
}
