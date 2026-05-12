//! AML OU cost snapshot — Foundry's `forge .gas-snapshot` equivalent.
//!
//! The committed file `ou-snapshot.txt` records the deterministic
//! OU cost (per `ou_cost_model::estimate_program_costs`) of every
//! public AML method in `program/main.aml`. This test re-runs the
//! estimator and fails if the live result diverges, forcing a
//! reviewer to look at why a method's cost changed.
//!
//! To update the committed snapshot after an intentional change:
//!
//!     OCTRAVPN_OU_UPDATE_SNAPSHOT=1 cargo test -p octraforge --test ou_snapshot

use std::path::PathBuf;

const SNAPSHOT_FILE: &str = "ou-snapshot.txt";

fn workspace_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    std::path::Path::new(&manifest)
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn read_program_source() -> String {
    let p = workspace_root().join("program").join("main.aml");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn snapshot_path() -> PathBuf {
    workspace_root().join(SNAPSHOT_FILE)
}

#[test]
fn ou_snapshot_matches_committed_file() {
    let src = read_program_source();
    let live = octraforge::ou_cost_model::estimate_program_costs(&src);
    let live_text = octraforge::ou_cost_model::format_snapshot(&live);

    if std::env::var("OCTRAVPN_OU_UPDATE_SNAPSHOT").as_deref() == Ok("1") {
        std::fs::write(snapshot_path(), &live_text).unwrap();
        return;
    }

    let path = snapshot_path();
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}\n\nFirst run:\n  OCTRAVPN_OU_UPDATE_SNAPSHOT=1 cargo test --test ou_snapshot",
            path.display()
        )
    });

    if committed != live_text {
        let diff = diff_pretty(&committed, &live_text);
        panic!(
            "AML OU cost snapshot drift detected.\n\
             Either an AML method changed (intentional → re-snapshot) or the cost \
             model was updated (review carefully).\n\n\
             To accept the new costs:\n  \
             OCTRAVPN_OU_UPDATE_SNAPSHOT=1 cargo test -p octraforge --test ou_snapshot\n\n\
             Diff:\n{diff}"
        );
    }
}

fn diff_pretty(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = String::new();
    let max = old_lines.len().max(new_lines.len());
    for i in 0..max {
        let a = old_lines.get(i).copied().unwrap_or("");
        let b = new_lines.get(i).copied().unwrap_or("");
        if a == b {
            continue;
        }
        use std::fmt::Write;
        if !a.is_empty() {
            let _ = writeln!(out, "- {a}");
        }
        if !b.is_empty() {
            let _ = writeln!(out, "+ {b}");
        }
    }
    out
}
