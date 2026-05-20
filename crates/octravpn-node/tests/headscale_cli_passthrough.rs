//! Pass-through contract tests for the embedded `headscale` admin
//! CLI surface (`octravpn-node headscale …`).
//!
//! The contract: every admin subcommand the standalone `headscale`
//! binary supports is reachable as `octravpn-node headscale …` and
//! produces byte-identical stdout + stderr + exit code. These tests
//! enforce that contract by driving both binaries side-by-side
//! through `assert_cmd` and `diff`-ing the captured output.
//!
//! Network-touching paths (`users list`, `nodes list`, …) are
//! exercised against a non-routable address (`127.0.0.1:1`) so the
//! "connection refused" error path runs the same code in both
//! binaries. No live mesh-control is required.
//!
//! See `docs/operators/cli-migration.md` for the operator-facing
//! migration table.

use assert_cmd::Command;
use escargot::CargoBuild;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Build the standalone `headscale` binary from the sibling
/// `headscale-rs` workspace once, then re-use the path across every
/// test. `OnceLock` keeps the build cost bounded — `escargot` itself
/// is a thin wrapper around `cargo build` so a no-op rebuild is fast,
/// but skipping it entirely when the artefact is already on disk is
/// even faster.
fn headscale_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        // Manifest path is relative to the integration-test cwd
        // (`crates/octravpn-node/`). The sibling repo lives at
        // `../../../headscale-rs/headscale-cli/Cargo.toml` — same
        // shape as the `headscale-cli` path-dep in `Cargo.toml`.
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../headscale-rs/headscale-cli/Cargo.toml")
            .canonicalize()
            .expect("canonicalize sibling manifest path");
        let bin = CargoBuild::new()
            .manifest_path(&manifest)
            .bin("headscale")
            .current_release()
            .current_target()
            .run()
            .expect("build standalone headscale binary");
        bin.path().to_path_buf()
    })
}

/// Spawn `octravpn-node` with the supplied args. Captures stdout +
/// stderr + exit code. The `--config` flag is set to a definitely-
/// missing path so we can be sure none of the headscale subcommands
/// accidentally read it (they shouldn't — admin surface only touches
/// `--server` / env).
fn octravpn(args: &[&str]) -> CommandOutput {
    let out = Command::cargo_bin("octravpn-node")
        .expect("octravpn-node bin under test")
        .arg("--config")
        .arg("/nonexistent/octravpn-headscale-passthrough-test.toml")
        .args(args)
        .output()
        .expect("spawn octravpn-node");
    CommandOutput::from(out)
}

/// Spawn the standalone `headscale` binary with the supplied args.
fn standalone(args: &[&str]) -> CommandOutput {
    let out = Command::new(headscale_bin())
        .args(args)
        .output()
        .expect("spawn standalone headscale");
    CommandOutput::from(out)
}

#[derive(Debug)]
struct CommandOutput {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl From<std::process::Output> for CommandOutput {
    fn from(out: std::process::Output) -> Self {
        Self {
            code: out.status.code(),
            stdout: out.stdout,
            stderr: out.stderr,
        }
    }
}

/// Assert that two runs are byte-identical on stdout + stderr + exit.
/// Pretty-prints the mismatch when they aren't.
#[track_caller]
fn assert_byte_identical(label: &str, embed: &CommandOutput, stand: &CommandOutput) {
    if embed.stdout != stand.stdout || embed.stderr != stand.stderr || embed.code != stand.code {
        panic!(
            "{label}: pass-through divergence
embed exit:   {:?}
stand exit:   {:?}
embed stdout: {:?}
stand stdout: {:?}
embed stderr: {:?}
stand stderr: {:?}",
            embed.code,
            stand.code,
            String::from_utf8_lossy(&embed.stdout),
            String::from_utf8_lossy(&stand.stdout),
            String::from_utf8_lossy(&embed.stderr),
            String::from_utf8_lossy(&stand.stderr),
        );
    }
}

// ---------------------------------------------------------------------------
// Contract tests
// ---------------------------------------------------------------------------

/// `--help` on the embedded surface mentions every admin subcommand.
/// The standalone binary's `--help` carries non-admin verbs (`server`,
/// `node`, `identity`, `init-config`, `status`) so the two are *not*
/// byte-identical at the top level; we just assert the embedded help
/// includes the admin set.
#[test]
fn headscale_help_lists_every_admin_subcommand() {
    let out = octravpn(&["headscale", "--help"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.is_empty(), "stdout should be non-empty");
    for verb in ["users", "nodes", "preauthkeys", "policy", "tailnet"] {
        assert!(
            s.contains(verb),
            "headscale --help missing `{verb}` subcommand:\n{s}"
        );
    }
    assert_eq!(out.code, Some(0), "help exits 0");
}

/// Missing `--server` is the same error in both binaries — emitted
/// before any HTTP call. Same stdout (empty), same stderr message,
/// same exit code (6 — Server / Local error per the ExitCode contract).
#[test]
fn users_list_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "users", "list"]);
    let stand = standalone(&["users", "list"]);
    assert_byte_identical("users list (missing --server)", &embed, &stand);
}

#[test]
fn users_create_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "users", "create", "alice"]);
    let stand = standalone(&["users", "create", "alice"]);
    assert_byte_identical("users create (missing --server)", &embed, &stand);
}

#[test]
fn nodes_list_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "nodes", "list"]);
    let stand = standalone(&["nodes", "list"]);
    assert_byte_identical("nodes list (missing --server)", &embed, &stand);
}

#[test]
fn preauthkeys_create_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "preauthkeys", "create", "--user", "alice"]);
    let stand = standalone(&["preauthkeys", "create", "--user", "alice"]);
    assert_byte_identical("preauthkeys create (missing --server)", &embed, &stand);
}

#[test]
fn policy_get_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "policy", "get"]);
    let stand = standalone(&["policy", "get"]);
    assert_byte_identical("policy get (missing --server)", &embed, &stand);
}

#[test]
fn tailnet_status_missing_server_is_byte_identical() {
    let embed = octravpn(&["headscale", "tailnet", "status"]);
    let stand = standalone(&["tailnet", "status"]);
    assert_byte_identical("tailnet status (missing --server)", &embed, &stand);
}

/// Connection refused against a non-routable address — exercises the
/// HTTP client path. Both binaries pipe through the same
/// `admin::run_users` library function so the diagnostic body matches
/// byte-for-byte.
#[test]
fn users_list_connection_refused_is_byte_identical() {
    let embed = octravpn(&[
        "headscale",
        "--server",
        "http://127.0.0.1:1",
        "users",
        "list",
    ]);
    let stand = standalone(&["--server", "http://127.0.0.1:1", "users", "list"]);
    assert_byte_identical("users list (connection refused)", &embed, &stand);
    // The contract says exit code 3 for connection failure. Both
    // binaries should agree (already covered by assert_byte_identical
    // above, but a direct check makes the regression site explicit).
    assert_eq!(
        embed.code,
        Some(3),
        "connection-refused should exit 3 (ExitCode::Connection)"
    );
}

#[test]
fn nodes_list_connection_refused_is_byte_identical() {
    let embed = octravpn(&[
        "headscale",
        "--server",
        "http://127.0.0.1:1",
        "nodes",
        "list",
    ]);
    let stand = standalone(&["--server", "http://127.0.0.1:1", "nodes", "list"]);
    assert_byte_identical("nodes list (connection refused)", &embed, &stand);
    assert_eq!(embed.code, Some(3));
}

#[test]
fn policy_get_connection_refused_is_byte_identical() {
    let embed = octravpn(&[
        "headscale",
        "--server",
        "http://127.0.0.1:1",
        "policy",
        "get",
    ]);
    let stand = standalone(&["--server", "http://127.0.0.1:1", "policy", "get"]);
    assert_byte_identical("policy get (connection refused)", &embed, &stand);
    assert_eq!(embed.code, Some(3));
}

#[test]
fn tailnet_status_connection_refused_is_byte_identical() {
    let embed = octravpn(&[
        "headscale",
        "--server",
        "http://127.0.0.1:1",
        "tailnet",
        "status",
    ]);
    let stand = standalone(&["--server", "http://127.0.0.1:1", "tailnet", "status"]);
    assert_byte_identical("tailnet status (connection refused)", &embed, &stand);
    assert_eq!(embed.code, Some(3));
}

/// Clap exit code on bad usage is 2 in both binaries — same code, same
/// usage block. (We can't byte-diff because the binary name differs in
/// the "Usage:" line.)
#[test]
fn bad_usage_exits_two() {
    let embed = octravpn(&["headscale", "users", "create"]); // missing positional
    let stand = standalone(&["users", "create"]);
    assert_eq!(embed.code, Some(2), "missing arg should be clap exit 2");
    assert_eq!(stand.code, Some(2));
    // The standalone says `Usage: headscale users create <NAME>`, the
    // embedded says `Usage: octravpn-node headscale users create
    // <NAME>`. Otherwise the body is the same.
    assert!(
        String::from_utf8_lossy(&embed.stderr).contains("Usage:"),
        "embedded should print clap usage block"
    );
    assert!(
        String::from_utf8_lossy(&stand.stderr).contains("Usage:"),
        "standalone should print clap usage block"
    );
}

/// `octravpn-node mesh status` still works but prints a deprecation
/// warning on stderr. This is the migration runway: operator scripts
/// keep working but loudly tell the operator to migrate.
#[test]
fn mesh_status_emits_deprecation_warning() {
    // Use a non-routable remote so the network call fails quickly.
    let out = octravpn(&["mesh", "status", "--remote", "http://127.0.0.1:1"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deprecated"),
        "mesh status should warn about deprecation:\n{stderr}"
    );
    assert!(
        stderr.contains("octravpn-node headscale nodes list"),
        "warning should name the replacement command:\n{stderr}"
    );
}

/// Same deprecation contract for `mesh policy`.
#[test]
fn mesh_policy_emits_deprecation_warning() {
    let out = octravpn(&["mesh", "policy", "get", "--remote", "http://127.0.0.1:1"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deprecated"),
        "mesh policy should warn about deprecation:\n{stderr}"
    );
    assert!(
        stderr.contains("octravpn-node headscale policy"),
        "warning should name the replacement command:\n{stderr}"
    );
}
