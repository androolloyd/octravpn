// Skipped under cargo-tarpaulin: this subprocess-driven CLI test deadlocks
// tarpaulin's ptrace coverage engine (and adds no in-process coverage).
// Normal cargo test still runs it.
#![cfg(not(tarpaulin))]

//! Pass-through contract tests for the embedded `headscale` admin
//! CLI surface (`octravpn-node headscale …`).
//!
//! The contract: every admin subcommand the standalone `headscale`
//! binary supports is reachable as `octravpn-node headscale …` and
//! produces byte-identical stdout + stderr + exit code. These tests
//! enforce that contract by driving both binaries side-by-side
//! through `assert_cmd` and `diff`-ing the captured output. The only
//! canonicalization is the wall-clock timestamp prefix on upstream's
//! default-config warning line; the warning text and all other output
//! bytes remain strict.
//!
//! Network-touching paths are exercised through two hermetic failure
//! modes: a definitely-missing local gRPC Unix socket for migrated
//! upstream-compatible commands, and `127.0.0.1:1` for the legacy
//! `--server` HTTP fallback. No live mesh-control is required.
//!
//! See `docs/operators/cli-migration.md` for the operator-facing
//! migration table.

use assert_cmd::Command;
use escargot::CargoBuild;
use std::{env, path::PathBuf, sync::OnceLock, time::Duration};

const HEADSCALE_ENV_VARS: &[&str] = &[
    "HEADSCALE_CONFIG",
    "HEADSCALE_URL",
    "HEADSCALE_ADMIN_TOKEN",
    "HEADSCALE_CLI_ADDRESS",
    "HEADSCALE_CLI_API_KEY",
    "HEADSCALE_UNIX_SOCKET",
    "HEADSCALE_CLI_INSECURE",
];

/// Build the standalone `headscale` binary from the sibling
/// `headscale-rs` workspace once, then re-use the path across every
/// test. `OnceLock` keeps the build cost bounded — `escargot` itself
/// is a thin wrapper around `cargo build` so a no-op rebuild is fast,
/// but skipping it entirely when the artefact is already on disk is
/// even faster.
fn headscale_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(path) = env::var_os("HEADSCALE_BIN") {
            return PathBuf::from(path);
        }

        // By default, mirror the path-dep shape in Cargo.toml. Set
        // HEADSCALE_RS_PATH when the headscale-rs checkout is elsewhere.
        let headscale_rs = env::var_os("HEADSCALE_RS_PATH").map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../..")
                    .join("headscale-rs")
            },
            PathBuf::from,
        );
        let manifest = headscale_rs
            .join("headscale-cli/Cargo.toml")
            .canonicalize()
            .expect("canonicalize sibling manifest path");
        let bin = CargoBuild::new()
            .manifest_path(&manifest)
            .bin("headscale")
            .current_release()
            .target_dir(octra_target_dir())
            .run()
            .expect("build standalone headscale binary");
        bin.path().to_path_buf()
    })
}

fn octra_target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target")
}

fn child_timeout() -> Duration {
    Duration::from_secs(2)
}

fn scrub_headscale_env(cmd: &mut Command) {
    for key in HEADSCALE_ENV_VARS {
        cmd.env_remove(key);
    }
}

/// Spawn `octravpn-node` with the supplied args. Captures stdout +
/// stderr + exit code. The `--config` flag is set to a definitely-
/// missing path so we can be sure none of the headscale subcommands
/// accidentally read it (they shouldn't — admin surface only touches
/// `--server` / env).
fn octravpn(args: &[&str]) -> CommandOutput {
    let mut cmd = Command::cargo_bin("octravpn-node").expect("octravpn-node bin under test");
    scrub_headscale_env(&mut cmd);
    let out = cmd
        .timeout(child_timeout())
        .arg("--config")
        .arg("/nonexistent/octravpn-headscale-passthrough-test.toml")
        .args(args)
        .output()
        .expect("spawn octravpn-node");
    CommandOutput::from(out)
}

/// Spawn the standalone `headscale` binary with the supplied args.
fn standalone(args: &[&str]) -> CommandOutput {
    let mut cmd = Command::new(headscale_bin());
    scrub_headscale_env(&mut cmd);
    let out = cmd
        .timeout(child_timeout())
        .args(args)
        .output()
        .expect("spawn standalone headscale");
    CommandOutput::from(out)
}

fn octravpn_local_grpc_owned(args: Vec<String>) -> CommandOutput {
    let mut cmd = Command::cargo_bin("octravpn-node").expect("octravpn-node bin under test");
    scrub_headscale_env(&mut cmd);
    let out = cmd
        .timeout(child_timeout())
        .arg("--config")
        .arg("/nonexistent/octravpn-headscale-passthrough-test.toml")
        .arg("headscale")
        .arg("--unix-socket")
        .arg(missing_unix_socket_path())
        .args(args)
        .output()
        .expect("spawn octravpn-node");
    CommandOutput::from(out)
}

fn standalone_local_grpc_owned(args: Vec<String>) -> CommandOutput {
    let mut cmd = Command::new(headscale_bin());
    scrub_headscale_env(&mut cmd);
    let out = cmd
        .timeout(child_timeout())
        .arg("--unix-socket")
        .arg(missing_unix_socket_path())
        .args(args)
        .output()
        .expect("spawn standalone headscale");
    CommandOutput::from(out)
}

fn local_grpc_pair(args: &[&str]) -> (CommandOutput, CommandOutput) {
    let _ = headscale_bin();
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    (
        octravpn_local_grpc_owned(args.clone()),
        standalone_local_grpc_owned(args),
    )
}

fn missing_unix_socket_path() -> PathBuf {
    let path = env::temp_dir().join(format!(
        "octravpn-headscale-passthrough-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
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

/// Assert that two runs are byte-identical on stdout + stderr + exit, after
/// canonicalizing the wall-clock timestamp prefix on the upstream default-config
/// warning line.
/// Pretty-prints the mismatch when they aren't.
///
/// `clippy::manual_assert` would rewrite the body as a multi-line
/// `assert!(...)`, but the divergence report needs the explicit
/// `panic!` block for readability of the formatted diagnostic.
#[allow(clippy::manual_assert)]
#[track_caller]
fn assert_byte_identical(label: &str, embed: &CommandOutput, stand: &CommandOutput) {
    let embed_stderr = canonical_stderr(&embed.stderr);
    let stand_stderr = canonical_stderr(&stand.stderr);
    if embed.stdout != stand.stdout || embed_stderr != stand_stderr || embed.code != stand.code {
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

fn canonical_stderr(stderr: &[u8]) -> Vec<u8> {
    let stderr = String::from_utf8_lossy(stderr);
    let mut out = String::with_capacity(stderr.len());
    for line in stderr.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix_default_config_warning_timestamp() {
            out.push_str("<timestamp>");
            out.push_str(rest);
        } else {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

trait WarningTimestamp {
    fn strip_prefix_default_config_warning_timestamp(&self) -> Option<&str>;
}

impl WarningTimestamp for str {
    fn strip_prefix_default_config_warning_timestamp(&self) -> Option<&str> {
        let marker = " WRN no config file found, using defaults";
        let marker_start = self.find(marker)?;
        let timestamp = &self[..marker_start];
        let valid_timestamp = timestamp.len() == "2026-07-02T07:33:14-03:00".len()
            && timestamp.as_bytes().get(4) == Some(&b'-')
            && timestamp.as_bytes().get(7) == Some(&b'-')
            && timestamp.as_bytes().get(10) == Some(&b'T')
            && timestamp.as_bytes().get(13) == Some(&b':')
            && timestamp.as_bytes().get(16) == Some(&b':');
        valid_timestamp.then_some(&self[marker_start..])
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
    for verb in [
        "users",
        "nodes",
        "preauthkeys",
        "auth",
        "apikeys",
        "policy",
        "debug",
    ] {
        assert!(
            s.contains(verb),
            "headscale --help missing `{verb}` subcommand:\n{s}"
        );
    }
    assert_eq!(out.code, Some(0), "help exits 0");
}

/// Migrated commands use the local upstream-compatible gRPC endpoint
/// and fail the same way when its Unix socket is absent.
#[test]
fn users_list_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["users", "list"]);
    assert_byte_identical("users list (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn users_create_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["users", "create", "alice"]);
    assert_byte_identical("users create (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn nodes_list_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["nodes", "list"]);
    assert_byte_identical("nodes list (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn preauthkeys_create_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["preauthkeys", "create", "--user", "42"]);
    assert_byte_identical(
        "preauthkeys create (local gRPC missing socket)",
        &embed,
        &stand,
    );
}

#[test]
fn policy_get_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["policy", "get"]);
    assert_byte_identical("policy get (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn tailnet_status_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["tailnet", "status"]);
    assert_byte_identical("tailnet status (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn apikeys_list_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["apikeys", "list"]);
    assert_byte_identical("apikeys list (local gRPC missing socket)", &embed, &stand);
}

#[test]
fn auth_approve_local_grpc_missing_socket_is_byte_identical() {
    let (embed, stand) = local_grpc_pair(&["auth", "approve", "--auth-id", "pending-id"]);
    assert_byte_identical("auth approve (local gRPC missing socket)", &embed, &stand);
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
    // Upstream removed `tailnet`; it is rejected before the connection
    // path, even if a legacy `--server` flag is present.
    assert_eq!(embed.code, Some(2));
}

/// Upstream now maps this Cobra-compatible usage error through its
/// binary-level error wrapper, so it exits 1 instead of clap's raw 2.
/// Keep this assertion pinned to the standalone binary's current
/// contract.
#[test]
fn bad_usage_exits_one_like_upstream() {
    let embed = octravpn(&["headscale", "users", "create"]); // missing positional
    let stand = standalone(&["users", "create"]);
    assert_byte_identical("users create missing name", &embed, &stand);
    assert_eq!(embed.code, Some(1), "missing arg should follow upstream");
    assert!(
        String::from_utf8_lossy(&embed.stderr).contains("Error: missing parameters"),
        "embedded should print upstream missing-parameters error"
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
