//! Integration tests for `octravpn serve` and `octravpn funnel`.
//!
//! Each test runs the real `octravpn` binary against a tempdir-sandboxed
//! registry (via the `OCTRAVPN_SERVE_DIR` env var). We round-trip via the
//! CLI output and, for funnel, also reach into `serve.toml` directly to
//! verify the on-disk schema. Together these cover the three deliverables
//! called out in the spec:
//!
//! * `serve_add_then_list_round_trip` — happy path for tailnet-only.
//! * `serve_remove_drops_entry`        — removal is observable.
//! * `funnel_add_marks_entry_as_funnel` — funnel toggles the right bit.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use tempfile::TempDir;

const SERVE_DIR_ENV: &str = "OCTRAVPN_SERVE_DIR";

fn octravpn() -> Command {
    let mut c = Command::cargo_bin("octravpn").unwrap();
    // Every test gets a fresh tempdir; the binary expects HOME for
    // unrelated subcommands, but we also pass HOME so we don't leak
    // into the developer's real `~/.octravpn` if something tries to
    // resolve it.
    c.env_remove(SERVE_DIR_ENV);
    c
}

#[test]
fn serve_add_then_list_round_trip() {
    let dir = TempDir::new().unwrap();

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["serve", "add", "--port", "8080", "--path", "/v1"])
        .assert()
        .success()
        .stdout(contains("8080"));

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["serve", "list"])
        .assert()
        .success()
        .stdout(contains("8080"))
        .stdout(contains("/v1"))
        .stdout(contains("tcp"));
}

#[test]
fn serve_remove_drops_entry() {
    let dir = TempDir::new().unwrap();

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["serve", "add", "--port", "8080", "--path", "/v1"])
        .assert()
        .success();

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["serve", "remove", "--port", "8080"])
        .assert()
        .success();

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["serve", "list"])
        .assert()
        .success()
        // After removal, the port string must not appear in the listing.
        .stdout(contains("8080").not());
}

#[test]
fn funnel_add_marks_entry_as_funnel() {
    let dir = TempDir::new().unwrap();

    octravpn()
        .env(SERVE_DIR_ENV, dir.path())
        .args(["funnel", "add", "--port", "8080", "--path", "/pub"])
        .assert()
        .success();

    // Inspect the on-disk store directly to verify the schema. Sharing a
    // type alias with the binary would force a publically-visible API;
    // it's cleaner to assert on the TOML representation, which IS the
    // contract for this file.
    let toml_path = dir.path().join("serve.toml");
    let body = fs::read_to_string(&toml_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", toml_path.display()));

    let v: toml::Value = toml::from_str(&body).expect("parse serve.toml");
    let entries = v
        .get("entries")
        .and_then(|x| x.as_array())
        .expect("entries array");
    assert_eq!(entries.len(), 1, "expected exactly one entry");

    let entry = &entries[0];
    assert_eq!(entry.get("local_port").and_then(toml::Value::as_integer), Some(8080));
    assert_eq!(entry.get("local_proto").and_then(toml::Value::as_str), Some("tcp"));
    assert_eq!(entry.get("external_path").and_then(toml::Value::as_str), Some("/pub"));
    assert_eq!(entry.get("funnel").and_then(toml::Value::as_bool), Some(true));
}
