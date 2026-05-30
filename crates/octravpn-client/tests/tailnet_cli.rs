// Skipped under cargo-tarpaulin: this subprocess-driven CLI test deadlocks
// tarpaulin's ptrace coverage engine (and adds no in-process coverage).
// Normal cargo test still runs it.
#![cfg(not(tarpaulin))]

//! Smoke tests for `octravpn tailnet ...` subcommands. We exercise the
//! help dispatch + a config-less path so the clap routing is verified
//! end-to-end without needing a live chain.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("octravpn").unwrap()
}

#[test]
fn tailnet_help_lists_subcommands() {
    cmd()
        .args(["tailnet", "--help"])
        .assert()
        .success()
        .stdout(contains("create"))
        .stdout(contains("add-member"))
        .stdout(contains("remove-member"))
        .stdout(contains("info"))
        .stdout(contains("up"))
        .stdout(contains("top-up"))
        .stdout(contains("set-acl"))
        .stdout(contains("configure-exit"))
        .stdout(contains("advertise-subnet"))
        .stdout(contains("register-device"))
        .stdout(contains("revoke-device"))
        .stdout(contains("issue-token"))
        .stdout(contains("redeem-token"));
}

#[test]
fn tailnet_create_help_shows_required_args() {
    cmd()
        .args(["tailnet", "create", "--help"])
        .assert()
        .success()
        .stdout(contains("--treasury"))
        .stdout(contains("--acl"))
        .stdout(contains("--name"));
}

#[test]
fn tailnet_up_help_shows_stun_and_dns_defaults() {
    cmd()
        .args(["tailnet", "up", "--help"])
        .assert()
        .success()
        .stdout(contains("stun.l.google.com"))
        .stdout(contains("1.1.1.1"));
}

#[test]
fn unknown_subcommand_fails_cleanly() {
    cmd()
        .args(["tailnet", "nonsense"])
        .assert()
        .failure()
        .stderr(contains("error").or(contains("unrecognized")));
}
