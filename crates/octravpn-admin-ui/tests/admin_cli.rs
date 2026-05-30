// Skipped under cargo-tarpaulin: this subprocess-driven CLI test deadlocks
// tarpaulin's ptrace coverage engine (and adds no in-process coverage).
// Normal cargo test still runs it.
#![cfg(not(tarpaulin))]

//! Smoke tests for `octravpn-admin` CLI subcommands.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("octravpn-admin").unwrap()
}

#[test]
fn help_lists_bulk_subcommands() {
    cmd()
        .args(["--help"])
        .assert()
        .success()
        .stdout(contains("serve"))
        .stdout(contains("list-tailnets"))
        .stdout(contains("tailnet-info"))
        .stdout(contains("add-member"))
        .stdout(contains("remove-member"))
        .stdout(contains("top-up"))
        .stdout(contains("set-acl"))
        .stdout(contains("broadcast-acl"))
        .stdout(contains("list-endpoints"));
}

#[test]
fn broadcast_acl_requires_file_flag() {
    cmd()
        .args(["broadcast-acl"])
        .assert()
        .failure()
        .stderr(contains("--file"));
}

#[test]
fn set_acl_requires_wallet_for_write() {
    // Without a wallet, write paths must error clearly.
    cmd()
        .args(["set-acl", "--tailnet", "abc", "--file", "/dev/null"])
        .assert()
        .failure()
        .stderr(contains("wallet").or(contains("parse")));
}
