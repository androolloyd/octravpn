//! Basic CLI hygiene: `--help`, `--version`, completions for each shell.

use assert_cmd::Command;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn version_runs() {
    cmd().arg("--version").assert().success();
}

#[test]
fn help_lists_subcommands() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("forge"))
        .stdout(contains("cast"))
        .stdout(contains("anvil"))
        .stdout(contains("chisel"));
}

#[test]
fn completions_bash() {
    cmd().args(["completions", "bash"]).assert().success();
}

#[test]
fn completions_zsh() {
    cmd().args(["completions", "zsh"]).assert().success();
}
