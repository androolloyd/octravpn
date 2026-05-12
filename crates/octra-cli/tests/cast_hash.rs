//! Hash-helper tests.

use assert_cmd::Command;
use predicates::str::contains;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn sha256_empty_hex() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    cmd()
        .args(["cast", "sha256", "0x"])
        .assert()
        .success()
        .stdout(contains(
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ));
}

#[test]
fn keccak_aliases_sha256() {
    cmd()
        .args(["cast", "keccak", "0x"])
        .assert()
        .success()
        .stdout(contains(
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ));
}
