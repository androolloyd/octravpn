//! Wallet round-trip tests for `cast wallet new`, `cast wallet addr`,
//! and `cast wallet sign`.
//!
//! We exercise the binary via `assert_cmd` so the integration covers
//! argv parsing in addition to the underlying logic.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("octra").unwrap()
}

#[test]
fn wallet_new_and_addr_roundtrip() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wallet.hex");
    cmd()
        .args(["cast", "wallet", "new", "--out"])
        .arg(&key_path)
        .assert()
        .success();
    let body = fs::read_to_string(&key_path).unwrap();
    assert_eq!(body.trim().len(), 64, "key file should be 64 hex chars");

    // Derive the address from the same key file and verify it has the
    // 47-char `oct...` shape.
    let out = cmd()
        .args(["cast", "wallet", "addr", "--key"])
        .arg(&key_path)
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let addr = s.trim();
    assert!(addr.starts_with("oct"), "got: {addr}");
    assert_eq!(addr.len(), 47, "len was {}; got: {addr}", addr.len());

    // Verify the same address matches what `octravpn_core` would compute
    // directly, sanity-checking that the CLI uses the real codec.
    let secret_hex = fs::read_to_string(&key_path).unwrap();
    let secret = hex::decode(secret_hex.trim()).unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&secret);
    let kp = octravpn_core::sig::KeyPair::from_secret_bytes(&k);
    let expected = octravpn_core::address::Address::from_pubkey(&kp.public.0)
        .display()
        .to_string();
    assert_eq!(addr, expected);
}

#[test]
fn wallet_sign_returns_base64() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.hex");
    fs::write(&key_path, "00".repeat(32)).unwrap();
    let out = cmd()
        .args(["cast", "wallet", "sign", "--key"])
        .arg(&key_path)
        .arg("hello")
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let sig = s.trim();
    // Base64 of a 64-byte signature is 88 chars.
    assert_eq!(sig.len(), 88, "got: {sig}");
}

#[test]
fn wallet_new_stdout_form() {
    cmd()
        .args(["cast", "wallet", "new"])
        .assert()
        .success()
        .stdout(contains("\"address\""))
        .stdout(contains("\"public_key\""));
}
