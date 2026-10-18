#![cfg(unix)]
//! Relative node identity paths must publish durably on the first invocation.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn relative_identity_cli_publishes_private_key_and_refuses_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_octra-node");
    let invoke = || {
        Command::new(binary)
            .current_dir(directory.path())
            .args(["init-identity", "--key", "node.key"])
            .output()
            .unwrap()
    };
    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let public: Value = serde_json::from_slice(&first.stdout).unwrap();
    let fields = public.as_object().unwrap();
    assert_eq!(fields.len(), 3);
    for field in ["address", "public_key", "key_path"] {
        assert!(fields.contains_key(field));
    }
    assert_eq!(public["key_path"], "node.key");
    let path = directory.path().join("node.key");
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 32);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let identity = octra_node::identity::read(&path).unwrap();
    let encoded = STANDARD.encode(identity.verifying_key().as_bytes());
    assert_eq!(public["public_key"], encoded);
    assert_eq!(
        public["address"],
        String::from_utf8(octra_node_protocol::transaction::address_from_public_key(
            encoded.as_bytes()
        ))
        .unwrap()
    );
    let before = zeroize::Zeroizing::new(std::fs::read(&path).unwrap());
    let names = || {
        directory
            .path()
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(), [std::ffi::OsString::from("node.key")]);
    let second = invoke();
    assert!(!second.status.success());
    assert!(second.stdout.is_empty());
    assert!(String::from_utf8(second.stderr)
        .unwrap()
        .contains("durable record differs"));
    assert!(std::fs::read(&path).unwrap().as_slice() == before.as_slice());
    assert_eq!(names(), [std::ffi::OsString::from("node.key")]);
}
