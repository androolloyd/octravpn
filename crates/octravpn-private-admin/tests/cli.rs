use std::process::Command;

#[test]
fn single_party_setup_requires_explicit_development_mode() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_octravpn-private-admin"))
        .args(["setup", "--out"])
        .arg(dir.path().join("keys"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("test-only"));
    assert!(!dir.path().join("keys").exists());
}

#[test]
fn credential_creation_is_exclusive_and_stdout_contains_only_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credential");
    let generate = || {
        Command::new(env!("CARGO_BIN_EXE_octravpn-private-admin"))
            .args(["credential", "--out"])
            .arg(&path)
            .output()
            .unwrap()
    };
    let output = generate();
    assert!(output.status.success());
    let secret = std::fs::read(&path).unwrap();
    assert_eq!(secret.len(), 32);
    let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(public.as_object().unwrap().len(), 1);
    assert_eq!(public["commitment"].as_str().unwrap().len(), 64);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex::encode(&secret)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!generate().status.success());
    assert_eq!(std::fs::read(path).unwrap(), secret);
}

#[cfg(unix)]
#[test]
fn prover_rejects_publicly_readable_credential_before_loading_any_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let credential = dir.path().join("credential");
    std::fs::write(&credential, [42; 32]).unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_octravpn-private-admin"))
        .args(["authorize", "--credential"])
        .arg(credential)
        .args([
            "--proving-key",
            "absent",
            "--request",
            "absent",
            "--domain",
            "absent",
            "--program",
            "absent",
            "--nonce",
            "0",
            "--out",
            "absent",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("accessible only to its owner"));
}

#[cfg(unix)]
#[test]
fn prover_rejects_symlink_and_oversized_secret_before_loading_key() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, [1; 33]).unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link");
    symlink(&secret, &link).unwrap();
    for path in [secret, link] {
        let output = Command::new(env!("CARGO_BIN_EXE_octravpn-private-admin"))
            .args(["authorize", "--credential"])
            .arg(path)
            .args([
                "--proving-key",
                "absent",
                "--request",
                "absent",
                "--domain",
                "absent",
                "--program",
                "absent",
                "--nonce",
                "0",
                "--out",
                "absent",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("absent"));
    }
}
