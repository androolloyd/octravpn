//! Transport/ownership controls use deliberately local scripts. They do not
//! certify a native executable or stand in for the real tool differentials.
use super::*;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::atomic::AtomicUsize,
};

fn backend(directory: &Path, body: &str) -> (NativeBackend, PathBuf) {
    let source = directory.join("local-fixture.sh");
    fs::write(&source, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    let sha = hex::encode(Sha256::digest(fs::read(&source).unwrap()));
    let image = crate::legacy_repair::process::freeze(&source, &sha).unwrap();
    (
        NativeBackend {
            tool: NativeTool::CheckStore,
            image: Arc::new(image),
        },
        source,
    )
}
fn absent(pid: u32) -> bool {
    !Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}
async fn child_pid(path: &Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(pid) = raw.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn frozen_tool_preserves_exact_exit_and_output_after_original_is_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let (tool, source) = backend(
        temp.path(),
        "printf 'original output'; printf 'diagnostic' >&2; exit 7",
    );
    fs::write(source, "#!/bin/sh\nprintf replaced\n").unwrap();
    let output = tool
        .run(vec![], Policy::ReadOnly, (), Bounds::default())
        .await
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"original output");
    assert_eq!(output.stderr, b"diagnostic");
}

#[tokio::test]
async fn native_tool_timeout_and_output_overflow_reap_the_actual_child() {
    for overflow in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("pid");
        let body = if overflow {
            "printf '%s' $$ > \"$1\"; while :; do printf 'abcdefghijklmnopqrstuvwxyz'; done"
        } else {
            "printf '%s' $$ > \"$1\"; exec /bin/sleep 30"
        };
        let (tool, _) = backend(temp.path(), body);
        let error = tool
            .run(
                vec![pid_file.clone().into_os_string()],
                Policy::ReadOnly,
                (),
                Bounds {
                    timeout: Duration::from_secs(1),
                    max_output: 100,
                },
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(if overflow {
                "output exceeds"
            } else {
                "deadline"
            }),
            "{error}"
        );
        let pid = child_pid(&pid_file).await;
        assert!(absent(pid), "owned child {pid} still exists");
    }
}

#[tokio::test]
async fn native_parent_cannot_report_success_and_leave_a_redirected_descendant() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("descendant.pid");
    let (tool, _) = backend(
        temp.path(),
        "/bin/sleep 30 >/dev/null 2>&1 & printf '%s' $! > \"$1\"; exit 0",
    );
    let error = tool
        .run(
            vec![pid_file.clone().into_os_string()],
            Policy::ReadOnly,
            (),
            Bounds::default(),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("background descendants"),
        "{error}"
    );
    let pid = child_pid(&pid_file).await;
    assert!(absent(pid), "owned descendant {pid} still exists");
}

#[tokio::test]
async fn cancelling_caller_retains_writer_ownership_until_child_is_reaped() {
    struct Owner {
        directory: Option<NativeDirectoryOwner>,
        dropped: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            drop(self.directory.take());
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("chaindata");
    fs::create_dir(&directory).unwrap();
    let owner = NativeDirectoryOwner::acquire(&directory).unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let (mut tool, _) = backend(temp.path(), "printf '%s' $$ > \"$2\"; exec /bin/sleep 30");
    tool.tool = NativeTool::VoteFloor;
    let pid_file = temp.path().join("pid");
    let task = tokio::spawn({
        let pid_file = pid_file.clone();
        let dropped = dropped.clone();
        async move {
            tool.run(
                vec![
                    "--data-dir".into(),
                    pid_file.into_os_string(),
                    "--chain-id".into(),
                    "private-fixture".into(),
                    "--validator".into(),
                    "validator".into(),
                    "--validator-pub".into(),
                    "public-key".into(),
                    "--head-epoch".into(),
                    "0".into(),
                    "--round".into(),
                    "1".into(),
                ],
                Policy::StoppedOwner,
                Owner {
                    directory: Some(owner),
                    dropped,
                },
                Bounds::default(),
            )
            .await
        }
    });
    let pid = child_pid(&pid_file).await;
    assert!(NativeDirectoryOwner::acquire(&directory).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(5), async {
        while dropped.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(absent(pid));
    assert!(NativeDirectoryOwner::acquire(&directory).is_ok());
}

#[test]
fn directory_owner_uses_the_native_directory_inode_and_refuses_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("chaindata");
    fs::create_dir(&directory).unwrap();
    let alias = temp.path().join("alias");
    symlink(&directory, &alias).unwrap();
    let owner = NativeDirectoryOwner::acquire(&directory).unwrap();
    assert!(NativeDirectoryOwner::acquire(&directory.join(".")).is_err());
    assert!(NativeDirectoryOwner::acquire(&alias).is_err());
    drop(owner);
    assert!(NativeDirectoryOwner::acquire(&directory).is_ok());
}

#[tokio::test]
async fn command_policy_and_invalid_bounds_refuse_before_any_execution() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("must-not-exist");
    let (mut tool, _) = backend(temp.path(), "printf unexpected > \"$1\"");
    tool.tool = NativeTool::StateSyncManifest;
    let args = vec![
        marker.clone().into_os_string(),
        "--command".into(),
        "seal".into(),
    ];
    assert!(tool
        .run(args.clone(), Policy::ReadOnly, (), Bounds::default())
        .await
        .is_err());
    assert!(tool
        .run(
            args,
            Policy::StoppedOwner,
            (),
            Bounds {
                timeout: Duration::ZERO,
                ..Bounds::default()
            }
        )
        .await
        .is_err());
    assert!(!marker.exists());
}

#[test]
fn binding_is_bounded_nofollow_and_rejects_duplicate_fields() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("binding.json");
    fs::write(
        &path,
        r#"{"executable":"tool","sha256":"aa","certificate":"build.json"}"#,
    )
    .unwrap();
    let binding = NativeBackendOptions::read(&path).unwrap();
    assert_eq!(binding.executable, temp.path().join("tool"));
    assert_eq!(binding.certificate, temp.path().join("build.json"));
    let alias = temp.path().join("alias.json");
    symlink(&path, &alias).unwrap();
    assert!(NativeBackendOptions::read(&alias).is_err());
    fs::write(
        &path,
        r#"{"executable":"one","executable":"two","sha256":"aa","certificate":"build.json"}"#,
    )
    .unwrap();
    assert!(NativeBackendOptions::read(&path).is_err());
    fs::write(&path, vec![b' '; MAX_JSON as usize + 1]).unwrap();
    assert!(NativeBackendOptions::read(&path).is_err());
}

#[test]
fn unverifiable_source_certificate_cannot_start_even_a_known_executable() {
    let temp = tempfile::tempdir().unwrap();
    let (_, source) = backend(temp.path(), "exit 0");
    let certificate = temp.path().join("certificate.json");
    let certificate_bytes = serde_json::json!({
        "schema":"octra_native_tools_build_artifacts_v1", "native_pin":UPSTREAM,
        "native_sources":{}, "native_archive_inputs":{}, "native_production_bodies_changed":false,
        "native_sources_rechecked_after_build":true,"native_archive_rechecked_after_build":true,
        "artifacts":{}
    });
    fs::write(
        &certificate,
        serde_json::to_vec(&certificate_bytes).unwrap(),
    )
    .unwrap();
    let options = NativeBackendOptions {
        executable: source.clone(),
        sha256: hex::encode(Sha256::digest(fs::read(source).unwrap())),
        certificate,
    };
    let error = NativeBackend::verified(NativeTool::CheckStore, &options)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("native module source map differs"),
        "{error}"
    );
}

#[test]
fn ownership_policy_distinguishes_native_option_positions_from_literal_values() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| OsString::from(*value))
            .collect::<Vec<_>>()
    };
    for key in [
        "--source",
        "--chain-id",
        "--output",
        "--draft",
        "--certificate",
        "--wallet",
        "--finality",
    ] {
        let writing = args(&["--command", "seal", key, "--command"]);
        assert!(NativeTool::StateSyncManifest
            .check_policy(&writing, Policy::StoppedOwner)
            .is_ok());
        assert!(NativeTool::StateSyncManifest
            .check_policy(&writing, Policy::ReadOnly)
            .is_err());
    }
    let reading = args(&["--command", "verify", "--certificate", "--command"]);
    assert!(NativeTool::StateSyncManifest
        .check_policy(&reading, Policy::ReadOnly)
        .is_ok());
    for malformed in [
        args(&["--command", "verify", "--command", "seal"]),
        args(&["--command", "verify", "--certificate"]),
        args(&["--command", "verify", "--unknown", "x"]),
        args(&["--command", "--command"]),
    ] {
        assert!(NativeTool::StateSyncManifest
            .check_policy(&malformed, Policy::ReadOnly)
            .is_err());
        assert!(NativeTool::StateSyncManifest
            .check_policy(&malformed, Policy::StoppedOwner)
            .is_err());
    }
    let base = args(&[
        "--data-dir",
        "store",
        "--chain-id",
        "--check",
        "--validator",
        "v",
        "--validator-pub",
        "pub",
        "--head-epoch",
        "0",
        "--round-sync",
        "--check",
    ]);
    assert!(NativeTool::VoteFloor
        .check_policy(&base, Policy::StoppedOwner)
        .is_ok());
    assert!(NativeTool::VoteFloor
        .check_policy(&base, Policy::ReadOnly)
        .is_err());
    let mut checking = base.clone();
    checking.push("--check".into());
    assert!(NativeTool::VoteFloor
        .check_policy(&checking, Policy::ReadOnly)
        .is_ok());
    assert!(NativeTool::VoteFloor
        .check_policy(&checking, Policy::StoppedOwner)
        .is_err());
    // The native command refuses these combinations without writing. Keep
    // its semantic refusal reachable under the read-only capability.
    for option in ["--staged", "--prepared"] {
        let mut sync_check = checking.clone();
        sync_check.push(option.into());
        assert!(NativeTool::VoteFloor
            .check_policy(&sync_check, Policy::ReadOnly)
            .is_ok());
        assert!(NativeTool::VoteFloor
            .check_policy(&sync_check, Policy::StoppedOwner)
            .is_err());
    }
    for suffix in [
        args(&["--check", "--check"]),
        args(&["--round", "1"]),
        args(&["--unknown", "x"]),
        args(&["--validator"]),
        args(&["--staged", "--prepared"]),
    ] {
        let mut malformed = base.clone();
        malformed.extend(suffix);
        assert!(NativeTool::VoteFloor
            .check_policy(&malformed, Policy::ReadOnly)
            .is_err());
        assert!(NativeTool::VoteFloor
            .check_policy(&malformed, Policy::StoppedOwner)
            .is_err());
    }
}
