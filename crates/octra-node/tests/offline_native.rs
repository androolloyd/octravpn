#![cfg(unix)]
//! Explicit unchanged-native differential; missing bindings fail when invoked.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use octra_node::native_tools::{
    Bounds, NativeBackend, NativeBackendOptions, NativeDirectoryOwner, NativeTool, Policy,
};
use octra_node_protocol::{
    consensus::{
        codec::Wire, hash, journal::JournalOwner, pending_log::PendingCommit, RoundStep, RoundSync,
        Vote, VoteType,
    },
    fork_repair,
    state_sync::head::Head,
    transaction::address_from_public_key,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};

fn all_contents(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if fs::symlink_metadata(&path).unwrap().file_type().is_dir() {
                walk(root, &path, out);
            } else {
                assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
                assert!(fs::metadata(&path).unwrap().len() <= 8 * 1024 * 1024);
                assert!(out.len() < 512);
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(path, path, &mut out);
    out
}
fn contents(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = all_contents(path);
    // Only the exact root-level Rust ownership inode is additional to native.
    out.remove(Path::new("validator_journal.lock"));
    out
}

fn rust_binary() -> PathBuf {
    std::env::var_os("OCTRA_OFFLINE_RUST_NODE").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_octra-node")),
        PathBuf::from,
    )
}

fn digest(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    assert!(file.metadata().unwrap().len() <= 512 * 1024 * 1024);
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 65_536];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    hex::encode(digest.finalize())
}
fn artifacts() -> PathBuf {
    let directory = PathBuf::from(
        std::env::var_os("OCTRA_NATIVE_TOOL_ARTIFACTS")
            .expect("actual native artifacts directory is required"),
    );
    for (name, expected) in [
        (
            "check_store",
            "4bd60b5dfd14e0370bb65b6301225fcca0cc519b510f8038574c4b62ff6690ef",
        ),
        (
            "fhe_audit",
            "03cbf82674ca4be23c6899e258f58528e36ec21c85714dddce5b5e413bbce256",
        ),
        (
            "vote_floor",
            "0a078875836e03f1d2440e2278af111fa9f4d10fbfb19384a2a856c950659344",
        ),
        (
            "octra_state_sync_manifest",
            "d06e0bf3acac4d1d1498746ecfd5ac5a6f6207464123c9cc2dafeb96436a85e5",
        ),
        (
            "build_certificate",
            "cf4f8b32ff1cf4155bff43effd0dac2ef734a50f0c74e8202f56cdd8677ec178",
        ),
    ] {
        assert!(fs::symlink_metadata(directory.join(name))
            .unwrap()
            .is_file());
        assert_eq!(
            digest(&directory.join(name)),
            expected,
            "actual native artifact {name}"
        );
    }
    directory
}
fn backend(directory: &Path, tool: NativeTool, name: &str) -> NativeBackend {
    NativeBackend::verified(
        tool,
        &NativeBackendOptions {
            executable: directory.join(name),
            sha256: digest(&directory.join(name)),
            certificate: directory.join("build_certificate"),
        },
    )
    .unwrap()
}
async fn rust_output(command: &str, args: Vec<OsString>) -> Output {
    let mut out = tempfile::tempfile().unwrap();
    let mut err = tempfile::tempfile().unwrap();
    let mut child = tokio::process::Command::new(rust_binary())
        .env_clear()
        .arg(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(err.try_clone().unwrap()))
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let status =
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(60), child.wait()).await {
            result.unwrap()
        } else {
            let _ = child.kill().await;
            child.wait().await.unwrap();
            panic!("owned Rust utility timeout");
        };
    out.seek(SeekFrom::Start(0)).unwrap();
    err.seek(SeekFrom::Start(0)).unwrap();
    let mut stdout = vec![];
    let mut stderr = vec![];
    out.take(1_048_577).read_to_end(&mut stdout).unwrap();
    err.take(1_048_577).read_to_end(&mut stderr).unwrap();
    assert!(stdout.len() + stderr.len() <= 1_048_576);
    Output {
        status,
        stdout,
        stderr,
    }
}
fn exact(observed: &Output, expected: &Output) {
    assert_eq!(observed.status.code(), expected.status.code());
    assert_eq!(observed.stdout, expected.stdout);
    assert_eq!(observed.stderr, expected.stderr);
}

#[tokio::test]
#[ignore = "requires actual source-certified native tools and retained genuine physical store"]
async fn unchanged_native_physical_check_and_fhe_audit_have_positive_exact_dispatch() {
    let raw = include_bytes!("fixtures/offline-native-store.json");
    assert_eq!(
        hex::encode(Sha256::digest(raw)),
        "90a65d16bf4c7b6467433d346aa6a0be4d79daf6537553ecb003dddcdbe91188"
    );
    let manifest: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        manifest["schema"],
        "octra_genuine_native_offline_store_fixture_v1"
    );
    assert_eq!(
        manifest["native_pin"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let original = PathBuf::from(
        std::env::var_os("OCTRA_NATIVE_STORE_FIXTURE")
            .expect("captured genuine physical fixture is required"),
    );
    let before = all_contents(&original);
    assert_eq!(before.len(), 24);
    let expected_files = manifest["files"].as_object().unwrap();
    assert_eq!(before.len(), expected_files.len());
    for (path, bytes) in &before {
        let expected = &expected_files[path.to_str().unwrap()];
        assert_eq!(bytes.len() as u64, expected["bytes"].as_u64().unwrap());
        assert_eq!(
            hex::encode(Sha256::digest(bytes)),
            expected["sha256"].as_str().unwrap()
        );
    }
    let tools = artifacts();
    for (tool, name, command) in [
        (NativeTool::CheckStore, "check_store", "check-store"),
        (NativeTool::FheAudit, "fhe_audit", "fhe-audit"),
    ] {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("native-store");
        fs::create_dir(&root).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (path, bytes) in &before {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let destination = root.join(path);
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(destination.parent().unwrap())
                .unwrap();
            fs::write(&destination, bytes).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let expected = backend(&tools, tool, name)
            .run(
                vec![root.as_os_str().to_owned()],
                Policy::ReadOnly,
                (),
                Bounds::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            expected.status.code(),
            Some(0),
            "actual native positive {name}: {}",
            String::from_utf8_lossy(&expected.stderr)
        );
        let output = String::from_utf8(expected.stdout.clone()).unwrap();
        if name == "check_store" {
            assert!(output.starts_with("event = store_check status = verified action = "));
            assert!(output.ends_with(" epoch = 0 readonly = true\n"));
        } else {
            assert!(output.contains("event = account account = "));
            assert!(output.contains("event = cipher_format format = absent accounts = 1\n"));
            assert!(output.contains("status = complete accounts = 1 rejected = 0 loader_clears = 0 loader_refuses = 0 cipher_bytes = 0 result = storage_readable\n"));
            assert!(output.contains(manifest["origin"]["ledger_root"].as_str().unwrap()));
            assert!(output.contains(manifest["origin"]["irmin_commit"].as_str().unwrap()));
        }
        let observed = rust_output(
            command,
            vec![
                root.as_os_str().to_owned(),
                "--backend".into(),
                tools.join(name).into_os_string(),
                "--backend-sha256".into(),
                digest(&tools.join(name)).into(),
                "--backend-certificate".into(),
                tools.join("build_certificate").into_os_string(),
            ],
        )
        .await;
        exact(&observed, &expected);
        let mut after = all_contents(&root);
        let mut input = before.clone();
        // Native LMDB readers may update this exact reader-lock mapping. The
        // native fixture's own Recovery_case.files makes the same distinction.
        let lock = Path::new("chaindata/index/lock.mdb");
        let lock_changed = after.get(lock) != input.get(lock);
        assert!(after.remove(lock).is_some());
        assert!(input.remove(lock).is_some());
        assert_eq!(
            after, input,
            "read-only tool changed canonical/journal bytes or names"
        );
        println!("native_physical_positive tool={name} status=0 exact_dispatch=true lmdb_reader_lock_changed={lock_changed}");
    }
    assert_eq!(
        all_contents(&original),
        before,
        "captured retained source was mutated"
    );
    let _unchanged_artifacts = artifacts();
}

#[tokio::test]
#[ignore = "requires actual adopted native vote_floor and source certificate"]
async fn unchanged_native_signed_sync_positive_and_refusals_preserve_exact_contents() {
    let tools = artifacts();
    let native = tempfile::tempdir().unwrap();
    let rust = tempfile::tempdir().unwrap();
    fixture(native.path());
    fixture(rust.path());
    let tool = backend(&tools, NativeTool::VoteFloor, "vote_floor");
    let key = SigningKey::from_bytes(&[41; 32]);
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address = String::from_utf8(address_from_public_key(public.as_bytes())).unwrap();
    for variant in [
        "positive_check",
        "positive_write",
        "signature",
        "chain",
        "epoch",
        "request",
        "validator",
        "prepared_sync",
        "minimum",
    ] {
        let mut sync = RoundSync {
            chain_id: b"offline-native-sync".to_vec(),
            epoch_id: 8,
            round: 4,
            step: RoundStep::Precommit,
            request: false,
            validator: address.as_bytes().to_vec(),
            signature: vec![],
        };
        match variant {
            "chain" => sync.chain_id = b"another".to_vec(),
            "epoch" => sync.epoch_id = 9,
            "request" => sync.request = true,
            "validator" => sync.validator = b"another-validator".to_vec(),
            _ => (),
        }
        sync.signature = key
            .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
            .to_bytes()
            .to_vec();
        if variant == "signature" {
            sync.signature[0] ^= 1;
        }
        let encoded = STANDARD.encode(sync.encode().unwrap());
        let write = variant == "positive_write";
        let args = |directory: &Path| {
            let mut values = vec![
                "--data-dir".into(),
                directory.as_os_str().to_owned(),
                "--chain-id".into(),
                "offline-native-sync".into(),
                "--validator".into(),
                address.clone().into(),
                "--validator-pub".into(),
                public.clone().into(),
                "--head-epoch".into(),
                "7".into(),
                "--round-sync".into(),
                encoded.clone().into(),
                "--round-min".into(),
                if variant == "minimum" {
                    "-1".into()
                } else {
                    "6".into()
                },
            ];
            if !write {
                values.push("--check".into());
            }
            if variant == "prepared_sync" {
                values.push("--prepared".into());
            }
            values
        };
        let before_native = contents(native.path());
        let before_rust = contents(rust.path());
        let owner = (
            NativeDirectoryOwner::acquire(&native.path().join("chaindata")).unwrap(),
            JournalOwner::open(native.path()).unwrap(),
        );
        let expected = tool
            .run(
                args(native.path()),
                if write {
                    Policy::StoppedOwner
                } else {
                    Policy::ReadOnly
                },
                owner,
                Bounds::default(),
            )
            .await
            .unwrap();
        let observed = rust_output("vote-floor", args(rust.path())).await;
        exact(&observed, &expected);
        assert_eq!(
            expected.status.code(),
            Some(i32::from(!variant.starts_with("positive_"))),
            "{variant}"
        );
        assert_eq!(contents(native.path()), contents(rust.path()));
        if write {
            let owner = JournalOwner::open(rust.path()).unwrap();
            assert_eq!(owner.floor().unwrap(), Some(7));
            assert_eq!(owner.round_mark().unwrap().unwrap().round, 6);
        } else {
            assert_eq!(contents(native.path()), before_native);
            assert_eq!(contents(rust.path()), before_rust);
        }
        println!(
            "native_signed_sync case={variant} status={} exact_output_and_contents=true",
            expected.status.code().unwrap()
        );
    }
    let _unchanged_artifacts = artifacts();
}
fn fixture(path: &Path) {
    fs::create_dir(path.join("chaindata")).unwrap();
    let head = Head {
        schema_version: 3,
        generation: 7,
        epoch_id: 7,
        state_root: b"root".to_vec(),
        ledger_state_root: None,
        irmin_commit: None,
        txid_hi: -1,
        txlog_seg: None,
        txlog_off: None,
        epochlog_off: None,
        commit_id: b"commit".to_vec(),
        ts: 0.0,
        quorum_cert_hash: None,
        epoch_index_hash: None,
        epoch_index_root: None,
    };
    fs::write(
        path.join("HEAD.json"),
        fork_repair::encode_head(&head).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an actual adopted native vote_floor executable and build certificate"]
async fn unchanged_native_vote_floor_output_and_durable_plan_match_rust() {
    let binding = std::env::var_os("OCTRA_NATIVE_VOTE_FLOOR_BINDING")
        .expect("explicit native tool binding is required");
    let backend = NativeBackend::verified(
        NativeTool::VoteFloor,
        &NativeBackendOptions::read(Path::new(&binding)).unwrap(),
    )
    .unwrap();
    let native = tempfile::tempdir().unwrap();
    let rust = tempfile::tempdir().unwrap();
    fixture(native.path());
    fixture(rust.path());
    let key = SigningKey::from_bytes(&[41; 32]);
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address = String::from_utf8(address_from_public_key(public.as_bytes())).unwrap();
    for (index, (round, flags)) in [
        (3, vec!["--check"]),
        (3, vec![]),
        (3, vec!["--check", "--prepared"]),
        (3, vec!["--check", "--staged"]),
        (2, vec!["--check", "--prepared"]),
        (0, vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        if round == 0 {
            let mut vote = Vote {
                chain_id: b"offline-native-differential".to_vec(),
                epoch_id: 8,
                round: 9,
                vote_type: VoteType::Precommit,
                proposal_id: vec![7; 32],
                validator: address.as_bytes().to_vec(),
                signature: vec![],
            };
            vote.signature = key
                .sign(&hash::vote_sign_bytes(&vote).unwrap())
                .to_bytes()
                .to_vec();
            let pending = PendingCommit {
                epoch_id: 8,
                round: 9,
                proposal_id: hex::encode(&vote.proposal_id).into_bytes(),
                proposed_state_root: b"root".to_vec(),
                txid_hi: -1,
                ts: 0.0,
                validator_addr: vote.validator.clone(),
                proposal_b64: None,
                vote_b64: Some(STANDARD.encode(vote.encode().unwrap()).into_bytes()),
                tx_hashes: vec![],
                txs_json: vec![],
                receipts_json: vec![],
            };
            for directory in [native.path(), rust.path()] {
                let owner = JournalOwner::open(directory).unwrap();
                owner.keep_pending(&pending).unwrap();
            }
        }
        let args = |directory: &Path| {
            let mut args = vec![
                OsString::from("--data-dir"),
                directory.as_os_str().to_owned(),
                "--chain-id".into(),
                "offline-native-differential".into(),
                "--validator".into(),
                address.clone().into(),
                "--validator-pub".into(),
                public.clone().into(),
                "--head-epoch".into(),
                "7".into(),
                "--round".into(),
                round.to_string().into(),
            ];
            args.extend(flags.iter().map(|flag| OsString::from(*flag)));
            args
        };
        let native_owner = (
            NativeDirectoryOwner::acquire(&native.path().join("chaindata")).unwrap(),
            JournalOwner::open(native.path()).unwrap(),
        );
        let policy = if flags.contains(&"--check") {
            Policy::ReadOnly
        } else {
            Policy::StoppedOwner
        };
        let expected = backend
            .run(args(native.path()), policy, native_owner, Bounds::default())
            .await
            .unwrap();
        let mut out = tempfile::tempfile().unwrap();
        let mut err = tempfile::tempfile().unwrap();
        let mut command = tokio::process::Command::new(rust_binary());
        command
            .env_clear()
            .arg("vote_floor")
            .args(args(rust.path()))
            .stdin(Stdio::null())
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(err.try_clone().unwrap()))
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let status =
            if let Ok(result) = tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
                result.unwrap()
            } else {
                let _ = child.kill().await;
                child.wait().await.unwrap();
                panic!("owned Rust offline tool timeout");
            };
        out.seek(SeekFrom::Start(0)).unwrap();
        err.seek(SeekFrom::Start(0)).unwrap();
        let mut stdout = vec![];
        let mut stderr = vec![];
        out.take(1_048_577).read_to_end(&mut stdout).unwrap();
        err.take(1_048_577).read_to_end(&mut stderr).unwrap();
        assert!(stdout.len() + stderr.len() <= 1_048_576);
        let observed = Output {
            status,
            stdout,
            stderr,
        };
        assert_eq!(observed.status.code(), expected.status.code());
        assert_eq!(expected.status.code(), Some(i32::from(round == 2)));
        assert_eq!(observed.stdout, expected.stdout);
        assert_eq!(observed.stderr, expected.stderr);
        assert_eq!(contents(rust.path()), contents(native.path()));
        println!(
            "native_round_plan step={index} status={} exact_output_and_contents=true",
            expected.status.code().unwrap()
        );
    }
}
