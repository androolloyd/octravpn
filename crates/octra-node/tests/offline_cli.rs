#![cfg(unix)]
//! Real CLI processes; no mocked journal, signature or durable-store success.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{ChainIdentity, StateRoot};
use octra_node_protocol::{
    consensus::{
        codec::Wire, hash, journal::JournalOwner, pending_log::PendingCommit, RoundStep, RoundSync,
        Vote, VoteType,
    },
    epoch_index, fork_repair,
    state::Account,
    state_sync::head::Head,
    transaction::address_from_public_key,
};
use octra_node_runtime::{canonical::CanonicalStore, state_batch::StateBatch};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn process(args: &[String]) -> Output {
    process_from(args, None)
}
fn process_from(args: &[String], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_octra-node"));
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            child.wait().unwrap();
            panic!("owned offline CLI exceeded test deadline");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[41; 32])
}
fn address() -> String {
    String::from_utf8(address_from_public_key(
        STANDARD.encode(key().verifying_key().as_bytes()).as_bytes(),
    ))
    .unwrap()
}
fn native_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("chaindata")).unwrap();
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
        dir.path().join("HEAD.json"),
        fork_repair::encode_head(&head).unwrap(),
    )
    .unwrap();
    dir
}
fn floor_args(dir: &Path, round: i64) -> Vec<String> {
    vec![
        "vote-floor".into(),
        "--data-dir".into(),
        dir.display().to_string(),
        "--chain-id".into(),
        "offline-chain".into(),
        "--validator".into(),
        address(),
        "--validator-pub".into(),
        STANDARD.encode(key().verifying_key().as_bytes()),
        "--head-epoch".into(),
        "7".into(),
        "--round".into(),
        round.to_string(),
    ]
}
fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}
fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.file_name().unwrap() != "validator_journal.lock" {
                out.insert(
                    path.strip_prefix(root).unwrap().into(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn vote(round: i64, proposal: u8) -> Vote {
    let mut vote = Vote {
        chain_id: b"offline-chain".to_vec(),
        epoch_id: 8,
        round,
        vote_type: VoteType::Precommit,
        proposal_id: vec![proposal; 32],
        validator: address().into_bytes(),
        signature: vec![],
    };
    vote.signature = key()
        .sign(&hash::vote_sign_bytes(&vote).unwrap())
        .to_bytes()
        .to_vec();
    vote
}
fn pending(vote: &Vote) -> PendingCommit {
    PendingCommit {
        epoch_id: vote.epoch_id,
        round: vote.round,
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
    }
}

#[test]
fn native_layout_write_check_prepared_and_staged_are_durable_and_monotone() {
    let dir = native_dir();
    let output = process(&floor_args(dir.path(), 3));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "status = vote_floor_ready head_epoch = 7 round = 3\n"
    );
    assert_eq!(fs::read(dir.path().join("vote_log/floor")).unwrap(), b"7\n");
    let before = files(dir.path());
    for kind in ["--check", "--prepared", "--staged"] {
        let mut args = floor_args(dir.path(), 3);
        args.push("--check".into());
        if kind != "--check" {
            args.push(kind.into());
        }
        let output = process(&args);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "status = vote_floor_checked head_epoch = 7 round = 3\n"
        );
        assert_eq!(files(dir.path()), before);
    }
    let mut args = floor_args(dir.path(), 2);
    args.extend(["--check".into(), "--prepared".into()]);
    let output = process(&args);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("vote floor round does not match staged round"));
    assert_eq!(files(dir.path()), before);
}

#[test]
fn authenticated_pending_vote_is_recovered_and_invalid_signature_cannot_write() {
    for tampered in [false, true] {
        let dir = native_dir();
        let mut signed = vote(9, 3);
        if tampered {
            signed.signature[0] ^= 1;
        }
        let journal = JournalOwner::open(dir.path()).unwrap();
        journal.keep_pending(&pending(&signed)).unwrap();
        drop(journal);
        let before = files(dir.path());
        let output = process(&floor_args(dir.path(), 1));
        if tampered {
            assert_eq!(output.status.code(), Some(1));
            assert!(stderr(&output).contains("pending vote signature is invalid"));
            assert_eq!(files(dir.path()), before);
        } else {
            assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
            assert_eq!(
                stdout(&output),
                "status = vote_floor_ready head_epoch = 7 round = 9\n"
            );
            let owner = JournalOwner::open(dir.path()).unwrap();
            assert_eq!(owner.find_vote(&signed).unwrap(), Some(signed));
            assert_eq!(owner.floor().unwrap(), Some(7));
        }
    }
}

#[test]
fn conflicting_durable_vote_and_future_wal_refuse_without_floor_changes() {
    for future in [false, true] {
        let dir = native_dir();
        let owner = JournalOwner::open(dir.path()).unwrap();
        owner.keep_vote(vote(3, 1)).unwrap();
        let mut row = pending(&vote(3, 2));
        if future {
            row.epoch_id = 9;
        }
        owner.keep_pending(&row).unwrap();
        drop(owner);
        let before = files(dir.path());
        let output = process(&floor_args(dir.path(), 0));
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(if future {
            "pending consensus vote exceeds current epoch"
        } else {
            "local vote conflicts with stored vote"
        }));
        assert_eq!(files(dir.path()), before);
    }
}

#[test]
fn both_native_store_inode_and_rust_journal_owner_exclude_live_writers() {
    let dir = native_dir();
    let file = fs::File::open(dir.path().join("chaindata")).unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let before = files(dir.path());
    let output = process(&floor_args(dir.path(), 0));
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(files(dir.path()), before);
    drop(file);
    let owner = JournalOwner::open(dir.path()).unwrap();
    let output = process(&floor_args(dir.path(), 0));
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("validator journal is already owned"));
    assert_eq!(files(dir.path()), before);
    drop(owner);
    assert!(process(&floor_args(dir.path(), 0)).status.success());
}

#[test]
fn exact_round_sync_signature_chain_and_request_are_authenticated() {
    let dir = native_dir();
    for variant in ["good", "signature", "chain", "epoch", "request"] {
        let mut sync = RoundSync {
            chain_id: b"offline-chain".to_vec(),
            epoch_id: 8,
            round: 4,
            step: RoundStep::Precommit,
            request: false,
            validator: address().into_bytes(),
            signature: vec![],
        };
        match variant {
            "chain" => sync.chain_id = b"other".to_vec(),
            "epoch" => sync.epoch_id = 9,
            "request" => sync.request = true,
            _ => (),
        }
        sync.signature = key()
            .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
            .to_bytes()
            .to_vec();
        if variant == "signature" {
            sync.signature[0] ^= 1;
        }
        let mut args = floor_args(dir.path(), 0);
        args.truncate(args.len() - 2);
        args.extend([
            "--round-sync".into(),
            STANDARD.encode(sync.encode().unwrap()),
            "--round-min".into(),
            "6".into(),
            "--check".into(),
        ]);
        let before = files(dir.path());
        let output = process(&args);
        assert_eq!(
            output.status.code(),
            Some(i32::from(variant != "good")),
            "{}",
            stderr(&output)
        );
        if variant == "good" {
            assert_eq!(
                stdout(&output),
                "status = vote_floor_checked head_epoch = 7 round = 6\n"
            );
        }
        assert_eq!(files(dir.path()), before);
    }
}

async fn checkpoint_fixture(database: &Path) {
    use sqlx::Connection;

    // Finish fixture-owned WAL writes before comparing the diagnostic's bytes.
    let mut connection = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(database)
            .create_if_missing(false)
            .busy_timeout(Duration::from_secs(10)),
    )
    .await
    .unwrap();
    let (busy, log, checkpointed): (i64, i64, i64) =
        sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    assert_eq!(
        (busy, log, checkpointed),
        (0, 0, 0),
        "fixture WAL checkpoint must finish before the byte baseline"
    );
    connection.close().await.unwrap();
}

async fn canonical(path: &Path, ciphers: &[Option<&[u8]>]) {
    let mut state = StateBatch::default();
    state.begin().unwrap();
    for (id, cipher) in ciphers.iter().enumerate() {
        let address = format!("private-account-{id}");
        let account = Account {
            encrypted_balance: cipher.map(<[u8]>::to_vec),
            ..Account::default()
        };
        state
            .set(
                &[b"accounts", address.as_bytes(), b"data"],
                account.to_json_bytes(),
            )
            .unwrap();
    }
    let (_, index) =
        epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
            .unwrap();
    let root = epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap();
    let store = CanonicalStore::create(
        &path.join("canonical.sqlite"),
        ChainIdentity::genesis("offline-chain", StateRoot(root)),
        state.snapshot(),
        0,
    )
    .await
    .unwrap();
    checkpoint_fixture(&path.join("canonical.sqlite")).await;
    store.close().await;
}
#[tokio::test]
async fn canonical_checks_and_fhe_classification_are_readonly_and_do_not_log_private_data() {
    let dir = tempfile::tempdir().unwrap();
    canonical(
        dir.path(),
        &[
            None,
            Some(b"0"),
            Some(b"hfhe_v1|opaque-private-cipher"),
            Some(b"unsupported-secret"),
        ],
    )
    .await;
    let database = dir.path().join("canonical.sqlite");
    let before = fs::read(&database).unwrap();
    let output = process(&[
        "check_store".into(),
        dir.path().display().to_string(),
        "--canonical".into(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output)
        .contains("action = stay epoch = 0 readonly = true backend = canonical_sqlite"));
    let output = process(&[
        "fhe_audit".into(),
        dir.path().display().to_string(),
        "--canonical".into(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let body = stdout(&output);
    assert!(body.contains("accounts = 4 rejected = 0 loader_clears = 1 loader_refuses = 1"));
    assert!(body.contains("result = needs_review"));
    for secret in [
        "private-account-",
        "opaque-private-cipher",
        "unsupported-secret",
    ] {
        assert!(!body.contains(secret));
    }
    assert_eq!(fs::read(database).unwrap(), before);
}
#[tokio::test]
async fn canonical_floor_uses_the_same_plan_and_refuses_a_different_chain() {
    let dir = tempfile::tempdir().unwrap();
    canonical(dir.path(), &[None]).await;
    let mut args = floor_args(dir.path(), 2);
    let epoch = args.iter().position(|arg| arg == "--head-epoch").unwrap() + 1;
    args[epoch] = "0".into();
    args.push("--canonical".into());
    let database = fs::read(dir.path().join("canonical.sqlite")).unwrap();
    let output = process(&args);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "status = vote_floor_ready head_epoch = 0 round = 2\n"
    );
    let owner = JournalOwner::open(dir.path()).unwrap();
    assert_eq!(owner.floor().unwrap(), Some(0));
    assert_eq!(owner.round_mark().unwrap().unwrap().epoch_id, 1);
    drop(owner);
    let chain = args.iter().position(|arg| arg == "--chain-id").unwrap() + 1;
    args[chain] = "another-chain".into();
    args.push("--check".into());
    let before = files(dir.path());
    let output = process(&args);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("vote floor chain does not match local canonical chain"));
    assert_eq!(files(dir.path()), before);
    assert_eq!(
        fs::read(dir.path().join("canonical.sqlite")).unwrap(),
        database
    );
}
#[tokio::test]
async fn canonical_bad_object_missing_schema_and_live_owner_are_not_repaired() {
    let dir = tempfile::tempdir().unwrap();
    canonical(dir.path(), &[None]).await;
    let database = dir.path().join("canonical.sqlite");
    let owner = octra_node::single::writer_lock(&database).unwrap();
    let before = fs::read(&database).unwrap();
    let args = vec![
        "check-store".into(),
        dir.path().display().to_string(),
        "--canonical".into(),
    ];
    assert!(!process(&args).status.success());
    assert_eq!(fs::read(&database).unwrap(), before);
    drop(owner);
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", database.display()))
        .await
        .unwrap();
    sqlx::query("UPDATE node_objects SET data=X'00' WHERE contents=1")
        .execute(&pool)
        .await
        .unwrap();
    checkpoint_fixture(&database).await;
    pool.close().await;
    let before = fs::read(&database).unwrap();
    assert!(!process(&args).status.success());
    assert_eq!(fs::read(&database).unwrap(), before);
    let empty = tempfile::tempdir().unwrap();
    fs::write(empty.path().join("canonical.sqlite"), []).unwrap();
    assert!(!process(&[
        "check-store".into(),
        empty.path().display().to_string(),
        "--canonical".into()
    ])
    .status
    .success());
    assert_eq!(
        fs::metadata(empty.path().join("canonical.sqlite"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn native_physical_reads_require_explicit_backend_identity_before_any_execution() {
    let dir = native_dir();
    fs::create_dir(dir.path().join("irmin_store")).unwrap();
    for command in ["check-store", "fhe-audit"] {
        let before = files(dir.path());
        let output = process(&[command.into(), dir.path().display().to_string()]);
        assert!(!output.status.success());
        assert_eq!(files(dir.path()), before);
    }
}

#[test]
fn native_negative_numeric_lexemes_reach_semantic_refusal_without_storage_changes() {
    let dir = native_dir();
    let before = files(dir.path());
    for (flag, reason) in [
        ("--head-epoch", "vote floor epoch is invalid"),
        ("--round", "vote floor round is invalid"),
        ("--round-min", "round minimum is invalid"),
    ] {
        let mut args = floor_args(dir.path(), 0);
        if let Some(index) = args.iter().position(|value| value == flag) {
            args[index + 1] = "-1".into();
        } else {
            args.extend([flag.into(), "-1".into()]);
        }
        let output = process(&args);
        assert_eq!(output.status.code(), Some(1), "{flag}: {}", stderr(&output));
        assert_eq!(
            stderr(&output),
            format!("status = refused reason = {reason}\n")
        );
        assert_eq!(files(dir.path()), before);
    }
}

#[tokio::test]
async fn native_literal_hyphen_values_preserve_effective_inputs_and_semantic_refusals() {
    let cwd = tempfile::tempdir().unwrap();
    let dir = native_dir();
    let before = files(dir.path());
    for (flag, value, reason) in [
        (
            "--data-dir",
            "-missing-native-store",
            "vote floor round is invalid",
        ),
        (
            "--validator",
            "-native-validator",
            "validator public key does not match address",
        ),
        (
            "--validator-pub",
            "-native-public",
            "vote floor arguments are invalid",
        ),
        (
            "--round-sync",
            "-native-sync",
            "round sync base64 decode failed",
        ),
    ] {
        let mut args = floor_args(dir.path(), 3);
        if flag == "--round-sync" {
            args.truncate(args.len() - 2);
            args.extend([flag.into(), value.into()]);
        } else {
            let index = args.iter().position(|arg| arg == flag).unwrap() + 1;
            args[index] = value.into();
        }
        if flag == "--data-dir" {
            let index = args.iter().position(|arg| arg == "--round").unwrap() + 1;
            args[index] = "-1".into();
        }
        args.push("--check".into());
        let output = process_from(&args, Some(cwd.path()));
        assert_eq!(output.status.code(), Some(1), "{flag}: {}", stderr(&output));
        let error = stderr(&output);
        assert!(
            error.starts_with(&format!("status = refused reason = {reason}")),
            "{flag}: {error}"
        );
        assert!(!error.contains("unexpected argument"));
        assert_eq!(files(dir.path()), before);
        assert!(!cwd.path().join("-missing-native-store").exists());
    }
    // A hyphen-leading chain ID remains the actual signed RoundSync identity.
    let mut sync = RoundSync {
        chain_id: b"-native-chain".to_vec(),
        epoch_id: 8,
        round: 4,
        step: RoundStep::Precommit,
        request: false,
        validator: address().into_bytes(),
        signature: vec![],
    };
    sync.signature = key()
        .sign(&hash::round_sync_sign_bytes(&sync).unwrap())
        .to_bytes()
        .to_vec();
    let mut args = floor_args(dir.path(), 0);
    args.truncate(args.len() - 2);
    let index = args.iter().position(|arg| arg == "--chain-id").unwrap() + 1;
    args[index] = "-native-chain".into();
    args.extend([
        "--round-sync".into(),
        STANDARD.encode(sync.encode().unwrap()),
        "--check".into(),
    ]);
    let output = process_from(&args, Some(cwd.path()));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "status = vote_floor_checked head_epoch = 7 round = 4\n"
    );
    assert_eq!(files(dir.path()), before);
    // Both native positional forms consume a literal path before host options.
    let path = cwd.path().join("-native-store");
    fs::create_dir(&path).unwrap();
    canonical(&path, &[None]).await;
    let database = fs::read(path.join("canonical.sqlite")).unwrap();
    for command in ["check_store", "fhe_audit"] {
        let output = process_from(
            &[command.into(), "-native-store".into(), "--canonical".into()],
            Some(cwd.path()),
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command}: {}",
            stderr(&output)
        );
        assert!(stdout(&output).contains(if command == "check_store" {
            "store_check status = verified"
        } else {
            "result = storage_readable"
        }));
        assert_eq!(fs::read(path.join("canonical.sqlite")).unwrap(), database);
    }
}
