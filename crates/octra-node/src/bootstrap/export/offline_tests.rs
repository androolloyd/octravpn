//! Real snapshot files/signatures through the public snapshot command grammar.
//! Parent fixture supplies signed finalized history; transaction execution is not
//! the subject of these offline administration tests.
use super::*;
use crate::bootstrap::export::{codec, Commands};
use clap::Parser;
use std::{ffi::OsString, os::unix::fs::PermissionsExt};

#[derive(Parser)]
struct SnapshotCli {
    #[command(subcommand)]
    command: Commands,
}
struct Input {
    current_finality: Vec<u8>,
    current_root: [u8; 32],
    config: PathBuf,
    source: PathBuf,
    canonical: PathBuf,
    validator: PathBuf,
    exporter: PathBuf,
    network: bootstrap::Network,
    limits: Limits,
}
fn wallet(path: &Path, key: &SigningKey) {
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let address = octra_node_protocol::transaction::address_from_public_key(public.as_bytes());
    let raw = serde_json::to_vec(&serde_json::json!({
        "address":String::from_utf8(address).unwrap(),"pub":public,
        "priv":STANDARD.encode(key.to_bytes())
    }))
    .unwrap();
    fs::write(path, raw).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn copy(from: &Path, to: &Path) {
    fs::create_dir(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy(&entry.path(), &destination);
        } else {
            assert!(entry.file_type().unwrap().is_file());
            fs::copy(entry.path(), &destination).unwrap();
            fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}
async fn input(root: &Path) -> Input {
    input_with_transition(root, false).await
}
async fn input_with_transition(root: &Path, transition: bool) -> Input {
    let canonical = root.join("canonical");
    fs::create_dir(&canonical).unwrap();
    let epoch = if transition { 67 } else { 66 };
    let (node, configured, exporter) = fixture_inner(&canonical, epoch, transition).await;
    let archive = archive::Archive::open(&configured).unwrap();
    let id = publish_at(&node, &configured, &archive, &exporter, epoch - 1).await;
    let source = root.join("portable");
    copy(&archive.path(&id).unwrap(), &source);
    drop(archive);
    let config = root.join("trusted-config.json");
    fs::write(
        &config,
        serde_json::to_vec(&bootstrap::Config {
            network: configured.network.clone(),
            sources: Vec::new(),
            allow_private_http: false,
            max_bytes: configured.limits.bytes,
            max_records: configured.limits.records,
            max_string_bytes: configured.limits.string_bytes,
        })
        .unwrap(),
    )
    .unwrap();
    let validator = root.join("validator-wallet.json");
    wallet(&validator, &key(1));
    let exporter_path = root.join("exporter-wallet.json");
    wallet(&exporter_path, &exporter);
    let current_root = node.store.head().await.unwrap().cursor.state_root.0;
    let authority = bootstrap::Authority::new(configured.network.clone()).unwrap();
    let current_finality = chain::finality(&node, &authority, epoch)
        .await
        .unwrap()
        .unwrap();
    let current_finality = octra_node_protocol::state_sync::anchor::Anchor {
        steps: Vec::new(),
        finalize: current_finality.finalize,
        validator_set: current_finality.validator_set,
    }
    .encode()
    .unwrap();
    let store = node.store.clone();
    drop(node);
    // Offline administration must not retain the fixture's real live writer.
    Arc::try_unwrap(store)
        .unwrap_or_else(|_| panic!("fixture store owners survived"))
        .close()
        .await;
    Input {
        current_finality,
        current_root,
        config,
        source,
        canonical,
        validator,
        exporter: exporter_path,
        network: configured.network,
        limits: configured.limits,
    }
}
fn flags(pairs: &[(&str, &Path)]) -> Vec<OsString> {
    pairs
        .iter()
        .flat_map(|(flag, path)| [OsString::from(flag), path.as_os_str().to_os_string()])
        .collect()
}
async fn invoke(
    input: &Input,
    action: &str,
    source: Option<&Path>,
    extra: Vec<OsString>,
) -> Result<()> {
    let mut args = vec![
        OsString::from("snapshot-test"),
        OsString::from(action),
        OsString::from("--config"),
        input.config.as_os_str().to_os_string(),
    ];
    if let Some(source) = source {
        args.extend([
            OsString::from("--source"),
            source.as_os_str().to_os_string(),
        ]);
    }
    args.extend(extra);
    let parsed = SnapshotCli::try_parse_from(args)?;
    parsed
        .command
        .run(tokio::sync::watch::channel(false).1)
        .await
}
fn body(path: &Path) -> octra_node_protocol::state_sync::manifest::Draft {
    codec::parse_draft(&fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn portable_cli_build_sign_and_finalized_verify_use_exact_native_domains() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    invoke(&input, "seal", Some(&input.source), vec![])
        .await
        .unwrap();
    let draft = root.path().join("new-draft.json");
    invoke(
        &input,
        "build",
        Some(&input.source),
        flags(&[("--output", &draft)]),
    )
    .await
    .unwrap();
    let checkpoint = root.path().join("checkpoint-signature.json");
    invoke(
        &input,
        "sign-checkpoint",
        Some(&input.source),
        flags(&[
            ("--draft", &draft),
            ("--wallet", &input.validator),
            ("--output", &checkpoint),
        ]),
    )
    .await
    .unwrap();
    let manifest = root.path().join("manifest-signature.json");
    invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[
            ("--draft", &draft),
            ("--wallet", &input.exporter),
            ("--output", &manifest),
        ]),
    )
    .await
    .unwrap();
    let authority = bootstrap::Authority::new(input.network.clone()).unwrap();
    let signed = body(&draft);
    let signature = codec::signatures(&fs::read(checkpoint).unwrap()).unwrap();
    octra_node_protocol::state_sync::checkpoint::verify_signature(
        authority.trust().validators,
        &signed.checkpoint.hash().unwrap(),
        &signature[0],
    )
    .unwrap();
    let exporter = codec::signatures(&fs::read(&manifest).unwrap()).unwrap();
    octra_node_protocol::state_sync::manifest::verify_exporters(
        authority.trust().exporters,
        1,
        &signed.manifest.hash().unwrap(),
        &exporter,
    )
    .unwrap();
    let certificate = root.path().join("certificate.json");
    invoke(
        &input,
        "assemble-finalized",
        Some(&input.source),
        flags(&[
            ("--draft", &draft),
            ("--finality", &input.source.join("snapshot.finality")),
            ("--exporter-signature", &manifest),
            ("--output", &certificate),
        ]),
    )
    .await
    .unwrap();
    invoke(
        &input,
        "verify",
        Some(&input.source),
        flags(&[("--certificate", &certificate)]),
    )
    .await
    .unwrap();
    assert_eq!(
        authority
            .trust()
            .verify(&fs::read(certificate).unwrap(), now().unwrap())
            .unwrap()
            .draft(),
        &signed
    );
}

#[tokio::test]
async fn portable_signing_refuses_corruption_wrong_role_and_output_replacement() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    invoke(&input, "seal", Some(&input.source), vec![])
        .await
        .unwrap();
    let wrong = root.path().join("wrong-wallet.json");
    wallet(&wrong, &key(8));
    let output = root.path().join("signature.json");
    assert!(invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &wrong), ("--output", &output)])
    )
    .await
    .is_err());
    assert!(!output.exists());
    let wallet_before = fs::read(&input.exporter).unwrap();
    invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &input.exporter), ("--output", &output)]),
    )
    .await
    .unwrap();
    let before = fs::read(&output).unwrap();
    assert!(invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &input.exporter), ("--output", &output)])
    )
    .await
    .is_err());
    assert_eq!(fs::read(&output).unwrap(), before);
    assert_eq!(fs::read(&input.exporter).unwrap(), wallet_before);
    let ledger = input.source.join("ledger.dat");
    let saved = fs::read(&ledger).unwrap();
    fs::write(&ledger, b"corrupt").unwrap();
    let refused = root.path().join("refused.json");
    assert!(invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &input.exporter), ("--output", &refused)])
    )
    .await
    .is_err());
    assert!(!refused.exists());
    fs::write(ledger, saved).unwrap();
    fs::write(input.source.join("pvac/unlisted"), b"unexpected input").unwrap();
    assert!(invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &input.exporter), ("--output", &refused)])
    )
    .await
    .is_err());
    assert!(!refused.exists());
}

#[tokio::test]
async fn build_refuses_missing_or_mismatched_ready_marker_without_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    let output = root.path().join("draft.json");
    let marker = input.source.join(".ready.json");
    let archived = fs::read(&marker).unwrap();
    assert_eq!(archived, fs::read(input.source.join("HEAD.json")).unwrap());
    invoke(&input, "seal", Some(&input.source), vec![])
        .await
        .unwrap();
    assert_eq!(
        fs::read(&marker).unwrap(),
        archived,
        "valid archive marker must remain byte-identical"
    );
    let head: serde_json::Value = serde_json::from_slice(&archived).unwrap();
    let mut mismatched = head.clone();
    mismatched["commit_id"] = serde_json::json!("different archived head");
    let mut extra = head.clone();
    extra["unknown_ready_field"] = serde_json::json!(true);
    let duplicate = {
        let mut raw = archived.clone();
        let last = raw.iter().rposition(|byte| *byte == b'}').unwrap();
        raw.splice(last..last, b",\"epoch_id\":65".iter().copied());
        raw
    };
    for invalid in [
        serde_json::to_vec(&mismatched).unwrap(),
        serde_json::to_vec(&extra).unwrap(),
        duplicate,
    ] {
        fs::write(&marker, &invalid).unwrap();
        assert!(invoke(&input, "seal", Some(&input.source), vec![])
            .await
            .is_err());
        assert_eq!(
            fs::read(&marker).unwrap(),
            invalid,
            "invalid marker must not be replaced or ignored"
        );
        assert!(invoke(
            &input,
            "build",
            Some(&input.source),
            flags(&[("--output", &output)])
        )
        .await
        .is_err());
        assert!(!output.exists());
    }
    // Construct an actually unsealed PRIVATE test copy. The original published
    // archive and every malformed marker above remain untouched by production.
    fs::write(&marker, &archived).unwrap();
    fs::remove_file(&marker).unwrap();
    assert!(invoke(
        &input,
        "build",
        Some(&input.source),
        flags(&[("--output", &output)])
    )
    .await
    .is_err());
    assert!(!output.exists());
    invoke(&input, "seal", Some(&input.source), vec![])
        .await
        .unwrap();
    let marker = input.source.join(".ready.json");
    let saved = fs::read(&marker).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    changed["commit_id"] = serde_json::json!("wrong commit");
    fs::write(&marker, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(invoke(
        &input,
        "build",
        Some(&input.source),
        flags(&[("--output", &output)])
    )
    .await
    .is_err());
    assert!(!output.exists());
    fs::write(marker, saved).unwrap();
    for (flag, reason) in [
        ("--chunk-size", "invalid chunk size"),
        ("--validity", "validity must be"),
    ] {
        let mut args = flags(&[("--output", &output)]);
        args.extend([OsString::from(flag), OsString::from("-1")]);
        let error = invoke(&input, "build", Some(&input.source), args)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(reason), "{error}");
        assert!(!output.exists());
    }
    fs::write(&output, b"retained output").unwrap();
    assert!(invoke(
        &input,
        "build",
        Some(&input.source),
        flags(&[("--output", &output)])
    )
    .await
    .is_err());
    assert_eq!(fs::read(output).unwrap(), b"retained output");
}

#[test]
fn snapshot_numeric_flags_accept_native_base_and_negative_lexemes() {
    let parse = |values: &[&str]| {
        SnapshotCli::try_parse_from(std::iter::once("snapshot-test").chain(values.iter().copied()))
    };
    let parsed = parse(&["build", "--chunk-size", "0x10_0000", "--validity", "0x10"]).unwrap();
    let Commands::Build(options) = parsed.command else {
        panic!("wrong parsed command")
    };
    assert_eq!(options.chunk_size, 1_048_576);
    assert_eq!(options.validity, 16);
    let parsed = parse(&["build", "--chunk-size", "-1", "--validity", "-0x1"]).unwrap();
    let Commands::Build(options) = parsed.command else {
        panic!("wrong parsed command")
    };
    assert_eq!(options.chunk_size, -1);
    assert_eq!(options.validity, -1);
    assert!(parse(&["build", "--chunk-size", "4611686018427387904"]).is_err());
    assert!(parse(&["build", "--validity", "9223372036854775808"]).is_err());
}

#[tokio::test]
async fn canonical_checkpoint_requires_current_head_or_explicit_history_and_keeps_wallet() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    let output = root.path().join("historical-signature.json");
    let mut flags = flags(&[
        ("--draft", &input.source.join("snapshot.draft.json")),
        ("--finality", &input.source.join("snapshot.finality")),
        ("--wallet", &input.validator),
        ("--output", &output),
    ]);
    let before = fs::read(&input.validator).unwrap();
    assert!(invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        flags.clone()
    )
    .await
    .is_err());
    assert!(!output.exists());
    flags.push(OsString::from("--historical"));
    invoke(&input, "sign-checkpoint", Some(&input.canonical), flags)
        .await
        .unwrap();
    assert_eq!(fs::read(&input.validator).unwrap(), before);
    let signature = codec::signatures(&fs::read(output).unwrap()).unwrap();
    let authority = bootstrap::Authority::new(input.network).unwrap();
    let draft = body(&input.source.join("snapshot.draft.json"));
    octra_node_protocol::state_sync::checkpoint::verify_signature(
        authority.trust().validators,
        &draft.checkpoint.hash().unwrap(),
        &signature[0],
    )
    .unwrap();
}

#[tokio::test]
async fn canonical_seal_captures_current_finality_and_refuses_writer_conflict_or_old_head() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    let authority = bootstrap::Authority::new(input.network.clone()).unwrap();
    let finality_path = root.path().join("current-finality.txt");
    fs::write(&finality_path, &input.current_finality).unwrap();
    let output = root.path().join("canonical-export");
    let args = flags(&[("--finality", &finality_path), ("--output", &output)]);
    let lease = crate::single::writer_lock(&input.canonical.join("canonical.sqlite")).unwrap();
    assert!(invoke(&input, "seal", Some(&input.canonical), args.clone())
        .await
        .is_err());
    assert!(!output.exists());
    drop(lease);
    let old = fs::read(input.source.join("snapshot.finality")).unwrap();
    fs::write(&finality_path, &old).unwrap();
    assert!(invoke(&input, "seal", Some(&input.canonical), args.clone())
        .await
        .is_err());
    assert!(!output.exists());
    fs::write(&finality_path, &input.current_finality).unwrap();
    let original = fs::read(input.canonical.join("canonical.sqlite")).unwrap();
    invoke(&input, "seal", Some(&input.canonical), args)
        .await
        .unwrap();
    assert_eq!(
        fs::read(input.canonical.join("canonical.sqlite")).unwrap(),
        original
    );
    assert!(output.join(".ready.json").is_file());
    let draft_path = output.join("snapshot.draft.json");
    let captured = body(&draft_path);
    assert_eq!(captured.checkpoint.epoch, 66);
    assert_eq!(
        captured.checkpoint.state_root,
        hex::encode(input.current_root).as_bytes()
    );
    let signature_path = root.path().join("current-checkpoint-signature.json");
    invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        flags(&[
            ("--draft", &draft_path),
            ("--finality", &finality_path),
            ("--wallet", &input.validator),
            ("--output", &signature_path),
        ]),
    )
    .await
    .unwrap();
    let signature = codec::signatures(&fs::read(signature_path).unwrap()).unwrap();
    octra_node_protocol::state_sync::checkpoint::verify_signature(
        authority.trust().validators,
        &captured.checkpoint.hash().unwrap(),
        &signature[0],
    )
    .unwrap();
    assert_eq!(
        fs::read(input.canonical.join("canonical.sqlite")).unwrap(),
        original
    );
}

fn rebound(draft: &mut octra_node_protocol::state_sync::manifest::Draft) {
    draft.checkpoint_hash = hex::encode(draft.checkpoint.hash().unwrap()).into_bytes();
    draft.manifest.checkpoint_hash = draft.checkpoint_hash.clone();
    draft.manifest.snapshot_id = draft.checkpoint_hash.clone();
    draft.manifest_hash = hex::encode(draft.manifest.hash().unwrap()).into_bytes();
}

#[tokio::test]
async fn canonical_signing_authenticates_transition_and_refuses_arbitrary_role_selection() {
    use octra_node_protocol::state_sync::anchor;
    let root = tempfile::tempdir().unwrap();
    let input = input_with_transition(root.path(), true).await;
    let draft_path = input.source.join("snapshot.draft.json");
    let finality_path = input.source.join("snapshot.finality");
    let active_wallet = root.path().join("active-wallet.json");
    wallet(&active_wallet, &key(2));
    let output = root.path().join("transition-signature.json");
    let mut args = flags(&[
        ("--draft", &draft_path),
        ("--finality", &finality_path),
        ("--wallet", &active_wallet),
        ("--output", &output),
    ]);
    args.push("--historical".into());
    invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        args.clone(),
    )
    .await
    .unwrap();
    let trusted = bootstrap::Authority::new(input.network.clone()).unwrap();
    let draft = body(&draft_path);
    let verified = anchor::verify(
        trusted.trust().validators,
        &draft.checkpoint,
        &fs::read(&finality_path).unwrap(),
    )
    .unwrap();
    let active = anchor::encoded_validator_set(&verified.anchor().validator_set).unwrap();
    assert_ne!(active.validators, trusted.trust().validators.validators);
    let signature = codec::signatures(&fs::read(&output).unwrap()).unwrap();
    octra_node_protocol::state_sync::checkpoint::verify_signature(
        &active,
        &draft.checkpoint.hash().unwrap(),
        &signature[0],
    )
    .unwrap();
    fs::remove_file(&output).unwrap();
    let mut forged_args = args.clone();
    for entry in &input.network.validators {
        forged_args.extend([OsString::from("--validator"), OsString::from(entry)]);
    }
    let error = invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        forged_args,
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("selected signer roles differ"),
        "{error}"
    );
    assert!(!output.exists());
    let wrong_wallet_args = args
        .iter()
        .map(|arg| {
            if arg.as_os_str() == active_wallet.as_os_str() {
                input.validator.as_os_str().to_os_string()
            } else {
                arg.clone()
            }
        })
        .collect();
    assert!(invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        wrong_wallet_args
    )
    .await
    .is_err());
    assert!(!output.exists());
}

#[tokio::test]
async fn canonical_signing_refuses_shape_valid_stored_bad_qc_wrong_anchor_and_missing_authority() {
    use octra_node_protocol::state_sync::anchor;
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    let original_path = input.source.join("snapshot.draft.json");
    let original_finality = input.source.join("snapshot.finality");
    let output = root.path().join("must-not-sign.json");
    let mut base = flags(&[
        ("--draft", &original_path),
        ("--wallet", &input.validator),
        ("--output", &output),
    ]);
    base.push("--historical".into());
    let missing = invoke(
        &input,
        "sign-checkpoint",
        Some(&input.canonical),
        base.clone(),
    )
    .await
    .unwrap_err();
    assert!(
        missing.to_string().contains("--finality is required"),
        "{missing}"
    );
    let wrong_anchor_path = root.path().join("wrong-current-anchor");
    fs::write(&wrong_anchor_path, &input.current_finality).unwrap();
    let mut wrong = base.clone();
    wrong.extend(flags(&[("--finality", &wrong_anchor_path)]));
    assert!(
        invoke(&input, "sign-checkpoint", Some(&input.canonical), wrong)
            .await
            .is_err()
    );
    assert!(!output.exists());

    let forged_wallet = root.path().join("forged-role-wallet.json");
    wallet(&forged_wallet, &key(8));
    let public = STANDARD.encode(key(8).verifying_key().as_bytes());
    let address = String::from_utf8(octra_node_protocol::transaction::address_from_public_key(
        public.as_bytes(),
    ))
    .unwrap();
    let role = format!("{address}:{public}");
    let selected =
        octra_node_protocol::state_sync::manifest::signer_set(&[role.as_bytes().to_vec()]).unwrap();
    let raw = anchor::raw_validator_set(&selected).unwrap();
    let mut fake = body(&original_path);
    fake.checkpoint.validator_set_hash =
        hex::encode(octra_node_protocol::consensus::hash::validator_set_hash(&raw).unwrap())
            .into_bytes();
    rebound(&mut fake);
    let fake_path = root.path().join("forged-role-draft.json");
    fs::write(&fake_path, codec::draft(&fake).unwrap()).unwrap();
    let mut fake_args = flags(&[
        ("--draft", &fake_path),
        ("--finality", &original_finality),
        ("--wallet", &forged_wallet),
        ("--output", &output),
    ]);
    fake_args.extend([
        OsString::from("--historical"),
        OsString::from("--validator"),
        OsString::from(role),
    ]);
    let role_error = invoke(&input, "sign-checkpoint", Some(&input.canonical), fake_args)
        .await
        .unwrap_err();
    assert!(
        role_error
            .to_string()
            .contains("finality validator set mismatch"),
        "{role_error}"
    );
    assert!(!output.exists());

    let mut bad = anchor::Anchor::decode(&fs::read(&original_finality).unwrap()).unwrap();
    bad.finalize.precommits[0].signature = vec![0; 64];
    let wire = bad.finalize.encode().unwrap();
    // Keep every local header, index, ledger, transaction and signature shape
    // valid. Only the actual QC authentication has been invalidated.
    assert_eq!(Finalize::decode(&wire).unwrap().header, bad.finalize.header);
    let database = input.canonical.join("canonical.sqlite");
    let owner = crate::single::writer_lock(&database).unwrap();
    let journal =
        octra_node_protocol::consensus::journal::JournalOwner::open(&input.canonical).unwrap();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&database)
                .create_if_missing(false),
        )
        .await
        .unwrap();
    let original: Vec<u8> =
        sqlx::query_scalar("SELECT certificate FROM node_epochs WHERE sequence=65")
            .fetch_one(&pool)
            .await
            .unwrap();
    let modified = sqlx::query("UPDATE node_epochs SET certificate=? WHERE sequence=65")
        .bind(&wire)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(modified.rows_affected(), 1);
    pool.close().await;
    let inspected = octra_node_runtime::canonical::OfflineStore::open(&database)
        .await
        .unwrap();
    assert_eq!(
        inspected
            .certificate(octra_exex::Sequence(65))
            .await
            .unwrap(),
        wire
    );
    let stored = inspected
        .retained_head(octra_exex::Sequence(65))
        .await
        .unwrap();
    assert_eq!(
        stored.cursor.state_root.0.as_slice(),
        bad.finalize.header.proposed_state_root.as_slice()
    );
    inspected.close().await;
    drop(journal);
    drop(owner);

    let mut forged = body(&original_path);
    forged.checkpoint.quorum_cert_hash = Some(anchor::finalize_hash(&bad.finalize).unwrap());
    rebound(&mut forged);
    let bad_path = root.path().join("shape-valid-bad-qc-anchor");
    fs::write(&bad_path, bad.encode().unwrap()).unwrap();
    let draft_path = root.path().join("bad-qc-draft.json");
    fs::write(&draft_path, codec::draft(&forged).unwrap()).unwrap();
    let trusted = bootstrap::Authority::new(input.network.clone()).unwrap();
    assert!(anchor::verify(
        trusted.trust().validators,
        &forged.checkpoint,
        &fs::read(&bad_path).unwrap()
    )
    .is_err());
    let mut args = flags(&[
        ("--draft", &draft_path),
        ("--finality", &bad_path),
        ("--wallet", &input.validator),
        ("--output", &output),
    ]);
    args.push("--historical".into());
    assert!(
        invoke(&input, "sign-checkpoint", Some(&input.canonical), args)
            .await
            .is_err()
    );
    assert!(!output.exists());
    // Even a valid trusted anchor must exactly match the retained wire; a
    // matching locally committed root cannot mask the altered certificate.
    base.extend(flags(&[("--finality", &original_finality)]));
    let mismatch = invoke(&input, "sign-checkpoint", Some(&input.canonical), base)
        .await
        .unwrap_err();
    assert!(
        mismatch
            .to_string()
            .contains("differs from retained canonical certificate"),
        "{mismatch}"
    );
    assert!(!output.exists());
    // Retain the original bytes in the fixture's scope; no production store is
    // edited and no invalid-QC fixture is advertised as a finalized authority.
    assert_ne!(original, wire);
}

#[tokio::test]
async fn detached_native_signature_objects_feed_existing_assembler_and_quorum_envelope() {
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    invoke(&input, "seal", Some(&input.source), vec![])
        .await
        .unwrap();
    let mut signatures = Vec::new();
    for id in 1..=3 {
        let wallet_path = root.path().join(format!("validator-{id}.json"));
        wallet(&wallet_path, &key(id));
        let output = root.path().join(format!("signature-{id}.json"));
        invoke(
            &input,
            "sign-checkpoint",
            Some(&input.source),
            flags(&[("--wallet", &wallet_path), ("--output", &output)]),
        )
        .await
        .unwrap();
        signatures.push(output);
    }
    let exporter = root.path().join("exporter-signature.json");
    invoke(
        &input,
        "sign-manifest",
        Some(&input.source),
        flags(&[("--wallet", &input.exporter), ("--output", &exporter)]),
    )
    .await
    .unwrap();
    fs::remove_file(input.source.join("snapshot.certificate.json")).unwrap();
    let authority = bootstrap::Authority::new(input.network.clone()).unwrap();
    bootstrap::export::assemble(
        &authority,
        &input.source,
        bootstrap::export::Assemble {
            exporter_key: None,
            exporter_signatures: vec![exporter.clone()],
            checkpoint_signatures: signatures.clone(),
            limits: input.limits,
        },
    )
    .unwrap();
    invoke(
        &input,
        "verify",
        Some(&input.source),
        flags(&[(
            "--certificate",
            &input.source.join("snapshot.certificate.json"),
        )]),
    )
    .await
    .unwrap();
    // Native standalone quorum bodies bind encoded signer roles, unlike
    // finalized Anchor bodies which bind raw consensus public keys. Preserve
    // both exact encodings rather than changing or reinterpreting a body.
    let mut legacy = body(&input.source.join("snapshot.draft.json"));
    legacy.checkpoint.validator_set_hash =
        octra_node_protocol::state_sync::manifest::set_hash(authority.trust().validators).unwrap();
    legacy.checkpoint_hash = hex::encode(legacy.checkpoint.hash().unwrap()).into_bytes();
    legacy.manifest.checkpoint_hash = legacy.checkpoint_hash.clone();
    legacy.manifest.snapshot_id = legacy.checkpoint_hash.clone();
    legacy.manifest_hash = hex::encode(legacy.manifest.hash().unwrap()).into_bytes();
    let legacy_path = root.path().join("legacy-draft.json");
    fs::write(&legacy_path, codec::draft(&legacy).unwrap()).unwrap();
    let mut arguments = flags(&[("--draft", &legacy_path)]);
    for id in 1..=3 {
        let wallet = root.path().join(format!("validator-{id}.json"));
        let signature = crate::validator_cli::transaction::sign_message(
            &wallet,
            authority.trust().validators,
            &legacy.checkpoint.hash().unwrap(),
        )
        .unwrap();
        let output = root.path().join(format!("legacy-checkpoint-{id}.json"));
        fs::write(
            &output,
            serde_json::to_vec(&serde_json::json!({
            "signer":String::from_utf8(signature.signer).unwrap(),
            "signature":String::from_utf8(signature.signature).unwrap()}))
            .unwrap(),
        )
        .unwrap();
        arguments.extend(flags(&[("--checkpoint-signature", &output)]));
    }
    let signature = crate::validator_cli::transaction::sign_message(
        &input.exporter,
        authority.trust().exporters,
        &legacy.manifest.hash().unwrap(),
    )
    .unwrap();
    let exporter = root.path().join("legacy-exporter.json");
    fs::write(
        &exporter,
        serde_json::to_vec(&serde_json::json!({
        "signer":String::from_utf8(signature.signer).unwrap(),
        "signature":String::from_utf8(signature.signature).unwrap()}))
        .unwrap(),
    )
    .unwrap();
    let quorum = root.path().join("quorum-certificate.json");
    arguments.extend(flags(&[
        ("--exporter-signature", &exporter),
        ("--output", &quorum),
    ]));
    invoke(&input, "assemble-quorum", None, arguments)
        .await
        .unwrap();
    invoke(&input, "verify", None, flags(&[("--certificate", &quorum)]))
        .await
        .unwrap();
    assert!(
        authority
            .trust()
            .verify(&fs::read(quorum).unwrap(), now().unwrap())
            .is_err(),
        "offline legacy quorum envelope must not silently become reference bootstrap authority"
    );
}

#[tokio::test]
async fn native_physical_options_are_explicit_and_unknown_flags_are_not_forwarded() {
    assert!(SnapshotCli::try_parse_from([
        "snapshot-test",
        "seal",
        "--native-backend",
        "binding.json",
        "--source",
        "native-store",
        "--chain-id",
        "chain",
        "--config-hash",
        &"ab".repeat(32),
        "--validator",
        "address:public"
    ])
    .is_ok());
    assert!(
        SnapshotCli::try_parse_from(["snapshot-test", "verify", "--shell", "anything"]).is_err()
    );
    use crate::bootstrap::export::offline::{native_source_owner, Action, NativeSourceOwner};
    use crate::native_tools::NativeDirectoryOwner;
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let input = input(root.path()).await;
    let head_before = fs::read(input.source.join("HEAD.json")).unwrap();
    assert!(
        octra_node_protocol::state_sync::head::Head::parse(&head_before)
            .unwrap()
            .irmin_commit
            .is_some()
    );
    let ledger_before = fs::read(input.source.join("ledger.dat")).unwrap();
    let owner = native_source_owner(&input.source, Action::SignCheckpoint, false).unwrap();
    assert!(matches!(owner, NativeSourceOwner::Portable { .. }));
    assert!(NativeDirectoryOwner::acquire(&input.source).is_err());
    assert!(!input.source.join("validator_journal.lock").exists());
    drop(owner);
    drop(NativeDirectoryOwner::acquire(&input.source).unwrap());
    for (action, historical) in [
        (Action::SignCheckpoint, true),
        (Action::SignManifest, false),
        (Action::Seal, false),
        (Action::Build, false),
    ] {
        assert!(native_source_owner(&input.source, action, historical).is_err());
    }
    for name in ["chaindata", "irmin_store", "canonical.sqlite"] {
        let marker = input.source.join(name);
        symlink(root.path().join("missing-marker-target"), &marker).unwrap();
        assert!(native_source_owner(&input.source, Action::SignCheckpoint, false).is_err());
        fs::remove_file(marker).unwrap();
    }
    fs::create_dir(input.source.join("chaindata")).unwrap();
    fs::create_dir(input.source.join("irmin_store")).unwrap();
    let owner = native_source_owner(&input.source, Action::SignCheckpoint, false).unwrap();
    assert!(matches!(owner, NativeSourceOwner::Physical { .. }));
    assert!(NativeDirectoryOwner::acquire(&input.source.join("chaindata")).is_err());
    assert!(octra_node_protocol::consensus::journal::JournalOwner::open(&input.source).is_err());
    drop(owner);
    drop(NativeDirectoryOwner::acquire(&input.source.join("chaindata")).unwrap());
    drop(octra_node_protocol::consensus::journal::JournalOwner::open(&input.source).unwrap());
    assert_eq!(
        fs::read(input.source.join("HEAD.json")).unwrap(),
        head_before
    );
    assert_eq!(
        fs::read(input.source.join("ledger.dat")).unwrap(),
        ledger_before
    );
}
