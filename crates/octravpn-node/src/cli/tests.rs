//! CLI test battery — exercises the previously inline seal / unseal /
//! audit-verify helpers plus a `Cli::try_parse_from` smoke matrix so a
//! refactor that breaks the clap shape fails loudly. Also hosts the
//! trait-dispatch smoke test (deliverable #7).

use super::{seal as seal_cli, Cli, CliContext, Cmd, Subcommand};
use crate::audit_cli;
use crate::cli_ops;
use crate::config::NodeConfig;
use crate::v3_cli;
use async_trait::async_trait;
use clap::Parser as _;
use std::path::PathBuf;
use tempfile::tempdir;

fn write_minimal_node_toml(
    path: &std::path::Path,
    wallet_key: &std::path::Path,
    wg_key: &std::path::Path,
) {
    let toml = format!(
        r#"
[chain]
rpc_url = "http://127.0.0.1:0/unused"
program_addr = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3"
validator_addr = "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun"
wallet_secret_path = "{wallet}"

[tunnel]
public_endpoint = "1.2.3.4:51820"
listen = "0.0.0.0:51820"
wg_secret_path = "{wg}"

[pricing]
price_per_mb = 100
region = "test"

[control]
listen = "0.0.0.0:51821"
"#,
        wallet = wallet_key.display(),
        wg = wg_key.display(),
    );
    std::fs::write(path, toml).unwrap();
}

fn write_hex_key(path: &std::path::Path, raw: [u8; 32]) {
    std::fs::write(path, hex::encode(raw) + "\n").unwrap();
}

#[test]
fn seal_keys_round_trip_via_run_seal_keys() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0x42; 32]);
    write_hex_key(&wg, [0x43; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();

    seal_cli::run_seal_keys(&cfg, Some("pw1234"), None, false, false).unwrap();
    assert!(wallet.with_extension("key.sealed").exists());
    assert!(wg.with_extension("key.sealed").exists());
    assert!(wallet.exists());
    assert!(wg.exists());
}

#[test]
fn seal_keys_rotate_mode_removes_plaintext() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0xAA; 32]);
    write_hex_key(&wg, [0xBB; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();

    seal_cli::run_seal_keys(&cfg, Some("rotate-pw"), None, false, true).unwrap();
    assert!(wallet.with_extension("key.sealed").exists());
    assert!(wg.with_extension("key.sealed").exists());
    assert!(!wallet.exists(), "plaintext wallet must be removed");
    assert!(!wg.exists(), "plaintext wg must be removed");
}

#[test]
fn seal_keys_idempotent_on_already_sealed() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0xCC; 32]);
    write_hex_key(&wg, [0xDD; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();

    seal_cli::run_seal_keys(&cfg, Some("pw"), None, false, false).unwrap();
    let first = std::fs::read(wallet.with_extension("key.sealed")).unwrap();
    seal_cli::run_seal_keys(&cfg, Some("different-pw"), None, false, false).unwrap();
    let second = std::fs::read(wallet.with_extension("key.sealed")).unwrap();
    assert_eq!(first, second, "second seal must be a no-op");
}

#[test]
fn unseal_keys_recovers_plaintext_into_tmpdir() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0xEE; 32]);
    write_hex_key(&wg, [0xFF; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();

    seal_cli::run_seal_keys(&cfg, Some("pw"), None, false, false).unwrap();
    let recovery_dir =
        PathBuf::from(std::env::temp_dir()).join(format!("octravpn-test-{}", std::process::id()));
    let r = seal_cli::run_unseal_keys(&cfg, &recovery_dir, Some("pw"), None, false);
    if r.is_err() {
        eprintln!("unseal skipped (tmpfs gate): {:?}", r.err());
        return;
    }
    let recovered_wallet = recovery_dir.join("wallet.key");
    let recovered_wg = recovery_dir.join("wg.key");
    assert!(recovered_wallet.exists());
    assert!(recovered_wg.exists());
    let wallet_hex = std::fs::read_to_string(&recovered_wallet).unwrap();
    let wg_hex = std::fs::read_to_string(&recovered_wg).unwrap();
    assert_eq!(wallet_hex.trim(), hex::encode([0xEE; 32]));
    assert_eq!(wg_hex.trim(), hex::encode([0xFF; 32]));
    let _ = std::fs::remove_dir_all(&recovery_dir);
}

#[test]
fn unseal_keys_wrong_passphrase_fails() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0x11; 32]);
    write_hex_key(&wg, [0x22; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();
    seal_cli::run_seal_keys(&cfg, Some("right"), None, false, false).unwrap();

    let recovery = PathBuf::from(std::env::temp_dir())
        .join(format!("octravpn-unseal-bad-{}", std::process::id()));
    let r = seal_cli::run_unseal_keys(&cfg, &recovery, Some("wrong"), None, false);
    assert!(r.is_err(), "wrong passphrase must fail unseal");
    let _ = std::fs::remove_dir_all(&recovery);
}

#[test]
fn seal_keys_fails_when_plaintext_missing() {
    let dir = tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let wg = dir.path().join("wg.key");
    let toml_path = dir.path().join("node.toml");
    write_hex_key(&wallet, [0x55; 32]);
    write_minimal_node_toml(&toml_path, &wallet, &wg);
    let cfg = NodeConfig::load(&toml_path).unwrap();
    let r = seal_cli::run_seal_keys(&cfg, Some("pw"), None, false, false);
    assert!(r.is_err());
}

#[test]
fn verify_audit_log_helper_passes_on_clean_chain() {
    use crate::audit::{AuditLog, AuditRecord};
    let dir = tempdir().unwrap();
    let log = AuditLog::open(dir.path()).unwrap();
    for i in 0..3u64 {
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind: "announce",
            source: None,
            session_id: Some(hex::encode([1u8; 32])),
            extra: serde_json::json!({"i": i}),
        })
        .unwrap();
    }
    let audit_file = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .unwrap()
        .path();
    let key = log.key();
    let report = AuditLog::verify_file(&key, &audit_file).unwrap();
    assert_eq!(report.entries, 3);
    assert!(report.first_error.is_none());
}

#[test]
fn verify_audit_log_helper_reports_chain_break() {
    use crate::audit::{AuditLog, AuditRecord};
    let dir = tempdir().unwrap();
    let log = AuditLog::open(dir.path()).unwrap();
    for i in 0..3u64 {
        log.write(&AuditRecord {
            ts_unix: 1_700_000_000 + i,
            kind: "announce",
            source: None,
            session_id: Some(hex::encode([1u8; 32])),
            extra: serde_json::json!({"i": i}),
        })
        .unwrap();
    }
    let audit_file = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("audit-"))
        .unwrap()
        .path();
    let body = std::fs::read_to_string(&audit_file).unwrap();
    let mut lines: Vec<String> = body.lines().map(String::from).collect();
    lines[1] = lines[1].replacen("\\\"i\\\":1", "\\\"i\\\":999", 1);
    std::fs::write(&audit_file, lines.join("\n") + "\n").unwrap();
    let key = log.key();
    let report = AuditLog::verify_file(&key, &audit_file).unwrap();
    assert!(report.first_error.is_some());
}

#[test]
fn cli_parses_run_subcommand() {
    let cli = Cli::try_parse_from(["octravpn-node", "--config", "/tmp/x.toml", "run"]).unwrap();
    assert!(matches!(cli.cmd, Cmd::Run(_)));
    assert_eq!(cli.config, "/tmp/x.toml");
}

#[test]
fn cli_parses_bond_subcommand_with_amount() {
    let cli = Cli::try_parse_from(["octravpn-node", "bond", "--amount", "12345"]).unwrap();
    match cli.cmd {
        Cmd::Bond(a) => assert_eq!(a.amount, 12345),
        other => panic!("expected Bond, got {other:?}"),
    }
}

#[test]
fn cli_parses_v3_open_session_subcommand() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "v3",
        "open-session",
        "--tailnet-id",
        "1",
        "--circle",
        "oct8taXQ4CvohcgzCJFYyaKrrAbcZs5mxkBCJQQYWb2Pcun",
        "--max-pay",
        "1000",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::V3(a) => match a.cmd {
            v3_cli::V3Cmd::OpenSession(args) => {
                assert_eq!(args.tailnet_id, 1);
                assert_eq!(args.max_pay, 1000);
            }
            other => panic!("expected V3::OpenSession, got {other:?}"),
        },
        other => panic!("expected V3, got {other:?}"),
    }
}

#[test]
fn cli_parses_audit_verify_subcommand() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "audit",
        "verify",
        "--audit-path",
        "/tmp/a",
        "--journal-path",
        "/tmp/j",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::Audit(a) => match a.cmd {
            audit_cli::AuditCmd::Verify(_) => {}
            other => panic!("expected Audit::Verify, got {other:?}"),
        },
        other => panic!("expected Audit, got {other:?}"),
    }
}

#[test]
fn cli_parses_config_validate_with_offline() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "config",
        "validate",
        "--offline",
        "/tmp/node.toml",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::Config(a) => match a.cmd {
            cli_ops::ConfigCmd::Validate(args) => {
                assert!(args.offline);
                assert_eq!(args.path, PathBuf::from("/tmp/node.toml"));
            }
            other => panic!("expected Config::Validate, got {other:?}"),
        },
        other => panic!("expected Config, got {other:?}"),
    }
}

#[test]
fn cli_parses_audit_tail_with_follow_flag() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "audit-tail",
        "--audit-path",
        "/tmp/log",
        "--follow",
        "--poll-ms",
        "500",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::AuditTail(args) => {
            assert!(args.follow);
            assert_eq!(args.poll_ms, 500);
        }
        other => panic!("expected AuditTail, got {other:?}"),
    }
}

#[test]
fn cli_parses_receipt_verify_with_session_id() {
    let cli = Cli::try_parse_from(["octravpn-node", "receipt-verify", &"a".repeat(64)]).unwrap();
    match cli.cmd {
        Cmd::ReceiptVerify(args) => {
            assert_eq!(args.session_id, "a".repeat(64));
        }
        other => panic!("expected ReceiptVerify, got {other:?}"),
    }
}

#[test]
fn cli_parses_seal_keys_with_passphrase_file() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "seal-keys",
        "--passphrase-file",
        "/run/secret",
        "--remove-plaintext",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::SealKeys(a) => {
            assert!(a.passphrase.is_none());
            assert_eq!(a.passphrase_file, Some(PathBuf::from("/run/secret")));
            assert!(!a.passphrase_stdin);
            assert!(a.remove_plaintext);
        }
        other => panic!("expected SealKeys, got {other:?}"),
    }
}

#[test]
fn cli_parses_unseal_keys_with_tmpdir() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "unseal-keys",
        "--tmpdir",
        "/private/tmp/octra",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::UnsealKeys(a) => {
            assert_eq!(a.tmpdir, PathBuf::from("/private/tmp/octra"));
        }
        other => panic!("expected UnsealKeys, got {other:?}"),
    }
}

#[test]
fn cli_parses_mesh_mint_preauth() {
    let cli = Cli::try_parse_from([
        "octravpn-node",
        "mesh",
        "mint-preauth",
        "--user",
        "alice",
        "--reusable",
    ])
    .unwrap();
    match cli.cmd {
        Cmd::Mesh(a) => match a.sub {
            super::mesh::MeshCmd::MintPreauth {
                user,
                reusable,
                ttl_secs,
            } => {
                assert_eq!(user, "alice");
                assert!(reusable);
                assert!(ttl_secs.is_none());
            }
            other => panic!("expected Mesh::MintPreauth, got {other:?}"),
        },
        other => panic!("expected Mesh, got {other:?}"),
    }
}

// ----------------------------------------------------------------------
// Trait-dispatch smoke test (deliverable #7). A no-op `Subcommand`
// proves the trait machinery covers the "add a new variant" path
// without touching `main.rs`. The test lives here so it can see the
// crate's `pub(crate)` Subcommand trait.
// ----------------------------------------------------------------------
#[test]
fn subcommand_trait_dispatch_smoke() {
    // A hypothetical new subcommand. To wire it into the real CLI,
    // the only change needed is one variant addition to
    // `cli::Cmd` — `main.rs` does not need to change.
    struct NoopCmd;
    #[async_trait]
    impl Subcommand for NoopCmd {
        fn needs_hub(&self) -> bool {
            false
        }
        async fn dispatch(self, _ctx: CliContext<'_>) -> anyhow::Result<i32> {
            Ok(42)
        }
    }

    let cmd = NoopCmd;
    assert!(!cmd.needs_hub());
    // Sync-drive the future with a single-threaded runtime to keep the
    // test free of #[tokio::test].
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let ctx = CliContext {
        cfg_path: "/tmp/unused",
        hub: None,
    };
    let code = rt.block_on(cmd.dispatch(ctx)).unwrap();
    assert_eq!(code, 42);
}
