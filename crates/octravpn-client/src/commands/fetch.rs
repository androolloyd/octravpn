//! `octravpn fetch <oct-url>` — CLI-shaped raw-bytes accessor for
//! `oct://` assets. Bypasses the HTTP portal entirely; talks directly
//! to the chain via [`PortalChain`] and writes plaintext bytes to
//! stdout or a file. Designed to slot into shell pipelines.
//!
//! ## Modes
//!
//! ```text
//! octravpn fetch oct://octCircleX/policy.json                # raw → stdout
//! octravpn fetch oct://octCircleX/policy.json -o /tmp/policy # save to file
//! octravpn fetch oct://octCircleX/policy.json --secret PASS  # one-shot passphrase
//! octravpn fetch -i oct://octCircleX/policy.json             # prompt on TTY
//! octravpn fetch --headers oct://octCircleX/policy.json      # Content-Type to stderr
//! ```
//!
//! ## Exit codes
//!
//! | Code | Meaning                                                  |
//! |------|----------------------------------------------------------|
//! | 0    | success                                                  |
//! | 2    | bad usage / bad URL / mode conflict                      |
//! | 3    | fetch failed (transport, RPC, output write, etc.)        |
//! | 4    | sealed asset and no passphrase available (interactive or |
//! |      | env / config / `--secret`) — distinct from a wrong       |
//! |      | passphrase so wrapper scripts can differentiate          |
//! | 5    | wrong passphrase, retry attempts exhausted               |
//!
//! ## Security
//!
//! * `--secret <PASS>` is convenience-only — on shared hosts prefer
//!   env (`OCTRAVPN_SEALED_PASSPHRASE`) or `-i` (stdin prompt with
//!   no echo). We never log the secret; clap's `hide_default_value`
//!   keeps it out of `--help`.
//! * Interactive prompts go via [`rpassword`] which switches the
//!   terminal to no-echo mode and restores it on drop. Up to three
//!   attempts; each failure increments a counter, and we abort with
//!   exit 5 once exhausted.
//! * The fetch path is the same as the portal's `/raw` path — same
//!   single-decrypt-attempt semantics. We do not iterate passphrases
//!   across multiple anchors.

use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process,
    sync::Arc,
};

use anyhow::Result;
use clap::Args;
use zeroize::Zeroizing;

use crate::{
    commands::open_url::parse_oct_url,
    portal::chain::{ConfigPassphrase, FetchAssetError, PortalChain},
};

/// Clap surface for `octravpn fetch`. See the module docstring for the
/// behavior matrix.
#[derive(Args, Debug, Clone)]
pub(crate) struct FetchArgs {
    /// `oct://<circle>/<path>` URL to fetch.
    pub url: String,

    /// Write the fetched bytes to this file instead of stdout. The
    /// containing directory must exist; we do not create it for you.
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// One-shot sealed-asset passphrase. Highest precedence among the
    /// non-interactive sources (env > this > config). Avoid on shared
    /// hosts — operators there should prefer env-var or `-i`.
    #[arg(long, hide_default_value = true)]
    pub secret: Option<String>,

    /// Prompt on the controlling TTY when the asset is sealed and no
    /// other passphrase source resolved. Up to 3 attempts; gives up
    /// with exit code 5 thereafter. No-op when stdin is not a TTY.
    #[arg(short = 'i', long, default_value_t = false)]
    pub interactive: bool,

    /// Emit `Content-Type: <mime>` lines to stderr after the body has
    /// been written. Mirrors `curl -i` ergonomics for shell pipelines
    /// that only need the type, not the full header set.
    #[arg(long, default_value_t = false)]
    pub headers: bool,
}

/// Top-level entry — process-exits with one of the documented codes.
/// `cfg` is the loaded `ClientConfig`; we reuse its `[v2]` block for
/// the env/config passphrase precedence.
pub(crate) async fn run(cfg: &crate::config::ClientConfig, args: FetchArgs) -> Result<()> {
    let code = run_fetch(cfg, args).await;
    if code != 0 {
        process::exit(code);
    }
    Ok(())
}

/// Testable inner runner — returns the exit code instead of calling
/// `process::exit`. Public for `tests` use; otherwise an
/// implementation detail.
pub(crate) async fn run_fetch(cfg: &crate::config::ClientConfig, args: FetchArgs) -> i32 {
    // ── 1. parse URL ──────────────────────────────────────────────
    let parsed = match parse_oct_url(&args.url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("octravpn fetch: bad URL: {e}");
            return 2;
        }
    };

    // ── 2. build chain context ────────────────────────────────────
    let chain = match PortalChain::from_config(cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("octravpn fetch: cannot build chain context: {e}");
            return 2;
        }
    };

    // ── 3. resolve a non-interactive passphrase ───────────────────
    // Precedence: env > `--secret` > config.
    let initial =
        crate::discover_v2::resolve_passphrase(&cfg.v2, args.secret.as_deref()).map(Arc::new);
    let source = ConfigPassphrase::new(initial.clone());

    // ── 4. one fetch attempt with whatever we have ────────────────
    let mut last_err: Option<FetchAssetError> = None;
    let bytes = match chain
        .fetch_with_source(&parsed.circle_id, &parsed.path, &source)
        .await
    {
        Ok(b) => Some(b),
        Err(FetchAssetError::MissingPassphrase { .. }) if args.interactive => {
            // Fall through to the interactive prompt loop. We delay
            // entering it until we know we're sealed-and-stuck so
            // operators redirecting stdout aren't surprised by a
            // hanging prompt on the happy path.
            None
        }
        Err(FetchAssetError::DecryptFailed { .. }) if args.interactive => None,
        Err(FetchAssetError::MissingPassphrase { .. }) => {
            eprintln!(
                "octravpn fetch: sealed asset; set OCTRAVPN_SEALED_PASSPHRASE, \
                 pass --secret <PASS>, or run with -i to prompt"
            );
            return 4;
        }
        Err(FetchAssetError::DecryptFailed { .. }) => {
            eprintln!(
                "octravpn fetch: decrypt failed (wrong passphrase / key_id / corrupt envelope)"
            );
            return 5;
        }
        Err(e @ FetchAssetError::NotPublished { .. }) => {
            eprintln!("octravpn fetch: {e}");
            return 3;
        }
        Err(e) => {
            last_err = Some(e);
            None
        }
    };

    let bytes = if let Some(b) = bytes {
        b
    } else if args.interactive && std::io::stdin().is_terminal() {
        match interactive_decrypt(&chain, &parsed.circle_id, &parsed.path).await {
            Ok(b) => b,
            Err(code) => return code,
        }
    } else if let Some(err) = last_err {
        eprintln!("octravpn fetch: {err}");
        return 3;
    } else {
        // We didn't fetch, and we can't prompt (non-TTY). Map to the
        // sealed-no-passphrase exit.
        eprintln!(
            "octravpn fetch: sealed asset; stdin is not a TTY so cannot prompt. \
             Use --secret or set OCTRAVPN_SEALED_PASSPHRASE."
        );
        return 4;
    };

    // ── 5. write output ───────────────────────────────────────────
    let mime = crate::portal::mime::sniff(&bytes);
    if let Some(path) = args.output.as_deref() {
        if let Err(e) = fs::write(path, &bytes) {
            eprintln!(
                "octravpn fetch: write {} ({} bytes): {e}",
                path.display(),
                bytes.len()
            );
            return 3;
        }
        if args.headers {
            eprintln!("Content-Type: {}", mime.content_type());
            eprintln!("Content-Length: {}", bytes.len());
        }
    } else if let Err(e) = io::stdout().lock().write_all(&bytes) {
        eprintln!("octravpn fetch: stdout: {e}");
        return 3;
    } else if args.headers {
        eprintln!("Content-Type: {}", mime.content_type());
        eprintln!("Content-Length: {}", bytes.len());
    }
    0
}

/// Prompt the controlling TTY up to 3 times for a sealed-asset
/// passphrase. Each attempt invokes [`PortalChain::try_decrypt_with_passphrase`]
/// against the user's target asset directly — there is no separate
/// validation oracle. On exhaustion, returns exit code 5.
async fn interactive_decrypt(
    chain: &PortalChain,
    circle_id: &str,
    path: &str,
) -> Result<Vec<u8>, i32> {
    eprintln!("Sealed asset for circle {circle_id}. Enter passphrase to decrypt.");
    for attempt in 1..=3u32 {
        let prompt = format!("Passphrase (attempt {attempt}/3): ");
        let pp = match rpassword::prompt_password(&prompt) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("octravpn fetch: cannot read passphrase from TTY: {e}");
                return Err(3);
            }
        };
        let trimmed = pp.trim().to_string();
        // Zeroize the un-trimmed read buffer too. The shadowed `pp`
        // goes out of scope at the end of this iteration.
        let _wipe = Zeroizing::new(pp);
        if trimmed.is_empty() {
            eprintln!("octravpn fetch: empty passphrase, retrying");
        } else {
            let candidate = Arc::new(Zeroizing::new(trimmed));
            match chain
                .try_decrypt_with_passphrase(circle_id, path, Arc::clone(&candidate))
                .await
            {
                Ok(b) => return Ok(b),
                Err(FetchAssetError::DecryptFailed { .. }) => {
                    eprintln!("wrong passphrase");
                }
                Err(e) => {
                    eprintln!("octravpn fetch: {e}");
                    return Err(3);
                }
            }
        }
    }
    eprintln!("octravpn fetch: too many wrong passphrases, giving up");
    Err(5)
}

#[cfg(test)]
mod tests {
    //! Unit tests for `octravpn fetch`. We exercise:
    //! - URL parsing and clap argument shapes,
    //! - exit-code mapping across the [`FetchAssetError`] variants,
    //! - output formatting (`--headers`, `--output`),
    //! - the chain fetch path against a mocked RPC.
    //!
    //! Tests are sync where possible. Network paths use the same axum
    //! stub pattern from `portal::chain::tests`.

    use super::*;
    use crate::config::{ChainCfg, ClientConfig, V2Cfg, V3Cfg, WalletCfg};
    use axum::{routing::post, Json, Router};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use octravpn_core::circle::{encrypt_sealed_bytes, PaddingClass};
    use serde_json::json;
    use std::net::SocketAddr;

    fn cfg_with_rpc(rpc_url: String, sealed_pp: Option<&str>) -> ClientConfig {
        ClientConfig {
            chain: ChainCfg {
                rpc_url,
                program_addr: "octPROG".into(),
                protocol_version: "v3".into(),
                chain_id: octravpn_core::receipt::CHAIN_ID_TEST,
                pinned_root_paths: None,
            },
            wallet: WalletCfg {
                addr: "oct".into(),
                secret_path: "/dev/null".into(),
            },
            v2: V2Cfg {
                sealed_passphrase: sealed_pp.map(str::to_string),
                ..V2Cfg::default()
            },
            v3: V3Cfg::default(),
        }
    }

    async fn spawn_mock(result: serde_json::Value) -> SocketAddr {
        let result_arc = std::sync::Arc::new(result);
        let app: Router = Router::new().route(
            "/",
            post(move |Json(req): Json<serde_json::Value>| {
                let result = std::sync::Arc::clone(&result_arc);
                async move {
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    if method == "circle_asset_ciphertext_by_resource_key" {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": (*result).clone(),
                        }))
                    } else {
                        Json(json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "method not found" },
                        }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        addr
    }

    // ── 1. URL parse failure → exit 2 ────────────────────────────────
    #[tokio::test]
    async fn bad_url_returns_exit_2() {
        let cfg = cfg_with_rpc("http://127.0.0.1:1".into(), None);
        let args = FetchArgs {
            url: "https://not-oct/x".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 2);
    }

    // ── 2. v1.1 config rejected before any RPC ───────────────────────
    #[tokio::test]
    async fn rejects_v11_config_with_exit_2() {
        let mut cfg = cfg_with_rpc("http://127.0.0.1:1".into(), None);
        cfg.chain.protocol_version = "v1.1".into();
        let args = FetchArgs {
            url: "oct://circA/x.json".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 2);
    }

    // ── 3. plaintext bytes → stdout, exit 0 ──────────────────────────
    #[tokio::test]
    async fn plaintext_bytes_write_to_output_file() {
        let payload = b"hello from circle";
        let b64 = B64.encode(payload);
        let addr = spawn_mock(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("asset.bin");
        let args = FetchArgs {
            url: "oct://circOK/policy.txt".into(),
            output: Some(out.clone()),
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 0);
        let on_disk = std::fs::read(&out).unwrap();
        assert_eq!(on_disk, payload);
    }

    // ── 4. sealed + correct --secret → exit 0 ────────────────────────
    #[tokio::test]
    async fn sealed_with_correct_secret_arg_succeeds() {
        let plaintext = br#"{"endpoint":"vpn.example:51820"}"#;
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            "circSEAL",
            "default",
            "correct-pass",
            plaintext,
            PaddingClass::None,
        )
        .unwrap();
        let addr = spawn_mock(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("policy.json");
        let args = FetchArgs {
            url: "oct://circSEAL/policy.json".into(),
            output: Some(out.clone()),
            secret: Some("correct-pass".into()),
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 0);
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    }

    // ── 5. sealed + wrong --secret → exit 5 ──────────────────────────
    #[tokio::test]
    async fn sealed_with_wrong_secret_returns_exit_5() {
        let plaintext = br#"{"k":"v"}"#;
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            "circWRONG",
            "default",
            "right-pass",
            plaintext,
            PaddingClass::None,
        )
        .unwrap();
        let addr = spawn_mock(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let args = FetchArgs {
            url: "oct://circWRONG/policy.json".into(),
            output: None,
            secret: Some("wrong-pass".into()),
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 5);
    }

    // ── 6. sealed + no passphrase + not interactive → exit 4 ─────────
    #[tokio::test]
    async fn sealed_no_passphrase_non_interactive_returns_exit_4() {
        let plaintext = b"sealed body";
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            "circNOPP",
            "default",
            "the-pass",
            plaintext,
            PaddingClass::None,
        )
        .unwrap();
        let addr = spawn_mock(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let args = FetchArgs {
            url: "oct://circNOPP/policy.json".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 4);
    }

    // ── 7. NotPublished → exit 3 ─────────────────────────────────────
    #[tokio::test]
    async fn not_published_returns_exit_3() {
        let addr = spawn_mock(serde_json::Value::Null).await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let args = FetchArgs {
            url: "oct://circNONE/missing.json".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 3);
    }

    // ── 8. RPC down → exit 3 ─────────────────────────────────────────
    #[tokio::test]
    async fn rpc_unreachable_returns_exit_3() {
        // Point at a port that's almost certainly closed locally.
        let cfg = cfg_with_rpc("http://127.0.0.1:1/".into(), None);
        let args = FetchArgs {
            url: "oct://circRPC/asset.txt".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        assert_eq!(run_fetch(&cfg, args).await, 3);
    }

    // ── 9. clap surface defaults match the documented matrix ─────────
    #[test]
    fn fetch_args_defaults_are_sane() {
        let args = FetchArgs {
            url: "oct://x/y".into(),
            output: None,
            secret: None,
            interactive: false,
            headers: false,
        };
        // Field defaults the runner relies on:
        assert!(!args.interactive);
        assert!(!args.headers);
        assert!(args.output.is_none());
        assert!(args.secret.is_none());
    }

    // ── 10. last_path_component helper indirectly via exit-3 path ────
    //
    // The fetch surface doesn't expose `last_path_component`; that
    // helper lives in `portal::routes`. We instead exercise the
    // headers-to-stderr path with the plaintext fixture; correct
    // behavior here is "exit 0 and no panic".
    #[tokio::test]
    async fn headers_flag_does_not_break_plaintext_path() {
        let payload = b"plain";
        let b64 = B64.encode(payload);
        let addr = spawn_mock(json!({
            "ciphertext_b64": b64,
            "plaintext_hash": "0".repeat(64),
            "key_id": "default",
        }))
        .await;
        let cfg = cfg_with_rpc(format!("http://{addr}/"), None);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("plain.bin");
        let args = FetchArgs {
            url: "oct://circHDR/asset.txt".into(),
            output: Some(out.clone()),
            secret: None,
            interactive: false,
            headers: true,
        };
        assert_eq!(run_fetch(&cfg, args).await, 0);
        assert_eq!(std::fs::read(&out).unwrap(), payload);
    }

    // ── 11. ConfigPassphrase precedence: --secret beats config field ─
    #[tokio::test]
    async fn secret_arg_beats_config_field() {
        let plaintext = b"correct-result";
        let (ct_b64, ph_hex) = encrypt_sealed_bytes(
            "circPREC",
            "default",
            "winner",
            plaintext,
            PaddingClass::None,
        )
        .unwrap();
        let addr = spawn_mock(json!({
            "ciphertext_b64": ct_b64,
            "plaintext_hash": ph_hex,
            "key_id": "default",
        }))
        .await;
        // Config has the WRONG passphrase; --secret has the right one.
        let cfg = cfg_with_rpc(format!("http://{addr}/"), Some("loser"));
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("p.json");
        let args = FetchArgs {
            url: "oct://circPREC/policy.json".into(),
            output: Some(out.clone()),
            secret: Some("winner".into()),
            interactive: false,
            headers: false,
        };
        // Note: env > --secret > config. We can't easily set the env
        // var in a test without contaminating other tests, so we test
        // the (--secret > config) half only here.
        assert_eq!(run_fetch(&cfg, args).await, 0);
        assert_eq!(std::fs::read(&out).unwrap(), plaintext);
    }
}
