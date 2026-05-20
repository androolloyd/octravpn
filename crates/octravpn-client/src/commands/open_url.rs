//! `octravpn open-url oct://<circle>/<path>` — fetch a circle asset
//! over the active VPN session and either stream it, save it, or hand
//! it off to the local portal for in-browser rendering.
//!
//! Modes (mutually exclusive on the CLI):
//!   * `--portal` (default when no other flag is given) — boot the
//!     portal if it isn't running, redirect the system browser at
//!     `http://127.0.0.1:<port>/o/<b64>`.
//!   * `--save <path>` — write the bytes to disk.
//!   * `--stdout` — stream the bytes to stdout.
//!
//! **Decision log.**
//! * Default mode is `--portal`. Operators who explicitly want non-UI
//!   output ask for `--save` or `--stdout` — there's no silent fallback
//!   from one to the other, because mixing them would hide failures.
//! * Portal auto-spawn: `open-url --portal` first probes
//!   `http://127.0.0.1:<port>/healthz`; if no portal answers, we spawn
//!   the server in a detached tokio task on the same loopback. Wait up
//!   to 2 s for the probe to succeed, then launch the browser.
//! * If the chain context can't be built (wrong protocol_version, etc.)
//!   we bail with a clear error — no silent fallback to stdout.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use clap::Args;
use tracing::warn;

use crate::{config::ClientConfig, portal, portal::chain::PortalChain};

/// Clap surface for `octravpn open-url`.
#[derive(Args, Debug, Clone)]
pub(crate) struct OpenUrlArgs {
    /// `oct://<circle>/<path>` URL to resolve.
    pub url: String,

    /// Write the fetched bytes to this file. Mutually exclusive with
    /// `--stdout`/`--portal`.
    #[arg(long)]
    pub save: Option<PathBuf>,

    /// Stream the fetched bytes to stdout. Mutually exclusive with
    /// `--save`/`--portal`.
    #[arg(long, default_value_t = false)]
    pub stdout: bool,

    /// Hand the URL off to the local portal (default if no other mode
    /// is set). Spawns the portal if it isn't already running.
    #[arg(long, default_value_t = false)]
    pub portal: bool,

    /// Override the portal's loopback bind. Only meaningful when
    /// running with `--portal`. Defaults to
    /// `127.0.0.1:<DEFAULT_PORTAL_PORT>`.
    #[arg(long)]
    pub portal_bind: Option<SocketAddr>,
}

impl OpenUrlArgs {
    /// Pick a single effective mode given the flags. `--portal` is the
    /// default when none are set.
    fn mode(&self) -> Result<Mode> {
        let count = u8::from(self.save.is_some()) + u8::from(self.stdout) + u8::from(self.portal);
        if count > 1 {
            bail!("at most one of --save, --stdout, --portal may be set");
        }
        Ok(if let Some(path) = self.save.clone() {
            Mode::Save(path)
        } else if self.stdout {
            Mode::Stdout
        } else {
            // Default: portal.
            Mode::Portal
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Save(PathBuf),
    Stdout,
    Portal,
}

/// Parsed `oct://<circle>/<path>[?spki=<b64>[,<b64>...]]` URL.
///
/// The `spki` query parameter, when present, carries one or more
/// base64-encoded sha256 fingerprints of the chain RPC's leaf-cert
/// SubjectPublicKeyInfo. The parsed pins are honoured by
/// [`PortalChain::from_config_for_url`] which installs a
/// [`octravpn_core::spki_verifier::SpkiPinVerifier`] for the RPC
/// client. Multiple pins (comma-separated) provide rotation grace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedOctUrl {
    pub circle_id: String,
    pub path: String,
}

/// Parse a string of the shape `oct://<circle>/<path>`.
///
/// Rules:
///   * Scheme must be `oct://` exactly (case-insensitive on the scheme).
///   * `<circle>` must be non-empty and contain no `/`.
///   * `<path>` is the rest of the URL, normalized to a leading `/`.
///     Empty path becomes `/` (the circle's index).
pub(crate) fn parse_oct_url(s: &str) -> Result<ParsedOctUrl> {
    // Strip the scheme, case-insensitive.
    let rest = s
        .strip_prefix("oct://")
        .or_else(|| s.strip_prefix("OCT://"))
        .or_else(|| {
            // Cheap case-insensitive prefix check for unusual casings.
            let lc: String = s.chars().take(6).collect::<String>().to_ascii_lowercase();
            if lc == "oct://" {
                Some(&s[6..])
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("not an oct:// URL: {s}"))?;

    let (circle, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };

    if circle.is_empty() {
        bail!("oct:// URL missing circle id: {s}");
    }
    if circle.contains(|c: char| c.is_whitespace() || matches!(c, '?' | '#' | ':')) {
        bail!("circle id contains forbidden chars: {circle}");
    }

    // Audit-1 H-1: strip the `?spki=…` query (and any fragment) from
    // the resource path so the on-chain `resource_key` is computed
    // against the canonical path, NOT against the SPKI pin bytes.
    // Without this strip an attacker who controls the URL could
    // index a different sealed asset by appending a different
    // `?spki=` value. The pin itself is still consulted via the
    // full raw URL string downstream (see
    // [`PortalChain::from_config_for_url`]).
    let path_no_query = path.split('?').next().unwrap_or(path);
    let path_no_frag = path_no_query.split('#').next().unwrap_or(path_no_query);
    let path = if path_no_frag.is_empty() {
        "/".to_string()
    } else if path_no_frag.starts_with('/') {
        path_no_frag.to_string()
    } else {
        format!("/{path_no_frag}")
    };

    Ok(ParsedOctUrl {
        circle_id: circle.to_string(),
        path,
    })
}

/// Entry point used from `main.rs`. Loads `ClientConfig` only once.
pub(crate) async fn open_url(cfg: &ClientConfig, args: OpenUrlArgs) -> Result<()> {
    let mode = args.mode()?;
    match mode {
        Mode::Stdout => fetch_to_stdout(cfg, &args.url).await,
        Mode::Save(path) => fetch_to_path(cfg, &args.url, &path).await,
        Mode::Portal => dispatch_to_portal(cfg, &args).await,
    }
}

async fn fetch_to_stdout(cfg: &ClientConfig, url: &str) -> Result<()> {
    let parsed = parse_oct_url(url)?;
    // Audit-1 H-1: when the user-supplied oct:// URL carries an
    // `?spki=<b64>` pin parameter, route the RPC client through
    // `SpkiPinVerifier`. Legacy pinless URLs fall back to CA-only
    // pinning (preserved wire shape).
    let chain = PortalChain::from_config_for_url(cfg, Some(url))?;
    let bytes = chain
        .fetch_circle_asset_bytes(&parsed.circle_id, &parsed.path)
        .await?;
    use std::io::Write;
    std::io::stdout()
        .write_all(&bytes)
        .context("write asset to stdout")?;
    Ok(())
}

async fn fetch_to_path(cfg: &ClientConfig, url: &str, path: &Path) -> Result<()> {
    let parsed = parse_oct_url(url)?;
    // Audit-1 H-1: when the user-supplied oct:// URL carries an
    // `?spki=<b64>` pin parameter, route the RPC client through
    // `SpkiPinVerifier`. Legacy pinless URLs fall back to CA-only
    // pinning (preserved wire shape).
    let chain = PortalChain::from_config_for_url(cfg, Some(url))?;
    let bytes = chain
        .fetch_circle_asset_bytes(&parsed.circle_id, &parsed.path)
        .await?;
    std::fs::write(path, &bytes)
        .with_context(|| format!("write {} ({} bytes)", path.display(), bytes.len()))?;
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

async fn dispatch_to_portal(cfg: &ClientConfig, args: &OpenUrlArgs) -> Result<()> {
    parse_oct_url(&args.url)?;
    // Build the chain context first so we fail-fast on bad config /
    // wrong protocol_version, BEFORE we open the user's browser at a
    // dead URL.
    // Audit-1 H-1: when the user-supplied oct:// URL carries an
    // `?spki=<b64>` pin parameter, route the RPC client through
    // `SpkiPinVerifier`. Legacy pinless URLs fall back to CA-only
    // pinning (preserved wire shape).
    let chain = PortalChain::from_config_for_url(cfg, Some(&args.url))?;

    let bind: SocketAddr = args.portal_bind.unwrap_or_else(|| {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            portal::DEFAULT_PORTAL_PORT,
        )
    });

    // Already running? Just open the browser.
    if portal::is_running(bind).await {
        let target = browser_target(bind, &args.url);
        let _ = portal::open_in_browser(&target).map_err(|e| {
            warn!(error = %e, "failed to open browser; URL below");
            e
        });
        println!("opened {target}");
        return Ok(());
    }

    // Spawn a background portal on the same loopback and wait for it
    // to become healthy.
    let bind_for_task = bind;
    let chain_for_task = chain.clone();
    tokio::spawn(async move {
        if let Err(e) = portal::run_portal(chain_for_task, bind_for_task).await {
            warn!(error = %e, "background portal exited");
        }
    });
    if !portal::wait_until_running(bind, std::time::Duration::from_secs(2)).await {
        bail!(
            "portal didn't come up on {bind} within 2s. \
             Try `octravpn portal` directly to surface the bind error."
        );
    }

    let target = browser_target(bind, &args.url);
    if let Err(e) = portal::open_in_browser(&target) {
        warn!(error = %e, "failed to open system browser; navigate manually");
    }
    println!("opened {target}");
    // Hold the runtime open so the spawned portal task keeps serving.
    // The operator stops it with Ctrl-C, same as `octravpn portal`.
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}

/// Build the `/o/<b64>` portal URL for a given oct-URL.
fn browser_target(bind: SocketAddr, oct_url: &str) -> String {
    let b64 = B64URL.encode(oct_url.as_bytes());
    format!("http://{bind}/o/{b64}")
}

// ─── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── existing parse_oct_url surface (kept stable) ─────────────────

    #[test]
    fn parses_simple_oct_url() {
        let p = parse_oct_url("oct://octCIRCLE/policy.json").unwrap();
        assert_eq!(p.circle_id, "octCIRCLE");
        assert_eq!(p.path, "/policy.json");
    }

    #[test]
    fn parses_root_path() {
        let p = parse_oct_url("oct://octCIRCLE").unwrap();
        assert_eq!(p.circle_id, "octCIRCLE");
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parses_nested_path() {
        let p = parse_oct_url("oct://oct1/a/b/c.txt").unwrap();
        assert_eq!(p.path, "/a/b/c.txt");
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(parse_oct_url("https://example/x").is_err());
        assert!(parse_oct_url("oct:/x").is_err());
    }

    #[test]
    fn rejects_empty_circle() {
        assert!(parse_oct_url("oct:///policy.json").is_err());
    }

    #[test]
    fn rejects_query_in_circle_id() {
        // Belt-and-braces: a `?` in the host slot is forbidden because
        // we don't try to parse query strings — operators who want
        // queries pass them inside the path component.
        assert!(parse_oct_url("oct://circle?bad/policy").is_err());
    }

    // ── Phase A new tests ────────────────────────────────────────────

    fn cfg_v3(secret_path: &std::path::Path) -> ClientConfig {
        use crate::config::{ChainCfg, V2Cfg, WalletCfg};
        ClientConfig {
            chain: ChainCfg {
                rpc_url: "http://127.0.0.1:1".into(),
                program_addr: "octPROG".into(),
                protocol_version: "v3".into(),
                chain_id: octravpn_core::receipt::CHAIN_ID_TEST,
                pinned_root_paths: None,
            },
            wallet: WalletCfg {
                addr: "oct".into(),
                secret_path: secret_path.display().to_string(),
            },
            v2: V2Cfg::default(),
            v3: crate::config::V3Cfg::default(),
        }
    }

    #[test]
    fn dispatches_to_portal_when_portal_running() {
        // The mode-resolver is the deterministic surface; the actual
        // dispatch is tested in the portal integration test (it needs
        // a real listener). Here we assert that with no flags set, the
        // resolved mode is Portal.
        let args = OpenUrlArgs {
            url: "oct://circ/policy.json".into(),
            save: None,
            stdout: false,
            portal: false,
            portal_bind: None,
        };
        assert_eq!(args.mode().unwrap(), Mode::Portal);

        // Explicit --portal also picks Portal.
        let args = OpenUrlArgs {
            url: "oct://circ/policy.json".into(),
            save: None,
            stdout: false,
            portal: true,
            portal_bind: None,
        };
        assert_eq!(args.mode().unwrap(), Mode::Portal);
    }

    #[tokio::test]
    async fn falls_back_to_stdout_when_save_unset_and_no_portal() {
        // `--stdout` is the explicit fallback (the brief calls this
        // out as "no portal needed"). Verify the mode resolver routes
        // there when `--stdout` is set even with no portal.
        let args = OpenUrlArgs {
            url: "oct://circ/policy.json".into(),
            save: None,
            stdout: true,
            portal: false,
            portal_bind: None,
        };
        assert_eq!(args.mode().unwrap(), Mode::Stdout);

        // And the dispatch surface refuses to fetch on a v1.1 config
        // (no silent fallback to portal mode either) — protocol gate
        // is the same regardless of mode.
        use crate::config::{ChainCfg, V2Cfg, WalletCfg};
        let cfg = ClientConfig {
            chain: ChainCfg {
                rpc_url: "http://127.0.0.1:1".into(),
                program_addr: "octPROG".into(),
                protocol_version: "v1.1".into(),
                chain_id: octravpn_core::receipt::CHAIN_ID_TEST,
                pinned_root_paths: None,
            },
            wallet: WalletCfg {
                addr: "oct".into(),
                secret_path: "/dev/null".into(),
            },
            v2: V2Cfg::default(),
            v3: crate::config::V3Cfg::default(),
        };
        let err = open_url(&cfg, args).await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(msg.contains("v3") || msg.contains("protocol"));
    }

    #[tokio::test]
    async fn save_writes_bytes_to_disk() {
        // Spin a stub chain RPC, point cfg at it, ask --save to land
        // the bytes on a tempfile, and verify the contents.
        use axum::{routing::post, Json, Router};
        use serde_json::json;
        use std::net::SocketAddr;

        let mock: Router = Router::new().route(
            "/",
            post(
                |axum::Json(req): axum::Json<serde_json::Value>| async move {
                    let id = req.get("id").cloned().unwrap_or(json!(1));
                    let payload = b"hello from circle";
                    let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "ciphertext_b64": b64,
                            "plaintext_hash": "0".repeat(64),
                            "key_id": "default",
                        }
                    }))
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let tmp = tempfile::tempdir().unwrap();
        let wallet = tmp.path().join("wallet.hex");
        std::fs::write(
            &wallet,
            "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677",
        )
        .unwrap();
        let mut cfg = cfg_v3(&wallet);
        cfg.chain.rpc_url = format!("http://{addr}/");

        let out = tmp.path().join("asset.bin");
        let args = OpenUrlArgs {
            url: "oct://circSAVE/policy.txt".into(),
            save: Some(out.clone()),
            stdout: false,
            portal: false,
            portal_bind: None,
        };
        open_url(&cfg, args).await.unwrap();
        let on_disk = std::fs::read(&out).unwrap();
        assert_eq!(on_disk, b"hello from circle");
    }

    // ── Phase-Z parser coverage ──────────────────────────────────────

    #[test]
    fn parse_accepts_uppercase_scheme() {
        let p = parse_oct_url("OCT://circle/policy.json").unwrap();
        assert_eq!(p.circle_id, "circle");
        assert_eq!(p.path, "/policy.json");
    }

    #[test]
    fn parse_accepts_mixed_case_scheme() {
        let p = parse_oct_url("Oct://circle/x").unwrap();
        assert_eq!(p.circle_id, "circle");
        assert_eq!(p.path, "/x");
    }

    #[test]
    fn parse_circle_only_no_trailing_slash() {
        let p = parse_oct_url("oct://circ").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_circle_with_trailing_slash() {
        let p = parse_oct_url("oct://circ/").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_double_trailing_slash() {
        // The parser doesn't canonicalize multi-slash paths — verifies
        // current behaviour. `//x` should stay as the path so callers
        // can canonicalize downstream.
        let p = parse_oct_url("oct://circ//policy.json").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "//policy.json");
    }

    #[test]
    fn parse_rejects_missing_scheme() {
        assert!(parse_oct_url("circle/policy.json").is_err());
        assert!(parse_oct_url("//circle/policy.json").is_err());
        assert!(parse_oct_url("").is_err());
    }

    #[test]
    fn parse_rejects_double_scheme_with_colon_in_circle() {
        assert!(parse_oct_url("oct://oct://double").is_err());
    }

    #[test]
    fn parse_rejects_whitespace_in_circle_id() {
        assert!(parse_oct_url("oct://bad circle/x").is_err());
        assert!(parse_oct_url("oct://bad\tcircle/x").is_err());
    }

    #[test]
    fn parse_rejects_fragment_marker_in_circle_id() {
        assert!(parse_oct_url("oct://circle#frag/x").is_err());
    }

    #[test]
    fn parse_allows_nested_dots_and_dashes_in_circle_id() {
        let p = parse_oct_url("oct://circle-1.subnet/asset.bin").unwrap();
        assert_eq!(p.circle_id, "circle-1.subnet");
        assert_eq!(p.path, "/asset.bin");
    }

    #[test]
    fn parse_strips_query_from_path() {
        // Audit-1 H-1: the parser now strips `?...` from the path so
        // the on-chain `resource_key` is computed against the canonical
        // path bytes (not the SPKI pin or any other query payload).
        // The pin itself is consumed downstream from the full URL.
        let p = parse_oct_url("oct://circ/api?spki=AAAA&y=2").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "/api");
    }

    #[test]
    fn parse_strips_anchor_from_path() {
        // `#fragment` is similarly stripped — fragments are
        // client-side only and never make it to the chain RPC.
        let p = parse_oct_url("oct://circ/page#section").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "/page");
    }

    #[test]
    fn parse_unicode_in_path_is_preserved() {
        let p = parse_oct_url("oct://circ/héllo").unwrap();
        assert_eq!(p.circle_id, "circ");
        assert_eq!(p.path, "/héllo");
    }

    #[test]
    fn parse_long_path() {
        let long: String = "a/".repeat(500);
        let url = format!("oct://circ/{long}");
        let p = parse_oct_url(&url).unwrap();
        assert_eq!(p.circle_id, "circ");
        assert!(p.path.starts_with("/a/a/"));
        assert_eq!(p.path.len(), long.len() + 1);
    }

    #[test]
    fn mode_save_takes_precedence_only_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let args = OpenUrlArgs {
            url: "oct://c/x".into(),
            save: Some(tmp.path().join("out.bin")),
            stdout: false,
            portal: false,
            portal_bind: None,
        };
        assert!(matches!(args.mode().unwrap(), Mode::Save(_)));
    }

    #[test]
    fn mode_combination_save_plus_stdout_is_rejected() {
        let args = OpenUrlArgs {
            url: "oct://c/x".into(),
            save: Some(std::path::PathBuf::from("/tmp/x")),
            stdout: true,
            portal: false,
            portal_bind: None,
        };
        let err = args.mode().unwrap_err();
        assert!(err.to_string().contains("at most one"));
    }

    #[test]
    fn mode_combination_portal_plus_stdout_is_rejected() {
        let args = OpenUrlArgs {
            url: "oct://c/x".into(),
            save: None,
            stdout: true,
            portal: true,
            portal_bind: None,
        };
        assert!(args.mode().is_err());
    }

    #[test]
    fn mode_combination_portal_plus_save_is_rejected() {
        let args = OpenUrlArgs {
            url: "oct://c/x".into(),
            save: Some(std::path::PathBuf::from("/tmp/x")),
            stdout: false,
            portal: true,
            portal_bind: None,
        };
        assert!(args.mode().is_err());
    }

    #[test]
    fn browser_target_b64_round_trips() {
        // browser_target() is private; reproduce its construction to
        // pin down the format the portal binary expects.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
        let url = "oct://circle/policy.json";
        let bind: SocketAddr = "127.0.0.1:51823".parse().unwrap();
        let got = browser_target(bind, url);
        let b64 = B64URL.encode(url.as_bytes());
        assert_eq!(got, format!("http://{bind}/o/{b64}"));
        // And the b64 must decode back to the original URL.
        let decoded = B64URL.decode(b64.as_bytes()).unwrap();
        assert_eq!(decoded, url.as_bytes());
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 512,
            .. proptest::test_runner::Config::default()
        })]

        /// The parser is a fixed-format hand-rolled split — it must
        /// never panic regardless of the input. Either it returns a
        /// well-formed `ParsedOctUrl`, or it returns an error. No
        /// third option.
        #[test]
        fn parse_oct_url_never_panics(s in ".{0,256}") {
            match parse_oct_url(&s) {
                Ok(p) => {
                    // Invariants on success:
                    //   * circle_id non-empty
                    //   * circle_id has no '/', no whitespace, no '?', no '#', no ':'
                    //   * path starts with '/'
                    proptest::prop_assert!(!p.circle_id.is_empty());
                    proptest::prop_assert!(!p.circle_id.contains('/'));
                    proptest::prop_assert!(!p.circle_id.contains('?'));
                    proptest::prop_assert!(!p.circle_id.contains('#'));
                    proptest::prop_assert!(!p.circle_id.contains(':'));
                    proptest::prop_assert!(!p.circle_id.contains(char::is_whitespace));
                    proptest::prop_assert!(p.path.starts_with('/'));
                }
                Err(_) => {
                    // Error path — must just be a clean anyhow.
                }
            }
        }

        /// For any valid-shaped input `oct://<id>/<path>`, parsing must
        /// succeed and recover the exact id.
        #[test]
        fn parse_oct_url_roundtrip_for_well_formed(
            id in "[a-zA-Z0-9._-]{1,32}",
            path in "[a-zA-Z0-9._/-]{0,64}",
        ) {
            let url = if path.is_empty() {
                format!("oct://{id}")
            } else if let Some(rest) = path.strip_prefix('/') {
                format!("oct://{id}/{rest}")
            } else {
                format!("oct://{id}/{path}")
            };
            let p = parse_oct_url(&url).unwrap();
            proptest::prop_assert_eq!(p.circle_id, id);
            proptest::prop_assert!(p.path.starts_with('/'));
        }
    }
}
