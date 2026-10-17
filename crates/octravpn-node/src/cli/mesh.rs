//! `mesh` subcommand tree — preauth minting + tailscale-wire control
//! plane + deprecated `mesh status` / `mesh policy` arms (still wired to
//! `mesh_ops`, with stderr deprecation warnings preserved).

use anyhow::{Context as _, Result};
use async_trait::async_trait;

use crate::mesh_ops;

use super::{CliContext, Subcommand};

/// `octravpn-node mesh <subcmd>` — Tailscale-interop control surface.
#[derive(clap::Args, Debug)]
pub(crate) struct MeshArgs {
    #[command(subcommand)]
    pub(crate) sub: MeshCmd,
}

#[async_trait]
impl Subcommand for MeshArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        run_mesh_cmd(self.sub, ctx.cfg_path).await?;
        Ok(0)
    }
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum MeshCmd {
    /// Run the shared native mesh service from a JSON configuration, including
    /// private token files, DNS and operator-supplied TLS certificates.
    Run {
        #[arg(long)]
        service_config: std::path::PathBuf,
    },
    /// Mint a fresh preauth key. Writes the key to stdout as a single
    /// line — easy to consume from a shell harness:
    ///
    ///   KEY=$(octravpn-node mesh mint-preauth --user alice)
    ///   tailscale up --login-server http://… --authkey "$KEY"
    ///
    /// Two modes:
    ///
    /// 1. **Local (default)** — `mesh mint-preauth --user alice`.
    ///    The key is generated in-process (no daemon contact) and
    ///    printed to stdout. Suitable for shell scripting and for
    ///    satisfying the interop test's "reachable surface" probe,
    ///    but cannot authorise a real `tailscale up` join because
    ///    the running daemon doesn't know about the key.
    ///
    /// 2. **Daemon-bound (remote)** — pass both `--remote <URL>` and
    ///    `--admin-token <TOKEN>`. The CLI POSTs to
    ///    `<remote>/admin/preauth` with `Authorization: Bearer
    ///    <token>`; the running daemon stores a hashed key in its durable
    ///    enrollment database and accepts it through the wire registration
    ///    path used by `tailscale up --authkey "$KEY"`. The key is printed
    ///    to stdout in the same shape as the local mode so existing
    ///    shell scripts work unchanged.
    MintPreauth {
        /// User label to bind the minted key to.
        #[arg(long, default_value = "default")]
        user: String,
        /// Mark the key as reusable (off by default — matches
        /// Tailscale's safer single-use default).
        #[arg(long)]
        reusable: bool,
        /// TTL in seconds. Defaults to `DEFAULT_PREAUTH_TTL` (1 h).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Optional. When set, switches to the daemon-bound mint
        /// path: POST to `<URL>/admin/preauth` instead of minting
        /// locally. Pair with `--admin-token`. Example:
        /// `--remote http://127.0.0.1:51821`.
        #[arg(long, requires = "admin_token")]
        remote: Option<String>,
        /// Bearer token for the daemon's admin surface. Required
        /// when `--remote` is set (and only meaningful then). Maps
        /// to `[control].admin_token` in the daemon's `node.toml`.
        #[arg(long, requires = "remote")]
        admin_token: Option<String>,
    },
    /// Run a minimal Tailscale-wire control plane (no chain / wallet
    /// dependencies). Used by the
    /// `docker/devnet/tailscale-interop/run-interop.sh` harness so a
    /// stock `tailscale up` can `GET /key`, `POST /machine/.../register`,
    /// `POST /machine/.../map` without bringing up the full Hub.
    ///
    /// Mounts in one process:
    ///   - `GET /key` + `POST /machine/.../register` + `POST /machine/.../map`
    ///     (the Tailscale-wire surface — `tailscale_wire_router`).
    ///   - `POST /admin/preauth` for minting keys over HTTP (bearer
    ///     token from `--admin-token` or `OCTRAVPN_ADMIN_TOKEN`).
    ///
    /// Admin minting and wire redemption share one persistent key store.
    Serve {
        /// `host:port` to listen on for plain HTTP. Defaults to
        /// `127.0.0.1:51821`; set an explicit public address for
        /// docker interop harnesses or remote clients.
        #[arg(long, default_value = "127.0.0.1:51821")]
        listen: String,
        /// `host:port` for the rustls-terminated HTTPS listener. Stock
        /// `tailscale up` v1.78+ forces a parallel HTTPS-on-443 dial
        /// after its initial /key probe; absent a TLS terminator the
        /// flow stalls before reaching `/machine/register`. Pass the
        /// empty string to disable (useful for hosts that can't bind
        /// :443).
        #[arg(long, default_value = "")]
        https_listen: String,
        /// SAN hostname embedded in the self-signed cert. Should match
        /// whatever the client resolves the login-server to (typically
        /// the docker service name, e.g. `tsi-mesh-control`).
        #[arg(long, default_value = "localhost")]
        cert_hostname: String,
        /// Directory for the Noise long-term static key + future wire
        /// state. Defaults to `./state/tailscale-wire`.
        #[arg(long, default_value = "./state/tailscale-wire")]
        state_dir: String,
        /// Tailnet identifier (drives the IP allocator).
        #[arg(long, default_value = "octravpn-interop")]
        tailnet_id: String,
        /// Bearer token for `/admin/preauth`. Falls back to the
        /// `OCTRAVPN_ADMIN_TOKEN` env var when unset.
        #[arg(long)]
        admin_token: Option<String>,
        /// Serve DERP natively on `/derp` through the same HTTPS
        /// listener and certificate as the control surface. Defaults
        /// off; the existing Go derper sidecar path remains unchanged
        /// unless this flag is set.
        #[arg(long = "serve-derp")]
        serve_derp: bool,
        /// Item 4: enforce this circle's anchored member set on the wire.
        /// Builds a chain context from `--config`'s `[chain]` table; the
        /// sealed passphrase comes from `OCTRAVPN_SEALED_PASSPHRASE` or
        /// `[chain].sealed_passphrase`. Absent ⇒ allow-all (unchanged).
        #[arg(long)]
        members_policy_circle: Option<String>,
        /// Enforce the personal tailnet's own member root instead of the
        /// registered operator Circle's /auth/members.json anchor. The
        /// Circle named above stores /tailnet-{id}/members.json.
        #[arg(long, requires = "members_policy_circle")]
        members_policy_tailnet_id: Option<u64>,
        /// Wallet that currently owns the personal tailnet. Distinct from
        /// the Circle address hosting its sealed member asset.
        #[arg(long, requires = "members_policy_tailnet_id")]
        members_policy_owner: Option<String>,
        /// Sync period for `--members-policy-circle`, seconds (default:
        /// `[control.members_policy].sync_period_secs`, i.e. 10).
        #[arg(long)]
        members_policy_period_secs: Option<u64>,
    },
    /// Wrap `GET /api/v1/machines` on the remote mesh-control admin
    /// surface — prints the current tailnet roster. Same auth posture
    /// as `mesh serve`'s `--admin-token` (bearer-gated).
    ///
    /// Equivalent to `headscale nodes list` from the sibling repo's
    /// CLI, but bound to octravpn-node so operators don't need the
    /// sibling repo installed.
    Status(mesh_ops::MeshStatusArgs),
    /// Wrap the `/api/v1/policy{,/validate}` admin CRUD surface.
    /// Subcommands:
    ///
    ///   * `get` — fetch the live hujson policy (optionally to file).
    ///   * `set --file <doc>` — PUT a new policy; takes effect within
    ///     ~1ms (the policy store's `Notify` wakes parked `/map`
    ///     long-pollers).
    ///   * `validate --file <doc>` — parse-only validation; never
    ///     mutates the live store.
    Policy {
        #[command(subcommand)]
        cmd: mesh_ops::MeshPolicyCmd,
    },
}

/// Dispatch a `mesh …` subcommand. Lives outside `dispatch` so future
/// subcommands (e.g. `mesh acl push`, `mesh peers list`) can drop in
/// next to `MintPreauth` without expanding the giant top-level match.
/// Returns `Result<()>` (rather than `()`) so future subcommands that
/// *do* fail (chain-touching ones) can `?`-propagate without a
/// signature change. The current single arm is infallible — clippy
/// allow is intentional.
#[allow(clippy::unnecessary_wraps)]
pub(crate) async fn run_mesh_cmd(sub: MeshCmd, cfg_path: &str) -> Result<()> {
    match sub {
        MeshCmd::Run { service_config } => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&service_config)?
                .take(65_537)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 65_536, "mesh configuration exceeds 64 KiB");
            let mut config: crate::mesh_control::Config = serde_json::from_slice(&bytes)?;
            config.resolve_paths(
                std::fs::canonicalize(service_config)?
                    .parent()
                    .context("mesh configuration directory")?,
            );
            run_bound_service(config.bind().await?).await
        }
        MeshCmd::MintPreauth {
            user,
            reusable,
            ttl_secs,
            remote,
            admin_token,
        } => {
            // Remote (daemon-bound) path: clap's `requires` keeps
            // these in lock-step — if one is set, the other must
            // be too, so we can match on `remote` and trust
            // `admin_token` is present.
            if let Some(remote_url) = remote {
                let token = admin_token.expect(
                    "clap `requires = \"admin_token\"` should have rejected `--remote` \
                     without `--admin-token`",
                );
                let minted = run_remote_mint(&remote_url, &token, &user, reusable, ttl_secs)
                    .await
                    .with_context(|| format!("daemon-bound mint via {remote_url}"))?;
                // Same stdout/stderr split as the local path so
                // `KEY=$(octravpn-node mesh mint-preauth ...)` keeps
                // working byte-identically.
                eprintln!(
                    "minted preauth (remote): user={} reusable={} expires_at={}",
                    minted.user, minted.reusable, minted.expires_at
                );
                println!("{}", minted.key);
                return Ok(());
            }

            use octravpn_mesh::{PreauthMinter, DEFAULT_PREAUTH_TTL};
            let ttl = ttl_secs.map_or(DEFAULT_PREAUTH_TTL, std::time::Duration::from_secs);
            let minter = PreauthMinter::new();
            let pk = minter.mint(&user, ttl, reusable);
            // Single-line stdout output so the harness can capture
            // with `KEY=$(octravpn-node mesh mint-preauth --user u)`.
            // Everything else (user, expiry) goes to stderr so it
            // doesn't pollute the captured value.
            eprintln!(
                "minted preauth: user={} reusable={} expires_at={}",
                pk.user, pk.reusable, pk.expires_at
            );
            println!("{}", pk.key);
            Ok(())
        }
        MeshCmd::Serve {
            listen,
            https_listen,
            cert_hostname,
            state_dir,
            tailnet_id,
            admin_token,
            serve_derp,
            members_policy_circle,
            members_policy_tailnet_id,
            members_policy_owner,
            members_policy_period_secs,
        } => {
            // Resolved before the listeners come up so a bad circle /
            // missing passphrase fails the command instead of leaving a
            // wire that silently allows everyone.
            let members_policy = match members_policy_circle {
                Some(circle) => {
                    let cfg = crate::config::NodeConfig::load(cfg_path)?;
                    Some(crate::members_policy::MembersPolicySync::from_config(
                        &cfg,
                        Some(circle),
                        members_policy_tailnet_id,
                        members_policy_owner,
                        members_policy_period_secs,
                    )?)
                }
                None => None,
            };
            run_mesh_serve(
                listen,
                https_listen,
                cert_hostname,
                state_dir,
                tailnet_id,
                admin_token,
                serve_derp,
                members_policy,
            )
            .await
        }
        // Remote control surface. Sync entry points (each builds its
        // own current-thread runtime) — exit codes propagate via
        // `std::process::exit` so a non-zero remote response surfaces
        // to the operator's shell.
        //
        // DEPRECATED: scheduled for removal 2026-Q3. Use
        // `octravpn-node headscale nodes list` /
        // `octravpn-node headscale policy {get,set,check}` — same
        // backend, byte-identical output. The warning is printed
        // unconditionally to stderr so cron / harness scripts surface
        // the migration TODO; stdout remains untouched for byte-diff
        // compatibility with the pre-deprecation contract. See
        // `docs/operators/cli-migration.md`.
        MeshCmd::Status(args) => {
            eprintln!(
                "WARN: 'octravpn-node mesh status' is deprecated; use \
                 'octravpn-node headscale nodes list' instead \
                 (removal scheduled 2026-Q3)"
            );
            let code = mesh_ops::run_status(args).await?;
            std::process::exit(code);
        }
        MeshCmd::Policy { cmd } => {
            eprintln!(
                "WARN: 'octravpn-node mesh policy' is deprecated; use \
                 'octravpn-node headscale policy {{get|set|check}}' instead \
                 (removal scheduled 2026-Q3)"
            );
            let code = mesh_ops::run_policy(cmd).await?;
            std::process::exit(code);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_mesh_serve(
    listen: String,
    https_listen: String,
    cert_hostname: String,
    state_dir: String,
    tailnet_id: String,
    admin_token: Option<String>,
    serve_derp: bool,
    members_policy: Option<crate::members_policy::MembersPolicySync>,
) -> Result<()> {
    let config = crate::mesh_control::Config {
        http_addr: Some(listen.parse().context("parse mesh HTTP address")?),
        https_addr: if https_listen.is_empty() {
            None
        } else {
            Some(https_listen.parse().context("parse mesh HTTPS address")?)
        },
        hostname: cert_hostname,
        state_dir: state_dir.into(),
        tailnet_id,
        serve_derp,
        derp_map: std::env::var_os("OCTRAVPN_DERP_MAP_PATH")
            .filter(|path| !path.is_empty())
            .map(Into::into),
        ..Default::default()
    };
    let token = admin_token
        .or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok())
        .map(std::sync::Arc::from);
    let service =
        crate::mesh_control::bind(config, token, members_policy, load_knock_cfg_from_env()?)
            .await?;
    run_bound_service(service).await
}

async fn run_bound_service(service: crate::mesh_control::Service) -> Result<()> {
    eprintln!(
        "mesh serve: HTTP={:?} HTTPS={:?}",
        service.http_addr, service.https_addr
    );
    if let Some(cert) = &service.certificate {
        eprintln!(
            "mesh serve: trust TLS certificate {} in clients",
            cert.display()
        );
    }
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stop.send_replace(true);
    });
    service.run(shutdown).await
}

/// Outcome of a successful daemon-bound preauth mint. Mirrors the
/// `POST /admin/preauth` response envelope (see
/// `crates/octravpn-node/src/control/handlers/preauth.rs::MintPreauthResponse`)
/// so the CLI's stdout shape matches the local path byte-for-byte
/// (single line `key`; user/reusable/expires_at go to stderr).
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct RemoteMintOutcome {
    pub(crate) key: String,
    pub(crate) user: String,
    pub(crate) reusable: bool,
    pub(crate) expires_at: u64,
}

/// Daemon-bound preauth mint. POSTs JSON to `<remote>/admin/preauth`
/// with a bearer token; on 2xx parses the `{key, user, reusable,
/// expires_at}` envelope. Non-2xx and transport errors are mapped to
/// operator-friendly messages here so the parent CLI can `?`-propagate
/// straight to stderr.
///
/// Both native mesh listeners honor `ttl_secs`; absent/null uses the default.
pub(crate) async fn run_remote_mint(
    remote: &str,
    admin_token: &str,
    user: &str,
    reusable: bool,
    ttl_secs: Option<u64>,
) -> Result<RemoteMintOutcome> {
    use anyhow::{anyhow, bail};
    use std::time::Duration;

    let url = {
        let trimmed = remote.trim_end_matches('/');
        format!("{trimmed}/admin/preauth")
    };

    // Match the mesh_ops `build_client` posture: 5s timeout, accept
    // self-signed certs on loopback so the same daemon's HTTPS surface
    // works without `--insecure` ergonomics. Bare-bones (no knock
    // header — the daemon's `/admin/preauth` route is bearer-gated, not
    // knock-gated).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| anyhow!("build http client: {e}"))?;

    let body = serde_json::json!({
        "user": user,
        "reusable": reusable,
        "ttl_secs": ttl_secs,
    });

    let resp = client
        .post(&url)
        .bearer_auth(admin_token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| {
            // reqwest::Error::is_connect() catches the "daemon not
            // running" case; anything else (DNS, timeout) bubbles up
            // with the underlying message.
            if e.is_connect() {
                anyhow!("daemon at {remote} not reachable: {e}")
            } else {
                anyhow!("POST {url} failed: {e}")
            }
        })?;

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        match status.as_u16() {
            // The daemon's BearerCheck::Hidden returns 404 for every
            // auth-rejection mode, but operators sometimes also stand
            // up the surface behind a reverse proxy that returns 401;
            // and `BearerCheck::Strict` (config: `admin_hidden = false`)
            // does return real 401s. Map both shapes.
            401 | 403 => bail!(
                "admin token rejected (check [control].admin_token in node.toml on the daemon at {remote})"
            ),
            // 404 is ambiguous: Hidden-mode auth failure looks identical
            // to "admin surface disabled". Bias the message towards the
            // most common ops mistake (missing token in node.toml), and
            // include the body for debugging.
            404 => bail!(
                "POST {url}: 404 — either the admin surface is disabled \
                 (daemon started without [control].admin_token) or the bearer \
                 was rejected in Hidden-mode. Body: {}",
                trim_body(&body_text, 200)
            ),
            503 => bail!(
                "admin surface disabled — daemon was started without [control].admin_token set"
            ),
            _ => bail!(
                "POST {url}: {status}: {}",
                trim_body(&body_text, 200)
            ),
        }
    }

    serde_json::from_str::<RemoteMintOutcome>(&body_text)
        .with_context(|| format!("parse mint response body: {}", trim_body(&body_text, 200)))
}

fn trim_body(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Load the PSK-gated handshake config from the operator environment.
///
/// Source of truth:
///   1. `OCTRAVPN_KNOCK_ENABLED` (any non-empty value enables)
///   2. `OCTRAVPN_KNOCK_PSK` (base64-encoded 32-byte secret)
///   3. `OCTRAVPN_KNOCK_WINDOW_SECS` (optional, defaults to 60)
///
/// Defaults to disabled when the env vars are absent — keeps existing
/// deployments backward-compatible. See `docs/operators/tls-rotation.md`
/// §"PSK-gated control plane" for the operator playbook.
fn load_knock_cfg_from_env() -> Result<octravpn_mesh::tailscale_wire::KnockConfig> {
    let enabled = std::env::var("OCTRAVPN_KNOCK_ENABLED")
        .is_ok_and(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"));
    if !enabled {
        return Ok(octravpn_mesh::tailscale_wire::KnockConfig::disabled());
    }
    let raw =
        std::env::var("OCTRAVPN_KNOCK_PSK").context("knock enabled without OCTRAVPN_KNOCK_PSK")?;
    let psk = octravpn_mesh::knock::decode_psk(raw.trim()).context("invalid knock PSK")?;
    let window_secs = std::env::var("OCTRAVPN_KNOCK_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(octravpn_mesh::tailscale_wire::knock::DEFAULT_WINDOW_SECS);
    eprintln!("mesh serve: PSK-gated handshake ENABLED (window={window_secs}s)");
    let mut cfg = octravpn_mesh::tailscale_wire::KnockConfig::enabled(psk);
    cfg.window_secs = window_secs;
    Ok(cfg)
}
