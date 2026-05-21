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
    async fn dispatch(self, _ctx: CliContext<'_>) -> Result<i32> {
        run_mesh_cmd(self.sub).await?;
        Ok(0)
    }
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum MeshCmd {
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
    ///    <token>`; the running daemon's persistent `PreauthMinter`
    ///    materialises the key so it survives across process
    ///    boundaries and is honoured by a real
    ///    `tailscale up --authkey "$KEY"`. The minted key is printed
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
    /// Both surfaces share one `PreauthMinter` so a key minted over
    /// HTTP is immediately redeemable through `register`.
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
pub(crate) async fn run_mesh_cmd(sub: MeshCmd) -> Result<()> {
    match sub {
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
        } => {
            run_mesh_serve(
                listen,
                https_listen,
                cert_hostname,
                state_dir,
                tailnet_id,
                admin_token,
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

/// Hub-free wire surface entry point. See `MeshCmd::Serve` for the
/// rationale.
async fn run_mesh_serve(
    listen: String,
    https_listen: String,
    cert_hostname: String,
    state_dir: String,
    tailnet_id: String,
    admin_token: Option<String>,
) -> Result<()> {
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Json, Router,
    };
    use octravpn_mesh::{
        ip_alloc::TailnetIpAllocator,
        tailscale_wire::{
            derp_config::{empty_derp_map, load_derp_map},
            serve::{serve as wire_serve, ServeConfig},
            tls::SanConfig,
            MachineRegistry,
        },
        PreauthMinter, ServerNoiseKey, WireState, DEFAULT_PREAUTH_TTL,
    };
    use serde::{Deserialize, Serialize};
    use std::{net::SocketAddr, sync::Arc};

    // Admin token resolution: explicit > env > absent.
    let admin_token = admin_token.or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok());

    let server_noise_key = Arc::new(
        ServerNoiseKey::load_or_generate(&state_dir)
            .context("load tailscale_wire noise static key")?,
    );
    let minter = PreauthMinter::new();
    // Wall 6: optional DERP-map fixture for the interop harness. The
    // env var points at a JSON file in the same shape as the on-wire
    // `DerpMap`. Unset (the production default) ⇒ empty map ⇒ same
    // behaviour as pre-Wall-6. See
    // `docs/tailscale-interop-blocker.md` 2026-05-19 §"Wall 6 closed".
    let derp_map = match std::env::var("OCTRAVPN_DERP_MAP_PATH") {
        Ok(path) if !path.is_empty() => {
            let map = load_derp_map(std::path::Path::new(&path))
                .with_context(|| format!("load DERP map from {path}"))?;
            eprintln!(
                "mesh serve: loaded DERP map from {path} ({} region(s))",
                map.regions.len()
            );
            map
        }
        _ => empty_derp_map(),
    };
    // Shared handles: the wire layer + the admin router both need to
    // see the same `MachineRegistry` (so `GET /api/v1/machines` reflects
    // the real wire roster) and the same `PolicyStore` (so
    // `PUT /api/v1/policy` lands a doc the wire `/map` handler will see
    // on its next poll). Cloning the `Arc`s is the standard headscale-rs
    // wiring — see `tests/policy_e2e.rs` for the in-process proof.
    let machines = Arc::new(MachineRegistry::new());
    let policy = octravpn_mesh::policy::PolicyStore::new();
    let ws = WireState {
        server_noise_key: server_noise_key.clone(),
        preauth: Arc::new(minter.clone()),
        ip_allocator: Arc::new(TailnetIpAllocator::new(tailnet_id)),
        machines: machines.clone(),
        derp_map: Arc::new(derp_map),
        // P1-policy: empty store ⇒ wire layer falls back to
        // `allow_all_packet_filter`. The admin surface (when
        // mounted) holds an `Arc` clone of this store and uses
        // PUT to push hujson docs; the store's `Notify` wakes
        // parked `/map` long-pollers within ~1 ms.
        policy: Arc::new(policy.clone()),
        // PSK-gated handshake (layer 3 of the active-probe shield).
        // Default-disabled — operators opt in via
        // `[control.knock] enabled = true` in node.toml, with the PSK
        // distributed out-of-band alongside the preauth key. See
        // `docs/operators/tls-rotation.md` §"PSK-gated control plane".
        knock: load_knock_cfg_from_env(),
        dns: Arc::new(octravpn_mesh::headscale_api::dns::DnsStore::new()),
    };

    eprintln!(
        "mesh serve: noise pubkey mkey:{} listen={listen}",
        server_noise_key.public_hex()
    );

    // /admin/preauth shim for the harness. Kept identical to the
    // ControlState handler's behaviour (404 when no token, 404 on
    // wrong token, 200+JSON on success) so the run-interop.sh probe
    // succeeds.
    #[derive(Clone)]
    struct AdminCtx {
        minter: PreauthMinter,
        token: Option<Arc<str>>,
    }
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    struct AdminReq {
        #[serde(default = "default_user")]
        user: String,
        #[serde(default)]
        reusable: bool,
    }
    fn default_user() -> String {
        "default".into()
    }
    #[derive(Serialize)]
    struct AdminResp {
        key: String,
        user: String,
        expires_at: u64,
        reusable: bool,
    }
    async fn mint_handler(
        State(ctx): State<AdminCtx>,
        headers: HeaderMap,
        body: Option<Json<AdminReq>>,
    ) -> impl IntoResponse {
        let Some(want) = ctx.token.as_deref() else {
            return (StatusCode::NOT_FOUND, "").into_response();
        };
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        let authed = got.is_some_and(|t| t == want);
        if !authed {
            return (StatusCode::NOT_FOUND, "").into_response();
        }
        let req = body.map(|Json(b)| b).unwrap_or_default();
        let pk = ctx.minter.mint(req.user, DEFAULT_PREAUTH_TTL, req.reusable);
        Json(AdminResp {
            key: pk.key,
            user: pk.user,
            expires_at: pk.expires_at,
            reusable: pk.reusable,
        })
        .into_response()
    }
    // Share the bearer token between the two admin sub-routers (the
    // legacy `POST /admin/preauth` shim + the unified
    // `/api/v1/{machines,policy,...}` surface built below). Cloning
    // the `Arc<str>` is cheap — both layers run the same byte-stable
    // 404 reject path on missing / wrong tokens.
    let admin_token_arc: Option<Arc<str>> = admin_token.map(Arc::from);
    let admin_ctx = AdminCtx {
        minter: minter.clone(),
        token: admin_token_arc.clone(),
    };
    let legacy_preauth_router = Router::new()
        .route("/admin/preauth", post(mint_handler))
        .with_state(admin_ctx);

    // Unified admin surface — same routes the full Hub would mount
    // (`/api/v1/machines` for the roster, `/api/v1/policy{,/validate}`
    // for the live ACL store, `/api/v1/preauthkeys` for HTTP mint /
    // expire, plus the operator HTML pages at `/admin/...`). Shares the
    // `MachineRegistry` + `PolicyStore` constructed above with the wire
    // layer, so `mesh status` / `mesh policy get` reflect (and mutate)
    // the live state seen by `/map`.
    //
    // Wrapped in `octravpn_mesh::build_admin_router`, which layers a
    // hidden-policy `BearerCheck` on top so every failed-auth response
    // is byte-stable `(404, NGINX_404_BODY)` — preserves the Audit-3
    // H-1 invariant `BearerCheck::Hidden` already enforces for
    // `/admin/preauth` and `/events`.
    let unified_admin_router = {
        let admin_state = octravpn_mesh::admin_surface::AdminState::builder()
            .bearer_token(admin_token_arc.as_deref().unwrap_or("").to_string())
            .users(octravpn_mesh::headscale_api::admin::UserRegistry::new())
            .machines(Arc::new(
                octravpn_mesh::headscale_api::admin::WireMachineAdmin::new(machines.clone()),
            ))
            .preauth(Arc::new(
                octravpn_mesh::headscale_api::admin::InMemoryPreauthAdmin::new(),
            ))
            .derp_regions(0)
            .policy(policy.clone())
            .build();
        octravpn_mesh::admin_surface::build_admin_router(admin_state, admin_token_arc.clone())
    };

    let admin_router = legacy_preauth_router.merge(unified_admin_router);

    // Dual-bind: plain HTTP on `listen` for /admin/preauth + curl
    // probes; rustls-terminated HTTPS on `https_listen` for the
    // forced-443 dial stock Tailscale clients make. Pass an empty
    // string to https_listen to skip TLS (useful on hosts that can't
    // bind 443).
    let http_addr: SocketAddr = listen.parse().context("parse http listen addr")?;
    let https_addr: Option<SocketAddr> = if https_listen.is_empty() {
        None
    } else {
        Some(https_listen.parse().context("parse https listen addr")?)
    };

    let cfg = ServeConfig {
        http_addr,
        https_addr,
        state_dir: std::path::PathBuf::from(&state_dir),
        sans: SanConfig::with_hostname(&cert_hostname),
    };
    let handle = wire_serve(ws, cfg, admin_router)
        .await
        .context("mesh serve: bind wire surface")?;
    if let Some(tls) = handle.tls.as_ref() {
        eprintln!(
            "mesh serve: HTTPS listening on {} (cert={}, key={})",
            https_addr.unwrap(),
            tls.cert_path.display(),
            tls.key_path.display()
        );
        eprintln!("mesh serve: trust the cert in peer containers with `update-ca-certificates`");
    }
    eprintln!("mesh serve: HTTP listening on {http_addr}");

    // Wait for whichever listener exits first. Either bubbling up an
    // error is fine — the harness teardown handles container restart.
    let http_fut = handle.http;
    let https_fut = handle.https;
    match https_fut {
        Some(https_fut) => {
            tokio::select! {
                r = http_fut => r.context("mesh serve: http listener")?
                    .context("mesh serve: http accept")?,
                r = https_fut => r.context("mesh serve: https listener")?
                    .context("mesh serve: https accept")?,
            };
        }
        None => {
            http_fut
                .await
                .context("mesh serve: http listener")?
                .context("mesh serve: http accept")?;
        }
    }
    Ok(())
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
/// `ttl_secs` is best-effort: the current daemon handler hard-codes
/// `DEFAULT_PREAUTH_TTL` and ignores any TTL field in the body. We
/// still send it (named `ttl_secs`, matching the contract the operator
/// docs advertise) so a future daemon-side patch can pick it up
/// without a wire-format break.
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
fn load_knock_cfg_from_env() -> octravpn_mesh::tailscale_wire::KnockConfig {
    let enabled = std::env::var("OCTRAVPN_KNOCK_ENABLED")
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);
    if !enabled {
        return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
    }
    let Ok(raw) = std::env::var("OCTRAVPN_KNOCK_PSK") else {
        eprintln!(
            "mesh serve: OCTRAVPN_KNOCK_ENABLED set but OCTRAVPN_KNOCK_PSK missing; \
             knock layer DISABLED (would otherwise reject every connection)"
        );
        return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
    };
    let psk = match octravpn_mesh::knock::decode_psk(raw.trim()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mesh serve: OCTRAVPN_KNOCK_PSK decode failed ({e}); knock layer DISABLED");
            return octravpn_mesh::tailscale_wire::KnockConfig::disabled();
        }
    };
    let window_secs = std::env::var("OCTRAVPN_KNOCK_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(octravpn_mesh::tailscale_wire::knock::DEFAULT_WINDOW_SECS);
    eprintln!("mesh serve: PSK-gated handshake ENABLED (window={window_secs}s)");
    let mut cfg = octravpn_mesh::tailscale_wire::KnockConfig::enabled(psk);
    cfg.window_secs = window_secs;
    cfg
}
