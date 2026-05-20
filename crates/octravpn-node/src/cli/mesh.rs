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
    /// The key is generated locally (no daemon contact) and is
    /// suitable for emitting to an operator. Cross-process binding
    /// (so a running daemon's coordination plane would accept the
    /// key) requires the persistent minter from
    /// `docs/tailscale-interop-blocker.md`; until that lands, this
    /// subcommand is fine for satisfying the interop test's "is the
    /// preauth surface reachable" probe but cannot, on its own,
    /// authorise a real tailscale join.
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
        } => {
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
    let ws = WireState {
        server_noise_key: server_noise_key.clone(),
        preauth: Arc::new(minter.clone()),
        ip_allocator: Arc::new(TailnetIpAllocator::new(tailnet_id)),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(derp_map),
        // P1-policy: empty store ⇒ wire layer falls back to
        // `allow_all_packet_filter`. The admin surface (when
        // mounted) holds an `Arc` clone of this store and uses
        // PUT to push hujson docs; the store's `Notify` wakes
        // parked `/map` long-pollers within ~1 ms.
        policy: Arc::new(octravpn_mesh::policy::PolicyStore::new()),
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
    let admin_ctx = AdminCtx {
        minter,
        token: admin_token.map(Arc::from),
    };
    let admin_router = Router::new()
        .route("/admin/preauth", post(mint_handler))
        .with_state(admin_ctx);

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
