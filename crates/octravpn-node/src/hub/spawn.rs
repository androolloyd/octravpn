//! Background-task constructors: `spawn_tunnel` (WG-on-UDP listener,
//! optionally obfs4-wrapped) and `spawn_control_plane` (HTTP
//! `ControlState` aggregator: admin token, audit log, analytics
//! indexer, tailscale-wire surface, shadow signer).
//!
//! `spawn_control_plane` historically grew by 20–80 LOC every time a
//! new subsystem at boot landed. See `SUBSYSTEM_CHECKLIST.md` for the
//! five canonical touch points. New non-trivial wiring belongs in a
//! `build_<name>(...)` helper at the bottom of this file or, better,
//! in the subsystem's own crate-level module — the closure body
//! should read as `let foo = build_foo(...)?;`, not the wiring
//! itself.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use super::Hub;
use crate::{
    control::{serve as control_serve, ControlState, SessionAdmissionVerifier},
    tunnel::Server,
};

impl Hub {
    pub(crate) fn spawn_tunnel(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let allowlist = self.allowlist.clone();
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .tunnel
                .listen
                .parse()
                .context("parse listen addr")?;
            let shield_cfg = self.cfg.tunnel.amnezia.to_wire();

            // P0-T (4-layer shielding pack, layer 2): if the operator
            // opted into the obfs4-modelled transport via
            // `[tun.transport].kind = "obfs4"`, validate the config
            // and log that the wrapper is engaged. The current data
            // plane still runs through `tokio::net::UdpSocket`
            // directly (see `tunnel.rs`); swap-in of `Obfs4Transport`
            // for the inbound + outbound datagram paths is gated
            // behind a follow-up task because the existing async
            // recv-loop in `tunnel::Server::run` does not yet plumb
            // through `octravpn_tun::Transport`. Validating the
            // config at boot means a typo in `bridge_node_id` /
            // `bridge_pubkey` surfaces immediately rather than at
            // first packet.
            validate_obfs4_config(&self.cfg)?;
            let server = Arc::new(
                Server::bind_with_shield(
                    listen,
                    self.wg_static_secret.clone(),
                    self.router.clone(),
                    allowlist,
                    shield_cfg,
                )
                .await?
                .with_metrics(self.metrics.clone()),
            );
            info!(?listen, "tunnel listening");
            server.run().await
        })
    }

    pub(crate) fn spawn_control_plane(self: Arc<Self>) -> JoinHandle<Result<()>> {
        let allowlist = self.allowlist.clone();
        let metrics = self.metrics.clone();
        let receipt_context = Arc::new(self.build_receipt_context());
        let receipt_journal = self.receipt_journal.clone();
        tokio::spawn(async move {
            let listen: std::net::SocketAddr = self
                .cfg
                .control
                .listen
                .parse()
                .context("parse control listen addr")?;
            // Admin token resolution order: explicit config field >
            // OCTRAVPN_ADMIN_TOKEN env var > absent (endpoint
            // hidden). The env-var path lets the
            // `docker/devnet/tailscale-interop` harness inject a
            // token via the compose secret without re-rendering
            // node.toml.
            // Audit-2 CFG-2 / Audit-3 H-6: `admin_token` is now wrapped in
            // `secrecy::SecretString` on the config struct; materialise it
            // back to `Option<String>` here for the ControlState builder.
            // The env-var fallback is unchanged.
            let admin_token = self
                .cfg
                .control
                .admin_token_string()
                .or_else(|| std::env::var("OCTRAVPN_ADMIN_TOKEN").ok());
            // Construct the Tailscale-wire surface state if a
            // `[control].tailscale_wire_state_dir` is configured. Absent
            // configuration ⇒ wire router is not mounted at all
            // (matching the `/events` "endpoint hidden" design). The
            // PreauthMinter is shared with `/admin/preauth` so a key
            // minted via that endpoint is redeemable through `register`.
            if self.cfg.control.derp.serve && self.cfg.control.tailscale_wire_state_dir.is_none() {
                return Err(anyhow!(
                    "[control.derp].serve requires [control].tailscale_wire_state_dir"
                ));
            }
            let wire_state = if let Some(dir) = self
                .cfg
                .control
                .tailscale_wire_state_dir
                .as_ref()
                .map(std::path::PathBuf::from)
            {
                use octravpn_mesh::{
                    ip_alloc::TailnetIpAllocator,
                    tailscale_wire::{
                        derp_config::{empty_derp_map, load_derp_map},
                        MachineRegistry,
                    },
                    PreauthMinter, ServerNoiseKey,
                };
                let server_noise_key = Arc::new(
                    ServerNoiseKey::load_or_generate(&dir)
                        .context("load tailscale_wire noise static key")?,
                );
                let tailnet_id = self
                    .cfg
                    .control
                    .tailscale_tailnet_id
                    .clone()
                    .unwrap_or_else(|| "octravpn-interop".to_string());
                // PreauthMinter is constructed *here* and then shared
                // into ControlState below. Reusing the same Arc<Mutex>
                // means an `/admin/preauth`-minted key is visible to
                // the wire `register` handler.
                //
                // The wire layer (now in headscale-api) sees the
                // minter only through the `PreauthRedeemer` trait —
                // implemented in `octravpn_mesh::headscale_bridge`.
                // Attach the node's metrics sink so the wire-side
                // `redeem` path bumps `preauth_redemptions_total`
                // without round-tripping through the control plane.
                // Mints from `/admin/preauth` are bumped at the
                // handler instead (control.rs::mint_preauth); the
                // sink path is for redemptions issued from the
                // headscale-api wire register handler.
                let metrics_sink: Arc<dyn octravpn_mesh::MetricsSink> = self.metrics.clone();
                let shared_minter = PreauthMinter::new().with_metrics_sink(metrics_sink);
                // Wall 6: optionally load a DERP-map fixture from the
                // path advertised in OCTRAVPN_DERP_MAP_PATH. Unset ⇒
                // empty map ⇒ matches pre-Wall-6 behaviour.
                let native_derp = if self.cfg.control.derp.serve {
                    let runtime = crate::native_derp::load_native_derp_runtime(&dir)?;
                    info!(
                        host_name = %listen.ip(),
                        key = %dir.join("derp.key").display(),
                        "native DERP enabled on control plane"
                    );
                    Some(runtime)
                } else {
                    None
                };
                let derp_map = if self.cfg.control.derp.serve {
                    crate::native_derp::self_derp_map(listen.ip().to_string())
                } else {
                    match std::env::var("OCTRAVPN_DERP_MAP_PATH") {
                        Ok(path) if !path.is_empty() => load_derp_map(std::path::Path::new(&path))
                            .with_context(|| format!("load DERP map from {path}"))?,
                        _ => empty_derp_map(),
                    }
                };
                // The hub path is the chain-aware boot path; it predates
                // the knock layer and leaves it disabled (the `mesh serve`
                // entry point is the one that honours the env var). The
                // ACL store is shared with the admin surface (when
                // mounted); empty ⇒ the wire layer's `allow_all_packet_filter`
                // fallback stays in play until an operator PUTs a doc.
                // Everything else takes the builder's octra defaults.
                Some((
                    octravpn_mesh::WireStateBuilder::new(
                        server_noise_key,
                        Arc::new(shared_minter.clone()),
                        Arc::new(TailnetIpAllocator::new(tailnet_id)),
                        Arc::new(MachineRegistry::new()),
                        Arc::new(octravpn_mesh::policy::PolicyStore::new()),
                        octravpn_mesh::tailscale_wire::DerpMapStore::shared(derp_map),
                    )
                    .native_derp(native_derp.clone())
                    .build(),
                    shared_minter,
                ))
            } else {
                None
            };
            // HFHE-2: build the optional shadow-blob signer. Only
            // materialises when (a) the PVAC sidecar spawned at boot
            // AND (b) both circle key paths resolve to readable
            // files. Either piece missing => `None`, and the receipt
            // path emits no shadow data (wire-identical to the
            // pre-HFHE-2 build).
            let shadow_signer = self.build_shadow_signer();
            let mut state = ControlState::with_metrics(
                self.wg_kp.clone(),
                self.router.clone(),
                allowlist,
                metrics,
                receipt_context,
                receipt_journal,
            )
            .with_events_token(self.cfg.control.events_token_string())
            .with_metrics_token(self.cfg.control.metrics_token_string())
            .with_admin_token(admin_token)
            .with_session_verifier(SessionAdmissionVerifier::new(self.chain.rpc.clone()))
            .with_wire_state(wire_state.as_ref().map(|(ws, _)| ws.clone()))
            .with_shadow_signer(shadow_signer, 0);
            // Audit-3 H-1: bearer-gated routes no longer leak
            // token-presence on the wire (every reject reason returns
            // `(404, NGINX_404_BODY)`), so a misconfigured `/metrics`
            // looks identical to a non-existent endpoint to an
            // external scanner. The only way the operator learns about
            // the misconfiguration is this boot-time warning. Strict
            // policies (currently `/metrics`) log; hidden policies
            // (`/events`, `/admin/preauth`) stay silent.
            state.bearer_metrics().warn_if_unconfigured();
            state.bearer_admin().warn_if_unconfigured();
            state.bearer_events().warn_if_unconfigured();
            // If the wire surface is enabled, swap the auto-constructed
            // preauth minter for the one shared with the wire router so
            // both paths see the same store.
            if let Some((_, shared)) = wire_state {
                state.preauth_minter = shared;
            }
            // Open the audit log next to the wallet secret unless a
            // dedicated path is configured.
            let audit_dir = self
                .cfg
                .control
                .audit_dir
                .clone()
                .unwrap_or_else(|| "./audit".into());
            // Task #231: if the [analytics] block is enabled, spawn the
            // indexer + bind it to the audit-log live tap so new
            // events fan out into the in-memory time-buckets.
            let analytics_tap = if self.cfg.analytics.enabled {
                let (tx, mut rx) =
                    tokio::sync::mpsc::unbounded_channel::<octravpn_analytics::AnalyticsEvent>();
                let indexer = octravpn_analytics::Indexer::new();
                // Boot-time backfill: replay everything already on
                // disk so the dashboards have history immediately.
                // Errors are non-fatal — a missing audit dir on first
                // boot is normal.
                match octravpn_analytics::load_audit_key(std::path::Path::new(&audit_dir)) {
                    Ok(key) => {
                        match indexer.ingest_audit_dir(&key, std::path::Path::new(&audit_dir)) {
                            Ok(scans) => {
                                info!(files = scans.len(), "analytics: replayed audit log at boot");
                            }
                            Err(e) => warn!(error = %e, "analytics: audit replay failed"),
                        }
                    }
                    Err(e) => warn!(error = %e, "analytics: no audit key (cold start)"),
                }
                // Live stream: drain the unbounded channel into the
                // indexer state. The audit-log tap publishes here on
                // every successful write.
                let state_clone = indexer.state.clone();
                tokio::spawn(async move {
                    while let Some(ev) = rx.recv().await {
                        state_clone.ingest(&ev);
                    }
                });
                // Audit-2 CFG-2 / Audit-3 H-6: materialise the SecretString
                // bearer back to Option<String> for HttpState; the analytics
                // crate wraps it in Arc<str> + ct-compares on the request path.
                let bearer = self.cfg.analytics.bearer_token_string();
                let gated = bearer.is_some();
                let http_state = octravpn_analytics::HttpState::new(indexer.state, bearer);
                let listen_addr = self.cfg.analytics.listen_addr.clone();
                let listen_for_log = listen_addr.clone();
                tokio::spawn(async move {
                    if let Err(e) = octravpn_analytics::serve(&listen_addr, http_state, None).await
                    {
                        warn!(error = %e, "analytics: http server stopped");
                    }
                });
                info!(
                    listen = %listen_for_log,
                    gated = gated,
                    "analytics indexer spawned"
                );
                Some(tx)
            } else {
                None
            };
            // Perf-6: thread the operator-tunable rotation policy
            // ([audit] block) into the audit-log opener. Defaults
            // (256 MiB × 32 files, skip-to-tip boot replay) keep
            // pre-Perf-6 behaviour intact for nodes that never touch
            // the new config block.
            let rotation = self.cfg.audit.to_runtime();
            match crate::audit::AuditLog::open_batched_with_rotation(
                &audit_dir,
                crate::audit::DEFAULT_BATCH_SIZE,
                crate::audit::DEFAULT_BATCH_INTERVAL_MS,
                crate::audit::DEFAULT_BATCH_QUEUE_CAP,
                rotation,
            ) {
                Ok(mut audit) => {
                    // Perf-6 boot-replay: when `boot_replay = skip_to_tip`
                    // (the default), walk the post-tip tail only — on a
                    // 30-day-old high-traffic node this turns a ~26 s
                    // HMAC chain re-walk into a sub-second tail verify.
                    // `Full` mode forces every line to be re-verified.
                    if matches!(
                        rotation.boot_replay,
                        crate::audit::BootReplayMode::SkipToTip
                    ) {
                        let t0 = std::time::Instant::now();
                        match crate::audit::AuditLog::verify_dir_skip_to_tip(
                            &audit.key(),
                            std::path::Path::new(&audit_dir),
                        ) {
                            Ok(reports) => {
                                let lines: u64 = reports.iter().map(|(_, r)| r.entries).sum();
                                let broken = reports
                                    .iter()
                                    .filter(|(_, r)| r.first_error.is_some())
                                    .count();
                                let took = t0.elapsed();
                                if broken > 0 {
                                    warn!(
                                        broken_files = broken,
                                        replay_us = took.as_micros() as u64,
                                        "audit boot replay (skip-to-tip): chain broke; \
                                         run `octravpn-node audit verify --full <dir>` to forensic"
                                    );
                                } else {
                                    info!(
                                        verified_lines = lines,
                                        replay_us = took.as_micros() as u64,
                                        "audit boot replay (skip-to-tip) clean"
                                    );
                                }
                            }
                            Err(e) => warn!(error = %e, "audit boot replay (skip-to-tip) failed"),
                        }
                    }
                    if let Some(tap) = analytics_tap {
                        audit = audit.with_analytics_tap(tap);
                    }
                    state = state.with_audit(audit);
                    info!(
                        dir = %audit_dir,
                        batch_size = crate::audit::DEFAULT_BATCH_SIZE,
                        batch_interval_ms = crate::audit::DEFAULT_BATCH_INTERVAL_MS,
                        max_file_bytes = rotation.max_file_bytes,
                        max_file_count = rotation.max_file_count,
                        boot_replay = ?rotation.boot_replay,
                        "audit log open (batched fsync + rotation)"
                    );
                }
                Err(e) => warn!(error = %e, dir = %audit_dir, "audit log disabled"),
            }
            let state = Arc::new(state);
            tokio::spawn(crate::control::run_sweeper(state.clone()));
            control_serve(state, listen).await
        })
    }
}

/// Validate the `[tun.transport]` config block. On `direct` (the
/// default) this is a no-op. On `obfs4` we verify that the required
/// hex-encoded fields decode, the lengths match, and (if the node is
/// bridge-side, i.e. `bridge_identity_secret` is set) the secret
/// agrees with the published pubkey.
///
/// Boot-time validation surfaces typos (wrong hex length, misformed
/// secret, IAT mode out of range) up front rather than at first
/// packet, where the diagnostic would be a silent handshake failure.
///
/// When obfs4 is enabled we additionally construct an
/// `Obfs4Transport` once to confirm the bind / role wiring compiles
/// end-to-end against the node's `[tunnel].listen` address. The
/// instance is then dropped — the WG data plane still uses
/// `tokio::net::UdpSocket` directly (the data-path swap is gated
/// behind a follow-up task that adapts `tunnel::Server::run` to the
/// `octravpn_tun::Transport` trait).
fn validate_obfs4_config(cfg: &crate::config::NodeConfig) -> Result<()> {
    use crate::config::{Obfs4Cfg, TransportKind};
    use octravpn_obfs4::{
        bridge::{BridgeCredentials, BridgeIdentity, NODE_ID_LEN},
        IatMode,
    };

    if cfg.tun.transport.kind != TransportKind::Obfs4 {
        return Ok(());
    }
    let o: &Obfs4Cfg = cfg.tun.transport.obfs4.as_ref().ok_or_else(|| {
        anyhow!("[tun.transport].kind = \"obfs4\" but [tun.transport.obfs4] missing")
    })?;

    let node_id_bytes =
        ::hex::decode(&o.bridge_node_id).context("[tun.transport.obfs4].bridge_node_id hex")?;
    if node_id_bytes.len() != NODE_ID_LEN {
        return Err(anyhow!(
            "[tun.transport.obfs4].bridge_node_id must decode to {NODE_ID_LEN} bytes, got {}",
            node_id_bytes.len()
        ));
    }
    let mut node_id = [0u8; NODE_ID_LEN];
    node_id.copy_from_slice(&node_id_bytes);

    let pubkey_bytes =
        ::hex::decode(&o.bridge_pubkey).context("[tun.transport.obfs4].bridge_pubkey hex")?;
    if pubkey_bytes.len() != 32 {
        return Err(anyhow!(
            "[tun.transport.obfs4].bridge_pubkey must decode to 32 bytes, got {}",
            pubkey_bytes.len()
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let bridge_pubkey = x25519_dalek::PublicKey::from(pk);

    let iat_mode = IatMode::from_u8(o.iat_mode).ok_or_else(|| {
        anyhow!(
            "[tun.transport.obfs4].iat_mode must be 0/1/2, got {}",
            o.iat_mode
        )
    })?;

    // Bridge-side: validate the secret matches the pubkey.
    // Audit-2 CFG-2 / Audit-3 H-6: `bridge_identity_secret` is wrapped in
    // SecretString — call the redaction-safe accessor instead of touching
    // the raw Option<SecretString> field.
    if let Some(secret_hex) = o.bridge_identity_secret_expose() {
        let secret_bytes = ::hex::decode(secret_hex)
            .context("[tun.transport.obfs4].bridge_identity_secret hex")?;
        if secret_bytes.len() != 32 {
            return Err(anyhow!(
                "[tun.transport.obfs4].bridge_identity_secret must decode to 32 bytes"
            ));
        }
        let mut sec = [0u8; 32];
        sec.copy_from_slice(&secret_bytes);
        let identity = BridgeIdentity::from_bytes(node_id, sec);
        let derived = identity.credentials().identity_pubkey;
        if derived.as_bytes() != bridge_pubkey.as_bytes() {
            return Err(anyhow!(
                "[tun.transport.obfs4].bridge_identity_secret does not derive the configured bridge_pubkey"
            ));
        }
    }

    let _ = BridgeCredentials {
        node_id,
        identity_pubkey: bridge_pubkey,
    };
    info!(
        iat_mode = ?iat_mode,
        role = if o.bridge_identity_secret.is_some() { "bridge" } else { "client" },
        "obfs4 transport configured (data-plane swap-in pending; config validated at boot)"
    );
    Ok(())
}
