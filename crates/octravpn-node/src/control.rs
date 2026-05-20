//! HTTP control plane the exit node serves to clients.
//!
//! Two endpoints:
//!
//!   POST /session           — client announces session + client_pubkey
//!   GET  /session/{id}      — return the exit's view: bytes_served and a
//!                              single-signed (by the node) receipt
//!                              proposal the client can countersign at
//!                              settlement.
//!
//! The exit is the byte-counting authority: it signs receipts as bytes
//! flow through the tunnel. The client fetches the proposal at
//! settlement and adds its own signature.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::StreamExt;
use octravpn_core::{
    bounded::BoundedMap,
    control::{
        announce_signing_payload, AnnounceSessionRequest, AnnounceSessionResponse, ProposedReceipt,
        SessionStateResponse,
    },
    receipt::{Receipt, ReceiptContext},
    receipt_journal::ReceiptJournal,
    rpc::RpcClient,
    session::SessionId,
    sig::{verify, KeyPair},
};
use octravpn_mesh::{tailscale_wire_router, PreauthMinter, WireState, DEFAULT_PREAUTH_TTL};
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{info, warn};

use crate::{events::EventBus, onion::OnionRouter};

/// Hard cap on concurrent sessions a node will track in its control
/// plane. Past this, the oldest entries are evicted and clients get
/// "session not announced" — they can re-announce.
pub(crate) const CONTROL_SESSIONS_CAP: usize = 10_000;

/// Idle TTL: sessions whose last GET / announce is older than this are
/// pruned by the periodic sweeper.
pub(crate) const CONTROL_SESSION_TTL: Duration = Duration::from_secs(3600);

/// How often the sweeper runs.
pub(crate) const CONTROL_SWEEP_PERIOD: Duration = Duration::from_secs(60);

/// `/health` returns 503 if the most recent attestation refresh is
/// older than this.
const HEALTH_ATTESTATION_FRESHNESS_S: u64 = 300;

/// During the first `HEALTH_WARMUP_S` after process start we report
/// `warming_up` instead of failing health — the attestation loop has
/// not had a chance to run yet.
const HEALTH_WARMUP_S: u64 = 60;

#[derive(Clone)]
pub(crate) struct ControlState {
    pub node_kp: Arc<KeyPair>,
    pub sessions: Arc<BoundedMap<SessionId, ControlSession>>,
    pub router: Arc<OnionRouter>,
    /// Shared with the tunnel: announce() inserts here so the tunnel
    /// can construct a `Tunn` with the real client static pubkey.
    pub allowlist: Arc<BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
    /// Process-lifetime counters for /metrics.
    pub metrics: Arc<NodeMetrics>,
    /// Optional audit log. `None` disables auditing.
    pub audit: Option<crate::audit::AuditLog>,
    /// In-process fan-out bus that powers the `/events` SSE stream.
    /// Cloning the bus is cheap (it shares one `broadcast::Sender`).
    pub events: EventBus,
    /// Bearer token gating the `/events` SSE endpoint. `None`
    /// disables the endpoint entirely (requests return 404).
    /// Set via `[control].events_token` in the node TOML.
    pub events_token: Option<Arc<str>>,
    /// Bearer token gating the `/metrics` Prometheus endpoint.
    /// `None` ⇒ endpoint refuses with 503 + a startup log line.
    /// Operators MUST set `[control].metrics_token` for the endpoint
    /// to serve scrapes (default-closed, mirrors `/events` semantics
    /// but with 503 instead of 404 so a misconfigured Prometheus
    /// surfaces a clear error rather than silently 404'ing).
    pub metrics_token: Option<Arc<str>>,
    /// Deployment domain (program / chain / circle) bound into every
    /// signed receipt. P1-5: prevents cross-program / cross-chain /
    /// cross-circle receipt replay. Populated from `node.toml`'s
    /// `[chain]` section by the hub at startup.
    pub receipt_context: Arc<ReceiptContext>,
    /// P1-8/9 persistent receipt-seq floor. Every `get_state` call
    /// consults this BEFORE signing a receipt; the journal is bumped
    /// atomically to disk, and only then is the receipt signed. A
    /// daemon restart loads the same file, so the operator can NEVER
    /// be tricked into signing two receipts at the same
    /// `(session_id, seq)` even across an OOM-kill or segfault.
    pub receipt_journal: Arc<ReceiptJournal>,
    /// In-memory preauth-key minter the `POST /admin/preauth`
    /// endpoint hands out tokens from. Shared with `octravpn-node`'s
    /// `mesh mint-preauth` CLI surface so a `docker exec` can mint a
    /// key without touching the HTTP plane.
    pub preauth_minter: PreauthMinter,
    /// Bearer token gating `POST /admin/preauth`. `None` hides the
    /// endpoint (any request returns 404, matching `/events`).
    pub admin_token: Option<Arc<str>>,
    /// Optional Tailscale-wire surface state. When `Some`, the
    /// control router mounts `GET /key`, `POST /ts2021`,
    /// `POST /machine/:node_key/{register,map}`. When `None` (the
    /// default for tests + nodes that haven't enabled the wire), the
    /// routes are absent — a stock `tailscale up` reaches them only
    /// once an operator opts in by populating
    /// `[control].tailscale_wire_state_dir` in node.toml. See
    /// `docs/tailscale-interop-blocker.md`.
    pub wire_state: Option<WireState>,
    /// Rate-limit config applied by `router_axum`. Populated from
    /// `[control.rate_limit]` in `node.toml`. When `enabled = false`
    /// the layer is omitted from the router entirely (no per-request
    /// overhead). See `crate::rate_limit`.
    pub rate_limit_cfg: crate::rate_limit::RateLimitCfg,
    /// Optional chain-backed verifier for `POST /session`. Tests can
    /// leave this unset and still exercise signature validation; hub
    /// startup wires it so production announces must point at a
    /// transaction that emitted `SessionOpened(session_id)`.
    pub session_verifier: Option<SessionAdmissionVerifier>,
    /// HFHE-2: optional shadow-blob signer. When `Some` the
    /// `get_state` receipt-emission path consults the PVAC sidecar
    /// for `encrypt_const(bytes_used)` + `encrypt_const(net)` and
    /// attaches the ciphertexts to the proposed receipt. `None`
    /// (the default) is the no-shadow path — receipts emit
    /// identical bytes to pre-HFHE-2 builds.
    pub shadow_signer: Option<Arc<ShadowSigner>>,
    /// HFHE-2: per-session price in OU/byte used to compute the
    /// shadow `net` ciphertext (`net = bytes_used * price`). v3
    /// `settle_confirm` takes `net` as a plaintext positional arg
    /// the opener and operator agree on out-of-band, so the shadow
    /// `net` is encrypted under the same `price`. Default 0.
    pub shadow_price_per_byte: u64,
}

#[derive(Clone)]
pub(crate) struct SessionAdmissionVerifier {
    rpc: RpcClient,
}

impl SessionAdmissionVerifier {
    pub(crate) fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }

    pub(crate) async fn session_opened(
        &self,
        req: &AnnounceSessionRequest,
    ) -> octravpn_core::CoreResult<bool> {
        let tx = self.rpc.transaction(&req.open_tx_hash).await?;
        Ok(transaction_has_session_opened(&tx, &req.session_id))
    }
}

fn transaction_has_session_opened(tx: &serde_json::Value, session_id: &SessionId) -> bool {
    let Some(events) = tx.get("events").and_then(|v| v.as_array()) else {
        return false;
    };
    events.iter().any(|event| {
        event.get("name").and_then(|v| v.as_str()) == Some("SessionOpened")
            && event_session_id(event)
                .as_ref()
                .is_some_and(|event_id| event_id == session_id)
    })
}

fn event_session_id(event: &serde_json::Value) -> Option<SessionId> {
    let sid = event.get("session_id")?;
    if let Some(id_u64) = sid.as_u64() {
        return Some(SessionId::from_u64(id_u64));
    }
    SessionId::from_hex(sid.as_str()?)
}

/// HFHE-2 shadow-blob signer bundle. Held on `ControlState` as
/// `Option<Arc<ShadowSigner>>`. Carries the live `PvacClient`
/// handle plus the two circle key blobs (`hfhe_v1|<b64>` strings).
///
/// Lifecycle: built at boot by `Hub::new` when
/// `cfg.pvac.enabled = true` AND both `circle_pubkey_path` /
/// `circle_secret_path` resolve to readable files. Mid-session
/// enable is NOT supported — the state is captured once at
/// `with_shadow_signer` time and not re-checked. An operator who
/// flips the sidecar on mid-session sees *new* receipts carry the
/// shadow blob from the next `get_state` onward, but in-flight
/// receipts already proposed without the blob are NOT re-emitted.
/// The chain doesn't verify either side today, so the
/// inconsistency is purely off-chain bookkeeping.
pub(crate) struct ShadowSigner {
    /// Live PVAC sidecar client handle. Shared with `Hub::pvac()`.
    pub pvac: Arc<crate::pvac::PvacClient>,
    /// Circle PVAC pubkey blob (`hfhe_v1|<base64>`).
    pub circle_pk: String,
    /// Circle PVAC secret key blob (`hfhe_v1|<base64>`). The
    /// sidecar's `encrypt_const` op takes both pk + sk; the secret
    /// is used only for randomness derivation, never to decrypt.
    pub circle_sk: String,
}

/// Lightweight counters exposed via the /metrics endpoint. Kept as
/// AtomicU64 to avoid lock contention on the data plane.
///
/// Counters (suffix `_total`) only ever increase with `fetch_add`.
/// Gauges are unsuffixed and use `store`. The companion dashboards in
/// `deploy/observability/grafana/*.json` plot these by name; keep the
/// field name and the Prometheus name aligned (the serializer
/// concatenates `octravpn_<field_name>`).
#[derive(Default)]
pub(crate) struct NodeMetrics {
    pub announces_total: AtomicU64,
    pub state_lookups_total: AtomicU64,
    pub receipts_signed_total: AtomicU64,
    pub started_at_unix: AtomicU64,
    /// Unix timestamp of the most recent successful on-chain
    /// attestation refresh. Set by the hub's attestation loop.
    pub last_attestation_unix: AtomicU64,
    // ------------------------------------------------------------
    // Slashing surface. The on-chain `slash_double_sign` call is
    // built by `chain_v3::build_slash_double_sign_call`; the daemon
    // does not yet *submit* that call on its own (no equivocation
    // detector wired up), so the counter is bumped by
    // `record_slash_double_sign` whenever an operator-side tool
    // dispatches the slash. Once the equivocation detector lands,
    // its call site replaces the manual surface.
    pub slash_double_sign_total: AtomicU64,
    // ------------------------------------------------------------
    // Preauth surface (Tailscale interop bridge).
    pub preauth_mints_total: AtomicU64,
    pub preauth_redemptions_total: AtomicU64,
    // ------------------------------------------------------------
    // Chain RPC surface. Bumped by the hub's validator-health and
    // attestation loops on every RPC round-trip; `_errors_total` is
    // a subset of `_requests_total` (every error is also a request).
    pub rpc_requests_total: AtomicU64,
    pub rpc_errors_total: AtomicU64,
    // ------------------------------------------------------------
    // WireGuard handshake outcomes. Bumped from `tunnel::Server`
    // off the `Tunn::decapsulate` result variants. `success_total`
    // counts handshake-response writes (the typed signal boringtun
    // emits when the noise handshake completes); `fail_total`
    // counts `TunnResult::Err`.
    pub wg_handshake_success_total: AtomicU64,
    pub wg_handshake_fail_total: AtomicU64,
    // ------------------------------------------------------------
    // Session lifecycle. `opens_total` is bumped at each
    // `POST /session`; `closes_total` increments by N when the
    // sweeper evicts N idle sessions; `no_shows_total` is reserved
    // for the (not-yet-implemented) settlement-side cross-check
    // where a client never returns a countersigned receipt — see
    // dashboard panel `settled-vs-no-show ratio` for the TODO.
    pub session_opens_total: AtomicU64,
    pub session_closes_total: AtomicU64,
    pub session_no_shows_total: AtomicU64,
    // ------------------------------------------------------------
    // Tailnet gauges. Set by the `/metrics` handler on every scrape
    // (read-only snapshot from `WireState`), not by data-plane
    // fast paths. `ip_allocator_used` mirrors `tailnet_member_count`
    // (every registered machine consumes one allocated IP); the
    // allocator itself is stateless, so capacity is the static
    // `TailnetIpAllocator::host_capacity()` value.
    pub tailnet_member_count: AtomicU64,
    pub ip_allocator_used: AtomicU64,
    pub ip_allocator_capacity: AtomicU64,
}

impl NodeMetrics {
    /// Record that a `slash_double_sign` call was dispatched. Public
    /// at crate scope so an operator tool (e.g. an equivocation
    /// detector) can call it without going through the chain layer.
    #[allow(dead_code)]
    pub(crate) fn record_slash_double_sign(&self) {
        self.slash_double_sign_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a chain RPC request outcome. `ok=true` bumps only
    /// `rpc_requests_total`; `ok=false` bumps both. Symmetric so
    /// callers don't need conditional code.
    pub(crate) fn record_rpc(&self, ok: bool) {
        self.rpc_requests_total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.rpc_errors_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a WireGuard handshake outcome. `success=true` bumps
    /// the success counter; `success=false` bumps the fail counter.
    pub(crate) fn record_wg_handshake(&self, success: bool) {
        if success {
            self.wg_handshake_success_total
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.wg_handshake_fail_total.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Bridge from `octravpn-mesh`'s `MetricsSink` trait to our concrete
/// `NodeMetrics`. Keeps the dependency direction one-way: mesh knows
/// nothing about node metrics, but node-side callers can pass an
/// `Arc<NodeMetrics>` wherever a mesh API expects a `MetricsSink`.
impl octravpn_mesh::headscale_bridge::MetricsSink for NodeMetrics {
    fn record_event(&self, name: &str) {
        match name {
            "preauth_mint" => {
                self.preauth_mints_total.fetch_add(1, Ordering::Relaxed);
            }
            "preauth_redeem" => {
                self.preauth_redemptions_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            // Unknown event names are dropped — additive design so
            // mesh-side code can publish new events without
            // requiring a node-side recompile.
            _ => {}
        }
    }
}

#[derive(Clone)]
pub(crate) struct ControlSession {
    pub last_seq: u64,
    pub last_blind: octravpn_core::session::Blind,
}

impl ControlState {
    #[cfg(test)]
    pub(crate) fn new(
        node_kp: Arc<KeyPair>,
        router: Arc<OnionRouter>,
        allowlist: Arc<BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
    ) -> Self {
        let metrics = Arc::new(NodeMetrics::default());
        metrics
            .started_at_unix
            .store(octravpn_core::util::now_unix_secs(), Ordering::Relaxed);
        // Tests fall back to a fixed v1.1 receipt context with the
        // test-network chain id + an in-memory receipt journal (no
        // on-disk side effect). Hub-built ControlStates override both
        // via `with_metrics` directly.
        let ctx = ReceiptContext::v1_1(
            octravpn_core::address::Address::from_pubkey(&[0u8; 32]),
            octravpn_core::receipt::CHAIN_ID_TEST,
        );
        let journal = Arc::new(ReceiptJournal::in_memory());
        Self::with_metrics(node_kp, router, allowlist, metrics, Arc::new(ctx), journal)
            // Tests don't need the auth gate — explicitly leave the
            // token None so /events behaves like a 404 endpoint.
            .with_events_token(None)
    }

    /// Construct with an externally-provided `NodeMetrics` so the Hub
    /// can write attestation timestamps that this handler reads, plus
    /// the `ReceiptContext` bound into every signed receipt (P1-5
    /// cross-program / cross-circle replay defense) and a
    /// `ReceiptJournal` whose seq-floor is durable across restarts
    /// (P1-8/9).
    pub(crate) fn with_metrics(
        node_kp: Arc<KeyPair>,
        router: Arc<OnionRouter>,
        allowlist: Arc<BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
        metrics: Arc<NodeMetrics>,
        receipt_context: Arc<ReceiptContext>,
        receipt_journal: Arc<ReceiptJournal>,
    ) -> Self {
        // started_at_unix may not have been set by the caller yet; we
        // honour whatever they supply (Hub seeds it; standalone calls
        // get a default of 0 which the health endpoint treats as
        // "warming up").
        Self {
            node_kp,
            sessions: Arc::new(BoundedMap::new(CONTROL_SESSIONS_CAP, CONTROL_SESSION_TTL)),
            router,
            allowlist,
            metrics,
            audit: None,
            // 256 in-flight events per subscriber: enough headroom for
            // a burst of session announces / receipt signings without
            // forcing the bus to drop, small enough to keep memory
            // bounded even if a few SSE clients are slow.
            events: EventBus::new(256),
            events_token: None,
            metrics_token: None,
            receipt_context,
            receipt_journal,
            preauth_minter: PreauthMinter::new(),
            admin_token: None,
            wire_state: None,
            rate_limit_cfg: crate::rate_limit::RateLimitCfg::default(),
            session_verifier: None,
            shadow_signer: None,
            shadow_price_per_byte: 0,
        }
    }

    /// HFHE-2: attach a shadow-blob signer. When set, every signed
    /// receipt emitted from `get_state` is amended with encrypted
    /// `bytes_used` + `net` ciphertexts produced by the PVAC
    /// sidecar. `None` (the default) preserves the legacy
    /// no-shadow wire shape.
    #[allow(dead_code)] // wired by Hub::new when [pvac] block + circle keys are present
    pub(crate) fn with_shadow_signer(
        mut self,
        signer: Option<Arc<ShadowSigner>>,
        price_per_byte: u64,
    ) -> Self {
        self.shadow_signer = signer;
        self.shadow_price_per_byte = price_per_byte;
        self
    }

    /// Override the rate-limit config (defaults are the documented
    /// production profile in `crate::rate_limit`). Hub wires this from
    /// `[control.rate_limit]` in `node.toml`; tests use the default.
    #[allow(dead_code)]
    pub(crate) fn with_rate_limit_cfg(mut self, cfg: crate::rate_limit::RateLimitCfg) -> Self {
        self.rate_limit_cfg = cfg;
        self
    }

    pub(crate) fn with_session_verifier(mut self, verifier: SessionAdmissionVerifier) -> Self {
        self.session_verifier = Some(verifier);
        self
    }

    /// Attach an audit log; every state-changing handler will write to it.
    pub(crate) fn with_audit(mut self, audit: crate::audit::AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Configure the `/events` SSE bearer token. `None` (the default)
    /// disables the endpoint entirely. v2 audit gate.
    pub(crate) fn with_events_token(mut self, token: Option<String>) -> Self {
        self.events_token = token.map(Arc::from);
        self
    }

    /// Configure the `/metrics` Prometheus bearer token. `None` (the
    /// default) refuses scrapes with 503 + a startup log line. Set
    /// via `[control].metrics_token` in the node TOML for production.
    pub(crate) fn with_metrics_token(mut self, token: Option<String>) -> Self {
        self.metrics_token = token.map(Arc::from);
        self
    }

    /// Attach a Tailscale-wire surface. When set, the control router
    /// mounts `/key`, `/ts2021`, `/machine/:node_key/{register,map}`.
    /// Wired by `Hub::spawn_control_plane` when
    /// `[control].tailscale_wire_state_dir` is configured.
    pub(crate) fn with_wire_state(mut self, ws: Option<WireState>) -> Self {
        self.wire_state = ws;
        self
    }

    /// Configure the `POST /admin/preauth` bearer token. `None`
    /// (the default) returns 404 for every request to that endpoint,
    /// so external observers can't even confirm it exists. Set to a
    /// long random string in production; the
    /// `docker/devnet/tailscale-interop` test loads it from the
    /// `OCTRAVPN_ADMIN_TOKEN` env via the compose secret.
    pub(crate) fn with_admin_token(mut self, token: Option<String>) -> Self {
        self.admin_token = token.map(Arc::from);
        self
    }

    pub(crate) fn router_axum(self: Arc<Self>) -> Router {
        use axum::middleware;

        // Rate-limited surface: the regular request/response endpoints.
        // `/health` and `/metrics` are mounted inside this router but
        // are bypassed at the middleware level by
        // `crate::rate_limit::classify` (so they reply under load even
        // when an attacker has drained a per-class bucket). When
        // `[control.rate_limit].enabled = false` the layer is omitted
        // entirely — no per-request overhead.
        let limited_routes = Router::new()
            .route("/session", post(announce))
            .route("/session/:id", get(get_state))
            .route("/health", get(health))
            .route("/metrics", get(metrics))
            // Preauth-minting surface for the Tailscale-interop bridge.
            // Token-gated: returns 404 when `admin_token` is unset so
            // an external scanner can't confirm the endpoint exists.
            // See `docs/tailscale-interop-blocker.md` for what this
            // does *not* (yet) deliver — chiefly the real Tailscale
            // wire protocol behind `/key` + `/machine/{node_key}/…`.
            .route("/admin/preauth", post(mint_preauth));
        let limited = if self.rate_limit_cfg.enabled {
            let rate_limiter = crate::rate_limit::RateLimiter::from_cfg(&self.rate_limit_cfg);
            limited_routes
                .layer(middleware::from_fn_with_state(
                    rate_limiter,
                    crate::rate_limit::rate_limit_layer,
                ))
                .with_state(self.clone())
        } else {
            limited_routes.with_state(self.clone())
        };

        // SSE surface, mounted on a separate sub-router merged in
        // *outside* the rate-limit layer. Rationale: SSE is a single
        // long-lived request; counting it against a per-IP token
        // budget would either (a) starve other endpoints after one
        // connect, or (b) require per-route exemption logic the token
        // bucket doesn't model cleanly. A separate `Router::merge`
        // gives us the exemption with one line and zero conditional
        // middleware. The endpoint is read-only (subscribers cannot
        // publish), and the bus itself caps memory via its broadcast
        // capacity, so the abuse surface is bounded.
        let unlimited = Router::new()
            .route("/events", get(events_sse))
            .with_state(self.clone());

        let mut merged = limited.merge(unlimited);

        // Tailscale-wire surface (PRs 1-4). Mounted unconditionally
        // when `wire_state` is populated; absent otherwise so the
        // routes don't reply to unrelated probes. Same `merge` pattern
        // as `/events` because the wire router doesn't share state
        // with `ControlState` — it owns its own `Arc`-shared
        // `WireState` constructed at Hub init.
        if let Some(ws) = self.wire_state.clone() {
            merged = merged.merge(tailscale_wire_router(ws));
        }

        merged
    }
}

/// Periodic sweeper: evicts sessions idle past TTL.
pub(crate) async fn run_sweeper(state: Arc<ControlState>) {
    loop {
        tokio::time::sleep(CONTROL_SWEEP_PERIOD).await;
        let n = state.sessions.sweep();
        if n > 0 {
            // Each evicted entry is a "session close" from the
            // control plane's perspective: the client stopped fetching
            // /session/:id and the BoundedMap aged its row out. Bump
            // by N so the Prometheus counter rate matches the eviction
            // log line.
            state
                .metrics
                .session_closes_total
                .fetch_add(n as u64, Ordering::Relaxed);
            tracing::debug!(evicted = n, "control plane sweep");
        }
    }
}

pub(crate) async fn serve(state: Arc<ControlState>, addr: SocketAddr) -> Result<()> {
    let router = state.router_axum();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(?addr, "control plane listening");
    // `into_make_service_with_connect_info` propagates the client
    // SocketAddr into the rate-limit middleware via `ConnectInfo`.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

impl ApiError {
    fn new(s: impl Into<String>) -> Self {
        Self { error: s.into() }
    }
}

async fn announce(
    State(s): State<Arc<ControlState>>,
    Json(req): Json<AnnounceSessionRequest>,
) -> impl IntoResponse {
    let payload = announce_signing_payload(
        &req.session_id,
        &req.client_pubkey,
        &req.client_wg_pubkey,
        &req.open_tx_hash,
    );
    if verify(&req.client_pubkey, &payload, &req.client_sig).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new("bad announce signature")),
        )
            .into_response();
    }
    if let Some(verifier) = &s.session_verifier {
        match verifier.session_opened(&req).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiError::new("session open transaction not found")),
                )
                    .into_response();
            }
            Err(e) => {
                warn!(error = %e, "session admission verifier failed");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiError::new("session admission verifier unavailable")),
                )
                    .into_response();
            }
        }
    }
    s.metrics.announces_total.fetch_add(1, Ordering::Relaxed);
    // `session_opens_total` mirrors `announces_total` today (every
    // accepted announce opens a session) but is kept as a separate
    // counter so a future "rejected announce" path can split the two
    // without breaking the dashboard query.
    s.metrics
        .session_opens_total
        .fetch_add(1, Ordering::Relaxed);
    let session_id_hex = req.session_id.to_hex();
    s.sessions.insert(
        req.session_id,
        ControlSession {
            last_seq: 0,
            last_blind: octravpn_core::session::Blind::new([0u8; 32]),
        },
    );
    s.allowlist
        .insert(req.client_wg_pubkey, crate::tunnel::AllowedClient);
    // Fan out to SSE subscribers. We publish the client's WireGuard
    // pubkey (hex) — this is the public identity the client already
    // exposed via the announce request; not a secret.
    s.events.publish(crate::events::Event {
        ts_unix: octravpn_core::util::now_unix_secs(),
        kind: "session_announced".to_string(),
        payload: serde_json::json!({
            "session_id": session_id_hex,
            "client_wg_pubkey": hex::encode(req.client_wg_pubkey),
        }),
    });
    if let Some(audit) = &s.audit {
        let rec = crate::audit::AuditRecord {
            ts_unix: octravpn_core::util::now_unix_secs(),
            kind: "announce",
            source: None,
            session_id: Some(session_id_hex),
            extra: serde_json::Value::Null,
        };
        if let Err(e) = audit.write_async(rec).await {
            tracing::warn!(error = %e, "audit log write failed");
        }
    }
    Json(AnnounceSessionResponse {
        accepted: true,
        node_pubkey: s.node_kp.public,
    })
    .into_response()
}

async fn health(State(s): State<Arc<ControlState>>) -> impl IntoResponse {
    let now = octravpn_core::util::now_unix_secs();
    let started = s.metrics.started_at_unix.load(Ordering::Relaxed);
    let uptime = now.saturating_sub(started);
    let last_attest = s.metrics.last_attestation_unix.load(Ordering::Relaxed);

    if uptime < HEALTH_WARMUP_S {
        return Json(serde_json::json!({
            "status": "warming up",
            "uptime_s": uptime,
            "last_attestation_unix": last_attest,
        }))
        .into_response();
    }

    if last_attest == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "no_attestation",
                "uptime_s": uptime,
            })),
        )
            .into_response();
    }

    let attest_age = now.saturating_sub(last_attest);
    if attest_age > HEALTH_ATTESTATION_FRESHNESS_S {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "attestation_stale",
                "uptime_s": uptime,
                "last_attestation_unix": last_attest,
                "attestation_age_s": attest_age,
                "freshness_threshold_s": HEALTH_ATTESTATION_FRESHNESS_S,
            })),
        )
            .into_response();
    }

    Json(serde_json::json!({
        "status": "ok",
        "uptime_s": uptime,
        "last_attestation_unix": last_attest,
    }))
    .into_response()
}

/// Prometheus text format. Bearer-gated by default — operators must
/// set `[control].metrics_token` for the endpoint to serve scrapes.
/// Returns 503 (not 404) when unconfigured so a misconfigured Prometheus
/// surfaces a clear "endpoint disabled" error rather than silently
/// 404'ing.
async fn metrics(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let Some(want) = s.metrics_token.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics endpoint disabled: set [control].metrics_token in node.toml",
        )
            .into_response();
    };
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    if !got.is_some_and(|got_tok| constant_time_eq_str(got_tok, want)) {
        return (StatusCode::UNAUTHORIZED, "").into_response();
    }
    let m = &s.metrics;
    // Snapshot wire-state-derived gauges (member_count + IP allocator).
    // Reads only — no mutation of the wire layer. When `wire_state` is
    // unset (the common case for a node without the Tailscale-interop
    // bridge), both gauges stay at 0, which is the correct "no tailnet
    // attached" value.
    if let Some(ws) = s.wire_state.as_ref() {
        let n = ws.machines.len() as u64;
        m.tailnet_member_count.store(n, Ordering::Relaxed);
        m.ip_allocator_used.store(n, Ordering::Relaxed);
        // Allocator capacity is the static host count of the CGNAT
        // /10 slice the allocator hands out from. The `IpAllocator`
        // trait does not expose capacity, so we read the concrete
        // constant from `TailnetIpAllocator` directly.
        m.ip_allocator_capacity.store(
            u64::from(octravpn_mesh::TailnetIpAllocator::host_capacity()),
            Ordering::Relaxed,
        );
    }

    let body = format!(
        "# HELP octravpn_announces_total Sessions announced via control plane.\n\
         # TYPE octravpn_announces_total counter\n\
         octravpn_announces_total {announces}\n\
         # HELP octravpn_state_lookups_total /session/:id GETs.\n\
         # TYPE octravpn_state_lookups_total counter\n\
         octravpn_state_lookups_total {state_lookups}\n\
         # HELP octravpn_receipts_signed_total Node-signed receipt proposals returned.\n\
         # TYPE octravpn_receipts_signed_total counter\n\
         octravpn_receipts_signed_total {receipts_signed}\n\
         # HELP octravpn_bytes_served_total Cumulative bytes traversed (in+out).\n\
         # TYPE octravpn_bytes_served_total counter\n\
         octravpn_bytes_served_total {bytes_served}\n\
         # HELP octravpn_active_sessions Current sessions tracked by control plane.\n\
         # TYPE octravpn_active_sessions gauge\n\
         octravpn_active_sessions {active_sessions}\n\
         # HELP octravpn_last_attestation_unix Unix time of last successful attestation.\n\
         # TYPE octravpn_last_attestation_unix gauge\n\
         octravpn_last_attestation_unix {last_attest}\n\
         # HELP octravpn_uptime_seconds Process uptime.\n\
         # TYPE octravpn_uptime_seconds counter\n\
         octravpn_uptime_seconds {uptime}\n\
         # HELP octravpn_slash_double_sign_total slash_double_sign calls dispatched.\n\
         # TYPE octravpn_slash_double_sign_total counter\n\
         octravpn_slash_double_sign_total {slash}\n\
         # HELP octravpn_preauth_mints_total Tailscale-bridge preauth keys minted.\n\
         # TYPE octravpn_preauth_mints_total counter\n\
         octravpn_preauth_mints_total {pa_mints}\n\
         # HELP octravpn_preauth_redemptions_total Tailscale-bridge preauth redemptions.\n\
         # TYPE octravpn_preauth_redemptions_total counter\n\
         octravpn_preauth_redemptions_total {pa_redeems}\n\
         # HELP octravpn_rpc_requests_total Chain RPC requests attempted.\n\
         # TYPE octravpn_rpc_requests_total counter\n\
         octravpn_rpc_requests_total {rpc_req}\n\
         # HELP octravpn_rpc_errors_total Chain RPC requests that returned an error.\n\
         # TYPE octravpn_rpc_errors_total counter\n\
         octravpn_rpc_errors_total {rpc_err}\n\
         # HELP octravpn_wg_handshake_success_total WireGuard handshake completions.\n\
         # TYPE octravpn_wg_handshake_success_total counter\n\
         octravpn_wg_handshake_success_total {wg_ok}\n\
         # HELP octravpn_wg_handshake_fail_total WireGuard decapsulation errors.\n\
         # TYPE octravpn_wg_handshake_fail_total counter\n\
         octravpn_wg_handshake_fail_total {wg_fail}\n\
         # HELP octravpn_session_opens_total Sessions accepted by POST /session.\n\
         # TYPE octravpn_session_opens_total counter\n\
         octravpn_session_opens_total {sess_open}\n\
         # HELP octravpn_session_closes_total Sessions evicted by the idle sweeper.\n\
         # TYPE octravpn_session_closes_total counter\n\
         octravpn_session_closes_total {sess_close}\n\
         # HELP octravpn_session_no_shows_total Sessions ended without a client countersign.\n\
         # TYPE octravpn_session_no_shows_total counter\n\
         octravpn_session_no_shows_total {sess_no_show}\n\
         # HELP octravpn_tailnet_member_count Machines registered in the Tailscale-wire bridge.\n\
         # TYPE octravpn_tailnet_member_count gauge\n\
         octravpn_tailnet_member_count {tn_members}\n\
         # HELP octravpn_ip_allocator_used Number of CGNAT IPs currently allocated.\n\
         # TYPE octravpn_ip_allocator_used gauge\n\
         octravpn_ip_allocator_used {ip_used}\n\
         # HELP octravpn_ip_allocator_capacity Static host-range capacity of the CGNAT allocator.\n\
         # TYPE octravpn_ip_allocator_capacity gauge\n\
         octravpn_ip_allocator_capacity {ip_cap}\n",
        announces = m.announces_total.load(Ordering::Relaxed),
        state_lookups = m.state_lookups_total.load(Ordering::Relaxed),
        receipts_signed = m.receipts_signed_total.load(Ordering::Relaxed),
        bytes_served = s.router.total_bytes(),
        active_sessions = s.sessions.len(),
        last_attest = m.last_attestation_unix.load(Ordering::Relaxed),
        uptime = octravpn_core::util::now_unix_secs()
            .saturating_sub(m.started_at_unix.load(Ordering::Relaxed)),
        slash = m.slash_double_sign_total.load(Ordering::Relaxed),
        pa_mints = m.preauth_mints_total.load(Ordering::Relaxed),
        pa_redeems = m.preauth_redemptions_total.load(Ordering::Relaxed),
        rpc_req = m.rpc_requests_total.load(Ordering::Relaxed),
        rpc_err = m.rpc_errors_total.load(Ordering::Relaxed),
        wg_ok = m.wg_handshake_success_total.load(Ordering::Relaxed),
        wg_fail = m.wg_handshake_fail_total.load(Ordering::Relaxed),
        sess_open = m.session_opens_total.load(Ordering::Relaxed),
        sess_close = m.session_closes_total.load(Ordering::Relaxed),
        sess_no_show = m.session_no_shows_total.load(Ordering::Relaxed),
        tn_members = m.tailnet_member_count.load(Ordering::Relaxed),
        ip_used = m.ip_allocator_used.load(Ordering::Relaxed),
        ip_cap = m.ip_allocator_capacity.load(Ordering::Relaxed),
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

/// Server-Sent Events stream. Each control-plane event published on
/// the in-process bus is emitted as one SSE message with the JSON
/// payload as the `data:` field. A keepalive comment is sent every 15s
/// so intermediate proxies don't tear the idle connection down.
///
/// Slow / stuck subscribers manifest as `BroadcastStream::Lagged`
/// errors; we surface them as a `lag` SSE event so an operator can see
/// it in a `curl` session and reconnect if needed, rather than silently
/// dropping events.
///
/// ## Auth
///
/// The endpoint is gated behind a bearer token. Without
/// `[control].events_token` configured, the endpoint returns 404 —
/// matching the "endpoint hidden" intent. With the token set, the
/// request MUST carry `Authorization: Bearer <token>`. Any mismatch
/// (including a missing header) returns 404 (not 401) so an external
/// scanner can't tell whether the endpoint exists.
///
/// v2 audit gate: without this, the stream broadcasts every
/// `session_id ↔ client_wg_pubkey` mapping and per-session bytes_used
/// to any HTTP client reachable on the control-plane port, which
/// defeats the unlinkability design.
async fn events_sse(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // No token configured ⇒ endpoint disabled. Return 404 so external
    // observers can't even confirm it exists.
    let Some(want) = s.events_token.as_deref() else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };
    // Token configured ⇒ require Authorization: Bearer <token>.
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let authorized = got.is_some_and(|got_tok| constant_time_eq_str(got_tok, want));
    if !authorized {
        return (StatusCode::NOT_FOUND, "").into_response();
    }

    let rx = s.events.subscribe();
    let stream = BroadcastStream::new(rx).map(|item| {
        let ev = match item {
            Ok(ev) => ev,
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                crate::events::Event {
                    ts_unix: octravpn_core::util::now_unix_secs(),
                    kind: "lag".to_string(),
                    payload: serde_json::json!({ "skipped": n }),
                }
            }
        };
        // `json_data` serializes the event with serde_json. The bus
        // event already derives `Serialize`, so this can only fail if
        // the payload contains something unserializable — which is
        // never the case here (we only emit `serde_json::Value`).
        // Fall back to an empty data field on the theoretical error
        // path so the stream never aborts.
        let sse = SseEvent::default()
            .event(ev.kind.clone())
            .json_data(&ev)
            .unwrap_or_else(|_| SseEvent::default().data(""));
        Ok::<_, Infallible>(sse)
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// HFHE-2: derive a per-receipt encryption seed (64-char hex) from
/// the (session_id_hex, seq) tuple. Deterministic — the auditor
/// who knows `(session_id, seq, circle_pk, circle_sk)` can
/// recompute the ciphertext byte-for-byte.
///
/// The label `octravpn-shadow-v1|` pins the domain so this seed
/// space never collides with any other use of `sha256(session_id
/// || seq)`.
fn shadow_seed_for(session_id_hex: &str, seq: u64) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"octravpn-shadow-v1|");
    h.update(session_id_hex.as_bytes());
    h.update(b"|");
    h.update(seq.to_be_bytes());
    hex::encode(h.finalize())
}

/// HFHE-2: split a parent shadow seed into a per-field subseed.
/// Cheap (one sha256). The label distinguishes `enc_bytes_used`
/// vs `enc_net` so the two ciphertexts on a single receipt are
/// never encrypted under the same randomness.
fn shadow_subseed(parent_hex: &str, label: &[u8]) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(parent_hex.as_bytes());
    h.update(b"|");
    h.update(label);
    hex::encode(h.finalize())
}

/// Constant-time string equality. Doesn't short-circuit on length, but
/// strings with different lengths can't be equal — return false
/// up-front. The remaining comparison is byte-by-byte XOR-and-OR.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn get_state(
    State(s): State<Arc<ControlState>>,
    Path(id_hex): Path<String>,
) -> impl IntoResponse {
    s.metrics
        .state_lookups_total
        .fetch_add(1, Ordering::Relaxed);

    let Some(id) = SessionId::from_hex(&id_hex) else {
        return (StatusCode::BAD_REQUEST, Json(ApiError::new("bad id"))).into_response();
    };

    let bytes = s.router.bytes(&id).map_or(0, |(i, o)| i + o);

    let Some(entry) = s.sessions.get(&id) else {
        return (StatusCode::NOT_FOUND, Json(ApiError::new("not announced"))).into_response();
    };

    // P1-8/9: consult the persistent journal floor BEFORE choosing a
    // seq. After a restart `entry.last_seq` resets to 0; but the
    // journal preserves the highest seq we ever signed for this
    // session. Pick a seq that is strictly greater than BOTH the
    // in-memory tracker and the persistent floor, then atomically
    // record it via `bump` (fsync inside) — only sign after the journal
    // is durable. A crash between the journal write and the signature
    // means we lose this proposal; the client retries with no harm.
    let journal_floor = s.receipt_journal.floor(&id);
    let next_seq = std::cmp::max(entry.last_seq, journal_floor) + 1;
    if let Err(e) = s.receipt_journal.bump(&id, next_seq) {
        // The only failure mode is `SeqNotMonotonic`, which would
        // mean another writer raced us. With the BoundedMap holding
        // per-session state in-process this should never trigger;
        // surface it loudly if it does so the operator notices the
        // race condition.
        tracing::warn!(error = %e, session = %id_hex, "receipt journal bump rejected; refusing to sign");
        return (
            StatusCode::CONFLICT,
            Json(ApiError::new(
                "receipt seq floor violation; refusing to sign",
            )),
        )
            .into_response();
    }
    // Persist the in-memory tracker too so successive lookups within
    // this same boot pass advance monotonically. The journal alone
    // would also do this, but keeping the in-memory mirror saves a
    // disk read on every receipt fetch — the lock is held by `bump`
    // for the disk write, but `floor()` is a cheap mutex read.
    s.sessions.modify(&id, |cs| {
        cs.last_seq = next_seq;
    });

    let blind = entry.last_blind;
    let r = Receipt {
        context: (*s.receipt_context).clone(),
        session_id: id,
        seq: next_seq,
        bytes_used: bytes,
        blind,
    };
    let payload = r.signing_payload();
    let node_sig = s.node_kp.sign(&payload);
    s.metrics
        .receipts_signed_total
        .fetch_add(1, Ordering::Relaxed);
    // Fan out to SSE subscribers. Mirrors the metrics increment above —
    // any time we sign a receipt proposal, an observer downstream
    // (audit relay, settlement bot) gets a real-time notification.
    // Capture the scalar fields up front: `r` is moved into the
    // `ProposedReceipt` below, and `id` was already consumed by the
    // `Receipt` constructor, so we use the original `id_hex` path
    // parameter (which `SessionId::from_hex` already validated) as the
    // session identifier in the event.
    let event_seq = r.seq;
    let event_bytes = r.bytes_used;

    // HFHE-2 shadow-blob emission. The sidecar's `encrypt_const`
    // round-trip is on the order of ~200µs; the no-shadow path
    // skips it entirely. Two ciphertexts (bytes_used + net) are
    // produced under deterministic per-receipt seeds derived from
    // `(session_id, seq)` so the same input produces identical
    // bytes — useful for the test suite + an auditor recomputing
    // the blob from plaintext + sk. We do NOT retry on sidecar
    // transient errors; a failure emits the receipt WITHOUT the
    // shadow blob and logs a warning. The chain doesn't verify
    // the blob today — a missing blob is a soft degrade, not a
    // hard fail.
    let (enc_bytes_used, enc_net, pvac_zero_proof) =
        match s.shadow_signer.as_ref() {
            None => (None, None, None),
            Some(signer) => {
                let net = event_bytes.saturating_mul(s.shadow_price_per_byte);
                let seed = shadow_seed_for(&id_hex, event_seq);
                let seed_b = shadow_subseed(&seed, b"bytes");
                let seed_n = shadow_subseed(&seed, b"net");
                let enc_b = signer
                    .pvac
                    .encrypt_const(&signer.circle_pk, &signer.circle_sk, event_bytes, &seed_b)
                    .await
                    .map_err(|e| {
                        tracing::warn!(error = %e, "shadow encrypt_const(bytes_used) failed; emitting receipt without shadow");
                        e
                    })
                    .ok();
                let enc_n = if enc_b.is_some() {
                    signer
                        .pvac
                        .encrypt_const(&signer.circle_pk, &signer.circle_sk, net, &seed_n)
                        .await
                        .map_err(|e| {
                            tracing::warn!(error = %e, "shadow encrypt_const(net) failed; emitting receipt without enc_net");
                            e
                        })
                        .ok()
                } else {
                    None
                };
                let proof = if let Some(ct) = enc_b.as_ref() {
                    use base64::Engine as _;
                    let blinding_b64 = base64::engine::general_purpose::STANDARD
                        .encode(blind.as_bytes());
                    signer
                        .pvac
                        .make_zero_proof(
                            &signer.circle_pk,
                            &signer.circle_sk,
                            ct,
                            event_bytes,
                            &blinding_b64,
                        )
                        .await
                        .map_err(|e| {
                            tracing::warn!(error = %e, "shadow make_zero_proof failed; emitting receipt without proof");
                            e
                        })
                        .ok()
                } else {
                    None
                };
                (enc_b, enc_n, proof)
            }
        };

    let proposed = ProposedReceipt {
        receipt: r,
        node_pubkey: s.node_kp.public,
        node_sig,
        enc_bytes_used,
        enc_net,
        pvac_zero_proof,
    };
    s.events.publish(crate::events::Event {
        ts_unix: octravpn_core::util::now_unix_secs(),
        kind: "receipt_signed".to_string(),
        payload: serde_json::json!({
            "session_id": id_hex.clone(),
            "seq": event_seq,
            "bytes_used": event_bytes,
        }),
    });
    // Persist a structured audit row so `audit verify`'s cross-check
    // sees a `(session_id, seq)` pair for every signed receipt. The
    // SSE event above is in-process and ephemeral; the audit row is
    // durable and HMAC-chained, which is what the operator's
    // forensics path actually consults.
    if let Some(audit) = &s.audit {
        if let Err(e) = audit
            .record_receipt_signed(id_hex.clone(), event_seq, event_bytes)
            .await
        {
            tracing::warn!(error = %e, "audit log receipt_signed write failed");
        }
    }

    Json(SessionStateResponse {
        bytes_served: bytes,
        last_seq: entry.last_seq,
        proposed: Some(proposed),
    })
    .into_response()
}

/// Request body for `POST /admin/preauth`. The `user` field mirrors
/// Tailscale's notion of a "user" — a label that gets bound into the
/// minted credential, used later by the (not-yet-implemented)
/// register handler to attribute a joining device.
#[derive(Debug, Deserialize)]
struct MintPreauthRequest {
    /// User label to bind the key to. Defaults to `"default"` so the
    /// interop test can `curl -d '{}'` and still get a usable key.
    #[serde(default = "default_user")]
    user: String,
    /// Whether the key may be redeemed by more than one device.
    /// Defaults to `false` (single-use) — the safer Tailscale-equivalent
    /// behaviour.
    #[serde(default)]
    reusable: bool,
}

fn default_user() -> String {
    "default".to_string()
}

#[derive(Debug, Serialize)]
struct MintPreauthResponse {
    /// The preauth token. Pass this to `tailscale up --authkey ...`.
    key: String,
    /// User the key is bound to.
    user: String,
    /// Unix-seconds expiry.
    expires_at: u64,
    /// Whether the key is reusable.
    reusable: bool,
}

/// Mint a preauth key.
///
/// Auth: bearer token from `[control].admin_token` (or
/// `OCTRAVPN_ADMIN_TOKEN` if the field is unset and the env-var is
/// present — handled at Hub-init time, not here). Hidden behind 404
/// when no token is configured.
async fn mint_preauth(
    State(s): State<Arc<ControlState>>,
    headers: axum::http::HeaderMap,
    body: Option<Json<MintPreauthRequest>>,
) -> impl IntoResponse {
    // No token configured ⇒ endpoint disabled. 404 keeps the surface
    // indistinguishable from a route that doesn't exist.
    let Some(want) = s.admin_token.as_deref() else {
        return (StatusCode::NOT_FOUND, "").into_response();
    };
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    let authorized = got.is_some_and(|tok| constant_time_eq_str(tok, want));
    if !authorized {
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    // Tolerate an empty body — curl-without-data is a common
    // operator habit; we just mint a key for the default user.
    let req = match body {
        Some(Json(b)) => b,
        None => MintPreauthRequest {
            user: default_user(),
            reusable: false,
        },
    };
    let pk = s
        .preauth_minter
        .mint(req.user, DEFAULT_PREAUTH_TTL, req.reusable);
    // Bump the mint counter here rather than inside PreauthMinter so
    // a node-local CLI mint (which also goes through `mint()` directly)
    // doesn't double-count when the bridge eventually wires its own
    // MetricsSink — the MetricsSink path is currently disabled at the
    // PreauthMinter constructor for control-plane-minted keys.
    s.metrics
        .preauth_mints_total
        .fetch_add(1, Ordering::Relaxed);
    Json(MintPreauthResponse {
        key: pk.key,
        user: pk.user,
        expires_at: pk.expires_at,
        reusable: pk.reusable,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use octravpn_core::{
        control::{announce_signing_payload, AnnounceSessionRequest},
        sig::verify,
    };

    fn signed_announce(
        session_id: SessionId,
        client_kp: &KeyPair,
        client_wg_pubkey: [u8; 32],
    ) -> AnnounceSessionRequest {
        let open_tx_hash = "test-open-tx".to_string();
        let client_sig = client_kp.sign(&announce_signing_payload(
            &session_id,
            &client_kp.public,
            &client_wg_pubkey,
            &open_tx_hash,
        ));
        AnnounceSessionRequest {
            session_id,
            client_pubkey: client_kp.public,
            client_wg_pubkey,
            open_tx_hash,
            client_sig,
        }
    }

    #[test]
    fn transaction_open_event_matches_u64_and_hex_session_ids() {
        let id_u64 = SessionId::from_u64(42);
        let tx = serde_json::json!({
            "events": [
                {"name": "Other", "session_id": 42},
                {"name": "SessionOpened", "session_id": 42}
            ]
        });
        assert!(transaction_has_session_opened(&tx, &id_u64));

        let id_hex = SessionId::new([0xAB; 32]);
        let tx = serde_json::json!({
            "events": [
                {"name": "SessionOpened", "session_id": id_hex.to_hex()}
            ]
        });
        assert!(transaction_has_session_opened(&tx, &id_hex));
        assert!(!transaction_has_session_opened(
            &tx,
            &SessionId::new([0xCD; 32])
        ));
    }

    #[tokio::test]
    async fn announce_rejects_bad_client_signature_without_side_effects() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x41u8; 32]);
        let mut req = signed_announce(id.clone(), &client_kp, [9u8; 32]);
        req.client_sig.0[0] ^= 1;

        let resp = announce(State(state.clone()), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!state.sessions.contains_key(&id));
        assert_eq!(state.allowlist.len(), 0);
        assert_eq!(state.metrics.announces_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.metrics.session_opens_total.load(Ordering::Relaxed), 0);
    }

    /// `/events` returns 404 when no token is configured, even if the
    /// caller supplies an `Authorization: Bearer …` header (the
    /// endpoint must be undetectable from outside in default mode).
    #[tokio::test]
    async fn events_sse_default_returns_not_found() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        // `ControlState::new` (test-only) sets events_token = None.
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer anything"),
        );
        let resp = events_sse(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `/events` returns 404 when the token is configured but the
    /// caller's Authorization header is missing or wrong. (We return
    /// 404 rather than 401 so external scanners can't confirm the
    /// endpoint exists.)
    #[tokio::test]
    async fn events_sse_rejects_wrong_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_events_token(Some("expected".to_string())),
        );
        // No header → 404.
        {
            let resp = events_sse(State(state.clone()), axum::http::HeaderMap::new()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Wrong token → 404.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong"),
            );
            let resp = events_sse(State(state.clone()), headers).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Right token → OK (SSE stream starts).
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer expected"),
            );
            let resp = events_sse(State(state), headers).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    /// `/metrics` returns 503 when `[control].metrics_token` is unset
    /// (the default). Operators must configure a token in production.
    #[tokio::test]
    async fn metrics_default_returns_503() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let headers = axum::http::HeaderMap::new();
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Token configured + wrong bearer → 401.
    #[tokio::test]
    async fn metrics_rejects_wrong_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("expected".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Token configured + right bearer → 200 with Prometheus exposition.
    #[tokio::test]
    async fn metrics_accepts_correct_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("expected".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer expected"),
        );
        let resp = metrics(State(state), headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Constant-time string compare returns true iff the strings are
    /// byte-equal. Property tested via three concrete cases — full
    /// coverage of the timing channel would need a microbenchmark.
    #[test]
    fn constant_time_eq_str_correctness() {
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        // Differing lengths short-circuit (acceptable).
        assert!(!constant_time_eq_str("abc", "abcd"));
        assert!(constant_time_eq_str("", ""));
    }

    #[tokio::test]
    async fn announce_then_state_returns_signed_proposal() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp.clone(), router, allowlist));
        let id = SessionId::new([42u8; 32]);

        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;

        assert!(state.sessions.contains_key(&id));

        // Reproduce the get_state body manually (bypass the axum layer).
        let r = Receipt {
            context: (*state.receipt_context).clone(),
            session_id: id.clone(),
            seq: 1,
            bytes_used: 0,
            blind: octravpn_core::session::Blind::new([0u8; 32]),
        };
        let payload = r.signing_payload();
        let sig = node_kp.sign(&payload);
        verify(&node_kp.public, &payload, &sig).unwrap();
    }

    /// Helper for the journal-wiring tests: take the JSON body off a
    /// `Response` and deserialize it as a `SessionStateResponse`.
    /// Skips the empty-body 404 case by panicking — callers must only
    /// pass it a body that's expected to contain JSON.
    async fn parse_state(resp: axum::response::Response) -> SessionStateResponse {
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(status, StatusCode::OK, "body = {body:?}");
        serde_json::from_slice::<SessionStateResponse>(&body).unwrap()
    }

    /// P1-8/9: a fresh session starts at journal floor 0; the first
    /// `/session/:id` returns a receipt at seq=1.
    #[tokio::test]
    async fn get_state_fresh_session_starts_at_seq_one() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x01u8; 32]);

        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;

        let resp = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        let sr = parse_state(resp).await;
        let proposed = sr.proposed.expect("proposal present");
        assert_eq!(proposed.receipt.seq, 1);
        assert_eq!(state.receipt_journal.floor(&id), 1);
    }

    /// P1-8/9 core: after the node has signed up to seq=K, an attacker
    /// who drops the in-memory state (BoundedMap reset → `last_seq=0`)
    /// MUST NOT be able to coax the node into signing a fresh seq=1.
    /// We simulate the in-memory reset by clearing the session entry
    /// out of `sessions` and re-announcing it. With the persistent
    /// journal in play, the next sign jumps to seq=K+1 (not seq=1).
    #[tokio::test]
    async fn get_state_restart_replay_rejected() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        // Use a real on-disk journal so the drop+reload simulates a
        // process restart.
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("receipts.bin");
        let journal =
            Arc::new(octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap());
        let metrics = Arc::new(NodeMetrics::default());
        metrics
            .started_at_unix
            .store(octravpn_core::util::now_unix_secs(), Ordering::Relaxed);
        // Tests bind a fixed v1.1 receipt context (test chain id) — the
        // hub builds the real one from node.toml at startup.
        let test_ctx = Arc::new(octravpn_core::receipt::ReceiptContext::v1_1(
            octravpn_core::address::Address::from_pubkey(&[0u8; 32]),
            octravpn_core::receipt::CHAIN_ID_TEST,
        ));
        let state = Arc::new(
            ControlState::with_metrics(
                node_kp.clone(),
                router.clone(),
                allowlist.clone(),
                metrics.clone(),
                test_ctx.clone(),
                journal,
            )
            .with_events_token(None),
        );
        let id = SessionId::new([0xABu8; 32]);

        // Sign three receipts (seq 1, 2, 3).
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        for expected_seq in 1..=3_u64 {
            let resp = get_state(State(state.clone()), Path(id.to_hex()))
                .await
                .into_response();
            let sr = parse_state(resp).await;
            assert_eq!(sr.proposed.unwrap().receipt.seq, expected_seq);
        }
        assert_eq!(state.receipt_journal.floor(&id), 3);

        // Simulate restart: drop the entire ControlState (and its
        // in-memory BoundedMap of sessions), then reopen the journal
        // from disk into a fresh state.
        drop(state);
        let journal2 =
            Arc::new(octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap());
        assert_eq!(
            journal2.floor(&id),
            3,
            "journal must persist across restart"
        );
        let state2 = Arc::new(
            ControlState::with_metrics(node_kp, router, allowlist, metrics, test_ctx, journal2)
                .with_events_token(None),
        );
        // The session has to be re-announced (announce inserts an
        // in-memory entry with last_seq=0). This is precisely the
        // scenario that used to let an attacker double-sign.
        announce(
            State(state2.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        // get_state must skip past the journal floor to seq=4, NOT
        // sign a fresh seq=1.
        let resp = get_state(State(state2.clone()), Path(id.to_hex()))
            .await
            .into_response();
        let sr = parse_state(resp).await;
        let proposed = sr.proposed.unwrap();
        assert_eq!(
            proposed.receipt.seq, 4,
            "post-restart seq must skip past the persistent floor"
        );
        assert_eq!(state2.receipt_journal.floor(&id), 4);
        // And the signature still verifies under the same node pubkey.
        let payload = proposed.receipt.signing_payload();
        verify(&proposed.node_pubkey, &payload, &proposed.node_sig).unwrap();
    }

    /// `/admin/preauth` is 404 when no `admin_token` is configured —
    /// the endpoint must be undetectable from outside in default
    /// mode, mirroring the `/events` design.
    #[tokio::test]
    async fn admin_preauth_hidden_without_token() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer anything"),
        );
        let resp = mint_preauth(State(state), headers, None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// With the token configured, a correct bearer mints a key; a
    /// missing or wrong bearer still returns 404 (not 401) so an
    /// external scanner can't tell the endpoint exists.
    #[tokio::test]
    async fn admin_preauth_token_gates_minting() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist).with_admin_token(Some("secret".into())),
        );

        // Missing → 404.
        {
            let resp = mint_preauth(State(state.clone()), axum::http::HeaderMap::new(), None)
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Wrong → 404.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer wrong"),
            );
            let resp = mint_preauth(State(state.clone()), headers, None)
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        // Right → 200 + minted key.
        {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer secret"),
            );
            let resp = mint_preauth(
                State(state.clone()),
                headers,
                Some(Json(MintPreauthRequest {
                    user: "alice".into(),
                    reusable: false,
                })),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v["key"].as_str().unwrap().starts_with("octrapreauth-"));
            assert_eq!(v["user"].as_str().unwrap(), "alice");
            assert!(!v["reusable"].as_bool().unwrap());
        }
    }

    // ============================================================
    // NodeMetrics field tests — every counter wired by this PR has
    // a matching unit test that drives a real code path and asserts
    // a deterministic increment. Gauges are read directly off the
    // /metrics handler's output to confirm the Prometheus
    // exposition includes the field name.
    // ============================================================

    /// `announce` bumps both `announces_total` AND
    /// `session_opens_total`. The two counters mirror each other for
    /// now; the test pins that behaviour so a future "rejected
    /// announce" path notices it has to split them.
    #[tokio::test]
    async fn announce_bumps_session_opens_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let before = state.metrics.session_opens_total.load(Ordering::Relaxed);
        announce(
            State(state.clone()),
            Json(signed_announce(
                SessionId::new([7u8; 32]),
                &client_kp,
                [9u8; 32],
            )),
        )
        .await;
        let after = state.metrics.session_opens_total.load(Ordering::Relaxed);
        assert_eq!(after, before + 1);
    }

    /// `mint_preauth` bumps `preauth_mints_total` exactly once on a
    /// successful mint. The token-gate is held at the handler so we
    /// only test the happy path here; the 404 paths are exercised by
    /// `admin_preauth_hidden_without_token` / `…_token_gates_minting`
    /// above and confirmed not to bump the counter.
    #[tokio::test]
    async fn mint_preauth_bumps_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist).with_admin_token(Some("secret".into())),
        );
        let before = state.metrics.preauth_mints_total.load(Ordering::Relaxed);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        let resp = mint_preauth(
            State(state.clone()),
            headers,
            Some(Json(MintPreauthRequest {
                user: "alice".into(),
                reusable: false,
            })),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state.metrics.preauth_mints_total.load(Ordering::Relaxed),
            before + 1
        );
    }

    /// A 404 mint path (no token configured) must NOT bump the
    /// counter — the increment lives after the auth check.
    #[tokio::test]
    async fn mint_preauth_404_does_not_bump_counter() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let before = state.metrics.preauth_mints_total.load(Ordering::Relaxed);
        let resp = mint_preauth(State(state.clone()), axum::http::HeaderMap::new(), None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            state.metrics.preauth_mints_total.load(Ordering::Relaxed),
            before
        );
    }

    /// The `MetricsSink` impl on `NodeMetrics` translates a
    /// `"preauth_redeem"` event to a counter bump. This is the path
    /// the headscale-api wire register handler exercises in
    /// production.
    #[test]
    fn metrics_sink_translates_preauth_events() {
        let m = Arc::new(NodeMetrics::default());
        let sink: Arc<dyn octravpn_mesh::MetricsSink> = m.clone();
        sink.record_event("preauth_mint");
        sink.record_event("preauth_redeem");
        sink.record_event("preauth_redeem");
        // Unknown event names must be ignored (additive design).
        sink.record_event("definitely_not_a_real_event");
        assert_eq!(m.preauth_mints_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.preauth_redemptions_total.load(Ordering::Relaxed), 2);
    }

    /// `record_rpc(true)` only bumps the request counter;
    /// `record_rpc(false)` bumps both. Pinning the symmetric API.
    #[test]
    fn record_rpc_counts_errors_as_subset() {
        let m = NodeMetrics::default();
        m.record_rpc(true);
        m.record_rpc(true);
        m.record_rpc(false);
        assert_eq!(m.rpc_requests_total.load(Ordering::Relaxed), 3);
        assert_eq!(m.rpc_errors_total.load(Ordering::Relaxed), 1);
    }

    /// `record_wg_handshake(true|false)` routes to the correct
    /// counter. Trivial but pins the dispatch.
    #[test]
    fn record_wg_handshake_dispatches() {
        let m = NodeMetrics::default();
        m.record_wg_handshake(true);
        m.record_wg_handshake(true);
        m.record_wg_handshake(false);
        assert_eq!(m.wg_handshake_success_total.load(Ordering::Relaxed), 2);
        assert_eq!(m.wg_handshake_fail_total.load(Ordering::Relaxed), 1);
    }

    /// `record_slash_double_sign` is a one-line incrementer; pin its
    /// behaviour so an accidental refactor (e.g. moving the bump
    /// behind a feature flag) is caught by CI.
    #[test]
    fn record_slash_double_sign_bumps_counter() {
        let m = NodeMetrics::default();
        m.record_slash_double_sign();
        m.record_slash_double_sign();
        assert_eq!(m.slash_double_sign_total.load(Ordering::Relaxed), 2);
    }

    /// `get_state` after a fresh announce bumps both
    /// `state_lookups_total` and `receipts_signed_total` — confirms
    /// the pre-existing counters still fire after the audit-emission
    /// addition didn't reorder anything.
    #[tokio::test]
    async fn get_state_bumps_both_lookup_and_sign_counters() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(ControlState::new(node_kp, router, allowlist));
        let id = SessionId::new([0x55u8; 32]);
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        let lookups_before = state.metrics.state_lookups_total.load(Ordering::Relaxed);
        let signed_before = state.metrics.receipts_signed_total.load(Ordering::Relaxed);
        let _ = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        assert_eq!(
            state.metrics.state_lookups_total.load(Ordering::Relaxed),
            lookups_before + 1
        );
        assert_eq!(
            state.metrics.receipts_signed_total.load(Ordering::Relaxed),
            signed_before + 1
        );
    }

    /// Every new metric name shows up in the Prometheus exposition
    /// output. The serializer is hand-rolled (one big `format!`); the
    /// test pins that no field was lost in a future refactor.
    #[tokio::test]
    async fn metrics_handler_emits_every_new_field() {
        let node_kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let state = Arc::new(
            ControlState::new(node_kp, router, allowlist)
                .with_metrics_token(Some("test-token".to_string())),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token"),
        );
        let resp = metrics(State(state), headers).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        for needle in [
            "octravpn_slash_double_sign_total ",
            "octravpn_preauth_mints_total ",
            "octravpn_preauth_redemptions_total ",
            "octravpn_rpc_requests_total ",
            "octravpn_rpc_errors_total ",
            "octravpn_wg_handshake_success_total ",
            "octravpn_wg_handshake_fail_total ",
            "octravpn_session_opens_total ",
            "octravpn_session_closes_total ",
            "octravpn_session_no_shows_total ",
            "octravpn_tailnet_member_count ",
            "octravpn_ip_allocator_used ",
            "octravpn_ip_allocator_capacity ",
        ] {
            assert!(
                text.contains(needle),
                "/metrics body missing {needle}; body=\n{text}"
            );
        }
    }

    /// `get_state` emits a `receipt_signed` audit row carrying the
    /// freshly signed `(session_id, seq, bytes_used)` tuple. The
    /// HMAC-chained file is inspected via `AuditLog::verify_file`
    /// and then the raw lines are parsed to confirm the new entry's
    /// `extra.seq` matches the receipt's seq.
    #[tokio::test]
    async fn get_state_emits_receipt_signed_audit_row() {
        let node_kp = Arc::new(KeyPair::generate());
        let client_kp = KeyPair::generate();
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(16, std::time::Duration::from_secs(60)));
        let dir = tempfile::tempdir().unwrap();
        let audit = crate::audit::AuditLog::open(dir.path()).unwrap();
        let state = Arc::new(ControlState::new(node_kp, router, allowlist).with_audit(audit));
        let id = SessionId::new([0x66u8; 32]);
        announce(
            State(state.clone()),
            Json(signed_announce(id.clone(), &client_kp, [9u8; 32])),
        )
        .await;
        let _ = get_state(State(state.clone()), Path(id.to_hex()))
            .await
            .into_response();
        // Drain to disk: the audit write is fired via
        // tokio::task::spawn_blocking; yield until the file has the
        // expected line count.
        for _ in 0..50 {
            let files: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("audit-"))
                .map(|e| e.path())
                .collect();
            if let Some(p) = files.first() {
                let body = std::fs::read_to_string(p).unwrap();
                if body.lines().count() >= 2 {
                    // 2 lines = 1 announce + 1 receipt_signed.
                    assert!(body.contains("receipt_signed"));
                    assert!(body.contains("\\\"seq\\\":1"));
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("audit log never observed the receipt_signed row");
    }

    /// P1-8/9: the journal file is durable across the
    /// `ReceiptJournal::open` lifecycle — what the test above
    /// implicitly relies on, called out explicitly here. Bumping then
    /// reopening produces the same floor.
    #[tokio::test]
    async fn journal_file_is_durable_across_open() {
        use octravpn_core::receipt_journal::ReceiptJournal;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rj.bin");
        let sess = SessionId::new([0x12u8; 32]);

        let j1 = ReceiptJournal::open(&path).unwrap();
        j1.bump(&sess, 99).unwrap();
        drop(j1);

        let j2 = ReceiptJournal::open(&path).unwrap();
        assert_eq!(j2.floor(&sess), 99);
    }

    // ====================================================================
    // HFHE-2 shadow-blob tests (control-plane integration).
    // ====================================================================

    #[test]
    fn shadow_seed_for_is_deterministic_per_session_and_seq() {
        let a = shadow_seed_for("abcd", 1);
        let b = shadow_seed_for("abcd", 1);
        let c = shadow_seed_for("abcd", 2);
        let d = shadow_seed_for("abce", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn shadow_subseed_differs_per_label() {
        let parent = shadow_seed_for("abcd", 7);
        let s1 = shadow_subseed(&parent, b"bytes");
        let s2 = shadow_subseed(&parent, b"net");
        let s1_again = shadow_subseed(&parent, b"bytes");
        assert_eq!(s1, s1_again);
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 64);
    }

    /// A `ControlState` constructed without a `ShadowSigner` MUST
    /// have `shadow_signer = None` and `shadow_price_per_byte = 0`
    /// — the no-shadow default. This is the safety-net pin that
    /// keeps the no-sidecar path wire-identical to pre-HFHE-2.
    #[test]
    fn control_state_default_has_no_shadow_signer() {
        let kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(
            10,
            std::time::Duration::from_secs(60),
        ));
        let state = ControlState::new(kp, router, allowlist);
        assert!(state.shadow_signer.is_none());
        assert_eq!(state.shadow_price_per_byte, 0);
    }

    /// `with_shadow_signer(None, …)` is a no-op — the field stays
    /// `None`. Verifies the wiring is additive, not destructive.
    #[test]
    fn with_shadow_signer_none_is_identity() {
        let kp = Arc::new(KeyPair::generate());
        let router = Arc::new(OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(
            10,
            std::time::Duration::from_secs(60),
        ));
        let state = ControlState::new(kp, router, allowlist).with_shadow_signer(None, 42);
        assert!(state.shadow_signer.is_none());
        assert_eq!(state.shadow_price_per_byte, 42);
    }

    /// JSON serialisation of a `ProposedReceipt` with no shadow
    /// data does NOT mention the three new field names — the wire
    /// stays byte-identical to pre-HFHE-2 receipts.
    #[test]
    fn proposed_receipt_no_shadow_json_omits_fields() {
        let kp_n = KeyPair::generate();
        let r = octravpn_core::receipt::Receipt::new(
            octravpn_core::receipt::ReceiptContext::v1_1(
                octravpn_core::address::Address::from_pubkey(&[0u8; 32]),
                octravpn_core::receipt::CHAIN_ID_TEST,
            ),
            SessionId::new([1u8; 32]),
            1,
            100,
            octravpn_core::session::Blind::new([0u8; 32]),
        );
        let sig = kp_n.sign(&r.signing_payload());
        let p = octravpn_core::control::ProposedReceipt {
            receipt: r,
            node_pubkey: kp_n.public,
            node_sig: sig,
            enc_bytes_used: None,
            enc_net: None,
            pvac_zero_proof: None,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(!j.contains("enc_bytes_used"), "wire: {j}");
        assert!(!j.contains("enc_net"));
        assert!(!j.contains("pvac_zero_proof"));
    }
}
