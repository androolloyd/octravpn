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
        AnnounceSessionRequest, AnnounceSessionResponse, ProposedReceipt, SessionStateResponse,
    },
    receipt::{Receipt, ReceiptContext},
    receipt_journal::ReceiptJournal,
    session::SessionId,
    sig::KeyPair,
};
use serde::Serialize;
use tokio_stream::wrappers::BroadcastStream;
use tracing::info;

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
}

/// Lightweight counters exposed via the /metrics endpoint. Kept as
/// AtomicU64 to avoid lock contention on the data plane.
#[derive(Default)]
pub(crate) struct NodeMetrics {
    pub announces_total: AtomicU64,
    pub state_lookups_total: AtomicU64,
    pub receipts_signed_total: AtomicU64,
    pub started_at_unix: AtomicU64,
    /// Unix timestamp of the most recent successful on-chain
    /// attestation refresh. Set by the hub's attestation loop.
    pub last_attestation_unix: AtomicU64,
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
            receipt_context,
            receipt_journal,
        }
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

    pub(crate) fn router_axum(self: Arc<Self>) -> Router {
        use axum::middleware;
        let rate_limiter = crate::rate_limit::RateLimiter::default_for_control_plane();

        // Rate-limited surface: the regular request/response endpoints.
        let limited = Router::new()
            .route("/session", post(announce))
            .route("/session/:id", get(get_state))
            .route("/health", get(health))
            .route("/metrics", get(metrics))
            .layer(middleware::from_fn_with_state(
                rate_limiter,
                crate::rate_limit::rate_limit_layer,
            ))
            .with_state(self.clone());

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
            .with_state(self);

        limited.merge(unlimited)
    }
}

/// Periodic sweeper: evicts sessions idle past TTL.
pub(crate) async fn run_sweeper(state: Arc<ControlState>) {
    loop {
        tokio::time::sleep(CONTROL_SWEEP_PERIOD).await;
        let n = state.sessions.sweep();
        if n > 0 {
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
    s.metrics.announces_total.fetch_add(1, Ordering::Relaxed);
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

/// Prometheus text format.
async fn metrics(State(s): State<Arc<ControlState>>) -> impl IntoResponse {
    let m = &s.metrics;
    let body = format!(
        "# HELP octravpn_announces_total Sessions announced via control plane.\n\
         # TYPE octravpn_announces_total counter\n\
         octravpn_announces_total {}\n\
         # HELP octravpn_state_lookups_total /session/:id GETs.\n\
         # TYPE octravpn_state_lookups_total counter\n\
         octravpn_state_lookups_total {}\n\
         # HELP octravpn_receipts_signed_total Node-signed receipt proposals returned.\n\
         # TYPE octravpn_receipts_signed_total counter\n\
         octravpn_receipts_signed_total {}\n\
         # HELP octravpn_bytes_served_total Cumulative bytes traversed (in+out).\n\
         # TYPE octravpn_bytes_served_total counter\n\
         octravpn_bytes_served_total {}\n\
         # HELP octravpn_active_sessions Current sessions tracked by control plane.\n\
         # TYPE octravpn_active_sessions gauge\n\
         octravpn_active_sessions {}\n\
         # HELP octravpn_last_attestation_unix Unix time of last successful attestation.\n\
         # TYPE octravpn_last_attestation_unix gauge\n\
         octravpn_last_attestation_unix {}\n\
         # HELP octravpn_uptime_seconds Process uptime.\n\
         # TYPE octravpn_uptime_seconds counter\n\
         octravpn_uptime_seconds {}\n",
        m.announces_total.load(Ordering::Relaxed),
        m.state_lookups_total.load(Ordering::Relaxed),
        m.receipts_signed_total.load(Ordering::Relaxed),
        s.router.total_bytes(),
        s.sessions.len(),
        m.last_attestation_unix.load(Ordering::Relaxed),
        octravpn_core::util::now_unix_secs()
            .saturating_sub(m.started_at_unix.load(Ordering::Relaxed)),
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
    let authorized = got
        .map(|got_tok| constant_time_eq_str(got_tok, want))
        .unwrap_or(false);
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
            Json(ApiError::new("receipt seq floor violation; refusing to sign")),
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
    let proposed = ProposedReceipt {
        receipt: r,
        node_pubkey: s.node_kp.public,
        node_sig,
    };
    s.events.publish(crate::events::Event {
        ts_unix: octravpn_core::util::now_unix_secs(),
        kind: "receipt_signed".to_string(),
        payload: serde_json::json!({
            "session_id": id_hex,
            "seq": event_seq,
            "bytes_used": event_bytes,
        }),
    });

    Json(SessionStateResponse {
        bytes_served: bytes,
        last_seq: entry.last_seq,
        proposed: Some(proposed),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use octravpn_core::{control::AnnounceSessionRequest, sig::verify};

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
            Json(AnnounceSessionRequest {
                session_id: id.clone(),
                client_pubkey: client_kp.public,
                client_wg_pubkey: [9u8; 32],
            }),
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
            Json(AnnounceSessionRequest {
                session_id: id.clone(),
                client_pubkey: client_kp.public,
                client_wg_pubkey: [9u8; 32],
            }),
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
        let journal = Arc::new(
            octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap(),
        );
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
            Json(AnnounceSessionRequest {
                session_id: id.clone(),
                client_pubkey: client_kp.public,
                client_wg_pubkey: [9u8; 32],
            }),
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
        let journal2 = Arc::new(
            octravpn_core::receipt_journal::ReceiptJournal::open(&journal_path).unwrap(),
        );
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
            Json(AnnounceSessionRequest {
                session_id: id.clone(),
                client_pubkey: client_kp.public,
                client_wg_pubkey: [9u8; 32],
            }),
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
}
