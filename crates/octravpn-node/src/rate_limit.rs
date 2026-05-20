//! Per-IP token-bucket rate limit for the control-plane HTTP service.
//!
//! Each (source-IP, route-class) pair gets `burst` tokens that refill at
//! `rps` tokens/sec. Requests consume one token; when the bucket is
//! empty the middleware returns `429 Too Many Requests` with a
//! `Retry-After` header in whole seconds.
//!
//! ## Route classes
//!
//! Routes are bucketed by path prefix so a flood against one surface
//! does not starve another. The defaults are:
//!
//! | Class       | Path prefix     | rps | burst |
//! |-------------|-----------------|----:|------:|
//! | `preauth`   | `/admin/preauth`|  60 |   120 |
//! | `receipt`   | `/session`      |  60 |   120 |
//! | `v3_calls`  | `/v3_calls`     |  10 |    30 |
//! | (default)   | everything else |  60 |   120 |
//!
//! `/health` and `/metrics` bypass the middleware entirely
//! (`/metrics` is already bearer-gated, `/health` is a liveness probe).
//! `/events` is an SSE stream and is mounted on a separate router
//! merged outside this layer; see `control.rs::router_axum`.
//!
//! ## Config
//!
//! Driven by the `[control.rate_limit]` block in `node.toml`. When
//! `enabled = false` the middleware is bypassed entirely (the router is
//! built without the `from_fn_with_state` layer) so disabling has zero
//! per-request overhead. Per-route overrides under
//! `[control.rate_limit.routes.<class>]` replace the class defaults.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde::Deserialize;

/// One token bucket per (IP, class) pair. We keep the (IP, class) split
/// inside the same map keyed by `(IpAddr, RouteClass)` so a single
/// `max_keys` budget bounds memory across all classes.
type BucketKey = (IpAddr, RouteClass);

/// Coarse route classes recognised by the middleware. The class is
/// derived from the request path; see [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RouteClass {
    /// `/admin/preauth` — preauth-key mint surface.
    Preauth,
    /// `/session*` — announces (`POST /session`) and receipt-signing
    /// state fetches (`GET /session/:id`).
    Receipt,
    /// `/v3_calls*` — v3 chain-call surface (reserved for future
    /// expansion; no routes mounted today but the class is wired so
    /// adding one does not require touching config or middleware).
    V3Calls,
    /// Everything else that did not bypass.
    Other,
}

impl RouteClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Preauth => "preauth",
            Self::Receipt => "receipt",
            Self::V3Calls => "v3_calls",
            Self::Other => "other",
        }
    }
}

/// Returns `Some(class)` for paths that the middleware should
/// rate-limit, or `None` for paths that bypass entirely (`/health`,
/// `/metrics`, anything under `/events`).
pub(crate) fn classify(path: &str) -> Option<RouteClass> {
    // Bypass list — these MUST short-circuit before any token-bucket
    // bookkeeping so `/health` keeps replying under load and
    // `/metrics` (already bearer-gated) can be scraped on schedule.
    if path == "/health" || path == "/metrics" || path.starts_with("/events") {
        return None;
    }
    if path.starts_with("/admin/preauth") {
        return Some(RouteClass::Preauth);
    }
    if path.starts_with("/v3_calls") {
        return Some(RouteClass::V3Calls);
    }
    if path == "/session" || path.starts_with("/session/") || path.starts_with("/receipt") {
        return Some(RouteClass::Receipt);
    }
    Some(RouteClass::Other)
}

/// Per-route policy. `rps` is the sustained refill rate and `burst` is
/// the bucket capacity (maximum tokens that may accumulate).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy {
    pub rps: f64,
    pub burst: f64,
}

impl Policy {
    fn default_for(class: RouteClass) -> Self {
        match class {
            RouteClass::Preauth | RouteClass::Receipt | RouteClass::Other => Self {
                rps: 60.0,
                burst: 120.0,
            },
            RouteClass::V3Calls => Self {
                rps: 10.0,
                burst: 30.0,
            },
        }
    }
}

/// TOML deserialisation surface — `[control.rate_limit]`.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct RateLimitCfg {
    /// Master switch. When `false` the layer is omitted entirely; when
    /// unset (the default for back-compat with existing configs) the
    /// layer is *enabled* with the defaults below.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Fallback rps for any class that lacks a `[routes.<class>]`
    /// override. Defaults to 60.
    #[serde(default)]
    pub default_rps: Option<f64>,
    /// Fallback burst for any class that lacks a `[routes.<class>]`
    /// override. Defaults to 120.
    #[serde(default)]
    pub burst: Option<f64>,
    /// Per-route overrides keyed by class name (`preauth`, `receipt`,
    /// `v3_calls`, `other`).
    #[serde(default)]
    pub routes: HashMap<String, RouteCfg>,
    /// Cap on the (IP, class) map to bound memory. Defaults to 10_000.
    #[serde(default)]
    pub max_keys: Option<usize>,
}

#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub(crate) struct RouteCfg {
    #[serde(default)]
    pub rps: Option<f64>,
    #[serde(default)]
    pub burst: Option<f64>,
}

fn default_enabled() -> bool {
    true
}

impl RateLimitCfg {
    fn policy_for(&self, class: RouteClass) -> Policy {
        let base_rps = self
            .default_rps
            .unwrap_or_else(|| Policy::default_for(class).rps);
        let base_burst = self
            .burst
            .unwrap_or_else(|| Policy::default_for(class).burst);
        // Class default trumps `default_rps` when no override is set —
        // the class defaults encode protocol intent (v3_calls is
        // intentionally tighter than preauth), so the `default_*`
        // fallbacks only matter for the `Other` class.
        let mut p = if matches!(class, RouteClass::Other) {
            Policy {
                rps: base_rps,
                burst: base_burst,
            }
        } else {
            Policy::default_for(class)
        };
        if let Some(over) = self.routes.get(class.as_str()) {
            if let Some(rps) = over.rps {
                p.rps = rps;
            }
            if let Some(burst) = over.burst {
                p.burst = burst;
            }
        }
        p
    }
}

#[derive(Clone)]
pub(crate) struct RateLimiter {
    policies: Arc<[(RouteClass, Policy); 4]>,
    max_keys: usize,
    inner: Arc<Mutex<HashMap<BucketKey, Bucket>>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Default limiter used when no `[control.rate_limit]` block is
    /// present. Matches the table in the module docstring.
    ///
    /// Kept around even though `router_axum` builds the limiter via
    /// [`from_cfg`] — the tests construct it directly to assert the
    /// documented defaults.
    #[cfg(test)]
    pub(crate) fn default_for_control_plane() -> Self {
        Self::from_cfg(&RateLimitCfg::default())
    }

    pub(crate) fn from_cfg(cfg: &RateLimitCfg) -> Self {
        let policies = [
            (RouteClass::Preauth, cfg.policy_for(RouteClass::Preauth)),
            (RouteClass::Receipt, cfg.policy_for(RouteClass::Receipt)),
            (RouteClass::V3Calls, cfg.policy_for(RouteClass::V3Calls)),
            (RouteClass::Other, cfg.policy_for(RouteClass::Other)),
        ];
        Self {
            policies: Arc::new(policies),
            max_keys: cfg.max_keys.unwrap_or(10_000),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn policy(&self, class: RouteClass) -> Policy {
        // Linear scan over a fixed-size array of 4 — faster than a hash
        // lookup and keeps the per-request hot path branch-free for the
        // common preauth/receipt classes.
        for (k, p) in self.policies.iter() {
            if *k == class {
                return *p;
            }
        }
        Policy::default_for(class)
    }

    /// Try to consume one token for `(ip, class)`. Returns `Ok(())`
    /// when allowed, or `Err(retry_after_secs)` (always >= 1) when the
    /// caller should wait.
    pub(crate) fn try_acquire(&self, ip: IpAddr, class: RouteClass) -> Result<(), u64> {
        let policy = self.policy(class);
        if policy.burst <= 0.0 {
            // A burst of 0 disables the class entirely. We surface that
            // as 429 with Retry-After: 1 so clients still back off
            // rather than tight-loop.
            return Err(1);
        }
        let now = Instant::now();
        let key = (ip, class);
        let mut m = self.inner.lock();
        if m.len() >= self.max_keys && !m.contains_key(&key) {
            // Evict an arbitrary key to bound memory under abuse. A
            // proper LRU would be more accurate but each entry is only
            // ~64B; eviction here is a release valve, not a fairness
            // mechanism.
            if let Some(k) = m.keys().next().copied() {
                m.remove(&k);
            }
        }
        let bucket = m.entry(key).or_insert_with(|| Bucket {
            tokens: policy.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = elapsed.mul_add(policy.rps, bucket.tokens).min(policy.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Time until the bucket has one whole token again. Round
            // up to whole seconds so the Retry-After value always
            // satisfies the request when honoured.
            let deficit = 1.0 - bucket.tokens;
            let secs = (deficit / policy.rps).ceil().max(1.0);
            Err(secs as u64)
        }
    }
}

/// axum middleware: classifies the request, consumes one token from
/// the appropriate bucket, returns 429 + `Retry-After` on rejection.
///
/// Bypassed paths (`/health`, `/metrics`, `/events*`) pass through
/// without touching the bucket map.
pub(crate) async fn rate_limit_layer(
    State(rl): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(class) = classify(req.uri().path()) else {
        return next.run(req).await;
    };
    match rl.try_acquire(addr.ip(), class) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            );
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, time::Duration};

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet))
    }

    #[test]
    fn classify_routes_correctly() {
        assert_eq!(classify("/health"), None);
        assert_eq!(classify("/metrics"), None);
        assert_eq!(classify("/events"), None);
        assert_eq!(classify("/events/foo"), None);
        assert_eq!(classify("/admin/preauth"), Some(RouteClass::Preauth));
        assert_eq!(classify("/session"), Some(RouteClass::Receipt));
        assert_eq!(classify("/session/abc-123"), Some(RouteClass::Receipt));
        assert_eq!(classify("/receipt/foo"), Some(RouteClass::Receipt));
        assert_eq!(classify("/v3_calls/foo"), Some(RouteClass::V3Calls));
        assert_eq!(classify("/unknown"), Some(RouteClass::Other));
    }

    #[test]
    fn defaults_match_documented_table() {
        let cfg = RateLimitCfg::default();
        let p = cfg.policy_for(RouteClass::Preauth);
        assert_eq!(p.rps, 60.0);
        assert_eq!(p.burst, 120.0);
        let p = cfg.policy_for(RouteClass::Receipt);
        assert_eq!(p.rps, 60.0);
        assert_eq!(p.burst, 120.0);
        let p = cfg.policy_for(RouteClass::V3Calls);
        assert_eq!(p.rps, 10.0);
        assert_eq!(p.burst, 30.0);
    }

    #[test]
    fn per_route_overrides_replace_class_defaults() {
        let mut cfg = RateLimitCfg::default();
        cfg.routes.insert(
            "preauth".into(),
            RouteCfg {
                rps: Some(5.0),
                burst: Some(10.0),
            },
        );
        let p = cfg.policy_for(RouteClass::Preauth);
        assert_eq!(p.rps, 5.0);
        assert_eq!(p.burst, 10.0);
        // Other classes untouched.
        let p = cfg.policy_for(RouteClass::Receipt);
        assert_eq!(p.rps, 60.0);
        assert_eq!(p.burst, 120.0);
    }

    #[test]
    fn try_acquire_allows_burst_then_returns_retry_after() {
        // Tight bucket: burst 3, refill 0.001/s (effectively static
        // for the test window) so we can assert the burst budget
        // exactly without flaking on timing.
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: Some(0.001),
            burst: Some(3.0),
            routes: HashMap::new(),
            max_keys: Some(100),
        };
        let rl = RateLimiter::from_cfg(&cfg);
        // The `Other` class picks up these defaults.
        for _ in 0..3 {
            rl.try_acquire(ip(1), RouteClass::Other).unwrap();
        }
        let err = rl.try_acquire(ip(1), RouteClass::Other).unwrap_err();
        assert!(err >= 1, "Retry-After must be >= 1 second");
    }

    #[test]
    fn classes_have_independent_buckets() {
        let rl = RateLimiter::default_for_control_plane();
        // Drain v3_calls (burst 30).
        for _ in 0..30 {
            rl.try_acquire(ip(1), RouteClass::V3Calls).unwrap();
        }
        assert!(rl.try_acquire(ip(1), RouteClass::V3Calls).is_err());
        // Receipt class on the same IP must still have its full burst.
        for _ in 0..120 {
            rl.try_acquire(ip(1), RouteClass::Receipt).unwrap();
        }
        assert!(rl.try_acquire(ip(1), RouteClass::Receipt).is_err());
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let rl = RateLimiter::default_for_control_plane();
        // Drain IP 1 on Preauth.
        for _ in 0..120 {
            rl.try_acquire(ip(1), RouteClass::Preauth).unwrap();
        }
        assert!(rl.try_acquire(ip(1), RouteClass::Preauth).is_err());
        // IP 2 still has its full budget.
        rl.try_acquire(ip(2), RouteClass::Preauth).unwrap();
    }

    #[test]
    fn refills_over_time() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: Some(100.0),
            burst: Some(1.0),
            routes: HashMap::new(),
            max_keys: Some(100),
        };
        let rl = RateLimiter::from_cfg(&cfg);
        rl.try_acquire(ip(1), RouteClass::Other).unwrap();
        assert!(rl.try_acquire(ip(1), RouteClass::Other).is_err());
        std::thread::sleep(Duration::from_millis(20)); // 2 tokens at 100/s
        rl.try_acquire(ip(1), RouteClass::Other)
            .expect("should have refilled by now");
    }

    // ------------------------------------------------------------
    // Router-level integration tests. These build a stub axum router
    // identical in shape to `control.rs::router_axum`'s limited
    // surface and drive it via `tower::ServiceExt::oneshot`, injecting
    // `ConnectInfo<SocketAddr>` into the request extensions (which
    // `into_make_service_with_connect_info` would do at serve time).
    // ------------------------------------------------------------

    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::Request,
        routing::{get, post},
    };
    use tower::ServiceExt;

    fn addr(octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), 12345)
    }

    fn build_router(cfg: RateLimitCfg) -> axum::Router {
        async fn ok() -> &'static str {
            "ok"
        }
        let routes = axum::Router::new()
            .route("/admin/preauth", post(ok))
            .route("/session", post(ok))
            .route("/session/:id", get(ok))
            .route("/v3_calls/:method", post(ok))
            .route("/health", get(ok))
            .route("/metrics", get(ok))
            .route("/unknown", get(ok));
        if cfg.enabled {
            let rl = RateLimiter::from_cfg(&cfg);
            routes.layer(axum::middleware::from_fn_with_state(rl, rate_limit_layer))
        } else {
            routes
        }
    }

    fn req(method: &str, path: &str, peer: SocketAddr) -> Request<Body> {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        r.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
        r
    }

    /// (1) Hammering `/admin/preauth` past the limit returns 429 with
    /// a `Retry-After` header in whole seconds >= 1.
    #[tokio::test]
    async fn preauth_flood_returns_429_with_retry_after() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: None,
            burst: None,
            routes: [(
                "preauth".into(),
                RouteCfg {
                    rps: Some(0.001),
                    burst: Some(3.0),
                },
            )]
            .into_iter()
            .collect(),
            max_keys: Some(1024),
        };
        let app = build_router(cfg);
        let peer = addr(11);
        for _ in 0..3 {
            let resp = app
                .clone()
                .oneshot(req("POST", "/admin/preauth", peer))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app
            .clone()
            .oneshot(req("POST", "/admin/preauth", peer))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After header must be present on 429")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(retry >= 1, "Retry-After must be >= 1, got {retry}");
    }

    /// (2) Bursts up to the configured budget succeed; the boundary is
    /// exact (Nth allowed, (N+1)th rejected).
    #[tokio::test]
    async fn burst_budget_is_honoured_to_the_token() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: None,
            burst: None,
            routes: [(
                "receipt".into(),
                RouteCfg {
                    rps: Some(0.001),
                    burst: Some(5.0),
                },
            )]
            .into_iter()
            .collect(),
            max_keys: Some(1024),
        };
        let app = build_router(cfg);
        let peer = addr(12);
        for i in 0..5 {
            let resp = app
                .clone()
                .oneshot(req("POST", "/session", peer))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request {i} should pass");
        }
        let resp = app
            .clone()
            .oneshot(req("POST", "/session", peer))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// (3) Per-route overrides are honoured AND classes are
    /// independent on the same source IP.
    #[tokio::test]
    async fn per_route_overrides_are_honoured() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: Some(60.0),
            burst: Some(120.0),
            routes: [(
                "v3_calls".into(),
                RouteCfg {
                    rps: Some(0.001),
                    burst: Some(3.0),
                },
            )]
            .into_iter()
            .collect(),
            max_keys: Some(1024),
        };
        let app = build_router(cfg);
        let peer = addr(13);
        for _ in 0..3 {
            let resp = app
                .clone()
                .oneshot(req("POST", "/v3_calls/foo", peer))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app
            .clone()
            .oneshot(req("POST", "/v3_calls/foo", peer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "v3_calls override must reject"
        );
        // Receipt class on same IP unaffected.
        let resp = app
            .clone()
            .oneshot(req("POST", "/session", peer))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "receipt bucket independent of v3_calls drain"
        );
    }

    /// (4) `enabled = false` bypasses the layer entirely — a flood
    /// that would 429 under the production defaults passes through.
    #[tokio::test]
    async fn disabling_via_config_bypasses_limits() {
        let cfg = RateLimitCfg {
            enabled: false,
            default_rps: None,
            burst: None,
            routes: HashMap::new(),
            max_keys: None,
        };
        let app = build_router(cfg);
        let peer = addr(14);
        for i in 0..200 {
            let resp = app
                .clone()
                .oneshot(req("POST", "/admin/preauth", peer))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "request {i} must pass when layer is disabled"
            );
        }
    }

    /// `/health` and `/metrics` bypass the layer regardless of the
    /// per-class budgets so liveness probes and Prometheus scrapes
    /// keep working under an abuse flood.
    #[tokio::test]
    async fn health_and_metrics_bypass_the_limit() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: Some(0.001),
            burst: Some(1.0),
            routes: HashMap::new(),
            max_keys: Some(1024),
        };
        let app = build_router(cfg);
        let peer = addr(15);
        // Drain the "other" bucket by hitting /unknown.
        let _ = app
            .clone()
            .oneshot(req("GET", "/unknown", peer))
            .await
            .unwrap();
        for path in ["/health", "/metrics"] {
            for _ in 0..10 {
                let resp = app.clone().oneshot(req("GET", path, peer)).await.unwrap();
                assert_ne!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "{path} must bypass the rate limit"
                );
            }
        }
    }

    #[test]
    fn max_keys_evicts_to_bound_memory() {
        let cfg = RateLimitCfg {
            enabled: true,
            default_rps: Some(0.001),
            burst: Some(1.0),
            routes: HashMap::new(),
            max_keys: Some(2),
        };
        let rl = RateLimiter::from_cfg(&cfg);
        for octet in 1..=5u8 {
            let _ = rl.try_acquire(ip(octet), RouteClass::Other);
        }
        assert!(rl.inner.lock().len() <= 2);
    }
}
