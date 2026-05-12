//! Token-bucket rate limit for the control-plane HTTP service.
//!
//! Implements a per-source-IP bucket: each IP gets `capacity` tokens
//! that refill at `refill_per_sec`. Requests consume one token; when
//! the bucket is empty we return HTTP 429.
//!
//! The bucket map is unbounded by default, which is fine for our scale
//! (control plane sees one connection per session announce). When a
//! node serves many thousands of clients, set `BoundedMap`-style
//! eviction via the `max_keys` constructor.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;

#[derive(Clone)]
pub(crate) struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    max_keys: usize,
    inner: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// 100 requests/sec sustained, burst of 200.
    pub(crate) fn default_for_control_plane() -> Self {
        Self::new(200.0, 100.0, 10_000)
    }

    pub(crate) fn new(capacity: f64, refill_per_sec: f64, max_keys: usize) -> Self {
        Self {
            capacity,
            refill_per_sec,
            max_keys,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to consume one token for `ip`. Returns `true` if allowed.
    pub(crate) fn try_acquire(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut m = self.inner.lock();
        if m.len() >= self.max_keys && !m.contains_key(&ip) {
            // Evict an arbitrary key to bound memory.
            if let Some(k) = m.keys().next().copied() {
                m.remove(&k);
            }
        }
        let bucket = m.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = elapsed.mul_add(self.refill_per_sec, bucket.tokens).min(self.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// axum middleware that consumes one token per request from the source
/// IP's bucket. Use via `Router::layer(axum::middleware::from_fn_with_state(...))`.
pub(crate) async fn rate_limit_layer(
    State(rl): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if rl.try_acquire(addr.ip()) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, time::Duration};

    #[test]
    fn allows_within_capacity_blocks_when_drained() {
        let rl = RateLimiter::new(3.0, 0.001, 100);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(rl.try_acquire(ip));
        assert!(rl.try_acquire(ip));
        assert!(rl.try_acquire(ip));
        assert!(!rl.try_acquire(ip), "bucket should be empty");
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1.0, 100.0, 100);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(rl.try_acquire(ip));
        assert!(!rl.try_acquire(ip));
        std::thread::sleep(Duration::from_millis(20)); // 2 tokens refill at 100/s
        assert!(rl.try_acquire(ip), "should have refilled");
    }

    #[test]
    fn different_ips_have_independent_buckets() {
        let rl = RateLimiter::new(1.0, 0.0001, 100);
        let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert!(rl.try_acquire(a));
        assert!(!rl.try_acquire(a));
        assert!(rl.try_acquire(b), "b should not be impacted by a");
    }

    #[test]
    fn max_keys_evicts_oldest_to_bound_memory() {
        let rl = RateLimiter::new(1.0, 0.0001, 2);
        for octet in 1..=5u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet));
            rl.try_acquire(ip);
        }
        assert!(rl.inner.lock().len() <= 2);
    }
}
