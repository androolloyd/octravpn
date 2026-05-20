//! `ValidatorOracle` — graceful fallback for `is_octra_validator`.
//!
//! The OctraVPN program's `register_endpoint` requires
//! `is_octra_validator(caller) == true`. The cleanest source for that
//! answer is an Octra-side RPC method, `octra_isValidator`. If Octra
//! hasn't yet shipped that helper, we fall back to:
//!
//!   1. **Bulk cache** — periodically fetch the full active-validator
//!      set via `octra_listValidators` (or whatever the upstream
//!      exposes) and answer membership locally.
//!   2. **Optional allowlist** — operator-supplied list of validator
//!      addresses for development / private testnets, picked up from
//!      env or config.
//!
//! Callers always go through `ValidatorOracle::is_validator(addr)`;
//! the source switching happens behind the trait.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde_json::json;

use crate::{address::Address, rpc::RpcClient, CoreResult};

/// How long to trust a cached bulk-listing result before refreshing.
const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

/// The RPC method names the oracle tries, in priority order. First is
/// the direct per-address query; remaining are bulk-listing fallbacks
/// for when the direct method isn't exposed.
pub const RPC_DIRECT: &str = "octra_isValidator";
const RPC_BULK_CANDIDATES: &[(&str, &[u64])] = &[
    ("octra_listValidators", &[0, 5_000]),
    ("validator_list", &[]),
];

/// Probing state for the direct RPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// Haven't tried yet.
    Unknown,
    /// Direct query works — keep using it.
    Direct,
    /// Direct query is unavailable; use the bulk-cache fallback.
    Bulk,
}

#[derive(Clone)]
pub struct ValidatorOracle {
    rpc: RpcClient,
    state: Arc<RwLock<OracleState>>,
    refresh: Duration,
}

struct OracleState {
    mode: Mode,
    /// Last bulk fetch result. `None` until first fetch.
    cached_set: Option<HashSet<String>>,
    last_refresh: Instant,
    /// Operator-supplied static allowlist (dev/testnet escape hatch).
    static_allowlist: HashSet<String>,
}

impl ValidatorOracle {
    pub fn new(rpc: RpcClient) -> Self {
        Self {
            rpc,
            state: Arc::new(RwLock::new(OracleState {
                mode: Mode::Unknown,
                cached_set: None,
                last_refresh: Instant::now()
                    .checked_sub(Duration::from_secs(86_400))
                    .unwrap_or_else(Instant::now),
                static_allowlist: HashSet::new(),
            })),
            refresh: DEFAULT_REFRESH,
        }
    }

    /// Configure a static allowlist that always answers `true`.
    /// Useful on private testnets where no validator-set RPC exists.
    pub fn with_static_allowlist(self, addrs: impl IntoIterator<Item = String>) -> Self {
        {
            let mut s = self.state.write();
            for a in addrs {
                s.static_allowlist.insert(a);
            }
        }
        self
    }

    pub fn with_refresh(mut self, d: Duration) -> Self {
        self.refresh = d;
        self
    }

    /// Authoritative answer: is `addr` an Octra validator right now?
    ///
    /// Strategy:
    ///   - First call: try `octra_isValidator`. If supported, remember
    ///     and keep using it.
    ///   - If unsupported (RPC returns `method not found`): fall back
    ///     to fetching the validator set and checking locally; refresh
    ///     periodically.
    ///   - The static allowlist short-circuits to `true` regardless.
    pub async fn is_validator(&self, addr: &Address) -> CoreResult<bool> {
        let display = addr.display().to_string();
        // Sample state into Copy / owned values so no guard is held
        // across `.await` (RwLockReadGuard isn't Send).
        let (in_allowlist, mode) = {
            let s = self.state.read();
            (s.static_allowlist.contains(&display), s.mode)
        };
        if in_allowlist {
            return Ok(true);
        }
        match mode {
            Mode::Direct => self.rpc.is_octra_validator(addr).await,
            Mode::Bulk => self.bulk_lookup(&display).await,
            Mode::Unknown => {
                if let Ok(v) = self.rpc.is_octra_validator(addr).await {
                    self.state.write().mode = Mode::Direct;
                    Ok(v)
                } else {
                    self.state.write().mode = Mode::Bulk;
                    self.bulk_lookup(&display).await
                }
            }
        }
    }

    async fn bulk_lookup(&self, addr: &str) -> CoreResult<bool> {
        if self.cache_is_stale() {
            self.refresh_bulk().await?;
        }
        let s = self.state.read();
        Ok(s.cached_set.as_ref().is_some_and(|x| x.contains(addr)))
    }

    fn cache_is_stale(&self) -> bool {
        let s = self.state.read();
        s.cached_set.is_none() || s.last_refresh.elapsed() > self.refresh
    }

    async fn refresh_bulk(&self) -> CoreResult<()> {
        for (method, args) in RPC_BULK_CANDIDATES {
            let params = if args.is_empty() {
                json!([])
            } else {
                json!(args)
            };
            if let Ok(v) = self.rpc.raw_call(method, params).await {
                if let Some(arr) = v.as_array() {
                    let set: HashSet<String> = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect();
                    let mut s = self.state.write();
                    s.cached_set = Some(set);
                    s.last_refresh = Instant::now();
                    return Ok(());
                }
            }
        }
        // No RPC works — but if we have a static allowlist, treat
        // bulk_lookup as "empty set" rather than erroring; that way
        // the static path still answers correctly above.
        let mut s = self.state.write();
        s.cached_set.get_or_insert_with(HashSet::new);
        s.last_refresh = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_allowlist_short_circuits() {
        let rpc = RpcClient::new("http://unreachable.test/rpc");
        let oracle =
            ValidatorOracle::new(rpc).with_static_allowlist(["octSTATICVALIDATOR0".into()]);
        let addr = Address::from_display("octSTATICVALIDATOR0");
        assert!(oracle.is_validator(&addr).await.unwrap());
    }

    #[tokio::test]
    async fn missing_rpc_falls_through_to_static() {
        // No RPC, no static allowlist — should report false (no panic,
        // no error to caller).
        let rpc = RpcClient::new("http://127.0.0.1:1/rpc"); // closed port
        let oracle = ValidatorOracle::new(rpc);
        let addr = Address::from_display("octUNKNOWN");
        // The very first call exhausts direct + bulk, returns Ok(false)
        // for the static-path semantics. Any error in the chain
        // bubbles up as Err; the test asserts we don't panic.
        let _ = oracle.is_validator(&addr).await;
    }

    /// Static allowlist with multiple entries: every entry resolves to
    /// true without touching the network. Catches a regression where
    /// the allowlist only honoured the first insertion.
    #[tokio::test]
    async fn static_allowlist_handles_multiple_entries() {
        let rpc = RpcClient::new("http://unreachable.test/rpc");
        let oracle = ValidatorOracle::new(rpc).with_static_allowlist([
            "octA".into(),
            "octB".into(),
            "octC".into(),
        ]);
        for s in ["octA", "octB", "octC"] {
            assert!(oracle
                .is_validator(&Address::from_display(s))
                .await
                .unwrap());
        }
    }

    /// `with_refresh` works in combination with the allowlist. Smoke
    /// test for the builder chain.
    #[tokio::test]
    async fn refresh_duration_does_not_affect_static_path() {
        let rpc = RpcClient::new("http://unreachable.test/rpc");
        let oracle = ValidatorOracle::new(rpc)
            .with_refresh(Duration::from_secs(1))
            .with_static_allowlist(["octX".into()]);
        assert!(oracle
            .is_validator(&Address::from_display("octX"))
            .await
            .unwrap());
    }

    /// An address NOT in the allowlist and not in any RPC-bulk set
    /// answers `Ok(false)` — graceful fallback, no panic.
    #[tokio::test]
    async fn unknown_address_with_allowlist_returns_false() {
        let rpc = RpcClient::new("http://127.0.0.1:1/rpc");
        let oracle = ValidatorOracle::new(rpc).with_static_allowlist(["octKNOWN".into()]);
        let unknown = Address::from_display("octOTHER");
        let res = oracle.is_validator(&unknown).await.unwrap();
        assert!(!res, "unknown address must NOT be considered a validator");
    }

    /// Repeated calls on an allowlisted address stay true (no caching
    /// regression that flips it to false).
    #[tokio::test]
    async fn static_allowlist_is_idempotent() {
        let rpc = RpcClient::new("http://unreachable.test/rpc");
        let oracle = ValidatorOracle::new(rpc).with_static_allowlist(["octIDEMP".into()]);
        let a = Address::from_display("octIDEMP");
        for _ in 0..5 {
            assert!(oracle.is_validator(&a).await.unwrap());
        }
    }
}
