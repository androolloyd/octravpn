//! `ValidatorOracle` — validator-set membership backed by
//! `octra_validatorSetProof`.
//!
//! The OctraVPN program's `register_endpoint` requires
//! `is_octra_validator(caller) == true`. The chain exposes exactly one
//! way to read the validator set: `octra_validatorSetProof`
//! (lite_node/node_runtime/status_read_rpc.ml:339). The per-address
//! helper this module used to probe first (`octra_isValidator`) and the
//! bulk fallbacks (`octra_listValidators`, `validator_list`) do not
//! exist anywhere in the node's dispatch tables — calling them always
//! failed, and the old fallback chain then cached an **empty set** and
//! answered `Ok(false)` for every address. A silent deny-all.
//!
//! Two invariants replace that behavior:
//!
//!   1. **Lookup failure is not "not a validator".** `status()` returns
//!      `Err` when the set cannot be fetched (and any cached copy is
//!      too stale to trust); `Ok(ValidatorStatus::Absent)` is only ever
//!      produced from a successfully fetched, well-formed set.
//!   2. **A failed refresh never poisons the cache.** On fetch failure
//!      the previous snapshot is kept and served while it is younger
//!      than `max_stale`; past that, callers get the error.
//!
//! Guidance for callers (`Err` = "could not determine"):
//!
//!   - **Admission gates** (e.g. a `register_endpoint` pre-check) must
//!     fail closed: treat `Err` as deny-and-retry. Do NOT collapse it
//!     to `false` — that re-creates the silent deny-all, and worse,
//!     collapsing it to `true` would admit anyone whenever the RPC is
//!     down. The program-side gate remains the authoritative check.
//!   - **Display surfaces** (status badges, dashboards) should fail
//!     open to "unknown": render the indeterminate state rather than
//!     wrongly branding a validator as an outsider.
//!
//! The operator-supplied static allowlist survives from the old design
//! as the dev/private-testnet escape hatch; it short-circuits to
//! `Active` without touching the network.
//!
//! Trust note: the "proof" is self-attested by the queried node. Its
//! `verify` (lite_node/lib/consensus/c_light_validator_set.ml) only
//! recomputes `n`/`f`/`quorum`/`validator_set_hash`/`config_hash` from
//! the validator list — there is no signature over the response, so a
//! hostile RPC endpoint can serve an arbitrary set. Our TLS SPKI
//! pinning (`RpcClient::new_with_pinned_spki`) is what binds the answer
//! to the intended node; trust-minimized verification would need a
//! `config_hash` pinned from an independent source plus a quorum-signed
//! root (`octra_signedRoot`), which is out of scope here.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use serde_json::{json, Value};

use crate::{address::Address, rpc::RpcClient, CoreError, CoreResult};

/// The one validator-set read the chain actually serves
/// (status_read_rpc.ml:339 `octra_validatorSetProof`).
pub const RPC_METHOD: &str = "octra_validatorSetProof";

/// How long a fetched set is considered fresh (no refetch).
const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

/// How old a cached set may get while the RPC is down before we stop
/// answering from it and surface the error instead. Bounded so that a
/// long outage can't keep admitting a since-removed validator forever.
const DEFAULT_MAX_STALE: Duration = Duration::from_secs(600);

/// Membership answer from a successfully fetched validator set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidatorStatus {
    /// In the ACTIVE set — a validator right now.
    Active,
    /// In the `scheduled` (next-epoch) set but not yet activated
    /// (rpc_view.ml:113-120). Not a validator *yet*; surfaced
    /// separately so UIs can say "pending" instead of "no".
    Scheduled,
    /// Confirmed absent from both sets of a well-formed response.
    Absent,
}

/// Address sets parsed out of one `octra_validatorSetProof` response,
/// stamped with when we fetched it.
struct Snapshot {
    active: HashSet<String>,
    scheduled: HashSet<String>,
    fetched_at: Instant,
}

#[derive(Clone)]
pub struct ValidatorOracle {
    rpc: RpcClient,
    state: Arc<RwLock<OracleState>>,
    refresh: Duration,
    max_stale: Duration,
}

struct OracleState {
    /// Last good fetch. `None` until the first success — never
    /// populated from a failure.
    snapshot: Option<Snapshot>,
    /// Operator-supplied static allowlist (dev/testnet escape hatch).
    static_allowlist: HashSet<String>,
}

impl ValidatorOracle {
    pub fn new(rpc: RpcClient) -> Self {
        Self {
            rpc,
            state: Arc::new(RwLock::new(OracleState {
                snapshot: None,
                static_allowlist: HashSet::new(),
            })),
            refresh: DEFAULT_REFRESH,
            max_stale: DEFAULT_MAX_STALE,
        }
    }

    /// Configure a static allowlist that always answers `Active`.
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

    /// Bound how long a stale cached set may keep answering during an
    /// RPC outage. `Duration::ZERO` disables stale serving entirely.
    pub fn with_max_stale(mut self, d: Duration) -> Self {
        self.max_stale = d;
        self
    }

    /// Is `addr` an Octra validator right now?
    ///
    /// `Ok(true)` iff confirmed `Active` (or allowlisted). `Ok(false)`
    /// iff a well-formed set confirmed the address absent (or merely
    /// scheduled). `Err` means **could not determine** — callers on an
    /// admission path must treat that as deny-and-retry, never as
    /// `false`; see the module docs.
    pub async fn is_validator(&self, addr: &Address) -> CoreResult<bool> {
        Ok(self.status(addr).await? == ValidatorStatus::Active)
    }

    /// Full tri-state answer; `Err` = could not determine.
    pub async fn status(&self, addr: &Address) -> CoreResult<ValidatorStatus> {
        let display = addr.display().to_string();
        // Sample state into owned values so no guard is held across
        // `.await` (RwLockReadGuard isn't Send). `cached` answers from
        // a fresh snapshot without a fetch; `stale_age` remembers
        // whether a fallback copy exists for the failure path.
        let (in_allowlist, cached, stale_age) = {
            let s = self.state.read();
            let cached = s.snapshot.as_ref().and_then(|snap| {
                (snap.fetched_at.elapsed() <= self.refresh).then(|| Self::classify(snap, &display))
            });
            (
                s.static_allowlist.contains(&display),
                cached,
                s.snapshot.as_ref().map(|snap| snap.fetched_at.elapsed()),
            )
        };
        if in_allowlist {
            return Ok(ValidatorStatus::Active);
        }
        if let Some(status) = cached {
            return Ok(status);
        }
        match self.refresh_snapshot().await {
            Ok(()) => {
                let s = self.state.read();
                let snap = s
                    .snapshot
                    .as_ref()
                    .expect("refresh_snapshot stores a snapshot on Ok");
                Ok(Self::classify(snap, &display))
            }
            Err(e) => {
                // Refresh failed. Serve the previous snapshot while it
                // is within the staleness bound; otherwise the honest
                // answer is "could not determine" — propagate.
                if stale_age.is_some_and(|age| age <= self.max_stale) {
                    let s = self.state.read();
                    if let Some(snap) = s.snapshot.as_ref() {
                        tracing::warn!(error = %e, "validator-set refresh failed; answering from stale cache");
                        return Ok(Self::classify(snap, &display));
                    }
                }
                Err(e)
            }
        }
    }

    fn classify(snap: &Snapshot, addr: &str) -> ValidatorStatus {
        if snap.active.contains(addr) {
            ValidatorStatus::Active
        } else if snap.scheduled.contains(addr) {
            ValidatorStatus::Scheduled
        } else {
            ValidatorStatus::Absent
        }
    }

    /// Fetch + parse one `octra_validatorSetProof` response and install
    /// it as the current snapshot. Any failure leaves the previous
    /// snapshot untouched.
    async fn refresh_snapshot(&self) -> CoreResult<()> {
        // Params are ignored server-side (status_read_rpc.ml:286-292
        // `validator_set_proof_params _params ctx`).
        let v = self.rpc.raw_call(RPC_METHOD, json!([])).await?;
        let (active, scheduled) = parse_validator_set_proof(&v)?;
        let mut s = self.state.write();
        s.snapshot = Some(Snapshot {
            active,
            scheduled,
            fetched_at: Instant::now(),
        });
        Ok(())
    }
}

/// Parse the `octra_validatorSetProof` result into (active, scheduled)
/// address sets.
///
/// Response shape (rpc_view.ml:170-184; validators at 104-111,
/// scheduled at 113-120):
///
/// ```json
/// {
///   "version": "octra-validator-set-proof-v1..v4",
///   "chain_id": "...", "config_hash": "<hex>",
///   "validator_set_hash": "<hex>", "n": 3, "f": 0, "quorum": 1,
///   "validators": [ {"address": "oct...", "pubkey": "<b64>", "weight"?: "1"} ],
///   "scheduled": null | {"activate_epoch": "<dec>", "weighted": bool,
///                        "validators": [ ... same entry shape ... ]}
/// }
/// ```
///
/// Parsing is deliberately STRICT: a malformed response is an error,
/// never a partial set. Silently dropping an unparseable entry could
/// turn a real validator into "confirmed absent" — the exact bug class
/// this module exists to prevent.
fn parse_validator_set_proof(v: &Value) -> CoreResult<(HashSet<String>, HashSet<String>)> {
    let malformed =
        |what: &str| CoreError::Rpc(format!("{RPC_METHOD}: malformed response: {what}"));
    let obj = v
        .as_object()
        .ok_or_else(|| malformed("result is not an object"))?;

    let addresses_of = |list: &Value, field: &str| -> CoreResult<HashSet<String>> {
        let arr = list
            .as_array()
            .ok_or_else(|| malformed(&format!("`{field}` is not an array")))?;
        let mut out = HashSet::with_capacity(arr.len());
        for entry in arr {
            let addr = entry
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(&format!("`{field}` entry without string `address`")))?;
            out.insert(addr.to_string());
        }
        Ok(out)
    };

    let active = addresses_of(
        obj.get("validators")
            .ok_or_else(|| malformed("missing `validators`"))?,
        "validators",
    )?;

    // Cross-check `n` against the list we parsed: the node always sets
    // n = List.length validators (c_types.ml:182), so a mismatch means
    // we mis-decoded or the response was truncated — refuse it.
    if let Some(n) = obj.get("n") {
        let n = n
            .as_u64()
            .ok_or_else(|| malformed("`n` is not an unsigned integer"))?;
        if n as usize != active.len() {
            return Err(malformed(&format!(
                "`n` = {n} disagrees with {} validator entries",
                active.len()
            )));
        }
    }

    let scheduled = match obj.get("scheduled") {
        None | Some(Value::Null) => HashSet::new(),
        Some(s) => addresses_of(
            s.get("validators")
                .ok_or_else(|| malformed("`scheduled` without `validators`"))?,
            "scheduled.validators",
        )?,
    };

    Ok((active, scheduled))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use axum::{extract::State, routing::post, Json, Router};

    use super::*;

    /// What the mock node should currently answer for
    /// `octra_validatorSetProof`: `Ok(result)` or a JSON-RPC error.
    type MockAnswer = Result<Value, (i64, &'static str)>;
    type SharedAnswer = Arc<Mutex<MockAnswer>>;

    async fn rpc_handler(
        State(answer): State<SharedAnswer>,
        Json(req): Json<Value>,
    ) -> Json<Value> {
        // Only the real method exists — anything else gets the same
        // -32601 the node would return, so these tests double as proof
        // that the oracle no longer calls octra_isValidator /
        // octra_listValidators.
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        if method != RPC_METHOD {
            return Json(json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32601, "message": format!("method not found: {method}")}
            }));
        }
        match &*answer.lock().unwrap() {
            Ok(result) => Json(json!({"jsonrpc": "2.0", "id": 1, "result": result})),
            Err((code, msg)) => Json(json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": code, "message": msg}
            })),
        }
    }

    async fn spawn_mock(initial: MockAnswer) -> (String, SharedAnswer) {
        let answer: SharedAnswer = Arc::new(Mutex::new(initial));
        let app = Router::new()
            .route("/", post(rpc_handler))
            .with_state(answer.clone());
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind mock rpc");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (format!("http://{addr}/"), answer)
    }

    /// A well-formed v1 proof over `active`, mirroring
    /// rpc_view.ml:170-184 field-for-field.
    fn proof_json(active: &[&str], scheduled: &[&str]) -> Value {
        let entries = |addrs: &[&str]| -> Vec<Value> {
            addrs
                .iter()
                .map(|a| json!({"address": a, "pubkey": "cHVia2V5"}))
                .collect()
        };
        let scheduled_json = if scheduled.is_empty() {
            Value::Null
        } else {
            json!({
                "activate_epoch": "42",
                "weighted": false,
                "validators": entries(scheduled),
            })
        };
        json!({
            "version": "octra-validator-set-proof-v1",
            "chain_id": "octra-devnet",
            "config_hash": "aa".repeat(32),
            "validator_set_hash": "bb".repeat(32),
            "n": active.len(),
            "f": 0,
            "quorum": 1,
            "validators": entries(active),
            "scheduled": scheduled_json,
        })
    }

    #[tokio::test]
    async fn present_validator_is_active() {
        let (url, _) = spawn_mock(Ok(proof_json(&["octVAL1", "octVAL2"], &[]))).await;
        let oracle = ValidatorOracle::new(RpcClient::new(url));
        let addr = Address::from_display("octVAL1");
        assert_eq!(oracle.status(&addr).await.unwrap(), ValidatorStatus::Active);
        assert!(oracle.is_validator(&addr).await.unwrap());
    }

    #[tokio::test]
    async fn absent_validator_is_confirmed_absent() {
        let (url, _) = spawn_mock(Ok(proof_json(&["octVAL1"], &[]))).await;
        let oracle = ValidatorOracle::new(RpcClient::new(url));
        let addr = Address::from_display("octOTHER");
        assert_eq!(oracle.status(&addr).await.unwrap(), ValidatorStatus::Absent);
        assert!(!oracle.is_validator(&addr).await.unwrap());
    }

    #[tokio::test]
    async fn scheduled_validator_is_not_yet_active() {
        let (url, _) = spawn_mock(Ok(proof_json(&["octVAL1"], &["octNEXT"]))).await;
        let oracle = ValidatorOracle::new(RpcClient::new(url));
        let addr = Address::from_display("octNEXT");
        assert_eq!(
            oracle.status(&addr).await.unwrap(),
            ValidatorStatus::Scheduled
        );
        // Scheduled is NOT admitted: not a validator until activation.
        assert!(!oracle.is_validator(&addr).await.unwrap());
    }

    /// THE bug this rewrite fixes: an RPC failure must surface as
    /// `Err`, never as `Ok(false)`.
    #[tokio::test]
    async fn rpc_error_is_err_not_false() {
        let (url, _) = spawn_mock(Err((-32000, "boom"))).await;
        let oracle = ValidatorOracle::new(RpcClient::new(url));
        let addr = Address::from_display("octVAL1");
        assert!(oracle.status(&addr).await.is_err());
        assert!(oracle.is_validator(&addr).await.is_err());
    }

    #[tokio::test]
    async fn unreachable_endpoint_is_err_not_false() {
        let rpc = RpcClient::new("http://127.0.0.1:1/rpc"); // closed port
        let oracle = ValidatorOracle::new(rpc);
        let addr = Address::from_display("octVAL1");
        assert!(oracle.is_validator(&addr).await.is_err());
    }

    #[tokio::test]
    async fn malformed_responses_are_err() {
        // Each shape is wrong in a way the strict parser must refuse
        // rather than degrade into a partial (or empty) set.
        let cases: Vec<Value> = vec![
            json!("not an object"),
            json!({"chain_id": "x"}),                 // missing validators
            json!({"validators": "nope"}),            // wrong type
            json!({"validators": [{"pubkey": "x"}]}), // entry w/o address
            json!({"validators": [{"address": 7}]}),  // non-string address
            {
                // n disagrees with the entry count (truncated body).
                let mut p = proof_json(&["octVAL1"], &[]);
                p["n"] = json!(9);
                p
            },
            {
                // scheduled present but not null and without validators.
                let mut p = proof_json(&["octVAL1"], &[]);
                p["scheduled"] = json!({"activate_epoch": "42"});
                p
            },
        ];
        for case in cases {
            let (url, _) = spawn_mock(Ok(case.clone())).await;
            let oracle = ValidatorOracle::new(RpcClient::new(url));
            let addr = Address::from_display("octVAL1");
            assert!(
                oracle.status(&addr).await.is_err(),
                "malformed case must be Err: {case}"
            );
        }
    }

    /// A failed fetch must not be cached as a negative: once the RPC
    /// recovers, the very next lookup succeeds. (The old code cached an
    /// empty set here and kept answering `false` for a minute.)
    #[tokio::test]
    async fn failure_is_never_cached_as_negative() {
        let (url, answer) = spawn_mock(Err((-32000, "down"))).await;
        let oracle = ValidatorOracle::new(RpcClient::new(url));
        let addr = Address::from_display("octVAL1");
        assert!(oracle.is_validator(&addr).await.is_err());
        *answer.lock().unwrap() = Ok(proof_json(&["octVAL1"], &[]));
        assert!(oracle.is_validator(&addr).await.unwrap());
    }

    /// During an outage a recent snapshot keeps answering (bounded by
    /// max_stale) — and past the bound the error surfaces.
    #[tokio::test]
    async fn stale_cache_serves_within_bound_then_errors() {
        let (url, answer) = spawn_mock(Ok(proof_json(&["octVAL1"], &[]))).await;
        // refresh = ZERO forces a refetch attempt on every call; the
        // generous max_stale lets the first snapshot keep serving.
        let oracle = ValidatorOracle::new(RpcClient::new(url.clone()))
            .with_refresh(Duration::ZERO)
            .with_max_stale(Duration::from_secs(3600));
        let addr = Address::from_display("octVAL1");
        assert!(oracle.is_validator(&addr).await.unwrap());

        *answer.lock().unwrap() = Err((-32000, "down"));
        // Refresh fails but the cached set is well within max_stale.
        assert!(oracle.is_validator(&addr).await.unwrap());

        // Same outage, but a zero staleness budget: honest Err.
        let strict = ValidatorOracle::new(RpcClient::new(url))
            .with_refresh(Duration::ZERO)
            .with_max_stale(Duration::ZERO);
        *answer.lock().unwrap() = Ok(proof_json(&["octVAL1"], &[]));
        assert!(strict.is_validator(&addr).await.unwrap());
        *answer.lock().unwrap() = Err((-32000, "down"));
        assert!(strict.is_validator(&addr).await.is_err());
    }

    /// A fresh snapshot answers without refetching — flipping the
    /// server to errors within the refresh window doesn't matter.
    #[tokio::test]
    async fn fresh_cache_avoids_refetch() {
        let (url, answer) = spawn_mock(Ok(proof_json(&["octVAL1"], &[]))).await;
        let oracle =
            ValidatorOracle::new(RpcClient::new(url)).with_refresh(Duration::from_secs(3600));
        let addr = Address::from_display("octVAL1");
        assert!(oracle.is_validator(&addr).await.unwrap());
        *answer.lock().unwrap() = Err((-32000, "down"));
        assert!(oracle.is_validator(&addr).await.unwrap());
    }

    #[tokio::test]
    async fn static_allowlist_short_circuits_without_network() {
        let rpc = RpcClient::new("http://unreachable.test/rpc");
        let oracle = ValidatorOracle::new(rpc).with_static_allowlist([
            "octA".into(),
            "octB".into(),
            "octC".into(),
        ]);
        for s in ["octA", "octB", "octC"] {
            let addr = Address::from_display(s);
            assert_eq!(oracle.status(&addr).await.unwrap(), ValidatorStatus::Active);
            assert!(oracle.is_validator(&addr).await.unwrap());
        }
    }

    /// An address outside the allowlist gets no free pass: with the RPC
    /// down it is `Err` (could not determine), NOT `Ok(false)`.
    #[tokio::test]
    async fn non_allowlisted_address_still_requires_the_chain() {
        let rpc = RpcClient::new("http://127.0.0.1:1/rpc");
        let oracle = ValidatorOracle::new(rpc).with_static_allowlist(["octKNOWN".into()]);
        let unknown = Address::from_display("octOTHER");
        assert!(oracle.is_validator(&unknown).await.is_err());
    }
}
