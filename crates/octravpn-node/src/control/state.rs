//! [`ControlState`] — shared state every handler reads from. Builder
//! methods (`with_metrics_token`, `with_admin_token`, `with_shadow_signer`,
//! …) are the `pub(crate)` API `Hub` wires at boot. Adding a field
//! requires: (a) `pub(crate)` field, (b) `with_<field>` builder, (c)
//! default in `new` + `with_metrics`. The bearer-check accessors
//! (`bearer_metrics` / `bearer_admin` / `bearer_events`) construct
//! [`octravpn_core::bearer::BearerCheck`] from the three token fields.

use std::sync::Arc;
use std::time::Duration;

use octravpn_core::{
    address::Address,
    bearer::BearerCheck,
    bounded::BoundedMap,
    control::{announce_opener_binding_payload, AnnounceSessionRequest},
    receipt::ReceiptContext,
    receipt_journal::ReceiptJournal,
    receipt_vault::ReceiptVault,
    rpc::RpcClient,
    session::SessionId,
    sig::{verify, KeyPair},
};
use octravpn_mesh::{PreauthMinter, WireState};

use crate::{chain_v3::SESSION_RELAY_ARMED, events::EventBus, onion::OnionRouter};

use super::metrics::NodeMetrics;

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
pub(crate) const HEALTH_ATTESTATION_FRESHNESS_S: u64 = 300;

/// During the first `HEALTH_WARMUP_S` after process start we report
/// `warming_up` instead of failing health — the attestation loop has
/// not had a chance to run yet.
pub(crate) const HEALTH_WARMUP_S: u64 = 60;

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
    /// v4 relay-settlement off-chain half: durable mirror of
    /// client-countersigned receipt blobs. Separate from
    /// `receipt_journal`, which remains a fixed-width seq-floor store.
    pub receipt_vault: Arc<ReceiptVault>,
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
    /// confirmed `open_session` transaction for the configured
    /// program. Full RPCs can prove that by event; devnet falls back
    /// to the program's `get_session_status` view.
    pub session_verifier: Option<SessionAdmissionVerifier>,
    /// Optional read-only relay lifecycle probe for
    /// `POST /session/:id/receipt`. Hub-built states set this so every
    /// countersigned receipt post checks whether the chain has already
    /// moved the session to `SESSION_RELAY_ARMED` before allowing the
    /// vault receipt to advance.
    pub relay_lifecycle_verifier: Option<RelayLifecycleVerifier>,
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

    /// Wallet-native device enrollment service. `Some` when this node
    /// hosts enrollment for a tailnet it operates (the owner-circle
    /// `/auth` member set + allowlist); `None` (the default) leaves the
    /// `/enroll*` routes 404. See [`super::enroll`].
    pub enroll: Option<super::enroll::EnrollService>,
}

#[derive(Clone)]
pub(crate) struct SessionAdmissionVerifier {
    rpc: RpcClient,
    program_addr: Address,
}

#[derive(Clone)]
pub(crate) struct RelayLifecycleVerifier {
    rpc: RpcClient,
    program_addr: Address,
    caller: Option<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayArmedState {
    pub deadline: u64,
    pub settlement_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionAdmission {
    Accepted,
    SessionNotFound,
    NotSignedByOpener,
}

impl SessionAdmissionVerifier {
    pub(crate) fn new(rpc: RpcClient, program_addr: Address) -> Self {
        Self { rpc, program_addr }
    }

    pub(crate) async fn session_opened(
        &self,
        req: &AnnounceSessionRequest,
    ) -> octravpn_core::CoreResult<SessionAdmission> {
        let tx = self.rpc.transaction(&req.open_tx_hash).await?;
        if transaction_has_session_opened(&tx, &req.session_id) {
            return Ok(opener_binding_admission(&tx, req));
        }
        if !transaction_is_confirmed_call_to_program(&tx, &self.program_addr) {
            return Ok(SessionAdmission::SessionNotFound);
        }
        let Some(session_id) = req.session_id.as_u64() else {
            return Ok(SessionAdmission::SessionNotFound);
        };
        let Ok(status) = self
            .rpc
            .contract_call_raw(
                &self.program_addr,
                "get_session_status",
                &[serde_json::json!(session_id)],
                None,
            )
            .await
        else {
            return Ok(SessionAdmission::SessionNotFound);
        };
        if session_status_allows_admission(&status, session_id) {
            Ok(opener_binding_admission(&tx, req))
        } else {
            Ok(SessionAdmission::SessionNotFound)
        }
    }
}

impl RelayLifecycleVerifier {
    pub(crate) fn new(rpc: RpcClient, program_addr: Address, caller: Option<Address>) -> Self {
        Self {
            rpc,
            program_addr,
            caller,
        }
    }

    pub(crate) async fn armed_state(
        &self,
        session_id: u64,
    ) -> octravpn_core::CoreResult<Option<RelayArmedState>> {
        let caller = self.caller.as_ref();
        let status = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_session_status",
                &[serde_json::json!(session_id)],
                caller,
            )
            .await?;
        if value_as_u64(&status).unwrap_or(0) != SESSION_RELAY_ARMED {
            return Ok(None);
        }

        let deadline = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_relay_deadline",
                &[serde_json::json!(session_id)],
                caller,
            )
            .await?;
        let settlement_hash = self
            .rpc
            .contract_call(
                &self.program_addr,
                "get_relay_settlement_hash",
                &[serde_json::json!(session_id)],
                caller,
            )
            .await?;

        Ok(Some(RelayArmedState {
            deadline: value_as_u64(&deadline).unwrap_or(0),
            settlement_hash: settlement_hash.as_str().unwrap_or_default().to_string(),
        }))
    }
}

fn opener_binding_admission(
    tx: &serde_json::Value,
    req: &AnnounceSessionRequest,
) -> SessionAdmission {
    if announce_signed_by_session_opener(tx, req) {
        SessionAdmission::Accepted
    } else {
        SessionAdmission::NotSignedByOpener
    }
}

fn announce_signed_by_session_opener(tx: &serde_json::Value, req: &AnnounceSessionRequest) -> bool {
    let Some(tx_from) = transaction_from_address(tx) else {
        return false;
    };
    let opener_addr = Address::from_pubkey(&req.opener_pubkey.0);
    if opener_addr.display() != tx_from {
        return false;
    }
    let payload = announce_opener_binding_payload(
        &req.session_id,
        &req.client_pubkey,
        &req.client_wg_pubkey,
        &req.open_tx_hash,
    );
    verify(&req.opener_pubkey, &payload, &req.opener_sig).is_ok()
}

fn transaction_from_address(tx: &serde_json::Value) -> Option<&str> {
    tx.get("from")
        .or_else(|| tx.get("from_"))
        .and_then(|v| v.as_str())
}

fn transaction_is_confirmed_call_to_program(
    tx: &serde_json::Value,
    program_addr: &Address,
) -> bool {
    let expected_program = program_addr.display().to_string();
    let confirmed = tx
        .get("status")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "confirmed");
    let call = tx
        .get("op_type")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s == "call");
    let to_program = tx
        .get("to")
        .or_else(|| tx.get("to_"))
        .and_then(|v| v.as_str())
        .is_some_and(|to| to == expected_program);
    let open_session = tx
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .map_or(true, |method| method == "open_session");
    confirmed && call && to_program && open_session
}

fn session_status_allows_admission(raw: &serde_json::Value, session_id: u64) -> bool {
    let Some(session_count) = raw
        .get("storage")
        .and_then(|s| s.get("session_count"))
        .and_then(value_as_u64)
    else {
        return false;
    };
    if session_id >= session_count {
        return false;
    }
    let Some(status) = raw.get("result").and_then(value_as_u64) else {
        return false;
    };
    matches!(status, 0 | 3)
}

fn value_as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
}

/// Inspect a chain-RPC transaction body for a `SessionOpened` event
/// whose `session_id` matches the request. Public at module scope so
/// tests can pin the matcher independently of a live RPC client.
pub(crate) fn transaction_has_session_opened(
    tx: &serde_json::Value,
    session_id: &SessionId,
) -> bool {
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

#[derive(Clone)]
pub(crate) struct ControlSession {
    pub last_seq: u64,
    pub last_blind: octravpn_core::session::Blind,
    /// The ed25519 client identity key that announced this session
    /// (`AnnounceSessionRequest::client_pubkey`). Bound here so
    /// `POST /session/:id/receipt` can reject a dual-signed receipt
    /// whose client countersignature is under a *different* key —
    /// otherwise anyone who can read a live session's node-signed
    /// proposal (`GET /session/:id`) could attach their own fresh
    /// client key, POST it, and poison the vault's "latest" receipt so
    /// the operator's later `relay_claim` carries an attacker-keyed
    /// countersignature that the chain rejects.
    pub client_pubkey: octravpn_core::sig::PublicKey,
}

impl ControlState {
    #[cfg(test)]
    pub(crate) fn new(
        node_kp: Arc<KeyPair>,
        router: Arc<OnionRouter>,
        allowlist: Arc<BoundedMap<[u8; 32], crate::tunnel::AllowedClient>>,
    ) -> Self {
        use std::sync::atomic::Ordering;
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
            receipt_vault: Arc::new(ReceiptVault::in_memory()),
            preauth_minter: PreauthMinter::new(),
            admin_token: None,
            wire_state: None,
            rate_limit_cfg: crate::rate_limit::RateLimitCfg::default(),
            session_verifier: None,
            relay_lifecycle_verifier: None,
            shadow_signer: None,
            shadow_price_per_byte: 0,
            enroll: None,
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

    /// Attach the persistent receipt-vault store used by
    /// `POST /session/:id/receipt`.
    pub(crate) fn with_receipt_vault(mut self, vault: Arc<ReceiptVault>) -> Self {
        self.receipt_vault = vault;
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

    pub(crate) fn with_relay_lifecycle_verifier(
        mut self,
        verifier: RelayLifecycleVerifier,
    ) -> Self {
        self.relay_lifecycle_verifier = Some(verifier);
        self
    }

    /// Attach a wallet-native enrollment service. When set, the
    /// `/enroll/challenge` + `/enroll` routes admit devices into the
    /// tailnet member set; absent, those routes 404.
    #[allow(dead_code)] // wired by Hub when an operator hosts a tailnet
    pub(crate) fn with_enroll(mut self, svc: super::enroll::EnrollService) -> Self {
        self.enroll = Some(svc);
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

    // -----------------------------------------------------------------
    // Bearer-check accessors. Each handler that gates on a token calls
    // one of these to materialise an `octravpn_core::bearer::BearerCheck`
    // with the route's policy (Strict vs Hidden) and current token.
    // Centralising them here means the three handlers can NEVER drift
    // on which policy / disabled-body / response-shape they emit — the
    // bearer::tests pin the byte-stable response across all of them.
    // -----------------------------------------------------------------

    /// `/metrics` is Strict-policy: post audit-3 H-1 the wire response
    /// for every reject reason is the same byte-stable
    /// `(404, NGINX_404_BODY)` as `Hidden`, but the `Strict` label
    /// causes `BearerCheck::warn_if_unconfigured` (called by
    /// `Hub::spawn_control_plane` at boot) to log a tracing warning
    /// so the operator notices a misconfigured Prometheus scrape via
    /// the node's log rather than via the wire.
    pub(crate) fn bearer_metrics(&self) -> BearerCheck {
        BearerCheck::strict(
            self.metrics_token.clone(),
            "metrics endpoint disabled: set [control].metrics_token in node.toml",
        )
    }

    /// `/admin/preauth` is Hidden-policy: 404 + NGINX_404_BODY for
    /// every failure mode so external scanners can't enumerate the
    /// route.
    pub(crate) fn bearer_admin(&self) -> BearerCheck {
        BearerCheck::hidden(self.admin_token.clone())
    }

    /// `/events` (SSE) is Hidden-policy: same shape as `/admin/preauth`
    /// — `[control].events_token` unset ⇒ 404; wrong bearer ⇒ 404.
    pub(crate) fn bearer_events(&self) -> BearerCheck {
        BearerCheck::hidden(self.events_token.clone())
    }

    /// Mount this state into a fully-configured axum `Router`. The
    /// implementation lives in [`super::router`] so the route table
    /// can be reviewed independently of state-builder churn.
    pub(crate) fn router_axum(self: Arc<Self>) -> axum::Router {
        super::router::router_axum(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State as AxumState, http::StatusCode, routing::post, Json, Router};
    use octravpn_core::bounded::BoundedMap;
    use octravpn_core::sig::KeyPair;
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    #[derive(Clone)]
    struct AdmissionMockRpc {
        tx: Value,
        status: Option<Value>,
        session_count: Value,
        contract_calls: Arc<Mutex<Vec<Value>>>,
    }

    async fn admission_mock_handler(
        AxumState(mock): AxumState<AdmissionMockRpc>,
        Json(req): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        let method = req
            .get("method")
            .and_then(Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let params = req.get("params").cloned().unwrap_or(json!([]));
        let body = match method {
            "octra_transaction" => {
                json!({ "jsonrpc": "2.0", "id": id, "result": mock.tx })
            }
            "contract_call" => {
                mock.contract_calls
                    .lock()
                    .expect("contract calls lock")
                    .push(params);
                if let Some(status) = &mock.status {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "result": status,
                            "storage": { "session_count": mock.session_count },
                        },
                    })
                } else {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32099, "message": "session not found" },
                    })
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" },
            }),
        };
        Ok(Json(body))
    }

    async fn spawn_admission_mock(
        tx: Value,
        status: Option<Value>,
        session_count: Value,
    ) -> (RpcClient, Arc<Mutex<Vec<Value>>>, oneshot::Sender<()>) {
        let contract_calls = Arc::new(Mutex::new(Vec::new()));
        let mock = AdmissionMockRpc {
            tx,
            status,
            session_count,
            contract_calls: contract_calls.clone(),
        };
        let app = Router::new()
            .route("/", post(admission_mock_handler))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind admission mock");
        let addr = listener.local_addr().expect("admission mock addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        (
            RpcClient::new(format!("http://{addr}/")),
            contract_calls,
            shutdown_tx,
        )
    }

    fn program_addr() -> Address {
        Address::from_display("oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3")
    }

    fn opener_addr(opener_kp: &KeyPair) -> String {
        Address::from_pubkey(&opener_kp.public.0)
            .display()
            .to_string()
    }

    fn announce_req(session_id: SessionId, opener_kp: &KeyPair) -> AnnounceSessionRequest {
        let client_kp = KeyPair::generate();
        let client_wg_pubkey = [9u8; 32];
        let open_tx_hash = "open-tx".to_string();
        let client_sig = client_kp.sign(&octravpn_core::control::announce_signing_payload(
            &session_id,
            &client_kp.public,
            &client_wg_pubkey,
            &open_tx_hash,
        ));
        let opener_sig = opener_kp.sign(&announce_opener_binding_payload(
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
            opener_pubkey: opener_kp.public,
            opener_sig,
        }
    }

    fn confirmed_open_tx(program: &Address, opener_kp: &KeyPair) -> Value {
        json!({
            "status": "confirmed",
            "tx_hash": "open-tx",
            "from_": opener_addr(opener_kp),
            "to": program.display().to_string(),
            "op_type": "call",
            "message": "[0,\"octCircle\",1500]"
        })
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

    #[test]
    fn session_status_allows_only_admission_live_states() {
        assert!(session_status_allows_admission(
            &json!({ "result": 0, "storage": { "session_count": 43 } }),
            42
        ));
        assert!(session_status_allows_admission(
            &json!({ "result": "3", "storage": { "session_count": "43" } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": Value::Null, "storage": { "session_count": 43 } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 0, "storage": { "session_count": 42 } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 0, "storage": {} }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 1, "storage": { "session_count": 43 } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 2, "storage": { "session_count": 43 } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 4, "storage": { "session_count": 43 } }),
            42
        ));
        assert!(!session_status_allows_admission(
            &json!({ "result": 5, "storage": { "session_count": 43 } }),
            42
        ));
    }

    #[tokio::test]
    async fn session_admission_event_present_accepts_without_state_read() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let tx = json!({
            "from": opener_addr(&opener_kp),
            "events": [
                {"name": "SessionOpened", "session_id": 42}
            ]
        });
        let (rpc, contract_calls, shutdown) = spawn_admission_mock(tx, None, json!(0)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::Accepted
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_accepts_open_session() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let (rpc, contract_calls, shutdown) = spawn_admission_mock(
            confirmed_open_tx(&program, &opener_kp),
            Some(json!(0)),
            json!(43),
        )
        .await;
        let verifier = SessionAdmissionVerifier::new(rpc, program.clone());

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::Accepted
        );
        let calls = contract_calls.lock().expect("contract calls lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            json!([program.display().to_string(), "get_session_status", [42u64]])
        );
        drop(calls);
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_rejects_opener_address_mismatch() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let attacker_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let tx = json!({
            "from": opener_addr(&opener_kp),
            "events": [
                {"name": "SessionOpened", "session_id": 42}
            ]
        });
        let (rpc, contract_calls, shutdown) = spawn_admission_mock(tx, None, json!(0)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &attacker_kp))
                .await
                .expect("session opened"),
            SessionAdmission::NotSignedByOpener
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_rejects_bad_opener_signature() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let tx = json!({
            "from": opener_addr(&opener_kp),
            "events": [
                {"name": "SessionOpened", "session_id": 42}
            ]
        });
        let (rpc, _contract_calls, shutdown) = spawn_admission_mock(tx, None, json!(0)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);
        let mut req = announce_req(session_id, &opener_kp);
        req.opener_sig.0[0] ^= 1;

        assert_eq!(
            verifier.session_opened(&req).await.expect("session opened"),
            SessionAdmission::NotSignedByOpener
        );
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_unset_status() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let (rpc, _contract_calls, shutdown) = spawn_admission_mock(
            confirmed_open_tx(&program, &opener_kp),
            Some(Value::Null),
            json!(43),
        )
        .await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_status_read_error() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let (rpc, _contract_calls, shutdown) =
            spawn_admission_mock(confirmed_open_tx(&program, &opener_kp), None, json!(43)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_out_of_range_session_id() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::from_u64(42);
        let (rpc, _contract_calls, shutdown) = spawn_admission_mock(
            confirmed_open_tx(&program, &opener_kp),
            Some(json!(0)),
            json!(42),
        )
        .await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_non_u64_session_id() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let session_id = SessionId::new([0xAB; 32]);
        let (rpc, contract_calls, shutdown) = spawn_admission_mock(
            confirmed_open_tx(&program, &opener_kp),
            Some(json!(0)),
            json!(43),
        )
        .await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(session_id, &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_tx_not_to_program() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let tx = json!({
            "status": "confirmed",
            "tx_hash": "open-tx",
            "from": opener_addr(&opener_kp),
            "to": "octWrongProgram",
            "op_type": "call",
        });
        let (rpc, contract_calls, shutdown) =
            spawn_admission_mock(tx, Some(json!(0)), json!(43)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(SessionId::from_u64(42), &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_non_open_session_method_when_present() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let tx = json!({
            "status": "confirmed",
            "tx_hash": "open-tx",
            "from": opener_addr(&opener_kp),
            "to": program.display().to_string(),
            "op_type": "call",
            "encrypted_data": "settle_claim",
        });
        let (rpc, contract_calls, shutdown) =
            spawn_admission_mock(tx, Some(json!(0)), json!(43)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(SessionId::from_u64(42), &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn session_admission_state_fallback_rejects_unconfirmed_tx() {
        let program = program_addr();
        let opener_kp = KeyPair::generate();
        let tx = json!({
            "status": "pending",
            "tx_hash": "open-tx",
            "from": opener_addr(&opener_kp),
            "to": program.display().to_string(),
            "op_type": "call",
        });
        let (rpc, contract_calls, shutdown) =
            spawn_admission_mock(tx, Some(json!(0)), json!(43)).await;
        let verifier = SessionAdmissionVerifier::new(rpc, program);

        assert_eq!(
            verifier
                .session_opened(&announce_req(SessionId::from_u64(42), &opener_kp))
                .await
                .expect("session opened"),
            SessionAdmission::SessionNotFound
        );
        assert!(contract_calls
            .lock()
            .expect("contract calls lock")
            .is_empty());
        let _ = shutdown.send(());
    }

    /// A `ControlState` constructed without a `ShadowSigner` MUST
    /// have `shadow_signer = None` and `shadow_price_per_byte = 0`
    /// — the no-shadow default. This is the safety-net pin that
    /// keeps the no-sidecar path wire-identical to pre-HFHE-2.
    #[test]
    fn control_state_default_has_no_shadow_signer() {
        let kp = Arc::new(KeyPair::generate());
        let router = Arc::new(crate::onion::OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(10, std::time::Duration::from_secs(60)));
        let state = ControlState::new(kp, router, allowlist);
        assert!(state.shadow_signer.is_none());
        assert_eq!(state.shadow_price_per_byte, 0);
    }

    /// Smoke-test the bearer-check primitive the node re-exports from
    /// `octravpn-core`. Originally lived inside `control.rs` as a
    /// node-local helper; the function moved to
    /// `octravpn_core::bearer::constant_time_eq_str` as part of XC-1,
    /// and this test stays on the node side so `cargo test -p
    /// octravpn-node` continues to cover the API contract every
    /// handler in this crate depends on.
    #[test]
    fn constant_time_eq_str_correctness() {
        use octravpn_core::bearer::constant_time_eq_str;
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        // Differing lengths short-circuit (acceptable).
        assert!(!constant_time_eq_str("abc", "abcd"));
        assert!(constant_time_eq_str("", ""));
    }

    /// `with_shadow_signer(None, …)` is a no-op — the field stays
    /// `None`. Verifies the wiring is additive, not destructive.
    #[test]
    fn with_shadow_signer_none_is_identity() {
        let kp = Arc::new(KeyPair::generate());
        let router = Arc::new(crate::onion::OnionRouter::new());
        let allowlist = Arc::new(BoundedMap::new(10, std::time::Duration::from_secs(60)));
        let state = ControlState::new(kp, router, allowlist).with_shadow_signer(None, 42);
        assert!(state.shadow_signer.is_none());
        assert_eq!(state.shadow_price_per_byte, 42);
    }
}
