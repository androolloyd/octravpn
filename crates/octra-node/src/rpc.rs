//! Loopback operator RPC and bounded transaction ingress. Submission never signs
//! for a caller and never treats queue acceptance as a canonical receipt.
use crate::{
    executor::{Native, Pending},
    import::Executor,
    Host, Node,
};
use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use octra_node_protocol::{
    native_json::Document,
    network::{frame::Frame, session::Peer, swarm::Swarm, transaction_gossip::Message},
    transaction::Transaction,
};
use octra_node_runtime::{
    account_store,
    finality::proposal::Policy,
    p2p_transaction::{self, Effect},
    state_batch::StateBatch,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
mod compute;
mod context;
pub(crate) use context::{Context, SingleOptions};
pub(crate) mod grpc;
pub(crate) mod http;
mod native;

pub struct Submission<A: Host> {
    pub node: Arc<Node<A>>,
    pub executor: Native,
    pub pending: Arc<Pending>,
    pub swarm: Swarm,
    pub policy: Policy,
    pub address: Vec<u8>,
    pub compute: Option<octra_node_runtime::compute_service::Service>,
    pub vpn_program: Option<String>,
    pub status: Option<Arc<octra_node_runtime::status_read::Service>>,
    pub tokens: Option<octra_node_runtime::token_rpc::Actor>,
    pub staging_notify: Arc<dyn Fn() + Send + Sync>,
    /// Immutable native history pagination setting captured at launch.
    pub history_epoch_limit: i64,
    pub fees: octra_node_protocol::submit_rpc::Fees,
    pub(crate) http: Arc<http::Service>,
}
impl<A: Host> Submission<A> {
    pub async fn submit_native(
        &self,
        tx: Transaction,
    ) -> std::result::Result<Vec<u8>, octra_node_runtime::admission::Error> {
        let capture = async {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
            Ok::<_, anyhow::Error>(
                self.node
                    .admission_capture(&self.executor.graph(), self.policy, &self.address, now)
                    .await?,
            )
        };
        let draft = Arc::new(capture.await.map_err(|error| {
            octra_node_runtime::admission::Error::Unavailable(error.to_string())
        })?);
        let hash = self
            .executor
            .submit_native(draft, &self.pending, tx)
            .await?;
        (self.staging_notify)();
        Ok(hash)
    }
    pub async fn submit(&self, tx: Transaction) -> Result<Vec<u8>> {
        self.submit_native(tx).await.map_err(anyhow::Error::new)
    }
    async fn submit_peer(&self, tx: Transaction) -> Result<Vec<u8>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let draft = Arc::new(
            self.node
                .admission_capture(&self.executor.graph(), self.policy, &self.address, now)
                .await?,
        );
        let hash = self.executor.submit(draft, &self.pending, tx).await?;
        (self.staging_notify)();
        Ok(hash)
    }
    pub async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()> {
        self.swarm
            .broadcast(
                Frame {
                    message: 0x20,
                    payload: Message::Inventory(vec![hash]).encode()?,
                },
                except,
                false,
            )
            .await?;
        Ok(())
    }
    pub fn router(self: Arc<Self>) -> Router {
        let swarm = self.swarm.clone();
        http::native_layer(
            router_base_with_limit(self.context(), 5_000_000 + 65_536).route(
                "/operator/peers",
                get(move || {
                    let swarm = swarm.clone();
                    async move { peer_diagnostics(&swarm) }
                }),
            ),
        )
    }

    pub async fn ingress(
        self: Arc<Self>,
        mut inbox: mpsc::Receiver<(Peer, Frame)>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut ingress = p2p_transaction::Ingress::default();
        loop {
            let Some((peer, frame)) = (tokio::select! {
                input=inbox.recv()=>input,
                _=stop.wait_for(|v|*v)=>return Ok(()),
            }) else {
                return Ok(());
            };
            let view = self.node.snapshot().ok();
            let mut captured = Captured::capture(
                self.executor.shared_transactions(),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
                self.pending.clone(),
                view.as_ref()
                    .map(|view| StateBatch::from_snapshot(view.state().clone())),
            )?;
            let duty = view.as_ref().map(|view| {
                let head = view.head().cursor.epoch.0 as i64;
                (
                    head,
                    octra_node_protocol::rules::at(
                        self.node.store.chain().chain_id.as_bytes(),
                        octra_node_protocol::rules::Rule::ReadyExecution,
                        head + 1,
                    ),
                )
            });
            if !captured.receive(
                &mut ingress,
                &peer.hello().node_id,
                &frame.payload,
                p2p_transaction::Rules {
                    max_drift: 300.,
                    duty,
                    bft: true,
                },
            )? {
                continue;
            }
            for effect in captured.effects {
                p2p_transaction::deliver(&self.swarm, &peer, effect).await?;
            }
            for tx in captured.transactions {
                if let Ok(hash) = self.submit_peer(tx).await {
                    self.announce(hash, Some(&peer.hello().node_id)).await?;
                }
            }
        }
    }
}
pub(crate) fn router(host: Arc<Context>) -> Router {
    router_with_limit(host, 5_000_000 + 65_536)
}
pub(crate) fn router_with_limit(host: Arc<Context>, maximum: usize) -> Router {
    http::native_layer(router_base_with_limit(host, maximum))
}
fn peer_diagnostics(swarm: &Swarm) -> Json<serde_json::Value> {
    let diagnostics = swarm.diagnostics();
    let mut score_reasons = BTreeMap::<String, usize>::new();
    for (_, score) in &diagnostics.scores {
        if !score.last_reason.is_empty() {
            let reason = String::from_utf8_lossy(&score.last_reason).into_owned();
            *score_reasons.entry(reason).or_default() += 1;
        }
    }
    Json(serde_json::json!({
        "connected": diagnostics.connected,
        "known": diagnostics.known,
        "public_sources": diagnostics.public_sources,
        "risks": diagnostics.risks.iter().map(|risk| String::from_utf8_lossy(risk).into_owned()).collect::<Vec<_>>(),
        "score_reasons": score_reasons,
        "connections": swarm.connection_diagnostics(),
    }))
}
fn router_base_with_limit(host: Arc<Context>, maximum: usize) -> Router {
    Router::new()
        .route("/operator/status", get(status))
        .route("/account/:address", get(account))
        .route("/transactions", post(submit))
        .route(
            "/rpc",
            post(native::handle).layer(DefaultBodyLimit::max(maximum.min(5_000_000 + 65_536))),
        )
        .merge(http::router())
        .layer(DefaultBodyLimit::max(maximum.min(5_000_000)))
        .with_state(host)
}
struct Captured {
    shared: octra_node_runtime::consensus_preverify_cache::Shared,
    now: f64,
    pending: Arc<Pending>,
    state: Option<StateBatch>,
    admitting: bool,
    failure: RefCell<Option<anyhow::Error>>,
    transactions: Vec<Transaction>,
    effects: Vec<Effect>,
}
impl Captured {
    fn capture(
        shared: octra_node_runtime::consensus_preverify_cache::Shared,
        now: f64,
        pending: Arc<Pending>,
        state: Option<StateBatch>,
    ) -> Result<Self> {
        let available = pending.ingress_read(|_| ())?.is_some();
        Ok(Self {
            shared,
            now,
            pending,
            admitting: available && state.is_some(),
            state,
            failure: RefCell::new(None),
            transactions: vec![],
            effects: vec![],
        })
    }
    fn receive(
        &mut self,
        ingress: &mut p2p_transaction::Ingress,
        peer: &[u8],
        payload: &[u8],
        rules: p2p_transaction::Rules,
    ) -> Result<bool> {
        let result = ingress.receive(peer, payload, rules, self);
        // Native callbacks cannot return a storage error. Do not mistake a
        // corrupt sender account/cache for a missing key or deliver effects
        // produced after that failed lookup.
        if let Some(error) = self.failure.take() {
            self.effects.clear();
            self.transactions.clear();
            return Err(error);
        }
        Ok(result.is_ok())
    }
    fn read<T>(&self, result: Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.failure.borrow_mut().get_or_insert(error);
                None
            }
        }
    }
}
impl p2p_transaction::Host for Captured {
    fn now(&self) -> f64 {
        self.now
    }
    fn has(&self, h: &[u8]) -> bool {
        self.read(self.pending.ingress_read(|pool| pool.find(h).is_some()))
            .flatten()
            .unwrap_or(false)
            || self
                .read(self.shared.contains(h).map_err(Into::into))
                .unwrap_or(false)
    }
    fn find(&self, h: &[u8]) -> Option<Transaction> {
        self.read(self.pending.ingress_read(|pool| pool.find(h).cloned()))
            .flatten()
            .flatten()
            .or_else(|| self.read(self.shared.find(h).map_err(Into::into)).flatten())
    }
    fn sender_key(&self, tx: &Transaction) -> Option<Vec<u8>> {
        if !self.admitting {
            return None;
        }
        let state = self.state.as_ref()?;
        self.read(account_store::load(state, &tx.from).map_err(Into::into))?
            .and_then(|a| a.public_key)
            .or_else(|| tx.public_key.clone())
    }
    fn add(&mut self, tx: Transaction) -> Result<Vec<u8>, String> {
        if self.admitting && self.failure.borrow().is_none() {
            self.transactions.push(tx);
        }
        // Proof work and final queue admission happen outside the peer reader.
        Err("admission queued".into())
    }
    fn emit(&mut self, effect: Effect) {
        self.effects.push(effect);
    }
}
#[cfg(test)]
mod gossip_tests;
async fn status(State(host): State<Arc<Context>>) -> impl IntoResponse {
    let head = host.node.head().await;
    match head {
        Ok(head) => {
            let status = host.node.status();
            let reason = match &status {
                crate::Status::Suspended(reason) => Some(reason),
                crate::Status::Serving(_) => None,
            };
            Json(serde_json::json!({
                "chain_id": host.node.chain().chain_id,
                "epoch": head.cursor.epoch.0,
                "state_root": hex::encode(head.cursor.state_root.0),
                "serving": matches!(status, crate::Status::Serving(_)),
                "suspension_reason": reason,
                "peers": host.peer_count(),
                "pending": host.pending.transactions().map(|t| t.len()).ok(),
                "vpn_settlement": if host.vpn_program.is_some() {"configured"} else {"unconfigured"},
                "vpn_program": host.vpn_program,
            }))
            .into_response()
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "canonical state unavailable",
        )
            .into_response(),
    }
}
async fn account(
    State(host): State<Arc<Context>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let result = (|| -> Result<serde_json::Value> {
        let view = host.node.snapshot()?;
        account_value(view.state(), &address, view.head().cursor.epoch.0)
    })();
    match result {
        Ok(v) => Json(v).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "account unavailable").into_response(),
    }
}
fn account_value(
    state: &octra_node_runtime::state_batch::Snapshot,
    address: &str,
    epoch: u64,
) -> Result<serde_json::Value> {
    let account = account_store::load(
        &StateBatch::from_snapshot(state.clone()),
        address.as_bytes(),
    )?
    .ok_or_else(|| anyhow::anyhow!("account unavailable"))?;
    anyhow::ensure!(
        account.encrypted_balance.as_deref() == Some(b"0")
            || octra_node_protocol::state::valid_cipher(account.encrypted_balance.as_deref()),
        "account cipher format unsupported"
    );
    Ok(
        serde_json::json!({"address":address,"balance":account.balance.to_string(),"nonce":account.nonce.get(),"epoch":epoch}),
    )
}
#[cfg(test)]
mod account_tests;
async fn submit(State(host): State<Arc<Context>>, body: Bytes) -> impl IntoResponse {
    let result = async {
        let tx = Transaction::from_document(&Document::parse(&body)?)?;
        let hash = host.submit(tx).await?;
        // Queue acceptance remains valid when a peer disconnects during gossip.
        let _ = host.announce(hash.clone(), None).await;
        Ok::<_, anyhow::Error>(String::from_utf8(hash)?)
    }
    .await;
    match result {
        Ok(hash) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"hash":hash,"status":"queued"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":e.to_string()})),
        )
            .into_response(),
    }
}
