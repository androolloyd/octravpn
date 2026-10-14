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
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};

pub struct Submission<A: Host> {
    pub node: Arc<Node<A>>,
    pub executor: Native,
    pub pending: Arc<Pending>,
    pub swarm: Swarm,
    pub policy: Policy,
    pub address: Vec<u8>,
}
impl<A: Host> Submission<A> {
    pub async fn submit(&self, tx: Transaction) -> Result<Vec<u8>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let draft = Arc::new(
            self.node
                .admission_capture(&self.executor.graph(), self.policy, &self.address, now)
                .await?,
        );
        self.executor.submit(draft, &self.pending, tx).await
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
        Router::new()
            .route("/status", get(status::<A>))
            .route("/account/:address", get(account::<A>))
            .route("/transactions", post(submit::<A>))
            .layer(DefaultBodyLimit::max(5_000_000))
            .with_state(self)
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
            let Ok(view) = self.node.snapshot() else {
                continue;
            };
            let ledger = account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))?;
            let mut captured = Captured {
                now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
                pending: self
                    .pending
                    .transactions()?
                    .into_iter()
                    .map(|tx| Ok((hex::encode(tx.hash()?).into_bytes(), tx)))
                    .collect::<Result<_>>()?,
                ledger,
                transactions: vec![],
                effects: vec![],
            };
            let mode = octra_node_protocol::rules::at(
                self.node.store.chain().chain_id.as_bytes(),
                octra_node_protocol::rules::Rule::ReadyExecution,
                view.head().cursor.epoch.0 as i64 + 1,
            );
            if ingress
                .receive(
                    &peer.hello().node_id,
                    &frame.payload,
                    p2p_transaction::Rules {
                        max_drift: 300.,
                        duty: Some((view.head().cursor.epoch.0 as i64, mode)),
                        bft: true,
                    },
                    &mut captured,
                )
                .is_err()
            {
                continue;
            }
            for effect in captured.effects {
                p2p_transaction::deliver(&self.swarm, &peer, effect).await?;
            }
            for tx in captured.transactions {
                if let Ok(hash) = self.submit(tx).await {
                    self.announce(hash, Some(&peer.hello().node_id)).await?;
                }
            }
        }
    }
}
struct Captured {
    now: f64,
    pending: BTreeMap<Vec<u8>, Transaction>,
    ledger: octra_node_protocol::state::Ledger,
    transactions: Vec<Transaction>,
    effects: Vec<Effect>,
}
impl p2p_transaction::Host for Captured {
    fn now(&self) -> f64 {
        self.now
    }
    fn has(&self, h: &[u8]) -> bool {
        self.pending.contains_key(h)
    }
    fn find(&self, h: &[u8]) -> Option<Transaction> {
        self.pending.get(h).cloned()
    }
    fn sender_key(&self, tx: &Transaction) -> Option<Vec<u8>> {
        self.ledger
            .account(&tx.from)
            .and_then(|a| a.public_key.clone())
            .or(tx.public_key.clone())
    }
    fn add(&mut self, tx: Transaction) -> Result<Vec<u8>, String> {
        self.transactions.push(tx);
        // Proof work and final queue admission happen outside the peer reader.
        Err("admission queued".into())
    }
    fn emit(&mut self, effect: Effect) {
        self.effects.push(effect);
    }
}
async fn status<A: Host>(State(host): State<Arc<Submission<A>>>) -> impl IntoResponse {
    let head = host.node.head().await;
    match head {
        Ok(head)=>Json(serde_json::json!({"chain_id":host.node.store.chain().chain_id,"epoch":head.cursor.epoch.0,"state_root":hex::encode(head.cursor.state_root.0),"serving":matches!(host.node.status(),crate::Status::Serving(_)),"peers":host.swarm.peers().len(),"pending":host.pending.transactions().map(|t|t.len()).ok(),"vpn_settlement":"unconfigured"})).into_response(),
        Err(_)=>(StatusCode::SERVICE_UNAVAILABLE,"canonical state unavailable").into_response(),
    }
}
async fn account<A: Host>(
    State(host): State<Arc<Submission<A>>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let result = (|| -> Result<serde_json::Value> {
        let view = host.node.snapshot()?;
        let ledger = account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))?;
        let account = ledger
            .account(address.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("account unavailable"))?;
        Ok(
            serde_json::json!({"address":address,"balance":account.balance.to_string(),"nonce":account.nonce.get(),"epoch":view.head().cursor.epoch.0}),
        )
    })();
    match result {
        Ok(v) => Json(v).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "account unavailable").into_response(),
    }
}
async fn submit<A: Host>(State(host): State<Arc<Submission<A>>>, body: Bytes) -> impl IntoResponse {
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
