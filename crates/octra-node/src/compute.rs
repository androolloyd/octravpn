// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Compute observes the same authenticated history as transaction execution.
//! Its peer lane cannot block consensus readers while waiting for escrow reads.
use crate::{peers::Authority, Host, Node};
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::ValidatorSet,
    network::{frame::Frame, session::Peer, swarm::Swarm},
    resource_compute::{
        call::Header,
        provider::{Config, Limits, SelfTest},
        wire::Message,
        Error, Result,
    },
    rules::{Graph, RootRead, Rule},
    transaction::RuleMode,
};
use octra_node_runtime::{
    canonical::Reader,
    circle::CircleRuntime,
    compute_deposits::{self, Funded},
    compute_history::History,
    compute_provider::{self, Dependencies as _},
    compute_service::{self, Head, HistoryWorker, Service},
};
use rand::RngCore;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
pub(crate) const MESSAGE: u8 = 0x41;
fn unavailable(error: impl std::fmt::Display) -> Error {
    Error::Unavailable(error.to_string().into_bytes())
}
struct Dependencies<A: Host> {
    node: Arc<Node<A>>,
    chain: Vec<u8>,
    address: Vec<u8>,
    key: SigningKey,
    history: Reader,
    authority: Authority,
    swarm: Swarm,
    graph: Graph,
    tester: Arc<compute_provider::Native>,
    provider: Option<compute_provider::Provider>,
}
#[async_trait::async_trait]
impl<A: Host> compute_service::Dependencies for Dependencies<A> {
    fn chain(&self) -> &[u8] {
        &self.chain
    }
    fn node(&self) -> &[u8] {
        &self.address
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(bytes).to_bytes().to_vec())
    }
    fn validators(&self) -> ValidatorSet {
        self.authority.compute_validators()
    }
    fn head(&self) -> Option<Head> {
        self.node.store.cached_head().and_then(|head| {
            i64::try_from(head.cursor.epoch.0).ok().map(|epoch| Head {
                epoch,
                state_root: head.cursor.state_root.0.to_vec(),
            })
        })
    }
    async fn state_root_at(&self, epoch: i64) -> Result<Option<Vec<u8>>> {
        self.node.history().root(epoch).await.map_err(unavailable)
    }
    async fn funding(&self, head: Head, header: Header) -> Result<Option<Funded>> {
        let epoch = u64::try_from(head.epoch).map_err(unavailable)?;
        let Some(retained) = self
            .history
            .head_for_epoch_opt(epoch)
            .await
            .map_err(unavailable)?
        else {
            return Err(Error::Unavailable(
                b"store snapshot branch missing".to_vec(),
            ));
        };
        if retained.cursor.state_root.0.as_slice() != head.state_root {
            return Err(Error::rejected(b"store snapshot root differs"));
        }
        compute_deposits::observe(
            &self.history,
            &self.chain,
            head.epoch,
            hex::encode(&head.state_root).as_bytes(),
            Some(retained.index_root.as_bytes()),
            &header,
        )
        .await
    }
    async fn self_test(&self) -> Result<SelfTest> {
        match &self.provider {
            Some(provider) => provider.self_test().await,
            None => self.tester.self_test().await,
        }
    }
    fn nonce(&self) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }
    async fn broadcast(&self, payload: Vec<u8>) -> Result<()> {
        let required = matches!(Message::decode(&payload)?, Message::Reveal(_));
        self.swarm
            .broadcast(
                Frame {
                    message: MESSAGE,
                    payload,
                },
                None,
                required,
            )
            .await
            .map_err(unavailable)
    }
    async fn send(&self, peer: Vec<u8>, payload: Vec<u8>) -> Result<()> {
        // Native send_to treats a disconnected destination as a no-op.
        let _ = self
            .swarm
            .send_to(
                &peer,
                Frame {
                    message: MESSAGE,
                    payload,
                },
            )
            .await;
        Ok(())
    }
    async fn cancel_rounds(&self) -> bool {
        let Some(head) = self.head() else {
            return false;
        };
        if head.epoch < 0 || head.epoch >= (1_i64 << 62) - 1 {
            return false;
        }
        let anchor = if let Some(plan) = self.graph.activation(Rule::VmBytes) {
            let root = match self.state_root_at(plan.anchor_epoch).await {
                Ok(Some(root)) => RootRead::Root(hex::encode(root).into_bytes()),
                Ok(None) => RootRead::Missing,
                Err(error) => RootRead::Unreadable(error.as_bytes().to_vec()),
            };
            Some((plan.anchor_epoch, root))
        } else {
            None
        };
        self.graph.mode(Rule::VmBytes, head.epoch, &|epoch| {
            anchor
                .as_ref()
                .filter(|(number, _)| *number == epoch)
                .map_or(RootRead::Missing, |(_, root)| root.clone())
        }) == Ok(RuleMode::Active)
    }
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_millis().min(i64::MAX as u128) as i64)
    }
    async fn relay(&self, source: Vec<u8>, payload: Vec<u8>) -> Result<()> {
        self.swarm
            .broadcast(
                Frame {
                    message: MESSAGE,
                    payload,
                },
                Some(&source),
                false,
            )
            .await
            .map_err(unavailable)
    }
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}
fn default_limits() -> Result<Limits> {
    match Config::from_inputs(true, |_| None)? {
        Config::Enabled(limits) => Ok(limits),
        Config::Disabled => Err(Error::Unavailable(
            b"compute default limits unavailable".to_vec(),
        )),
    }
}
pub(crate) async fn open<A: Host>(
    node: Arc<Node<A>>,
    history: Reader,
    authority: Authority,
    swarm: Swarm,
    key: SigningKey,
    address: Vec<u8>,
    runtime: CircleRuntime,
    graph: Graph,
    data: PathBuf,
    config: Config,
) -> Result<Service> {
    let chain = history.chain().chain_id.as_bytes().to_vec();
    let owner = address.clone();
    let identity = chain.clone();
    let retained = match tokio::task::spawn_blocking(move || {
        History::open(&data, &identity, &owner, 262_144, 4096)
    })
    .await
    {
        Ok(result) => result
            .map(Arc::new)
            .map_err(|error| Error::Unavailable(error.0)),
        Err(error) => Err(unavailable(error)),
    };
    let limits = match &config {
        Config::Enabled(limits) if retained.is_ok() => limits.clone(),
        _ => default_limits()?,
    };
    let native = Arc::new(compute_provider::Native::new(
        history.clone(),
        runtime,
        limits.clone(),
        tokio::runtime::Handle::current(),
    )?);
    let provider = match config {
        Config::Enabled(_) if retained.is_ok() => {
            Some(compute_provider::Provider::new(limits, native.clone()))
        }
        _ => None,
    };
    let deps = Arc::new(Dependencies {
        node,
        chain,
        address,
        key,
        history,
        authority,
        swarm,
        graph,
        tester: native,
        provider: provider.clone(),
    });
    Ok(Service::new(deps, provider, HistoryWorker::new(retained)))
}
pub(crate) async fn ingress(
    service: Service,
    mut inbox: mpsc::Receiver<(Peer, Frame)>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _=stop.wait_for(|value|*value)=>break,
            _=workers.join_next(),if !workers.is_empty()=>{},
            input=inbox.recv(),if workers.len()<16=>{
                let Some((peer,frame))=input else {break;};let service=service.clone();
                workers.spawn(async move {let _=service.on_message(peer.hello().node_id.clone(),frame.payload).await;});
            }
        }
    }
    inbox.close();
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    Ok(())
}
