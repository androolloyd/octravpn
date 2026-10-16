//! Native application services over the actual private Single producer. The
//! shared publication contains one immutable head and no BFT signing authority.
mod context;
mod publication;
use super::{History, Node};
use crate::{
    published::{Handle, Serving, Shared},
    Committed, Status,
};
use anyhow::{ensure, Result};
use octra_browser::{application::UnavailableHost, http::Browser};
use octra_node_protocol::network::{frame::Frame, swarm::Swarm, transaction_gossip::Message};
use octra_node_runtime::{circle_application::CanonicalApplications, circle_view};
use octravpn_node::admission::Revocation;
use publication::Bridge;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
pub struct Facade {
    node: Arc<Node>,
    bridge: Arc<Bridge>,
    published: Handle,
    refresh: Mutex<()>,
    swarm: Option<Swarm>,
}
impl Facade {
    pub async fn open(node: Arc<Node>, swarm: Option<Swarm>) -> Result<Arc<Self>> {
        let shared = Arc::new(Shared::new());
        let bridge = Arc::new(Bridge::new(shared.clone()));
        node.set_publication_hook(bridge.clone()).await?;
        bridge.initialize(node.head().await?);
        let facade = Arc::new(Self {
            node,
            bridge,
            published: Handle::new(shared),
            refresh: Mutex::new(()),
            swarm,
        });
        facade.resume().await?;
        Ok(facade)
    }
    pub(crate) fn node(&self) -> &Arc<Node> {
        &self.node
    }
    pub(crate) fn updates(&self) -> watch::Receiver<()> {
        self.bridge.subscribe()
    }
    pub(crate) fn completed_head(&self) -> Option<octra_node_runtime::canonical::Head> {
        self.bridge.completed_head()
    }
    pub(crate) fn published(&self) -> &Handle {
        &self.published
    }
    pub fn rpc_router(
        self: &Arc<Self>,
        key: &ed25519_dalek::SigningKey,
        data: &std::path::Path,
    ) -> Result<axum::Router> {
        Ok(crate::rpc::router(self.context(key, data, None)?))
    }
    pub async fn bind_gateway(
        &self,
        config: crate::gateway::Config,
    ) -> Result<crate::gateway::Service> {
        self.published.bind_gateway(config).await
    }
    pub fn snapshot(&self) -> Result<Committed> {
        Ok(self.published.shared.current()?.committed.clone())
    }
    pub fn status(&self) -> Status {
        self.published.shared.status()
    }
    pub(crate) fn peer_count(&self) -> usize {
        self.swarm.as_ref().map_or(0, |s| s.peers().len())
    }
    pub(crate) async fn announce(&self, hash: Vec<u8>, except: Option<&[u8]>) -> Result<()> {
        if let Some(swarm) = &self.swarm {
            swarm
                .broadcast(
                    Frame {
                        message: 0x20,
                        payload: Message::Inventory(vec![hash]).encode()?,
                    },
                    except,
                    false,
                )
                .await?;
        }
        Ok(())
    }
    pub async fn resume(&self) -> Result<bool> {
        let _refresh = self.refresh.lock().await;
        let lease = self.bridge.capture()?;
        let store = self.node.store();
        // Local signature + exact retained head/events, never QC verification.
        if lease.head.cursor.sequence.0 > 0 {
            ensure!(
                store.record(lease.head.cursor.sequence).await?.head == lease.head,
                "local record head changed"
            );
        }
        let assets = store.assets().await?;
        ensure!(
            assets.identity().epoch == lease.head.cursor.epoch.0
                && assets.identity().irmin_commit == lease.head.irmin_commit
                && assets.identity().state_root == hex::encode(lease.head.cursor.state_root.0),
            "local assets head changed"
        );
        let native = self.node.executor();
        let profile = circle_view::canonical_with_graph(
            &assets,
            &crate::import::Executor::graph(native),
            &History(store.clone()),
        )
        .await?;
        let revocation = Revocation::default();
        let application =
            CanonicalApplications::new(assets.clone(), native.circle_runtime(), profile)
                .with_wallet(Arc::new(crate::Wallet {
                    host: Arc::new(UnavailableHost),
                    revocation: revocation.clone(),
                }));
        let router = Browser::new(Arc::new(assets.clone()), "")?
            .with_application(Arc::new(application))?
            .router();
        Ok(self.bridge.install(
            &lease,
            Serving {
                committed: Committed {
                    head: lease.head.clone(),
                    assets,
                },
                router,
                revocation,
            },
        ))
    }
    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) -> Result<()> {
        let mut changed = self.bridge.subscribe();
        loop {
            tokio::select! {
                _=stop.wait_for(|value|*value)=>break,
                value=changed.changed()=>{if value.is_err(){break;}}
                ()=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}
            }
            if *stop.borrow() {
                break;
            }
            if !matches!(self.status(), Status::Serving(_)) {
                let _ = self.resume().await;
            }
        }
        self.bridge.close();
        Ok(())
    }
    pub fn close(&self) {
        self.bridge.close();
    }
}
impl Drop for Facade {
    fn drop(&mut self) {
        self.bridge.close();
    }
}
