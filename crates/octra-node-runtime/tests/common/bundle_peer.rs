//! Authenticated loopback peers for bundle/finality integration tests only.
#![allow(dead_code)] // Each integration target uses a different subset of controls.
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{Bytes, CatchupEpochRecord, Error, Finalize, ValidatorSet},
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{Config, Handler, MessageFuture, Swarm},
    },
};
use octra_node_runtime::epoch_roots::{self, EpochRoots};
use octra_node_runtime::finality_queries::{self, Finality, Range};
use octra_node_runtime::{
    bundle_queries::{Bundles, Host},
    consensus_bundle::RawBundle,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};
const WAIT: Duration = Duration::from_secs(10);
#[derive(Clone)]
pub(crate) struct Authority {
    pub(crate) history: Arc<Mutex<Option<Arc<dyn octra_node_runtime::finality::history::History>>>>,
    pub(crate) withheld: Arc<Mutex<BTreeSet<[u8; 32]>>>,
    pub(crate) ranges: Arc<Mutex<BTreeMap<i64, CatchupEpochRecord>>>,
    pub(crate) range_requests: Arc<Mutex<Vec<(i64, i64)>>>,
    pub(crate) finalities: Arc<Mutex<Vec<Finalize>>>,
    pub(crate) observations: Arc<Mutex<Vec<(i64, octra_node_runtime::epoch_roots::Response)>>>,
    pub(crate) key: SigningKey,
    pub(crate) address: Bytes,
    pub(crate) validators: ValidatorSet,
    pub(crate) activation: Arc<Mutex<Option<i64>>>,
    pub(crate) range_plan_error: Arc<AtomicBool>,
    pub(crate) cached: Arc<Mutex<BTreeMap<[u8; 32], RawBundle>>>,
    pub(crate) requests: Arc<Mutex<Vec<[u8; 32]>>>,
    pub(crate) corrupt: Arc<AtomicBool>,
    pub(crate) duplicate: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl Host for Authority {
    fn validators(&self) -> Result<ValidatorSet, Error> {
        Ok(self.validators.clone())
    }
    async fn lookup(&self, id: &[u8; 32]) -> Result<Option<RawBundle>, Error> {
        self.requests.lock().unwrap().push(*id);
        if self.withheld.lock().unwrap().contains(id) {
            return Ok(None);
        }
        let history = self.history.lock().unwrap().clone();
        if let Some(history) = history {
            return history
                .bundle(id)
                .await
                .map_err(|e| Error::from(e.to_string()));
        }
        Ok(self.cached.lock().unwrap().get(id).cloned())
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Ok(if self.corrupt.load(Ordering::SeqCst) {
            vec![0; 64]
        } else {
            self.key.sign(bytes).to_bytes().to_vec()
        })
    }
}
#[async_trait::async_trait]
impl finality_queries::Host for Authority {
    fn active_validators(&self) -> Result<ValidatorSet, Error> {
        Host::validators(self)
    }
    async fn range_plan(&self) -> Result<finality_queries::RangePlan, Error> {
        if self.range_plan_error.load(Ordering::SeqCst) {
            return Err("fixture range acquisition unavailable".into());
        }
        Ok(finality_queries::RangePlan {
            stake: self.validators.clone(),
            scheduled: self
                .activation
                .lock()
                .unwrap()
                .map(|epoch| (epoch, self.validators.clone())),
        })
    }
    async fn validators(&self, _: i64) -> Result<ValidatorSet, Error> {
        Host::validators(self)
    }
    async fn lookup(&self, epoch: i64, max: i64) -> Result<Range, Error> {
        self.range_requests.lock().unwrap().push((epoch, max));
        let history = self.history.lock().unwrap().clone();
        if let Some(history) = history {
            return history
                .range(epoch, max)
                .await
                .map_err(|e| Error::from(e.to_string()));
        }
        let record = self
            .ranges
            .lock()
            .unwrap()
            .get(&epoch)
            .filter(|_| max > 0)
            .cloned();
        Ok(record.map_or(Range::NotFound, |record| Range::Found {
            records: vec![record],
            next_epoch: Some(epoch + 1),
        }))
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Host::sign(self, bytes)
    }
    fn remember(&self, epoch: i64, response: octra_node_runtime::epoch_roots::Response) {
        self.observations.lock().unwrap().push((epoch, response));
    }
    fn finalized(&self, _: &Peer, finalized: Finalize) -> Result<(), Error> {
        self.finalities.lock().unwrap().push(finalized);
        Ok(())
    }
}
#[async_trait::async_trait]
impl epoch_roots::Host for Authority {
    async fn state(&self) -> Result<epoch_roots::State, Error> {
        let history = self.history.lock().unwrap().clone();
        let fixture_head = self
            .ranges
            .lock()
            .unwrap()
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0);
        let head = if let Some(history) = history {
            history
                .head()
                .await
                .map_err(|e| Error::from(e.to_string()))?
                .cursor
                .epoch
                .0 as i64
        } else {
            fixture_head
        };
        Ok(epoch_roots::State {
            active: self.validators.clone(),
            stake: self.validators.clone(),
            height: head + 1,
            head,
        })
    }
    async fn root(&self, epoch: i64) -> Result<Option<Bytes>, Error> {
        let history = self.history.lock().unwrap().clone();
        if let Some(history) = history {
            return history
                .root(epoch)
                .await
                .map_err(|e| Error::from(e.to_string()));
        }
        Ok(self
            .ranges
            .lock()
            .unwrap()
            .get(&epoch)
            .map(|r| r.state_root.clone()))
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Host::sign(self, bytes)
    }
    fn remember(&self, epoch: i64, response: &epoch_roots::Response) {
        self.observations
            .lock()
            .unwrap()
            .push((epoch, response.clone()));
    }
    async fn request_missing_finalize(
        &self,
        _: i64,
        _: &[epoch_roots::Response],
    ) -> Result<(), Error> {
        Ok(())
    }
}
struct Dispatch {
    consensus: Arc<Mutex<Option<octra_node_runtime::consensus_driver::Handle>>>,
    seen: Arc<Mutex<Vec<Frame>>>,
    finality: Finality<Authority>,
    roots: EpochRoots<Authority>,
    bundles: Bundles<Authority>,
    authority: Authority,
    gate: watch::Receiver<bool>,
}
impl Handler for Dispatch {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let consensus = self.consensus.lock().unwrap().clone();
        let seen = self.seen.clone();
        let service = self.bundles.clone();
        let finality = self.finality.clone();
        let roots = self.roots.clone();
        let repeat = frame.message == 0x36 && self.authority.duplicate.load(Ordering::SeqCst);
        let mut gate = self.gate.clone();
        Box::pin(async move {
            if let Some(consensus) = consensus {
                consensus
                    .enqueue(&peer, &frame)
                    .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            }
            if matches!(frame.message, 0x37 | 0x39 | 0x3b) {
                while !*gate.borrow_and_update() {
                    if gate.changed().await.is_err() {
                        return Ok(());
                    }
                }
            }
            finality
                .handle(&peer, &frame)
                .await
                .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            roots
                .handle(&peer, &frame)
                .await
                .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            service
                .handle(&peer, &frame)
                .await
                .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            if repeat {
                service
                    .handle(&peer, &frame)
                    .await
                    .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))?;
            }
            seen.lock().unwrap().push(frame);
            Ok(())
        })
    }
}
pub(crate) struct Node {
    pub(crate) consensus: Arc<Mutex<Option<octra_node_runtime::consensus_driver::Handle>>>,
    pub(crate) seen: Arc<Mutex<Vec<Frame>>>,
    pub(crate) finality: Finality<Authority>,
    pub(crate) roots: EpochRoots<Authority>,
    pub(crate) clock: Arc<AtomicI64>,
    pub(crate) swarm: Swarm,
    pub(crate) endpoint: Endpoint,
    pub(crate) bundles: Bundles<Authority>,
    pub(crate) authority: Authority,
    pub(crate) gate: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Drop for Node {
    fn drop(&mut self) {
        self.swarm.stop();
        self.task.abort();
    }
}
pub(crate) async fn node(
    chain: &[u8],
    address: Bytes,
    key: SigningKey,
    validators: ValidatorSet,
    bootstrap: Vec<Endpoint>,
) -> Node {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint {
        host: b"127.0.0.1".to_vec(),
        port: listener.local_addr().unwrap().port(),
    };
    let swarm = Swarm::new(
        Config {
            chain_id: chain.to_vec(),
            node_address: address.clone(),
            config_hash: vec![1; 32],
            binary_hash: vec![2; 32],
            require_binary_hash: false,
            upgrade: None,
            profiles: vec![],
            allowed_public_keys: validators
                .validators
                .iter()
                .map(|v| v.pubkey.clone())
                .collect(),
            bootstrap,
            maximum_validators: 16,
            advertised: endpoint.clone(),
            timeouts: Timeouts {
                handshake_read: WAIT,
                read_idle: Duration::from_secs(60),
                write_idle: WAIT,
            },
            head: Arc::new(|| (0, [0; 32])),
        },
        key.clone(),
    )
    .unwrap();
    let authority = Authority {
        activation: Arc::default(),
        range_plan_error: Arc::default(),
        history: Arc::default(),
        withheld: Arc::default(),
        ranges: Arc::default(),
        range_requests: Arc::default(),
        finalities: Arc::default(),
        observations: Arc::default(),
        key,
        address: address.clone(),
        validators,
        cached: Arc::default(),
        requests: Arc::default(),
        corrupt: Arc::default(),
        duplicate: Arc::default(),
    };
    let clock = Arc::new(AtomicI64::new(0));
    let monotonic = clock.clone();
    let finality = Finality::new(
        chain.to_vec(),
        address.clone(),
        authority.clone(),
        swarm.clone(),
        Arc::new(move || monotonic.load(Ordering::SeqCst)),
    );
    let roots = EpochRoots::new(
        chain.to_vec(),
        address.clone(),
        authority.clone(),
        swarm.clone(),
    );
    let bundles = Bundles::new(chain.to_vec(), address, authority.clone(), swarm.clone());
    let (gate, receive) = watch::channel(true);
    let seen = Arc::new(Mutex::new(vec![]));
    let consensus = Arc::default();
    let dispatch = Arc::new(Dispatch {
        consensus: Arc::clone(&consensus),
        seen: seen.clone(),
        finality: finality.clone(),
        roots: roots.clone(),
        bundles: bundles.clone(),
        authority: authority.clone(),
        gate: receive,
    });
    let runner = swarm.clone();
    let task = tokio::spawn(async move {
        runner.run(listener, dispatch).await.unwrap();
    });
    Node {
        consensus,
        seen,
        finality,
        roots,
        clock,
        swarm,
        endpoint,
        bundles,
        authority,
        gate,
        task,
    }
}
pub(crate) async fn wait_for(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
