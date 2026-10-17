//! Native peer services backed by authenticated canonical history. Connection
//! readers enqueue consensus work and stay available for its bundle replies.
use ed25519_dalek::{Signer, SigningKey};
use octra_node_protocol::{
    consensus::{codec::Wire, journal::JournalOwner, Bytes, Error, Finalize, ValidatorSet},
    network::{
        frame::Frame,
        session::Peer,
        swarm::{Config, Handler, MessageFuture, Swarm},
    },
};
use octra_node_runtime::{
    bundle_queries::{self, Bundles},
    canonical::{Head, Reader, ReliefSource},
    consensus_bundle::RawBundle,
    consensus_driver::Handle,
    epoch_roots::{self, EpochRoots},
    finality::history::History,
    finality_queries::{self, Finality, Range},
    validator_history::CanonicalValidators,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch},
};

fn error(e: impl std::fmt::Display) -> Error {
    e.to_string().into()
}
type Missing = (i64, Vec<epoch_roots::Response>);
mod raw_cache;
use raw_cache::RawCache;

struct Shared {
    history: Arc<dyn History>,
    reader: Reader,
    membership: CanonicalValidators,
    key: SigningKey,
    journal: JournalOwner,
    active: RwLock<ValidatorSet>,
    bundles: Mutex<RawCache>,
    driver: Mutex<Option<Handle>>,
    peer_states: Mutex<BTreeMap<Bytes, octra_node_protocol::status_rpc::consensus::Peer>>,
    missing: mpsc::Sender<Missing>,
    transactions: mpsc::Sender<(Peer, Frame)>,
    compute: mpsc::Sender<(Peer, Frame)>,
}
#[derive(Clone)]
pub struct Authority(Arc<Shared>);
impl octra_node_runtime::status_read::Consensus for Authority {
    fn snapshot(
        &self,
    ) -> Result<
        (
            Option<octra_node_runtime::consensus_driver::Diagnostics>,
            Vec<octra_node_protocol::status_rpc::consensus::Peer>,
        ),
        Error,
    > {
        let driver = self
            .driver()?
            .map(|driver| driver.diagnostics())
            .transpose()?
            .flatten();
        let peers = self
            .0
            .peer_states
            .lock()
            .map_err(error)?
            .values()
            .cloned()
            .collect();
        Ok((driver, peers))
    }
}
impl Authority {
    fn remember_peer(&self, source: &[u8], checked_epoch: i64, response: &epoch_roots::Response) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_secs_f64())
            .unwrap_or_default();
        self.0
            .peer_states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                response.responder_addr.clone(),
                octra_node_protocol::status_rpc::consensus::Peer {
                    responder_addr: response.responder_addr.clone(),
                    head_epoch: response.responder_head_epoch,
                    checked_epoch,
                    state_root: response.state_root.clone(),
                    last_seen: now,
                    source: source.to_vec(),
                },
            );
    }
    pub(crate) fn compute_validators(&self) -> ValidatorSet {
        self.0
            .active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub fn attach(&self, driver: Handle) -> Result<(), Error> {
        let mut current = self.0.driver.lock().map_err(error)?;
        if current.is_some() {
            return Err("peer services already have a driver".into());
        }
        *current = Some(driver);
        Ok(())
    }
    pub fn detach(&self) {
        if let Ok(mut current) = self.0.driver.lock() {
            *current = None;
        }
    }
    pub fn driver(&self) -> Result<Option<Handle>, Error> {
        Ok(self.0.driver.lock().map_err(error)?.clone())
    }
    pub fn set_validators(&self, validators: ValidatorSet) -> Result<(), Error> {
        *self.0.active.write().map_err(error)? = validators;
        Ok(())
    }
    pub fn cache(&self, epoch: i64, id: [u8; 32], bundle: RawBundle) -> Result<(), Error> {
        self.0
            .bundles
            .lock()
            .map_err(error)?
            .store(epoch, id, bundle)
    }
    pub fn prune(&self, committed: i64) -> Result<(), Error> {
        self.0.bundles.lock().map_err(error)?.prune(committed);
        Ok(())
    }
    async fn set_at(&self, epoch: i64) -> Result<ValidatorSet, Error> {
        if epoch < 1 {
            return Err("invalid validator epoch".into());
        }
        let current = self.0.history.head().await.map_err(error)?;
        let head = if epoch as u64 <= current.cursor.epoch.0 {
            self.0
                .reader
                .head_for_epoch((epoch - 1) as u64)
                .await
                .map_err(error)?
        } else {
            current
        };
        let relief = match self.0.reader.relief_after(&head).await.map_err(error)? {
            ReliefSource::Committed(mark) => mark,
            ReliefSource::Journal => {
                let journal = self.0.journal.clone();
                tokio::task::spawn_blocking(move || journal.latest_relief(epoch))
                    .await
                    .map_err(error)??
            }
        };
        self.0
            .membership
            .expected_set(&head, epoch, None, &|_| Ok(relief.clone()))
            .await
            .map_err(error)
    }
    pub async fn config(
        &self,
        head: &Head,
    ) -> Result<octra_node_protocol::validator::config::Config, Error> {
        self.0.membership.config(head).await.map_err(error)
    }
}
#[async_trait::async_trait]
impl bundle_queries::Host for Authority {
    fn validators(&self) -> Result<ValidatorSet, Error> {
        Ok(self.0.active.read().map_err(error)?.clone())
    }
    async fn lookup(&self, id: &[u8; 32]) -> Result<Option<RawBundle>, Error> {
        let pending = self.0.bundles.lock().map_err(error)?.lookup(id);
        if pending.is_some() {
            return Ok(pending);
        }
        self.0.history.bundle(id).await.map_err(error)
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        Ok(self.0.key.sign(bytes).to_bytes().to_vec())
    }
}
#[async_trait::async_trait]
impl finality_queries::Host for Authority {
    fn active_validators(&self) -> Result<ValidatorSet, Error> {
        bundle_queries::Host::validators(self)
    }
    async fn validators(&self, epoch: i64) -> Result<ValidatorSet, Error> {
        self.set_at(epoch).await
    }
    async fn range_plan(&self) -> Result<finality_queries::RangePlan, Error> {
        let head = self.0.history.head().await.map_err(error)?;
        let config = self.config(&head).await?;
        Ok(finality_queries::RangePlan {
            stake: config.stake,
            scheduled: config.scheduled.map(|s| (s.activate_epoch, s.validators)),
        })
    }
    async fn lookup(&self, epoch: i64, maximum: i64) -> Result<Range, Error> {
        self.0.history.range(epoch, maximum).await.map_err(error)
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        bundle_queries::Host::sign(self, bytes)
    }
    fn remember(&self, epoch: i64, response: epoch_roots::Response) {
        self.remember_peer(b"catchup_range", epoch, &response);
    }
    fn finalized(&self, peer: &Peer, finalized: Finalize) -> Result<(), Error> {
        let driver = self.driver()?.ok_or("consensus driver unavailable")?;
        driver.enqueue(
            peer,
            &Frame {
                message: 0x32,
                payload: finalized.encode()?,
            },
        )?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl epoch_roots::Host for Authority {
    async fn state(&self) -> Result<epoch_roots::State, Error> {
        let head = self.0.history.head().await.map_err(error)?;
        let epoch = i64::try_from(head.cursor.epoch.0).map_err(error)?;
        let stake = self
            .0
            .membership
            .stake_set(&head, epoch + 1)
            .await
            .map_err(error)?;
        Ok(epoch_roots::State {
            active: bundle_queries::Host::validators(self)?,
            stake,
            height: epoch + 1,
            head: epoch,
        })
    }
    async fn root(&self, epoch: i64) -> Result<Option<Bytes>, Error> {
        self.0.history.root(epoch).await.map_err(error)
    }
    fn sign(&self, bytes: &[u8]) -> Result<Bytes, Error> {
        bundle_queries::Host::sign(self, bytes)
    }
    fn remember(&self, epoch: i64, response: &epoch_roots::Response) {
        self.remember_peer(b"epoch_root", epoch, response);
    }
    async fn request_missing_finalize(
        &self,
        epoch: i64,
        responses: &[epoch_roots::Response],
    ) -> Result<(), Error> {
        self.0
            .missing
            .try_send((epoch, responses.to_vec()))
            .map_err(error)
    }
}

struct Dispatch {
    authority: Authority,
    finality: Finality<Authority>,
    roots: EpochRoots<Authority>,
    bundles: Bundles<Authority>,
}
impl Handler for Dispatch {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        let authority = self.authority.clone();
        let finality = self.finality.clone();
        let roots = self.roots.clone();
        let bundles = self.bundles.clone();
        Box::pin(async move {
            let work = async {
                if frame.message == 0x20 {
                    authority
                        .0
                        .transactions
                        .try_send((peer.clone(), frame.clone()))
                        .map_err(error)?;
                    return Ok(());
                }
                if frame.message == crate::compute::MESSAGE {
                    // Compute's bounded worker lane owns the payload after this
                    // point; peer readers remain available for consensus replies.
                    let _ = authority.0.compute.try_send((peer, frame));
                    return Ok(());
                }
                if let Some(driver) = authority.driver()? {
                    driver.enqueue(&peer, &frame)?;
                }
                finality.handle(&peer, &frame).await?;
                roots.handle(&peer, &frame).await?;
                bundles.handle(&peer, &frame).await?;
                Ok::<_, Error>(())
            };
            work.await
                .map_err(|e| octra_node_protocol::network::Error::from(e.to_string()))
        })
    }
}
pub struct Network {
    pub authority: Authority,
    pub swarm: Swarm,
    pub bundles: Bundles<Authority>,
    pub roots: EpochRoots<Authority>,
    pub finality: Finality<Authority>,
    pub inbox: Option<mpsc::Receiver<(Peer, Frame)>>,
    pub compute_inbox: Option<mpsc::Receiver<(Peer, Frame)>>,
    listener: TcpListener,
    missing: mpsc::Receiver<Missing>,
}
impl Network {
    pub fn new(
        listener: TcpListener,
        config: Config,
        key: SigningKey,
        history: Arc<dyn History>,
        reader: Reader,
        membership: CanonicalValidators,
        validators: ValidatorSet,
        journal: JournalOwner,
    ) -> Result<Self, Error> {
        let capacity = std::env::var("OCTRA_BUNDLE_CACHE_CAP").ok();
        Self::new_with_cache_inputs(
            listener,
            config,
            key,
            history,
            reader,
            membership,
            validators,
            journal,
            capacity.as_deref().map(str::as_bytes),
        )
    }
    /// Supply the effective captured startup setting rather than ambient environment.
    pub(crate) fn new_with_cache_inputs(
        listener: TcpListener,
        config: Config,
        key: SigningKey,
        history: Arc<dyn History>,
        reader: Reader,
        membership: CanonicalValidators,
        validators: ValidatorSet,
        journal: JournalOwner,
        bundle_cache_cap: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let chain = config.chain_id.clone();
        let address = config.node_address.clone();
        let swarm = Swarm::new(config, key.clone())?;
        let (send, missing) = mpsc::channel(16);
        let (transactions, inbox) = mpsc::channel(16);
        let (compute, compute_inbox) =
            mpsc::channel(octra_node_runtime::compute_service::DATA_CHANNEL_LIMIT);
        let authority = Authority(Arc::new(Shared {
            history,
            reader,
            membership,
            key,
            journal,
            active: RwLock::new(validators),
            bundles: Mutex::new(RawCache::from_inputs(bundle_cache_cap)),
            driver: Mutex::default(),
            peer_states: Mutex::default(),
            missing: send,
            transactions,
            compute,
        }));
        let started = Instant::now();
        let finality = Finality::new(
            chain.clone(),
            address.clone(),
            authority.clone(),
            swarm.clone(),
            Arc::new(move || i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)),
        );
        let roots = EpochRoots::new(
            chain.clone(),
            address.clone(),
            authority.clone(),
            swarm.clone(),
        );
        let bundles = Bundles::new(chain, address, authority.clone(), swarm.clone());
        Ok(Self {
            authority,
            swarm,
            bundles,
            roots,
            finality,
            listener,
            missing,
            inbox: Some(inbox),
            compute_inbox: Some(compute_inbox),
        })
    }
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<(), Error> {
        let _stop = Stop {
            authority: self.authority.clone(),
            finality: self.finality.clone(),
            swarm: self.swarm.clone(),
        };
        if *shutdown.borrow() {
            return Ok(());
        }
        let dispatch = Arc::new(Dispatch {
            authority: self.authority.clone(),
            finality: self.finality.clone(),
            roots: self.roots.clone(),
            bundles: self.bundles.clone(),
        });
        let swarm = self.swarm.clone();
        let mut running = Box::pin(swarm.run(self.listener, dispatch));
        let result = loop {
            tokio::select! {
                result=&mut running => break result.map_err(error),
                request=self.missing.recv() => if let Some((epoch,roots))=request { self.finality.request(epoch,&roots).await?; },
                changed=shutdown.changed() => if changed.is_err() || *shutdown.borrow_and_update() { break Ok(()); },
            }
        };
        self.authority.detach();
        self.finality.close();
        self.swarm.stop();
        result
    }
}

struct Stop {
    authority: Authority,
    finality: Finality<Authority>,
    swarm: Swarm,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.authority.detach();
        self.finality.close();
        self.swarm.stop();
    }
}
