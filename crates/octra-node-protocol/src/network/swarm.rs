// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Authenticated peer lifecycle, discovery and transport profile transitions.
use super::{
    budget::PeerClass,
    endpoint::Endpoint,
    frame::Frame,
    guard::{self, Bad, Guard},
    handshake::{self, Profile},
    peer_record::{self, Record, Registry},
    session::{Connection, Driver, LocalNode, Peer, Timeouts},
    swarm_policy::{self as policy, Direction},
    upgrade::{self, Plan},
    Error,
};
use ed25519_dalek::SigningKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{watch, Notify},
    task::JoinSet,
};
mod service;

pub type MessageFuture = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;
pub trait Handler: Send + Sync + 'static {
    fn connected(&self, _peer: Peer) {}
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture;
}
#[derive(Clone, Debug)]
pub struct Activation {
    pub epoch: i64,
    pub config_hash: Vec<u8>,
    pub profile_hash: Vec<u8>,
}
pub struct Config {
    pub chain_id: Vec<u8>,
    pub node_address: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub binary_hash: Vec<u8>,
    pub require_binary_hash: bool,
    pub upgrade: Option<Plan>,
    pub profiles: Vec<Activation>,
    pub allowed_public_keys: Vec<Vec<u8>>,
    pub bootstrap: Vec<Endpoint>,
    pub maximum_validators: i64,
    pub advertised: Endpoint,
    pub timeouts: Timeouts,
    /// Read the locally authenticated canonical head, never a peer's announcement.
    pub head: Arc<dyn Fn() -> (i64, [u8; 32]) + Send + Sync>,
}
struct Slot {
    peer: Peer,
    direction: Direction,
    offered: BTreeMap<i64, Vec<u8>>,
    remote_host: Vec<u8>,
}
struct State {
    started: bool,
    running: bool,
    generation: u64,
    active_hash: Vec<u8>,
    validators: Option<Vec<Vec<u8>>>,
    peers: BTreeMap<Vec<u8>, Slot>,
    registry: Registry,
    guard: Guard,
    dialing: BTreeSet<Vec<u8>>,
    record_dialing: BTreeSet<Vec<u8>>,
    due: BTreeMap<Vec<u8>, f64>,
    relayed: super::peer_diag::Relayed,
    proxy: Option<std::net::SocketAddr>,
}
struct Inner {
    config: Config,
    key: SigningKey,
    node_id: Vec<u8>,
    state: Mutex<State>,
    stop: watch::Sender<bool>,
    wake: Notify,
}
#[derive(Clone)]
pub struct Swarm(Arc<Inner>);
pub const SEND_DEADLINE: Duration = Duration::from_secs(2);
impl Swarm {
    pub fn new(config: Config, key: SigningKey) -> Result<Self, Error> {
        // Native codecs validate exact hash representations at their boundary.
        upgrade::handshake_hash(
            0,
            &config.config_hash,
            &config.binary_hash,
            config.require_binary_hash,
            config.upgrade.as_ref(),
        )?;
        if config.config_hash.len() != 32 || config.binary_hash.len() != 32 {
            return Err("swarm configuration hashes must contain 32 bytes".into());
        }
        // Native admission lists can overlap active and scheduled keys. The
        // independently installed active set is validated by set_validators.
        let validators =
            (!config.allowed_public_keys.is_empty()).then(|| config.allowed_public_keys.clone());
        let (stop, _) = watch::channel(false);
        let state = State {
            started: false,
            running: false,
            generation: 0,
            active_hash: config.config_hash.clone(),
            validators,
            peers: BTreeMap::new(),
            registry: Registry::default(),
            guard: Guard::default(),
            dialing: BTreeSet::new(),
            record_dialing: BTreeSet::new(),
            due: BTreeMap::new(),
            relayed: super::peer_diag::Relayed::default(),
            proxy: None,
        };
        Ok(Self(Arc::new(Inner {
            node_id: handshake::node_id(&key.verifying_key().to_bytes()),
            key,
            config,
            state: Mutex::new(state),
            stop,
            wake: Notify::new(),
        })))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().expect("swarm state poisoned")
    }
    /// Select a local transport before startup. This changes neither peer
    /// identity admission nor validator membership, and has no direct fallback.
    pub fn set_proxy(&self, proxy: std::net::SocketAddr) -> Result<(), Error> {
        super::proxy::validate(proxy)?;
        let mut state = self.state();
        if state.started {
            return Err("P2P proxy must be selected before swarm startup".into());
        }
        state.proxy = Some(proxy);
        Ok(())
    }
    pub fn node_id(&self) -> &[u8] {
        &self.0.node_id
    }
    pub fn direction(&self, peer_id: &[u8]) -> Option<Direction> {
        self.state().peers.get(peer_id).map(|p| p.direction)
    }
    pub fn profile_offer(&self, peer_id: &[u8], epoch: i64) -> Option<Vec<u8>> {
        self.state()
            .peers
            .get(peer_id)?
            .offered
            .get(&epoch)
            .cloned()
    }
    fn local_validator(&self, s: &State) -> bool {
        policy::local_is_validator(
            s.validators.as_deref(),
            &self.0.key.verifying_key().to_bytes(),
        )
    }
    fn accepts_observers(&self, s: &State) -> bool {
        policy::accepts_observers(
            s.validators.as_deref(),
            &self.0.key.verifying_key().to_bytes(),
        )
    }
    fn counts(s: &State) -> (i64, i64) {
        s.peers
            .iter()
            .filter(|(_, p)| p.peer.is_connected())
            .fold((0, 0), |(v, o), (id, _)| {
                match policy::role(s.validators.as_deref(), id) {
                    PeerClass::Validator => (v + 1, o),
                    PeerClass::Observer => (v, o + 1),
                }
            })
    }
    fn capacity(&self, s: &State, role: PeerClass) -> bool {
        let (v, o) = Self::counts(s);
        policy::capacity(self.0.config.maximum_validators, v, o, role)
    }
    fn epoch(&self, s: &State) -> i64 {
        let current = (self.0.config.head)().0;
        self.0
            .config
            .profiles
            .iter()
            .find(|p| p.config_hash == s.active_hash)
            .map_or(current, |p| current.max(p.epoch))
    }
    fn transport_hash(&self, epoch: i64, config: &[u8]) -> Result<Vec<u8>, Error> {
        upgrade::handshake_hash(
            epoch,
            config,
            &self.0.config.binary_hash,
            self.0.config.require_binary_hash,
            self.0.config.upgrade.as_ref(),
        )
    }
    fn hello(&self, listen_port: u16) -> Result<LocalNode, Error> {
        let s = self.state();
        let epoch = self.epoch(&s);
        Ok(LocalNode {
            chain_id: self.0.config.chain_id.clone(),
            node_address: self.0.config.node_address.clone(),
            config_hash: self
                .transport_hash(epoch, &s.active_hash)?
                .try_into()
                .map_err(|_| Error::from("invalid transport hash"))?,
            listen_port,
            best_epoch: epoch,
            best_root: (self.0.config.head)().1,
        })
    }
    pub fn peers(&self) -> Vec<Peer> {
        let mut s = self.state();
        s.peers.retain(|_, p| p.peer.is_connected());
        s.peers.values().map(|p| p.peer.clone()).collect()
    }
    pub fn records(&self) -> Vec<Record> {
        self.state().registry.values(now()).cloned().collect()
    }
    pub fn scores(&self) -> Vec<(Vec<u8>, guard::Score)> {
        self.state()
            .guard
            .snapshot()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect()
    }
    pub fn diagnostics(&self) -> super::peer_diag::Diagnostics {
        let mut s = self.state();
        s.peers.retain(|_, slot| slot.peer.is_connected());
        let connected = s
            .peers
            .values()
            .map(|slot| slot.remote_host.clone())
            .collect::<Vec<_>>();
        let records = s.registry.values(now()).cloned().collect::<Vec<_>>();
        let scores = s
            .guard
            .snapshot()
            .map(|(key, score)| (key.to_vec(), score.clone()))
            .collect();
        super::peer_diag::Diagnostics::make(&connected, &records, scores, s.relayed.clone(), 2)
    }
    pub fn set_validators(&self, keys: Vec<Vec<u8>>) -> Result<(), Error> {
        policy::validate_validators(&keys)?;
        let mut s = self.state();
        if s.validators.as_ref() == Some(&keys) {
            return Ok(());
        }
        s.validators = Some(keys);
        for (id, p) in &s.peers {
            p.peer
                .set_peer_class(policy::role(s.validators.as_deref(), id));
        }
        s.registry.clear();
        s.due.clear();
        Ok(())
    }
    /// Apply the latest locally configured activation reached during startup,
    /// catch-up or live consensus. A peer's offered profile is never authority.
    pub fn advance_profile(&self, epoch: i64) -> Result<Option<Vec<u8>>, Error> {
        let activation = self
            .0
            .config
            .profiles
            .iter()
            .filter(|p| p.epoch <= epoch)
            .max_by_key(|p| p.epoch);
        activation.map(|p| self.switch_profile(p.epoch)).transpose()
    }
    pub fn switch_profile(&self, epoch: i64) -> Result<Vec<u8>, Error> {
        let profile = self
            .0
            .config
            .profiles
            .iter()
            .find(|p| p.epoch == epoch)
            .ok_or_else(|| Error::from("profile switch is absent"))?;
        let mut s = self.state();
        if self
            .0
            .config
            .profiles
            .iter()
            .find(|p| p.config_hash == s.active_hash)
            .is_some_and(|p| epoch < p.epoch)
        {
            return Err("profile switch precedes active profile".into());
        }
        let target = self.transport_hash(epoch, &profile.config_hash)?;
        if s.active_hash == profile.config_hash {
            return Ok(profile.profile_hash.clone());
        }
        s.active_hash.clone_from(&profile.config_hash);
        s.registry.clear();
        s.due.clear();
        s.peers.retain(|_, p| {
            let keep = policy::keep_profile(
                &target,
                &p.peer.hello().config_hash,
                p.offered.get(&epoch).map(Vec::as_slice),
            );
            if !keep {
                p.peer.close();
            }
            keep
        });
        Ok(profile.profile_hash.clone())
    }
    pub fn report_bad(&self, peer_id: &[u8], reason: &[u8]) {
        let mut s = self.state();
        if let Bad::Banned(_) = s.guard.report(
            guard::Config::default(),
            now(),
            &guard::identity_key(peer_id),
            reason,
        ) {
            if let Some(p) = s.peers.get(peer_id) {
                p.peer.close();
            }
        }
    }
    /// Charge the authenticated identity, closing this connection if banned.
    /// A retired connection must not close a replacement session for its peer.
    pub fn report_peer(&self, peer: &Peer, reason: &[u8]) {
        if let Bad::Banned(_) = self.state().guard.report(
            guard::Config::default(),
            now(),
            &guard::identity_key(&peer.hello().node_id),
            reason,
        ) {
            peer.close();
        }
    }
    pub async fn send_to(&self, id: &[u8], frame: Frame) -> bool {
        let peer = self.state().peers.get(id).map(|p| p.peer.clone());
        match peer {
            Some(peer) => peer.enqueue(frame, SEND_DEADLINE).await,
            None => false,
        }
    }
    pub async fn broadcast(
        &self,
        frame: Frame,
        except: Option<&[u8]>,
        required: bool,
    ) -> Result<(), Error> {
        let mut sends = JoinSet::new();
        for peer in self
            .peers()
            .into_iter()
            .filter(|p| Some(p.hello().node_id.as_slice()) != except)
        {
            let frame = frame.clone();
            sends.spawn(async move { peer.enqueue(frame, SEND_DEADLINE).await });
        }
        let mut any = false;
        while let Some(sent) = sends.join_next().await {
            any |= sent.unwrap_or(false);
        }
        if required && !any {
            Err("broadcast queues unavailable".into())
        } else {
            Ok(())
        }
    }
    fn install(
        &self,
        generation: u64,
        direction: Direction,
        connection: Connection<TcpStream>,
        remote_host: Vec<u8>,
    ) -> Result<Option<(Peer, Driver<TcpStream>)>, Error> {
        let mut s = self.state();
        let hello = connection.peer();
        let id = &hello.node_id;
        if !s.running
            || s.generation != generation
            || id == self.node_id()
            || hello.config_hash != self.transport_hash(self.epoch(&s), &s.active_hash)?
            || s.guard.is_banned(now(), &guard::identity_key(id))
        {
            return Ok(None);
        }
        let role = policy::role(s.validators.as_deref(), id);
        if let Some(existing) = s.peers.get(id) {
            if !policy::replace_existing(
                self.node_id(),
                id,
                direction,
                existing.direction,
                existing.peer.is_connected(),
            ) {
                return Ok(None);
            }
            existing.peer.close();
        } else if (role == PeerClass::Observer && !self.accepts_observers(&s))
            || !self.capacity(&s, role)
        {
            return Ok(None);
        }
        let (peer, driver) = connection.into_driver()?;
        peer.set_peer_class(role);
        s.peers.insert(
            peer.hello().node_id.clone(),
            Slot {
                peer: peer.clone(),
                direction,
                offered: BTreeMap::new(),
                remote_host,
            },
        );
        Ok(Some((peer, driver)))
    }
    fn my_record(&self, s: &State) -> Result<Record, Error> {
        let config = &self.0.config;
        let mut record = Record {
            chain_id: config.chain_id.clone(),
            node_id: Vec::new(),
            node_address: config.node_address.clone(),
            public_key: Vec::new(),
            binary_hash: config.binary_hash.clone(),
            config_hash: s.active_hash.clone(),
            host: config.advertised.host.clone(),
            port: i64::from(config.advertised.port),
            features: vec![b"bft".to_vec(), b"pex".to_vec()],
            timestamp: now() as i64,
            signature: Vec::new(),
        };
        record.sign(&self.0.key)?;
        Ok(record)
    }
    async fn send_peers(&self, peer: &Peer) -> Result<(), Error> {
        let records = {
            let mut s = self.state();
            let own = if self.local_validator(&s) {
                Some(self.my_record(&s)?)
            } else {
                None
            };
            own.into_iter()
                .chain(s.registry.values(now()).cloned())
                .take(32)
                .collect::<Vec<_>>()
        };
        peer.enqueue_wait(Frame {
            message: 0x11,
            payload: peer_record::encode_list(&records)?,
        })
        .await;
        Ok(())
    }
    async fn exchange(&self, peer: &Peer) -> Result<(), Error> {
        self.send_peers(peer).await?;
        peer.enqueue_wait(Frame {
            message: 0x10,
            payload: vec![],
        })
        .await;
        Ok(())
    }
    async fn send_profiles(&self, peer: &Peer) -> Result<(), Error> {
        for p in &self.0.config.profiles {
            let profile = Profile::new(
                &self.0.config.chain_id,
                self.node_id(),
                p.epoch,
                self.transport_hash(p.epoch, &p.config_hash)?
                    .try_into()
                    .map_err(|_| Error::from("invalid profile hash"))?,
                &self.0.key,
            )?;
            peer.enqueue_wait(Frame {
                message: 0x12,
                payload: profile.encode()?,
            })
            .await;
        }
        Ok(())
    }
    fn accept_records(&self, records: Vec<Record>) {
        let mut s = self.state();
        let epoch = self.epoch(&s);
        let config = &self.0.config;
        let binary =
            upgrade::binary_required(epoch, config.require_binary_hash, config.upgrade.as_ref())
                .then(|| {
                    upgrade::expected_binary(epoch, &config.binary_hash, config.upgrade.as_ref())
                });
        for record in records {
            match record.validate(
                &config.chain_id,
                &s.active_hash,
                binary,
                &config.allowed_public_keys,
            ) {
                Err(reason) => s.relayed.reject(reason.as_bytes()),
                Ok(()) => {
                    if record.node_id == self.node_id() {
                        s.relayed.accept(false);
                    } else {
                        match s.registry.add(now(), record) {
                            Ok(added) => s.relayed.accept(added == peer_record::Added::New),
                            Err(reason) => s.relayed.reject(reason.as_bytes()),
                        }
                    }
                }
            }
        }
        self.0.wake.notify_one();
    }
    async fn handle(&self, handler: &dyn Handler, peer: Peer, frame: Frame) -> Result<(), Error> {
        match frame.message {
            0x10 => self.send_peers(&peer).await,
            0x11 => {
                match peer_record::decode_list(&frame.payload) {
                    Ok(records) => self.accept_records(records),
                    Err(_) => self.report_peer(&peer, b"invalid_frame_peers"),
                }
                Ok(())
            }
            0x12 => {
                let result = Profile::decode(&frame.payload)
                    .map_err(|_| Error::from("invalid_frame_profile"))
                    .and_then(|p| {
                        p.validate(
                            &self.0.config.chain_id,
                            &peer.hello().node_id,
                            &peer.hello().public_key,
                        )?;
                        Ok(p)
                    });
                match result {
                    Err(e) => self.report_peer(&peer, e.as_bytes()),
                    Ok(p) => {
                        if self
                            .0
                            .config
                            .profiles
                            .iter()
                            .any(|expected| expected.epoch == p.epoch)
                        {
                            if let Some(slot) = self.state().peers.get_mut(&peer.hello().node_id) {
                                slot.offered.insert(p.epoch, p.config_hash);
                            }
                        }
                    }
                }
                Ok(())
            }
            _ => handler.message(peer, frame).await,
        }
    }
    /// The listener is supplied by the host so binding errors precede startup.
    pub async fn run(&self, listener: TcpListener, handler: Arc<dyn Handler>) -> Result<(), Error> {
        service::run(self.clone(), listener, handler).await
    }
    pub fn stop(&self) {
        let mut s = self.state();
        s.running = false;
        for p in s.peers.values() {
            p.peer.close();
        }
        self.0.stop.send_replace(true);
    }
}
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}
