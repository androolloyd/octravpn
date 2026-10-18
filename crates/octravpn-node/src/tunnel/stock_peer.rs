//! Stock WireGuard state follows the registered key, not its direct/DERP address.
//! Framed clients retain the original endpoint-sharded transport.
use super::{Binding, Server, SocketAddr, Tunn, TunnResult};
use anyhow::{ensure, Result};
use boringtun::noise::Packet;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct Peers(Mutex<Index>);
#[derive(Default)]
struct Index {
    keys: HashMap<[u8; 32], Arc<Identity>>,
    receivers: HashMap<u32, [u8; 32]>,
    // Boringtun reserves the low eight bits for session rotation. Never reuse
    // an allocated high24 identifier while this server is alive.
    allocated: u32,
}
pub(super) struct Identity {
    pub(super) registration: crate::stock::Registration,
    index: u32,
    retired: AtomicBool,
    state: Mutex<State>,
}
struct State {
    noise: Tunn,
    endpoint: Option<SocketAddr>,
    authenticated: u64,
    touched: Instant,
    recovery: Option<Recovery>,
}
struct Recovery {
    endpoint: SocketAddr,
    attempted: Instant,
}
const RECOVERY_INTERVAL: Duration = Duration::from_secs(5);
enum Admission {
    Existing(Arc<Identity>),
    Verified(crate::stock::Registration),
}
impl Peers {
    fn prepare(
        &self,
        registration: &crate::stock::Registration,
        packet: &[u8],
        source: SocketAddr,
        make: impl FnOnce(u32) -> Tunn,
    ) -> Option<Admission> {
        if let Some(peer) = self
            .key(&registration.node_key)
            .filter(|peer| peer.registration == *registration)
        {
            return Some(Admission::Existing(peer));
        }
        // Anonymous-static decryption/MAC1 does not prove possession of the
        // registered private key. Verify the encrypted Noise timestamp before
        // consuming any table capacity or receiver index. This index0 response
        // is discarded and never published; the admitted Tunn gets its own
        // unique index and executes the original initiation independently.
        let mut probe = make(0);
        let mut work = [0; 2048];
        match probe.decapsulate(Some(source.ip()), packet, &mut work) {
            TunnResult::WriteToNetwork(bytes)
                if bytes.get(..4) == Some([2, 0, 0, 0].as_slice()) =>
            {
                Some(Admission::Verified(registration.clone()))
            }
            _ => None,
        }
    }
    fn install(
        &self,
        admission: Admission,
        make: impl FnOnce(u32) -> Tunn,
    ) -> Option<Arc<Identity>> {
        match admission {
            Admission::Existing(peer) => self.current(&peer).then_some(peer),
            Admission::Verified(registration) => self.acquire(&registration, make),
        }
    }
    fn acquire(
        &self,
        registration: &crate::stock::Registration,
        make: impl FnOnce(u32) -> Tunn,
    ) -> Option<Arc<Identity>> {
        let mut index = self.0.lock();
        if let Some(peer) = index.keys.get(&registration.node_key) {
            if peer.registration == *registration {
                return Some(peer.clone());
            }
        }
        if let Some(previous) = index.keys.remove(&registration.node_key) {
            previous.retired.store(true, Ordering::Release);
            index.receivers.remove(&previous.index);
        }
        if index.keys.len() >= super::PEERS_CAP || index.allocated == 0x00ff_ffff {
            return None;
        }
        index.allocated += 1;
        let number = index.allocated;
        let peer = Arc::new(Identity {
            registration: registration.clone(),
            index: number,
            retired: AtomicBool::new(false),
            state: Mutex::new(State {
                noise: make(number),
                endpoint: None,
                authenticated: 0,
                touched: Instant::now(),
                recovery: None,
            }),
        });
        index.receivers.insert(number, registration.node_key);
        index.keys.insert(registration.node_key, peer.clone());
        Some(peer)
    }
    // This key is supplied only by the authenticated DERP source association,
    // never by an unauthenticated UDP packet or its guessed receiver index.
    fn recover(
        &self,
        registration: &crate::stock::Registration,
        derp_key: Option<&[u8; 32]>,
        make: impl FnOnce(u32) -> Tunn,
    ) -> Option<Arc<Identity>> {
        if derp_key != Some(&registration.node_key) {
            return None;
        }
        self.acquire(registration, make)
    }
    pub(super) fn key(&self, key: &[u8; 32]) -> Option<Arc<Identity>> {
        self.0.lock().keys.get(key).cloned()
    }
    fn receiver(&self, packet: &Packet<'_>, expected: Option<&[u8; 32]>) -> Option<Arc<Identity>> {
        let receiver = match packet {
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
            Packet::HandshakeInit(_) => return None,
        } >> 8;
        let index = self.0.lock();
        let peer = index.keys.get(index.receivers.get(&receiver)?)?;
        if expected.is_some_and(|key| *key != peer.registration.node_key) {
            return None;
        }
        Some(peer.clone())
    }
    pub(super) fn current(&self, peer: &Arc<Identity>) -> bool {
        self.with_current(peer, || Ok(())).is_ok()
    }
    pub(super) fn with_current<T>(
        &self,
        peer: &Identity,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        // The table never locks a State while holding Index. IO follows the
        // publication/registration -> State -> Index order. Removal cannot
        // retire an identity in the middle of its nonblocking send.
        let index = self.0.lock();
        ensure!(
            !peer.retired.load(Ordering::Acquire)
                && index
                    .keys
                    .get(&peer.registration.node_key)
                    .is_some_and(|current| std::ptr::eq(current.as_ref(), peer)),
            "stock WireGuard identity retired"
        );
        action()
    }
    pub(super) fn snapshot(&self) -> Vec<Arc<Identity>> {
        self.0.lock().keys.values().cloned().collect()
    }
    pub(super) fn sweep(&self) {
        // Invalid packets and index guesses never refresh this activity clock.
        for peer in self.snapshot() {
            let state = peer.state.lock();
            if state.touched.elapsed() < super::PEER_IDLE_TTL {
                continue;
            }
            let mut index = self.0.lock();
            if index
                .keys
                .get(&peer.registration.node_key)
                .is_some_and(|p| Arc::ptr_eq(p, &peer))
            {
                peer.retired.store(true, Ordering::Release);
                index.keys.remove(&peer.registration.node_key);
                index.receivers.remove(&peer.index);
            }
        }
    }
}
impl Identity {
    fn receive<'a>(
        &self,
        packet: &[u8],
        source: SocketAddr,
        work: &'a mut [u8],
    ) -> (TunnResult<'a>, Option<u64>) {
        let mut state = self.state.lock();
        let result = state.noise.decapsulate(Some(source.ip()), packet, work);
        let authenticated = match (&Tunn::parse_incoming_packet(packet), &result) {
            (Ok(Packet::HandshakeInit(_)), TunnResult::WriteToNetwork(bytes)) => {
                bytes.get(..4) == Some([2, 0, 0, 0].as_slice())
            }
            (Ok(Packet::HandshakeResponse(_)), TunnResult::WriteToNetwork(bytes)) => {
                bytes.get(..4) == Some([4, 0, 0, 0].as_slice())
            }
            (
                Ok(Packet::PacketData(_)),
                TunnResult::WriteToTunnelV4(..)
                | TunnResult::WriteToTunnelV6(..)
                | TunnResult::Done,
            ) => true,
            _ => false,
        };
        // A successful type4 Done is an authenticated empty keepalive in pinned
        // boringtun. CookieReply also returns Done, but must never roam.
        let token = if authenticated {
            state
                .authenticated
                .checked_add(1)
                .inspect(|token| state.authenticated = *token)
        } else {
            None
        };
        (result, token)
    }
    fn promote(&self, peers: &Peers, token: u64, source: SocketAddr) -> Result<()> {
        let mut state = self.state.lock();
        peers.with_current(self, || {
            ensure!(
                state.authenticated == token,
                "newer authenticated stock packet observed"
            );
            state.endpoint = Some(source);
            state.recovery = None;
            state.touched = Instant::now();
            Ok(())
        })
    }
    fn recover<'a>(
        &self,
        peers: &Peers,
        source: SocketAddr,
        now: Instant,
        work: &'a mut [u8],
    ) -> Result<TunnResult<'a>> {
        let mut state = self.state.lock();
        peers.with_current(self, || {
            if state.endpoint.is_some()
                || state.recovery.as_ref().is_some_and(|pending| {
                    now.saturating_duration_since(pending.attempted) < RECOVERY_INTERVAL
                })
            {
                return Ok(TunnResult::Done);
            }
            state.recovery = Some(Recovery {
                endpoint: source,
                attempted: now,
            });
            // A pending handshake is not reset by repeated unknown-index data.
            // Boringtun's own timers supply its normal retransmissions.
            Ok(state.noise.format_handshake_initiation(work, false))
        })
    }
    fn send_control(
        &self,
        peers: &Peers,
        socket: &tokio::net::UdpSocket,
        bytes: &[u8],
        source_current: impl FnOnce(SocketAddr) -> bool,
    ) -> std::io::Result<usize> {
        let state = self.state.lock();
        peers
            .with_current(self, || {
                let endpoint = if let Some(endpoint) = state.endpoint {
                    endpoint
                } else {
                    ensure!(
                        bytes.get(..4) == Some([1, 0, 0, 0].as_slice()),
                        "unverified stock endpoint accepts handshake initiation only"
                    );
                    let pending = state
                        .recovery
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("stock recovery endpoint unavailable"))?;
                    // Source associations are rechecked for every retry, including
                    // timer output. They never authorize transport or plaintext.
                    ensure!(
                        source_current(pending.endpoint),
                        "stock DERP recovery source changed"
                    );
                    pending.endpoint
                };
                Ok(socket.try_send_to(bytes, endpoint)?)
            })
            .map_err(std::io::Error::other)
    }
    pub(super) fn send(
        &self,
        peers: &Peers,
        socket: &tokio::net::UdpSocket,
        bytes: &[u8],
    ) -> std::io::Result<usize> {
        let state = self.state.lock();
        peers
            .with_current(self, || {
                let endpoint = state
                    .endpoint
                    .ok_or_else(|| anyhow::anyhow!("stock endpoint not authenticated"))?;
                Ok(socket.try_send_to(bytes, endpoint)?)
            })
            .map_err(std::io::Error::other)
    }
    pub(super) fn encapsulate<'a>(
        &self,
        frame: &[u8],
        work: &'a mut [u8],
    ) -> (TunnResult<'a>, bool) {
        let mut state = self.state.lock();
        super::egress::encapsulate(&mut state.noise, frame, work, true)
    }
}

impl Server {
    fn stock_current(
        &self,
        peer: &Arc<Identity>,
        action: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.stock_registration_current(&peer.registration, action)
    }
    fn stock_registration_current(
        &self,
        registration: &crate::stock::Registration,
        action: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let binding = self
            .binding(&registration.node_key)
            .ok_or_else(|| anyhow::anyhow!("stock registration unavailable"))?;
        ensure!(
            binding.stock() == Some(registration),
            "stock registration changed"
        );
        match binding {
            Binding::Paid(connection) => connection.current(action),
            Binding::StockPortal(portal) => portal.current(action),
            Binding::Legacy(_) => anyhow::bail!("stock registration required"),
        }
    }
    /// Returns true for stock identities (including refused stock packets).
    pub(super) async fn handle_stock_packet(
        &self,
        packet: &[u8],
        source: SocketAddr,
        work: &mut [u8],
    ) -> bool {
        let expected = self.payments.as_ref().and_then(|p| p.stock_source(&source));
        let Ok(parsed) = Tunn::parse_incoming_packet(packet) else {
            return expected.is_some();
        };
        if matches!(parsed, Packet::HandshakeInit(_)) {
            return false;
        }
        let peer = self.stock_peers.receiver(&parsed, expected.as_ref());
        let Some(peer) = peer else {
            if let (Some(key), Packet::PacketData(_)) = (expected.as_ref(), &parsed) {
                self.recover_stock_derp(key, source, work);
            }
            return expected.is_some();
        };
        if expected.is_some_and(|key| key != peer.registration.node_key) {
            return true;
        }
        self.process_stock_peer(peer, packet, source, work).await;
        true
    }
    fn recover_stock_derp(&self, key: &[u8; 32], source: SocketAddr, work: &mut [u8]) {
        let Some(registration) = self
            .binding(key)
            .and_then(|binding| binding.stock().cloned())
        else {
            return;
        };
        let mut peer = None;
        if self
            .stock_registration_current(&registration, &mut || {
                ensure!(
                    self.payments
                        .as_ref()
                        .and_then(|payments| payments.stock_source(&source))
                        .as_ref()
                        == Some(key),
                    "stock DERP recovery source changed"
                );
                peer = self.stock_peers.recover(&registration, Some(key), |index| {
                    Tunn::new(
                        self.static_secret.clone(),
                        super::X25519Pub::from(*key),
                        None,
                        None,
                        index,
                        Some(self.handshake_limiter.clone()),
                    )
                });
                Ok(())
            })
            .is_err()
        {
            return;
        }
        let Some(peer) = peer else {
            return;
        };
        if let Ok(TunnResult::WriteToNetwork(bytes)) =
            peer.recover(&self.stock_peers, source, Instant::now(), work)
        {
            self.send_stock_control(&peer, bytes);
        }
    }
    fn send_stock_control(&self, peer: &Arc<Identity>, bytes: &[u8]) {
        let _ = self.stock_current(peer, &mut || {
            peer.send_control(&self.stock_peers, self.outbound_sock(), bytes, |source| {
                self.payments
                    .as_ref()
                    .and_then(|payments| payments.stock_source(&source))
                    == Some(peer.registration.node_key)
            })?;
            Ok(())
        });
    }
    pub(super) async fn admit_stock(
        &self,
        registration: &crate::stock::Registration,
        packet: &[u8],
        source: SocketAddr,
        work: &mut [u8],
    ) {
        let key = registration.node_key;
        let Some(admission) = self
            .stock_peers
            .prepare(registration, packet, source, |index| {
                Tunn::new(
                    self.static_secret.clone(),
                    super::X25519Pub::from(key),
                    None,
                    None,
                    index,
                    None,
                )
            })
        else {
            return;
        };
        let mut admission = Some(admission);
        let mut peer = None;
        // Capture again under the actual publication/registration guard. An
        // older in-flight registration may not replace a newer registered key.
        if self
            .stock_registration_current(registration, &mut || {
                let admission = admission
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("stock admission already consumed"))?;
                peer = self.stock_peers.install(admission, |index| {
                    Tunn::new(
                        self.static_secret.clone(),
                        super::X25519Pub::from(key),
                        None,
                        None,
                        index,
                        Some(self.handshake_limiter.clone()),
                    )
                });
                Ok(())
            })
            .is_err()
        {
            return;
        }
        let Some(peer) = peer else {
            return;
        };
        self.process_stock_peer(peer, packet, source, work).await;
    }
    async fn process_stock_peer(
        &self,
        peer: Arc<Identity>,
        packet: &[u8],
        source: SocketAddr,
        work: &mut [u8],
    ) {
        if self
            .stock_current(&peer, &mut || {
                self.stock_peers.with_current(&peer, || Ok(()))
            })
            .is_err()
        {
            return;
        }
        let mut input = packet;
        let mut authenticated = false;
        // No stock plaintext is queued by return encapsulation. Still honor the
        // boringtun empty-input drain after control output, bounded as before.
        for iteration in 0..=256 {
            let (result, token) = peer.receive(input, source, work);
            if iteration == 0 {
                authenticated = token.is_some_and(|token| {
                    self.stock_current(&peer, &mut || {
                        peer.promote(&self.stock_peers, token, source)
                    })
                    .is_ok()
                });
            }
            let drain = matches!(&result, TunnResult::WriteToNetwork(_));
            match result {
                TunnResult::WriteToNetwork(bytes) if authenticated => {
                    let _ = self.stock_current(&peer, &mut || {
                        peer.send(&self.stock_peers, self.outbound_sock(), bytes)?;
                        Ok(())
                    });
                }
                TunnResult::WriteToNetwork(bytes)
                    if bytes.get(..4) == Some([3, 0, 0, 0].as_slice()) =>
                {
                    let _ = self.shielded_send_to(bytes, source).await;
                }
                TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _)
                    if authenticated =>
                {
                    if let Some(binding) = self
                        .binding(&peer.registration.node_key)
                        .filter(|binding| binding.stock() == Some(&peer.registration))
                    {
                        self.dispatch_stock(bytes, source, binding, peer.clone())
                            .await;
                    }
                }
                _ => {}
            }
            if !drain || !authenticated {
                break;
            }
            input = &[];
        }
    }
    pub(super) async fn stock_timers(&self, work: &mut [u8]) {
        self.stock_peers.sweep();
        for peer in self.stock_peers.snapshot() {
            if self.stock_current(&peer, &mut || Ok(())).is_err() {
                continue;
            }
            let result = peer.state.lock().noise.update_timers(work);
            if let TunnResult::WriteToNetwork(bytes) = result {
                self.send_stock_control(&peer, bytes);
            }
        }
    }
}
#[cfg(test)]
mod tests;
